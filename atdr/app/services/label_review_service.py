"""Apply a human label review to reviewed ML labels without rewriting history.

A review decides, per source, whether traffic the team labeled differently
from detection is a real threat or normal. Each decision is added as a new
reviewed label (label_source "reviewed_import", a human provenance across
the ML code); earlier labels stay as history and the latest label wins.
Decisions that match the current label write nothing, so re-applying the
same review is a no-op.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, MLLabel
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.services.detection_scoreboard_service import THREAT_LABELS
from atdr.app.services.ml_label_service import VALID_ATTACK_TYPES

LABEL_SOURCE = "reviewed_import"
REVIEW_CONFIDENCE = 3
HARMLESS_DECISIONS = {"Normal": "benign", "Normal but unusual": "benign_unusual"}
THREAT_DECISION = "Real threat"
NO_CHANGE_DECISIONS = {"Unsure", "Decide per source", "", None}


@dataclass(frozen=True)
class LabelChange:
    log_id: int
    source_ip: str
    pattern: str
    decision: str
    from_label: str | None
    to_label: str
    attack_type: str
    note: str


def _latest_labels(db: Session, log_ids: list[int]) -> dict[int, MLLabel]:
    latest: dict[int, MLLabel] = {}
    for start in range(0, len(log_ids), 900):
        rows = db.scalars(
            select(MLLabel)
            .where(MLLabel.log_id.in_(log_ids[start:start + 900]), MLLabel.reviewed.is_(True))
            .order_by(MLLabel.id)
        )
        for row in rows:
            latest[row.log_id] = row
    return latest


def plan_label_review(db: Session, decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Work out which labels a review would add, without writing anything."""

    log_ids = sorted({int(log_id) for item in decisions for log_id in item.get("log_ids", [])})
    latest = _latest_labels(db, log_ids)
    changes: list[LabelChange] = []
    unchanged = skipped = 0
    for item in decisions:
        decision = item.get("decision")
        item_logs = [int(log_id) for log_id in item.get("log_ids", [])]
        if decision in NO_CHANGE_DECISIONS:
            skipped += len(item_logs)
            continue
        if decision != THREAT_DECISION and decision not in HARMLESS_DECISIONS:
            raise ValueError(f"Unknown review decision {decision!r} for {item.get('source_ip')}.")
        for log_id in item_logs:
            current = latest.get(log_id)
            if decision == THREAT_DECISION:
                # A review may also correct what kind of threat it is, e.g. when the
                # firewall's own signature names it (miner C2 labeled "policy violation").
                corrected_type = item.get("attack_type")
                if corrected_type is not None and corrected_type not in VALID_ATTACK_TYPES:
                    raise ValueError(f"Unknown attack type {corrected_type!r} for {item.get('pattern')}.")
                if current is not None and current.label in THREAT_LABELS:
                    if not corrected_type or current.attack_type == corrected_type:
                        unchanged += 1
                        continue
                    to_label, attack_type = current.label, corrected_type
                else:
                    to_label = "suspicious"
                    attack_type = corrected_type or infer_attack_type_from_rules([{"code": item.get("atdr_alert_type") or ""}])
            else:
                to_label = HARMLESS_DECISIONS[decision]
                # "benign_unusual" labels keep the attack type they resemble
                # (the existing labels use it that way); "benign" is "normal".
                attack_type = current.attack_type if to_label == "benign_unusual" and current is not None else "normal"
            if current is not None and current.label == to_label and current.attack_type == attack_type:
                unchanged += 1
                continue
            changes.append(
                LabelChange(
                    log_id=log_id,
                    source_ip=str(item.get("source_ip") or ""),
                    pattern=str(item.get("pattern") or ""),
                    decision=str(decision),
                    from_label=current.label if current is not None else None,
                    to_label=to_label,
                    attack_type=attack_type,
                    note=str(item.get("note") or ""),
                )
            )
    transitions: dict[str, int] = {}
    for change in changes:
        key = f"{change.from_label} -> {change.to_label}"
        transitions[key] = transitions.get(key, 0) + 1
    return {
        "changes": changes,
        "labels_to_add": len(changes),
        "unchanged": unchanged,
        "skipped_undecided": skipped,
        "transitions": transitions,
    }


def apply_label_review(
    db: Session,
    decisions: list[dict[str, Any]],
    *,
    reviewer: str,
    note_prefix: str,
    apply: bool = False,
) -> dict[str, Any]:
    plan = plan_label_review(db, decisions)
    summary = {key: value for key, value in plan.items() if key != "changes"}
    summary["applied"] = False
    if not apply or not plan["changes"]:
        return summary
    for change in plan["changes"]:
        db.add(
            MLLabel(
                log_id=change.log_id,
                label=change.to_label,
                attack_type=change.attack_type,
                confidence=REVIEW_CONFIDENCE,
                reviewer=reviewer,
                review_note=f"{note_prefix} | {change.pattern} {change.decision} | {change.note}"[:2000],
                label_source=LABEL_SOURCE,
                reviewed=True,
            )
        )
    db.add(
        AuditLog(
            actor=reviewer,
            action="ml_label_review_imported",
            target_type="ml_labels",
            target_value=f"{len(plan['changes'])} labels",
            details={**summary, "note": note_prefix},
        )
    )
    db.commit()
    summary["applied"] = True
    return summary
