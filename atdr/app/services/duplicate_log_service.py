"""Remove repeated copies of firewall log lines, keeping one copy of each.

Until 27 September 2026 an import stored a line again each time the same file was imported, so the first 10,000
lines of MFU's 20 May export were stored up to eight times: 31,001 of the 151,002 stored logs were copies. Imports
have stored each line once since then (``raw_line_hash``), but the old copies stayed, and rules that count events
counted them: three "brute-force" alerts were each one connection stored six or seven times.

For each line the first stored copy is kept. Whatever pointed at a removed copy points at the kept one afterwards:

- labels: the newest label made for the line stays in use, on the kept copy, and the other labels that sat on
  removed copies move to ``ml_label_archive`` with the reason (the copies of 12 lines disagreed, all of them
  "benign" against "benign_unusual");
- alert evidence, the evidence ids of archived alerts, and archived labels.

The alerts' counts and scores were worked out with the copies, so the alert list must be rebuilt afterwards:
``atdr.scripts.remove_duplicate_logs`` backs the database up, removes the copies and rebuilds.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from atdr.app.db.models import AlertArchive, AlertEvidence, AuditLog, MLLabel, MLLabelArchive, NormalizedLog, RawLog

REASON = (
    "Sat on a duplicate copy of a firewall log line. The copy was removed; the newest label made for the line "
    "stays in use on the copy that was kept."
)
CHUNK = 900


def _chunks(values: Iterable[int]) -> Iterator[list[int]]:
    ordered = sorted(values)
    for start in range(0, len(ordered), CHUNK):
        yield ordered[start:start + CHUNK]


def duplicate_copies(db: Session) -> tuple[dict[int, int], dict[int, int]]:
    """For every line stored more than once: removed raw id -> kept raw id, and removed log id -> kept log id.

    The kept copy is the first one stored that was parsed into a log, or the first one stored if none was.
    """

    repeated = (
        select(RawLog.raw_line_hash)
        .where(RawLog.raw_line_hash.is_not(None))
        .group_by(RawLog.raw_line_hash)
        .having(func.count(RawLog.id) > 1)
        .subquery()
    )
    copies: dict[str, list[int]] = defaultdict(list)
    for raw_id, fingerprint in db.execute(
        select(RawLog.id, RawLog.raw_line_hash).join(repeated, repeated.c.raw_line_hash == RawLog.raw_line_hash).order_by(RawLog.id)
    ):
        copies[fingerprint].append(int(raw_id))
    log_of: dict[int, int] = {}
    for chunk in _chunks(raw_id for ids in copies.values() for raw_id in ids):
        for raw_id, log_id in db.execute(select(NormalizedLog.raw_log_id, NormalizedLog.id).where(NormalizedLog.raw_log_id.in_(chunk))):
            log_of.setdefault(int(raw_id), int(log_id))
    raw_keep: dict[int, int] = {}
    log_keep: dict[int, int] = {}
    for ids in copies.values():
        kept = next((raw_id for raw_id in ids if raw_id in log_of), ids[0])
        for raw_id in ids:
            if raw_id == kept:
                continue
            raw_keep[raw_id] = kept
            if raw_id in log_of:
                log_keep[log_of[raw_id]] = log_of[kept]
    return raw_keep, log_keep


def _label_moves(db: Session, log_keep: dict[int, int]) -> tuple[dict[int, int], dict[int, int]]:
    """Label id -> kept log id for the labels to move, and for the labels to archive."""

    labels: dict[int, list[tuple[int, int]]] = defaultdict(list)  # kept log id -> (label id, log id)
    involved = set(log_keep) | set(log_keep.values())
    for chunk in _chunks(involved):
        for label_id, log_id in db.execute(select(MLLabel.id, MLLabel.log_id).where(MLLabel.log_id.in_(chunk))):
            labels[log_keep.get(int(log_id), int(log_id))].append((int(label_id), int(log_id)))
    move: dict[int, int] = {}
    archive: dict[int, int] = {}
    for kept_log, rows in labels.items():
        newest = max(label_id for label_id, _ in rows)
        for label_id, log_id in rows:
            if log_id == kept_log:
                continue
            (move if label_id == newest else archive)[label_id] = kept_log
    return move, archive


def plan_duplicate_removal(db: Session) -> dict[str, Any]:
    """What removing the copies would do, without changing anything."""

    raw_keep, log_keep = duplicate_copies(db)
    move, archive = _label_moves(db, log_keep)
    evidence_rows = 0
    alerts: set[int] = set()
    for chunk in _chunks(log_keep):
        for alert_id, in db.execute(select(AlertEvidence.alert_id).where(AlertEvidence.normalized_log_id.in_(chunk))):
            evidence_rows += 1
            alerts.add(int(alert_id))
    return {
        "stored_lines": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "lines_stored_more_than_once": len(set(raw_keep.values())),
        "copies_to_remove": len(raw_keep),
        "logs_to_remove": len(log_keep),
        "labels_to_move_to_the_kept_copy": len(move),
        "labels_to_archive": len(archive),
        "alert_evidence_rows_on_copies": evidence_rows,
        "alerts_citing_a_copy": len(alerts),
    }


def remove_duplicate_logs(db: Session, *, actor: str) -> dict[str, Any]:
    plan = plan_duplicate_removal(db)
    raw_keep, log_keep = duplicate_copies(db)
    if not raw_keep:
        return {**plan, "applied": False}

    # Labels: the newest label made for a line moves to the kept copy; the rest on removed copies are archived.
    move, archive = _label_moves(db, log_keep)
    for kept_log in set(move.values()):
        ids = [label_id for label_id, target in move.items() if target == kept_log]
        db.execute(update(MLLabel).where(MLLabel.id.in_(ids)).values(log_id=kept_log))
    for chunk in _chunks(archive):
        for label in db.scalars(select(MLLabel).where(MLLabel.id.in_(chunk))):
            db.add(MLLabelArchive(
                original_label_id=label.id, log_id=archive[label.id], label=label.label, attack_type=label.attack_type,
                confidence=label.confidence, reviewer=label.reviewer, review_note=label.review_note,
                label_source=label.label_source, reviewed=label.reviewed, label_created_at=label.created_at,
                reason=REASON, archived_by=actor,
            ))
        db.flush()
        db.execute(delete(MLLabel).where(MLLabel.id.in_(chunk)))
    archived_labels_repointed = 0
    for chunk in _chunks(log_keep):
        for row in db.scalars(select(MLLabelArchive).where(MLLabelArchive.log_id.in_(chunk))):
            row.log_id = log_keep[row.log_id]
            archived_labels_repointed += 1

    # Evidence: an alert that cited a removed copy cites the kept copy, once.
    cited: set[tuple[int, int]] = set()
    for chunk in _chunks(log_keep):
        for alert_id, log_id in db.execute(
            select(AlertEvidence.alert_id, AlertEvidence.normalized_log_id).where(AlertEvidence.normalized_log_id.in_(chunk))
        ):
            cited.add((int(alert_id), log_keep[int(log_id)]))
        db.execute(delete(AlertEvidence).where(AlertEvidence.normalized_log_id.in_(chunk)))
    already: set[tuple[int, int]] = set()
    for chunk in _chunks({log_id for _, log_id in cited}):
        already.update(
            (int(alert_id), int(log_id)) for alert_id, log_id in db.execute(
                select(AlertEvidence.alert_id, AlertEvidence.normalized_log_id).where(AlertEvidence.normalized_log_id.in_(chunk))
            )
        )
    for alert_id, log_id in sorted(cited - already):
        db.add(AlertEvidence(alert_id=alert_id, normalized_log_id=log_id))
    archived_alerts_repointed = 0
    for row in db.scalars(select(AlertArchive)):
        ids = list(row.evidence_log_ids or [])
        if any(log_id in log_keep for log_id in ids):
            row.evidence_log_ids = sorted({log_keep.get(log_id, log_id) for log_id in ids})
            archived_alerts_repointed += 1
    db.flush()

    for chunk in _chunks(log_keep):
        db.execute(delete(NormalizedLog).where(NormalizedLog.id.in_(chunk)))
    for chunk in _chunks(raw_keep):
        db.execute(delete(RawLog).where(RawLog.id.in_(chunk)))
    summary = {
        **plan,
        "applied": True,
        "stored_lines_after": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "archived_labels_repointed": archived_labels_repointed,
        "archived_alerts_repointed": archived_alerts_repointed,
    }
    db.add(AuditLog(actor=actor, action="duplicate_logs_removed", target_type="logs",
                    target_value=f"{len(raw_keep)} copies", details=summary))
    db.commit()
    return summary
