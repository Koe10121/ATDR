"""Experimental alerts from the MFU behaviour model, for the attack types the team switched on.

The model may raise alerts only for types that pass the quality bar declared before training
(docs/detection/ML_QUALITY_BAR.md). None did, and no further MFU traffic exists to test on, so on
28 Sep 2026 the team lead switched every type on as a recorded exception: *experimental*, not
qualified. The switch lives on the model card (``experimental_alerting``) with who, when and why.

A model alert is raised only where the model flags a device's five minutes of traffic and no rule
alert covers them; where the rules already alerted, the model's opinion shows on that alert
instead. Each one says it is experimental and low confidence, carries the model's explanation and
response guide, and is Low or Medium severity. It never triggers a response on its own.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AlertEvidence, AuditLog, NormalizedLog
from atdr.app.detection.playbooks import PLAYBOOK_GUIDANCE
from atdr.app.detection.scoring import severity_from_score
from atdr.app.ml.behavior_model import BehaviorModel
from atdr.app.services.behavior_findings_service import (
    DATA_LIMIT,
    MODEL_ALERT_CODE,
    WINDOW,
    available_windows,
    load_model,
    window_findings,
)
EXPERIMENTAL_NOTE = (
    "Experimental, low confidence: this attack type did not pass the model's quality bar, and the model was "
    "trained and tested on one 21-minute MFU export (20 May 2026)."
)
CONFIDENT = 0.995  # at or above: Medium; below: Low
SCORES = {"Medium": 45, "Low": 30}
MAX_EVIDENCE = 500


def experimental_alerting(model: BehaviorModel | None) -> dict[str, Any]:
    """The team's recorded switch on the model card; empty when model alerts are off."""

    if model is None:
        return {}
    switch = model.card.get("experimental_alerting") or {}
    return switch if switch.get("types") else {}


def _window_start(moment: datetime) -> datetime:
    return moment.replace(minute=moment.minute - moment.minute % 5, second=0, microsecond=0, tzinfo=None)


def _existing_model_alerts(db: Session, start: datetime) -> set[tuple[str | None, str]]:
    keys = set()
    for src_ip, rules in db.execute(select(Alert.src_ip, Alert.matched_rules_json).where(Alert.alert_type == MODEL_ALERT_CODE)):
        for rule in rules or []:
            if isinstance(rule, dict) and rule.get("code") == MODEL_ALERT_CODE and rule.get("window_start") == start.isoformat():
                keys.add((src_ip, rule["window_start"]))
    return keys


def _source_logs(db: Session, src_ip: str, start: datetime) -> list[NormalizedLog]:
    return list(db.scalars(
        select(NormalizedLog)
        .where(NormalizedLog.src_ip == src_ip, NormalizedLog.generated_time >= start, NormalizedLog.generated_time < start + WINDOW)
        .order_by(NormalizedLog.generated_time, NormalizedLog.id)
    ))


def _alert(finding: dict[str, Any], logs: list[NormalizedLog], *, in_training: bool, start: datetime) -> Alert:
    attack_type = finding["attack_type"]
    severity = "Medium" if finding["confidence"] >= CONFIDENT else "Low"
    score = SCORES[severity]
    reasons = "; ".join(finding["reasons"]) or "no single feature stands out"
    training = " This traffic was part of the model's training data." if in_training else ""
    explanation = (
        f"Found by the MFU behaviour model, not the rules: it reads this device's five minutes of traffic as "
        f"{finding['attack_label']} ({finding['confidence']:.1%} confident), and no rule alert covers them. Why: {reasons}. "
        f"{EXPERIMENTAL_NOTE}{training}"
    )
    guidance = PLAYBOOK_GUIDANCE.get(attack_type)
    response = (
        f"Experimental model alert: confirm before acting. {guidance.objective} {' '.join(guidance.containment)}"
        if guidance else "Experimental model alert: confirm with the evidence logs before acting."
    )
    times = [log.generated_time for log in logs if log.generated_time is not None]
    destinations = Counter(log.dst_ip for log in logs if log.dst_ip)
    ports = Counter(log.dst_port for log in logs if log.dst_port is not None)
    alert = Alert(
        title=f"{severity}: Experimental: MFU model sees possible {finding['attack_label']} from {finding['source']}",
        alert_type=MODEL_ALERT_CODE,
        src_ip=finding["source"],
        dst_ip=destinations.most_common(1)[0][0] if len(destinations) == 1 else None,
        threat_score=score,
        severity=severity_from_score(score),
        explanation=explanation,
        recommended_response=response,
        matched_rules_json=[
            {
                "code": MODEL_ALERT_CODE,
                "title": "MFU behaviour model (experimental)",
                "score": score,
                "explanation": explanation,
                "attack_type": attack_type,
                "confidence": finding["confidence"],
                "window_start": start.isoformat(),
                "experimental": True,
                "reasons": finding["reasons"],
                "matched_log_count": len(logs),
            },
            {
                "code": "group_metadata",
                "title": "Grouped alert metadata",
                "score": 0,
                "explanation": "The device's logs in the five-minute window the model read.",
                "evidence_count": len(logs),
                "first_seen": min(times).isoformat() if times else None,
                "last_seen": max(times).isoformat() if times else None,
                "unique_src_count": 1,
                "sample_src_ips": [finding["source"]],
                "unique_dst_count": len(destinations),
                "sample_dst_ips": [dst for dst, _ in destinations.most_common(10)],
                "sample_dst_ports": [port for port, _ in ports.most_common(10)],
            },
        ],
    )
    for log in logs[:MAX_EVIDENCE]:
        alert.evidence.append(AlertEvidence(normalized_log_id=log.id))
    return alert


def create_model_alerts(
    db: Session,
    *,
    windows: list[datetime] | None = None,
    model: BehaviorModel | None = None,
    actor: str = "system",
) -> dict[str, Any]:
    """Raise experimental alerts for the switched-on types in the given five-minute windows (default: all)."""

    model = model or load_model()
    switch = experimental_alerting(model)
    if not switch:
        return {"enabled": False, "created": 0}
    enabled = set(switch["types"])
    starts = sorted({_window_start(moment) for moment in windows} if windows is not None
                    else {datetime.fromisoformat(window["start"]) for window in available_windows(db, limit=500)})
    created: Counter = Counter()
    skipped = 0
    for start in starts:
        result = window_findings(db, start, model=model, limit=5000)
        findings = [finding for finding in result["findings"] if finding["found_by"] == "model_only" and finding["attack_type"] in enabled]
        if not findings:
            continue
        existing = _existing_model_alerts(db, start)
        in_training = bool((result.get("window") or {}).get("in_training_data"))
        for finding in findings:
            if (finding["source"], start.isoformat()) in existing:
                skipped += 1
                continue
            db.add(_alert(finding, _source_logs(db, finding["source"], start), in_training=in_training, start=start))
            created[finding["attack_type"]] += 1
    summary = {"enabled": True, "types": sorted(enabled), "windows": len(starts), "created": sum(created.values()),
               "created_by_type": dict(created), "already_raised": skipped}
    if created:
        db.add(AuditLog(actor=actor, action="model_alerts_created", target_type="alerts", target_value=f"{sum(created.values())} alerts",
                        details=summary))
    db.commit()
    return summary


def set_experimental_alerting(model: BehaviorModel, *, types: list[str], actor: str, reason: str) -> dict[str, Any]:
    """Record the team lead's switch on the model card (the caller saves the model)."""

    switch = {
        "types": sorted(types),
        "enabled_by": actor,
        "enabled_at": datetime.now(UTC).isoformat(),
        "reason": reason,
        "quality_bar_passed": sorted(t for t, entry in ((model.card.get("quality_bar") or {}).get("types") or {}).items() if entry.get("eligible")),
    }
    if types:
        model.card["experimental_alerting"] = switch
    else:
        model.card.pop("experimental_alerting", None)
    return switch

