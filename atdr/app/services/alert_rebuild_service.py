"""Replace alerts raised by retired rules with what the current rules find.

The rule catalog has changed since many stored alerts were raised: v5.32.0 made app_risk_4,
suspicious_app_characteristic and four other context signals supporting-only, and the old anomaly
model may no longer raise alerts at all. Those alerts stay on the list, so the list no longer shows
what ATDR detects today. A rebuild:

1. keeps every alert an analyst has worked on (status changed, assigned, escalated, ticketed, noted,
   or with a response action) exactly as it is;
2. moves every other alert into ``alert_archive`` with all its columns and evidence log ids, and takes
   it off the alert list;
3. marks every log unchecked and runs the current rules and watchlist over all of them, the same way
   the "check every unchecked log" action does.

Logs cited by a kept alert stay out of new alerts, as in any detection run. The archive is never
deleted, and ``atdr.scripts.rebuild_alerts`` backs the database up before it applies a rebuild.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import Alert, AlertArchive, AlertEvidence, AlertNote, AuditLog, NormalizedLog, ResponseAction
from atdr.app.detection.rule_catalog import RULE_CATALOG_VERSION
from atdr.app.services.detection_scoreboard_service import run_all_detection
from atdr.app.services.model_alert_service import create_model_alerts

CHUNK = 500


def worked_alert_ids(db: Session) -> set[int]:
    """Alerts an analyst has touched; a rebuild never archives these."""

    touched = select(Alert.id).where(or_(
        Alert.status != "open",
        Alert.assigned_to.is_not(None),
        Alert.priority_owner.is_not(None),
        Alert.escalated_at.is_not(None),
        Alert.ticket_reference.is_not(None),
    ))
    ids = set(db.scalars(touched))
    ids |= set(db.scalars(select(AlertNote.alert_id)))
    ids |= set(db.scalars(select(ResponseAction.alert_id).where(ResponseAction.alert_id.is_not(None))))
    return ids


def plan_rebuild(db: Session) -> dict[str, Any]:
    """What a rebuild would do, without changing anything."""

    keep = worked_alert_ids(db)
    by_type = Counter(
        {alert_type: count for alert_type, count in db.execute(
            select(Alert.alert_type, func.count(Alert.id)).where(Alert.id.not_in(keep) if keep else True).group_by(Alert.alert_type)
        )}
    )
    return {
        "catalog": RULE_CATALOG_VERSION,
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "keep": sorted(keep),
        "archive": int(sum(by_type.values())),
        "archive_by_type": dict(by_type.most_common()),
        "logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
    }


def _record(alert: Alert) -> dict[str, Any]:
    record = {}
    for column in Alert.__table__.columns:
        value = getattr(alert, column.key)
        record[column.key] = value.isoformat() if isinstance(value, datetime) else value
    return record


def rebuild_alerts(
    db: Session,
    *,
    actor: str,
    reason: str,
    detect: Callable[[Session], dict[str, Any]] = run_all_detection,
) -> dict[str, Any]:
    keep = worked_alert_ids(db)
    to_archive = [alert_id for alert_id in db.scalars(select(Alert.id).order_by(Alert.id)) if alert_id not in keep]
    archived_by_type: Counter = Counter()
    for start in range(0, len(to_archive), CHUNK):
        chunk = to_archive[start:start + CHUNK]
        evidence: dict[int, list[int]] = defaultdict(list)
        for alert_id, log_id in db.execute(
            select(AlertEvidence.alert_id, AlertEvidence.normalized_log_id).where(AlertEvidence.alert_id.in_(chunk))
        ):
            evidence[alert_id].append(int(log_id))
        for alert in db.scalars(select(Alert).where(Alert.id.in_(chunk))):
            archived_by_type[alert.alert_type] += 1
            db.add(AlertArchive(
                original_alert_id=alert.id, alert_type=alert.alert_type, severity=alert.severity, status=alert.status,
                src_ip=alert.src_ip, dst_ip=alert.dst_ip, threat_score=alert.threat_score, alert_created_at=alert.created_at,
                alert_json=_record(alert), evidence_log_ids=sorted(evidence.get(alert.id, [])), reason=reason,
                superseded_by_catalog=RULE_CATALOG_VERSION, archived_by=actor,
            ))
        db.flush()
        db.execute(delete(AlertEvidence).where(AlertEvidence.alert_id.in_(chunk)))
        db.execute(delete(Alert).where(Alert.id.in_(chunk)))
    db.execute(update(NormalizedLog).values(last_detection_run_id=None))
    db.commit()

    run = detect(db)
    # The live list also carries the MFU model's experimental alerts, when they are switched on.
    model_run = create_model_alerts(db, actor=actor) if get_settings().model_alerts_enabled else None
    # Every alert now on the list that was not kept is new. (Comparing ids with the old maximum fails:
    # SQLite reuses ids above the highest remaining row, so a second rebuild numbers new alerts lower.)
    new_alerts = Counter(db.scalars(select(Alert.alert_type).where(Alert.id.not_in(keep) if keep else True)))
    summary = {
        "catalog": RULE_CATALOG_VERSION,
        "kept": sorted(keep),
        "archived": len(to_archive),
        "archived_by_type": dict(archived_by_type.most_common()),
        "new_alerts": int(sum(new_alerts.values())),
        "new_alerts_by_type": dict(new_alerts.most_common()),
        "detection": run,
        "model_alerts": model_run,
        "reason": reason,
    }
    db.add(AuditLog(actor=actor, action="alerts_rebuilt", target_type="alerts", target_value=RULE_CATALOG_VERSION,
                    details={key: value for key, value in summary.items() if key != "kept"} | {"kept_alert_ids": sorted(keep)}))
    db.commit()
    return summary
