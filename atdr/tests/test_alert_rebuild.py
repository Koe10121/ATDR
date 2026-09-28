"""Rebuilding alerts with the current rules: analyst work is kept, old alerts are archived in full."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select

from atdr.app.db.models import Alert, AlertArchive, AlertEvidence, AlertNote, AuditLog, NormalizedLog, ResponseAction
from atdr.app.detection.rule_catalog import RULE_CATALOG_VERSION
from atdr.app.services.alert_rebuild_service import plan_rebuild, rebuild_alerts, worked_alert_ids
from atdr.tests.test_detection_grouping import _add_scan_log, _session


def _alert(db, alert_type, *, status="open", log_ids=(), **fields):
    alert = Alert(title=alert_type, alert_type=alert_type, threat_score=40, severity="Medium", status=status,
                  explanation=f"{alert_type} explanation", matched_rules_json=[{"code": alert_type}],
                  recommended_response="look", src_ip="203.0.113.10", **fields)
    db.add(alert)
    db.flush()
    for log_id in log_ids:
        db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=log_id))
    return alert


def _seed(db):
    for index in range(30):
        _add_scan_log(db, index)
    db.flush()
    logs = list(db.scalars(select(NormalizedLog.id).order_by(NormalizedLog.id)))
    retired = _alert(db, "app_risk_4", log_ids=logs[:25])
    investigating = _alert(db, "possible_port_scan", status="investigating", log_ids=logs[25:27])
    responded = _alert(db, "paloalto_threat_log", log_ids=logs[27:28])
    db.add(ResponseAction(alert_id=responded.id, action_type="block_ip", target_ip="203.0.113.10", status="simulated",
                          result_message="simulated block", executed_by="koe"))
    noted = _alert(db, "unusual_destination_port", log_ids=logs[28:29])
    db.add(AlertNote(alert_id=noted.id, author="koe", note="checked"))
    assigned = _alert(db, "deny_drop_action", log_ids=logs[29:30], assigned_to="koe")
    db.execute(NormalizedLog.__table__.update().values(last_detection_run_id=1))
    db.commit()
    return logs, retired, [investigating.id, responded.id, noted.id, assigned.id]


def test_the_plan_changes_nothing_and_keeps_every_worked_alert():
    db = _session()
    _logs, retired, worked = _seed(db)
    plan = plan_rebuild(db)
    assert plan["alerts"] == 5 and plan["keep"] == sorted(worked) and plan["archive"] == 1
    assert plan["archive_by_type"] == {"app_risk_4": 1}
    assert db.scalar(select(func.count(Alert.id))) == 5 and db.scalar(select(func.count(AlertArchive.id))) == 0
    assert worked_alert_ids(db) == set(worked) and retired.id not in worked_alert_ids(db)


def test_a_rebuild_archives_old_alerts_in_full_and_runs_the_current_rules_over_every_log():
    db = _session()
    logs, retired, worked = _seed(db)
    retired_id = retired.id
    seen = {}

    def detect(session):
        seen["unchecked"] = session.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.last_detection_run_id.is_(None)))
        seen["retired_evidence"] = session.scalar(select(func.count(AlertEvidence.id)).where(AlertEvidence.alert_id == retired_id))
        return {"logs_checked": seen["unchecked"]}

    summary = rebuild_alerts(db, actor="koe", reason="retired rules", detect=detect)

    assert seen == {"unchecked": 30, "retired_evidence": 0}, "every log is re-checked; the archived alert no longer claims its logs"
    assert db.get(Alert, retired_id) is None
    archive = db.scalar(select(AlertArchive))
    assert archive.original_alert_id == retired_id and archive.alert_type == "app_risk_4"
    assert archive.evidence_log_ids == logs[:25]
    assert archive.alert_json["explanation"] == "app_risk_4 explanation" and archive.alert_json["matched_rules_json"] == [{"code": "app_risk_4"}]
    assert archive.superseded_by_catalog == RULE_CATALOG_VERSION and archive.archived_by == "koe"

    kept = {alert.id: alert for alert in db.scalars(select(Alert))}
    assert sorted(kept) == sorted(worked)
    assert kept[worked[0]].status == "investigating" and len(kept[worked[0]].evidence) == 2
    assert db.scalar(select(ResponseAction.alert_id)) == worked[1]
    assert summary["archived"] == 1 and summary["kept"] == sorted(worked) and summary["new_alerts"] == 0

    audit = db.scalar(select(AuditLog).where(AuditLog.action == "alerts_rebuilt"))
    assert audit.actor == "koe" and audit.target_value == RULE_CATALOG_VERSION
    assert audit.details["archived"] == 1 and audit.details["kept_alert_ids"] == sorted(worked)


def test_the_current_rules_find_what_the_retired_alert_was_really_about():
    db = _session()
    logs, _retired, _worked = _seed(db)
    summary = rebuild_alerts(db, actor="koe", reason="retired rules")
    assert summary["new_alerts_by_type"] == {"possible_port_scan": 1}
    scan = db.scalar(select(Alert).where(Alert.id > max(_worked)))
    assert sorted(evidence.normalized_log_id for evidence in scan.evidence) == logs[:25], "logs held by kept alerts stay out"


def test_a_second_rebuild_counts_its_new_alerts_even_when_ids_are_reused():
    db = _session()
    _logs, _retired, worked = _seed(db)
    first = rebuild_alerts(db, actor="koe", reason="retired rules")
    second = rebuild_alerts(db, actor="koe", reason="rules changed again")
    alerts_now = db.scalar(select(func.count(Alert.id)))
    assert first["new_alerts"] == second["new_alerts"] == alerts_now - len(worked) == 1
    assert second["archived"] == 1, "the first rebuild's alert is archived by the second"
