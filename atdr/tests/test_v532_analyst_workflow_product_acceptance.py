from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    LogSource,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.services.dashboard_service import build_dashboard_summary


def _raw_log(source_id: int, index: int, *, app: str = "ssl", parser_error: str | None = None) -> RawLog:
    return RawLog(
        source_id=source_id,
        raw_line=f"private synthetic evidence {index}",
        raw_line_hash=f"{index:064x}",
        normalized=NormalizedLog(
            generated_time=datetime(2026, 8, 11, 10, index, tzinfo=timezone.utc),
            src_ip=f"192.0.2.{index}",
            dst_ip=f"198.51.100.{index}",
            app=app,
            action="deny" if index == 1 else "allow",
            parsed_json={"parser_error": parser_error} if parser_error else {},
        ),
    )


def _alert(index: int, *, alert_type: str, status: str, occurrences: int) -> Alert:
    return Alert(
        title=f"Synthetic alert {index}",
        alert_type=alert_type,
        src_ip=f"192.0.2.{index}",
        dst_ip=f"198.51.100.{index}",
        threat_score=80,
        severity="High",
        status=status,
        explanation="Synthetic governed-rule evidence.",
        matched_rules_json=[
            {"code": alert_type, "title": alert_type.replace("_", " ")},
            {
                "code": "group_metadata",
                "occurrence_count": occurrences,
                "related_log_count": occurrences,
            },
        ],
        recommended_response="Review evidence before any simulated response.",
    )


def test_detection_operations_are_truthful_aggregate_workload_not_accuracy():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    try:
        with Session() as db:
            source_a = LogSource(name="acceptance-firewall", source_type="firewall", parser_profile="palo_alto")
            source_b = LogSource(name="acceptance-router", source_type="router", parser_profile="generic_syslog")
            db.add_all([source_a, source_b])
            db.flush()

            raw_a1 = _raw_log(source_a.id, 1)
            raw_a2 = _raw_log(source_a.id, 2)
            raw_b1 = _raw_log(source_b.id, 3, app="unknown", parser_error="synthetic limited parse")
            db.add_all([raw_a1, raw_a2, raw_b1])
            db.flush()

            alert_one = _alert(1, alert_type="policy_deny", status="open", occurrences=4)
            alert_two = _alert(2, alert_type="possible_port_scan", status="false_positive", occurrences=2)
            db.add_all([alert_one, alert_two])
            db.flush()
            db.add_all(
                [
                    AlertEvidence(alert_id=alert_one.id, normalized_log_id=raw_a1.normalized.id),
                    AlertEvidence(alert_id=alert_one.id, normalized_log_id=raw_b1.normalized.id),
                    AlertEvidence(alert_id=alert_two.id, normalized_log_id=raw_a2.normalized.id),
                    AlertEvidence(alert_id=alert_two.id, normalized_log_id=raw_a2.normalized.id),
                    AuditLog(
                        actor="analyst",
                        action="alert_deduplicated",
                        target_type="alert",
                        target_value=str(alert_two.id),
                        details={"safe": True},
                    ),
                ]
            )
            db.commit()

            before_models = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
            before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
            operations = build_dashboard_summary(db)["detection_operations"]
            after_models = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
            after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

        rules = {item["name"]: item["count"] for item in operations["primary_rule_alert_volume"]}
        sources = {item["name"]: item["count"] for item in operations["source_alert_volume"]}

        assert rules == {"policy_deny": 1, "possible_port_scan": 1}
        assert sources == {"acceptance-firewall": 2, "acceptance-router": 1}
        assert operations["analyst_dispositions"] == {"false_positive": 1, "open": 1}
        assert operations["deduplication"] == {
            "unique_alerts": 2,
            "total_occurrences": 6,
            "deduplicated_updates": 1,
            "occurrences_per_alert": 3.0,
        }
        assert operations["parser_warning_context"]["status"] == "warning"
        assert operations["parser_warning_context"]["parse_failure_count"] == 1
        assert operations["accuracy_evidence"]["status"] == "insufficient_evidence"
        assert operations["accuracy_evidence"]["value"] is None
        assert "not accuracy" in operations["accuracy_evidence"]["message"]
        assert "private synthetic evidence" not in json.dumps(operations)
        assert before_models == after_models == 0
        assert before_responses == after_responses == 0
    finally:
        engine.dispose()
