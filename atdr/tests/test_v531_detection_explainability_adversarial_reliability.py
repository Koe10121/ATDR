from __future__ import annotations

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    ResponseAction,
)
from atdr.app.detection.explanations import (
    alert_explanation_completeness,
    build_alert_detection_summary,
)
from atdr.app.detection.rule_catalog import RULE_CATALOG, RULE_CATALOG_VERSION
from atdr.app.detection.v531_adversarial_reliability import (
    build_case_logs,
    load_v531_corpus,
    run_v531_adversarial_reliability,
)
from atdr.app.services.assistant_service import answer_assistant_question
from atdr.app.services.detection_service import run_detection


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(case_id: str) -> dict:
    return next(item for item in load_v531_corpus()["cases"] if item["id"] == case_id)


def _persist_case(db: Session, case_id: str) -> list[NormalizedLog]:
    logs = build_case_logs(_case(case_id))
    source_ids = sorted({int(log.raw_log.source_id) for log in logs if log.raw_log.source_id is not None})
    db.add_all(
        [
            LogSource(
                id=source_id,
                name=f"v531-source-{source_id}",
                source_type="firewall",
                parser_profile="palo_alto",
            )
            for source_id in source_ids
        ]
    )
    db.add_all(logs)
    db.commit()
    return logs


def _count(db: Session, model: type) -> int:
    return int(db.scalar(select(func.count()).select_from(model)) or 0)


def test_v531_adversarial_corpus_passes_without_false_positives_or_false_negatives() -> None:
    report = run_v531_adversarial_reliability()

    assert report["ok"] is True
    assert report["case_count"] == 27
    assert report["passed_count"] == report["case_count"]
    assert report["false_positive_case_count"] == 0
    assert report["false_negative_case_count"] == 0
    assert report["false_positives_by_rule"] == {}
    assert report["false_negatives_by_rule"] == {}
    assert report["near_miss_negative_accuracy"] == 1.0
    assert report["timing_boundary_correct"] is True
    assert report["source_isolation_correct"] is True
    assert report["duplicate_handling_correct"] is True
    assert report["uses_configured_database"] is False
    assert report["safety"]["labels_written"] == 0
    assert report["safety"]["models_trained_or_activated"] == 0
    assert report["safety"]["response_actions_created"] == 0


def test_v531_corpus_covers_positive_negative_boundary_degraded_duplicate_and_multi_source_cases() -> None:
    report = run_v531_adversarial_reliability()

    assert report["category_counts"] == {
        "boundary": 3,
        "degraded_input": 2,
        "duplicate": 1,
        "multi_source": 1,
        "near_miss": 5,
        "negative": 6,
        "positive": 9,
    }
    assert "possible_port_scan" in report["observed_rule_codes"]
    assert "possible_horizontal_scan" in report["observed_rule_codes"]
    assert "brute_force_like_attempts" in report["observed_rule_codes"]
    assert "beaconing_like_outbound" in report["observed_rule_codes"]
    assert "connection_flood_suspicion" in report["observed_rule_codes"]


def test_v531_missing_timestamps_do_not_create_cross_row_scan_correlation() -> None:
    logs = build_case_logs(_case("missing_timestamps_do_not_correlate"))
    report = run_v531_adversarial_reliability()
    case_result = next(
        item
        for item in report["cases"]
        if item["id"] == "missing_timestamps_do_not_correlate"
    )

    assert len(logs) == 10
    assert all(log.generated_time is None for log in logs)
    assert case_result["passed"] is True
    assert "possible_port_scan" not in case_result["observed_rules"]
    assert case_result["actual_alert_count"] == 0


def test_v531_independent_scan_windows_create_independent_alerts() -> None:
    db = _session()
    _persist_case(db, "separate_scan_windows_stay_separate")

    result = run_detection(db, limit=100, use_ml=False, actor="v531-test")
    alerts = list(db.scalars(select(Alert).order_by(Alert.id)))
    evidence_counts = [
        int(
            next(
                item
                for item in alert.matched_rules_json
                if item.get("code") == "group_metadata"
            )["evidence_count"]
        )
        for alert in alerts
    ]

    assert result["created_alerts"] == 2
    assert result["deduplicated_alert_updates"] == 0
    assert len(alerts) == 2
    assert evidence_counts == [10, 10]


def test_v531_missing_timestamp_alerts_do_not_deduplicate_without_time_evidence() -> None:
    db = _session()
    db.add(
        LogSource(
            id=1,
            name="v531-source-1",
            source_type="firewall",
            parser_profile="palo_alto",
        )
    )
    logs = build_case_logs(
        {
            "id": "missing-time-floods",
            "pattern": "flood",
            "params": {
                "count": 2,
                "source_id": 1,
                "action": "allow",
                "repeat_count": 100,
            },
        }
    )
    for log in logs:
        log.generated_time = None
    db.add_all(logs)
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="v531-test")

    assert result["created_alerts"] == 2
    assert result["deduplicated_alert_updates"] == 0
    assert _count(db, Alert) == 2


def test_v531_registered_sources_create_separate_alerts_and_do_not_cross_deduplicate() -> None:
    db = _session()
    db.add_all(
        [
            LogSource(id=1, name="v531-a", source_type="firewall", parser_profile="palo_alto"),
            LogSource(id=2, name="v531-b", source_type="firewall", parser_profile="palo_alto"),
        ]
    )
    first = build_case_logs(_case("horizontal_scan_positive"))
    second = build_case_logs(
        {
            **_case("horizontal_scan_positive"),
            "id": "horizontal_scan_second_source",
            "params": {**_case("horizontal_scan_positive")["params"], "source_id": 2},
        }
    )
    for offset, log in enumerate(second, start=len(first) + 1):
        log.id = offset
    db.add_all([*first, *second])
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="v531-test")
    alerts = list(db.scalars(select(Alert).order_by(Alert.id)))
    source_sets = []
    for alert in alerts:
        metadata = next(item for item in alert.matched_rules_json if item.get("code") == "group_metadata")
        source_sets.append(tuple(metadata["source_ids"]))

    assert result["created_alerts"] == 2
    assert result["deduplicated_alert_updates"] == 0
    assert len(alerts) == 2
    assert sorted(source_sets) == [(1,), (2,)]


def test_v531_alert_explanation_is_complete_traceable_and_claim_bounded() -> None:
    db = _session()
    _persist_case(db, "vertical_scan_positive")
    result = run_detection(db, limit=100, use_ml=False, actor="v531-test")
    alert = db.scalar(select(Alert))
    assert alert is not None

    summary = build_alert_detection_summary(db, alert)
    completeness = alert_explanation_completeness(alert, summary)

    assert result["created_alerts"] == 1
    assert summary["alert_identity"]["id"] == alert.id
    assert summary["attack_type"] == "port_scan"
    assert summary["attack_mapping"]["technique_id"] == "T1046"
    assert summary["attack_mapping"]["mapping_origin"] == "deterministic_rule_mapping"
    assert summary["attack_mapping"]["mitre_supported"] is True
    assert any(item["code"] == "possible_port_scan" for item in summary["exact_evidence_signals"])
    assert any(item["code"] == "possible_port_scan" for item in summary["risk_score_basis"]["components"])
    assert summary["false_positive_considerations"]
    assert summary["evidence_limitations"]
    assert summary["prioritized_analyst_checks"]
    assert summary["traceability"]["alert_id"] == alert.id
    assert summary["traceability"]["source_ids"] == [1]
    assert len(summary["traceability"]["evidence_log_ids"]) == 10
    assert summary["traceability"]["case"]["case_id"]
    assert completeness["passed"] is True
    assert completeness["score"] == 1.0


def test_v531_every_catalog_rule_has_explanation_and_false_positive_contract() -> None:
    assert RULE_CATALOG_VERSION == "atdr_rule_catalog_v5.31.0"
    assert len(RULE_CATALOG) == 19
    for code, spec in RULE_CATALOG.items():
        assert spec.rule_id
        assert spec.condition
        assert spec.required_fields
        assert spec.false_positives
        assert spec.explanation_template
        assert spec.claim_boundary
        assert spec.references
        if spec.mitre_technique_ids:
            assert any("attack.mitre.org" in reference for reference in spec.references), code

        alert = Alert(
            id=1,
            title=spec.title,
            alert_type=code,
            src_ip="203.0.113.1",
            dst_ip="10.0.0.1",
            threat_score=50,
            severity="Medium",
            status="open",
            explanation=spec.explanation_template,
            matched_rules_json=[{"code": code, "title": spec.title}],
            recommended_response="Review linked evidence and validate context.",
        )
        alert.evidence.append(AlertEvidence(normalized_log_id=1))
        completeness = alert_explanation_completeness(
            alert,
            {
                "why_flagged": spec.explanation_template,
                "matched_rule_names": [spec.title],
                "attack_type": spec.attack_type,
                "attack_mapping": {"mapping_origin": "deterministic_rule_mapping"},
                "exact_evidence_signals": [
                    {
                        "code": code,
                        "score_contribution": 10,
                        "observed": spec.explanation_template,
                    }
                ],
                "evidence_limitations": [spec.claim_boundary],
                "false_positive_considerations": list(spec.false_positives),
                "prioritized_analyst_checks": ["Review the linked evidence."],
                "traceability": {
                    "alert_id": 1,
                    "source_ids": [],
                    "evidence_log_ids": [1],
                    "related_log_count": 1,
                    "case": {"case_id": "synthetic-case"},
                },
                "decision_support_only": True,
                "response_automation_allowed": False,
            },
        )
        assert completeness["passed"] is True, code


def test_v531_assisted_or_weak_label_cannot_override_rule_attack_mapping() -> None:
    db = _session()
    logs = _persist_case(db, "vertical_scan_positive")
    run_detection(db, limit=100, use_ml=False, actor="v531-test")
    db.add(
        MLLabel(
            log_id=logs[0].id,
            label="malicious",
            attack_type="malware_c2",
            confidence=99,
            reviewer="assisted-test",
            label_source="assisted",
            reviewed=True,
        )
    )
    db.commit()
    alert = db.scalar(select(Alert))
    assert alert is not None

    summary = build_alert_detection_summary(db, alert)

    assert summary["attack_type"] == "port_scan"
    assert summary["attack_mapping"]["mapping_origin"] == "deterministic_rule_mapping"


def test_v531_assistant_explains_governed_rule_output_concisely_without_operational_mutation(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ASSISTANT_ENABLED", "false")
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "false")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "")
    monkeypatch.setenv("ASSISTANT_LLM_MODEL", "")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "")
    monkeypatch.setenv("ASSISTANT_ALLOW_RAW_LOG_CONTEXT", "false")
    monkeypatch.setenv("ASSISTANT_REDACT_IPS", "true")
    get_settings.cache_clear()

    db = _session()
    _persist_case(db, "vertical_scan_positive")
    run_detection(db, limit=100, use_ml=False, actor="v531-test")
    alert = db.scalar(select(Alert))
    assert alert is not None
    before = {
        "alerts": _count(db, Alert),
        "logs": _count(db, NormalizedLog),
        "responses": _count(db, ResponseAction),
        "labels": _count(db, MLLabel),
        "models": _count(db, MLModelRun),
        "detection_runs": _count(db, DetectionRun),
    }
    conversation_id = "v531assistant01"

    first = answer_assistant_question(
        db,
        question=f"Why was alert {alert.id} flagged?",
        actor="analyst",
        settings=get_settings(),
        conversation_id=conversation_id,
    )
    followup = answer_assistant_question(
        db,
        question="What should I check next?",
        actor="analyst",
        settings=get_settings(),
        conversation_id=conversation_id,
    )
    after = {
        "alerts": _count(db, Alert),
        "logs": _count(db, NormalizedLog),
        "responses": _count(db, ResponseAction),
        "labels": _count(db, MLLabel),
        "models": _count(db, MLModelRun),
        "detection_runs": _count(db, DetectionRun),
    }

    assert first["response_mode"] == "alert_explanation"
    assert len(first["answer"].split()) <= 110
    assert first["external_provider_used"] is False
    assert first["raw_log_context_included"] is False
    assert first["active_context"]["alert_id"] == alert.id
    assert first["details"]["answer_sections"]["direct_answer"]
    assert first["details"]["answer_sections"]["key_evidence"]
    assert any(
        citation["source"] == "/api/alerts/{alert_id}" and citation["reference_id"] == str(alert.id)
        for citation in first["citations"]
    )
    assert any(citation["source"] == "/api/alerts/cases" for citation in first["citations"])
    assert followup["response_mode"] == "safe_next_step"
    assert len(followup["answer"].split()) <= 100
    assert followup["active_context"]["alert_id"] == alert.id
    assert before == after
    assert _count(db, AuditLog) >= 2
    get_settings.cache_clear()
