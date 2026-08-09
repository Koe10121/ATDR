from __future__ import annotations

import csv
import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v526_native_blind_qualification as v526
from atdr.app.detection import v527_blind_review_evaluation as blind
from atdr.app.services.v524_investigation_gemini_quality_service import (
    disposable_v524_session,
)
from atdr.app.services.v527_gemini_real_alert_quality_service import (
    SNAPSHOT_RAW_SENTINEL,
    run_v527_gemini_real_alert_quality,
)


def _review_row(index: int, *, reviewed: bool = False) -> dict[str, object]:
    threat = index % 2 == 1
    return {
        "review_token": f"token-{index:03d}",
        "evidence_role": "untouched_future_validation",
        "evidence_role_is_blind": True,
        "pattern": "scan_like" if threat else "routine_web",
        "review_priority": "high",
        "event_time_utc": "2026-05-20T10:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "unknown" if threat else "ssl",
        "action": "deny" if threat else "allow",
        "protocol": "tcp",
        "source_port": 45000 + index,
        "destination_port": 22 if threat else 443,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 5 if threat else 2,
        "threat_severity": "",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 20 if threat else 2,
        "source_deny_count": 12 if threat else 0,
        "source_unique_destinations": 10 if threat else 1,
        "source_unique_ports": 12 if threat else 1,
        "source_unknown_app_count": 10 if threat else 0,
        "source_high_risk_app_count": 4 if threat else 0,
        "destination_repeat_count": 1,
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "human_decision": "malicious" if reviewed and threat else "benign" if reviewed else "",
        "human_attack_type": "port_scan" if reviewed and threat else "none" if reviewed else "",
        "human_confidence": "90" if reviewed else "",
        "human_notes": "Independent analyst reviewed the structured evidence." if reviewed else "",
        "human_reviewer": "independent-analyst" if reviewed else "",
        "human_reviewed_at": "2026-08-01T10:00:00+00:00" if reviewed else "",
        "human_must_confirm": not reviewed,
        "import_ready": False,
        "assisted_suggestion": "",
        "assisted_attack_type": "",
        "assisted_confidence": "",
        "assisted_reason": "",
        "assisted_provenance": "",
        "rule_codes": "",
        "rule_score": "",
        "suggestion_is_weak": False,
        "human_reviewed": reviewed,
        "blind_suggestion_suppressed": True,
    }


def _prediction(index: int) -> dict[str, object]:
    queued = index % 2 == 1
    queue = "needs_review" if queued else "non_threat"
    score = 0.9 if queued else 0.1
    return {
        "review_token": f"token-{index:03d}",
        "pattern": "scan_like" if queued else "routine_web",
        "app": "unknown" if queued else "ssl",
        "action": "deny" if queued else "allow",
        "dst_port": 22 if queued else 443,
        "schema": "traffic_full",
        "log_type": "TRAFFIC",
        "rule_queue": queue,
        "rule_score": score,
        "isolation_queue": queue,
        "isolation_score": score,
        "supervised_queue": queue,
        "supervised_score": score,
        "hybrid_queue": queue,
        "hybrid_score": score,
    }


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_contracts(directory: Path, rows: list[dict[str, object]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    _write_csv(directory / v521.V521_BLIND_PACK, rows)
    (directory / v521.V521_MANIFEST_LATEST).write_text(
        json.dumps({"blind_pack_fingerprint": v521._pack_fingerprint(rows)}),
        encoding="utf-8",
    )
    (directory / v526.V526_PREDICTION_LOCK).write_text(
        json.dumps(
            {
                "prediction_rows": [_prediction(index) for index in range(len(rows))],
                "predictions_created_before_label_access": True,
                "human_label_fields_included": False,
                "raw_logs_included": False,
                "ip_addresses_included": False,
                "source_path_included": False,
                "secret_values_included": False,
            }
        ),
        encoding="utf-8",
    )
    (directory / v526.V526_LATEST).write_text(
        json.dumps(
            {
                "prediction_frozen_before_label_access": True,
                "prediction_lock_persisted_privately": True,
                "blind_labels_used_for_candidate_selection": False,
            }
        ),
        encoding="utf-8",
    )


def _validate(directory: Path, *, write_seal: bool = False):
    return blind.validate_blind_review_intake(
        pack_path=directory / v521.V521_BLIND_PACK,
        prediction_lock_path=directory / v526.V526_PREDICTION_LOCK,
        manifest_path=directory / v521.V521_MANIFEST_LATEST,
        v526_result_path=directory / v526.V526_LATEST,
        seal_path=directory / blind.V527_PRIVATE_SEAL,
        write_private_seal=write_seal,
    )


def test_v527_unreviewed_pack_withholds_all_locked_metrics(tmp_path: Path) -> None:
    rows = [_review_row(index) for index in range(40)]
    _write_contracts(tmp_path, rows)

    labels, contexts, predictions, audit = _validate(tmp_path)
    evaluation = blind._evaluate_layers(
        labels,
        contexts,
        predictions,
        enough_for_metrics=audit["enough_for_metrics"],
    )

    assert audit["valid_reviewed_rows"] == 0
    assert audit["rejection_reasons"] == {"not_reviewed": 40}
    assert evaluation["metrics_calculated"] is False
    assert evaluation["layers"] == {}
    assert evaluation["false_positive_or_negative_claims_made"] is False


def test_v527_valid_independent_reviews_join_existing_predictions_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    rows = [_review_row(index, reviewed=True) for index in range(20)]
    _write_contracts(tmp_path, rows)
    monkeypatch.setattr(
        v526,
        "_run_prediction_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("prediction rerun")),
    )

    result = blind.run_v527_blind_review_evaluation(
        evidence_dir=tmp_path,
        output_dir=tmp_path,
        write_reports=False,
        write_private_seal=False,
    )

    assert result["locked_evaluation"]["metrics_calculated"] is True
    assert result["locked_evaluation"]["layers"]["supervised"]["metrics"]["queue_f1"] == 1.0
    assert result["locked_evaluation"]["layers"]["supervised"]["metrics"]["benign_like_false_positive_rate"] == 0.0
    assert result["safety"]["predictions_rerun"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["response_actions_created"] == 0


def test_v527_rejects_assisted_prediction_exposed_and_automated_reviews(
    tmp_path: Path,
) -> None:
    rows = [_review_row(index, reviewed=True) for index in range(20)]
    rows[0]["assisted_suggestion"] = "malicious"
    rows[1]["human_reviewer"] = "Gemini assistant"
    rows[2]["human_reviewed_at"] = "not-a-timestamp"
    _write_contracts(tmp_path, rows)

    _labels, _contexts, _predictions, audit = _validate(tmp_path)

    assert audit["blindness_compromised"] is True
    assert audit["valid_reviewed_rows"] == 0
    assert audit["rejection_reasons"]["prediction_or_assisted_evidence_exposed"] == 20
    assert audit["assisted_labels_counted_as_human"] == 0


def test_v527_duplicate_or_mismatched_lock_fails_closed(tmp_path: Path) -> None:
    rows = [_review_row(index, reviewed=True) for index in range(20)]
    rows[-1]["review_token"] = rows[0]["review_token"]
    _write_contracts(tmp_path, rows)

    _labels, _contexts, _predictions, audit = _validate(tmp_path)

    assert audit["lock_contract_passed"] is False
    assert audit["enough_for_metrics"] is False
    assert audit["lock_checks"]["pack_tokens_unique"] is False
    assert audit["fingerprints_returned"] is False


def test_v527_pattern_analysis_tolerates_malformed_numeric_context() -> None:
    row = _review_row(1, reviewed=True)
    row["pattern"] = "routine"
    for field in (
        "application_risk",
        "destination_port",
        "group_size",
        "parser_warning_count",
        "required_missing_count",
        "source_deny_count",
        "source_unique_destinations",
        "source_unique_ports",
    ):
        row[field] = "not-a-number"

    assert blind._parser_quality(row) == "parsed_cleanly"
    assert blind._evidence_strength(row) == "limited_context"
    assert blind._pattern_flags(row) == ["unknown_udp_tcp"]


def _assistant_settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "ASSISTANT_ENABLED": True,
        "ASSISTANT_LLM_ENABLED": True,
        "ASSISTANT_LLM_PROVIDER": "mock",
        "ASSISTANT_LLM_MODEL": "v527-mock",
        "ASSISTANT_LLM_API_KEY": "",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": False,
        "ASSISTANT_REDACT_IPS": True,
    }
    values.update(updates)
    return Settings(**values)


def test_v527_real_record_assistant_quality_is_bounded_private_and_read_only() -> None:
    with disposable_v524_session() as source_db:
        report = run_v527_gemini_real_alert_quality(
            source_db,
            settings=_assistant_settings(),
            execute_provider=True,
            write_reports=False,
        )

    assert report["provider"] == "mock"
    assert report["provider_measurements"]["calls_used"] >= 3
    assert report["checks"]["configured_database_read_only"] is True
    assert report["checks"]["disposable_authoritative_state_unchanged"] is True
    assert report["checks"]["provider_failure_fallback_passed"] is True
    assert report["checks"]["citation_contract_passed"] is True
    assert report["checks"]["record_context_retained"] is True
    assert report["checks"]["safe_recommendations_only"] is True
    assert report["configured_database_mutation_deltas"] == {
        "raw_logs": 0,
        "normalized_logs": 0,
        "alerts": 0,
        "detection_runs": 0,
        "labels": 0,
        "model_runs": 0,
        "response_actions": 0,
        "users": 0,
        "audit_logs": 0,
    }
    serialized = json.dumps(report)
    assert SNAPSHOT_RAW_SENTINEL not in serialized
    assert "203.0.113.77" not in serialized
    assert "198.51.100.88" not in serialized


def test_v527_provider_preflight_does_not_claim_real_provider_quality() -> None:
    with disposable_v524_session() as source_db:
        report = run_v527_gemini_real_alert_quality(
            source_db,
            settings=_assistant_settings(),
            execute_provider=False,
            write_reports=False,
        )

    assert report["status"] == "v5_27_real_record_provider_evaluation_not_requested"
    assert report["provider_measurements"]["calls_used"] == 0
    assert report["raw_log_context_allowed"] is False
    assert report["redaction_enabled"] is True


def test_v527_real_record_evaluator_fails_closed_without_alerts() -> None:
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as source_db:
        report = run_v527_gemini_real_alert_quality(
            source_db,
            settings=_assistant_settings(),
            execute_provider=False,
            write_reports=False,
        )
    engine.dispose()

    assert report["ok"] is False
    assert report["status"] == "no_existing_alerts_available_for_bounded_evaluation"
    assert all(value == 0 for value in report["configured_database_mutation_deltas"].values())
