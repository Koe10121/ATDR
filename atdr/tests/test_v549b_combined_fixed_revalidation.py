from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, DetectionRun, MLLabel, MLModelRun, ResponseAction
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548
from atdr.app.detection import (
    v549a_supplemental_threat_anchor_acquisition as v549a,
)
from atdr.app.detection import v549b_combined_fixed_revalidation as v549b
from atdr.app.main import app
from atdr.app.routers import evidence_review as review_router
from atdr.app.services.user_service import create_user


def _row(
    index: int,
    *,
    role: str,
    supplemental: bool,
) -> dict[str, object]:
    return {
        "review_token": (
            f"supplemental-token-{index:03d}"
            if supplemental
            else f"original-token-{index:03d}"
        ),
        "evidence_role": role,
        "selection_stratum": (
            "supplemental_rule_evidence" if supplemental else "original_anchor"
        ),
        "review_priority": (
            "supplemental_threat_anchor" if supplemental else "manual_anchor_gap"
        ),
        "event_time_utc": f"2026-08-01T{index % 24:02d}:{index % 60:02d}:00+00:00",
        "log_type": "THREAT" if supplemental and index % 4 == 0 else "TRAFFIC",
        "subtype": "end",
        "application": "unknown-tcp" if supplemental else "ssl",
        "action": "deny" if supplemental else "allow",
        "protocol": "tcp",
        "source_port": 45000 + index,
        "destination_port": 445 if supplemental else 443,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 4000 if supplemental else 1200,
        "packets": 20 if supplemental else 10,
        "elapsed_time": 2,
        "application_risk": 5 if supplemental else 2,
        "threat_severity": "high" if supplemental else "none",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 25 if supplemental else 2,
        "source_deny_count": 20 if supplemental else 0,
        "source_unique_destinations": 12 if supplemental else 1,
        "source_unique_ports": 15 if supplemental else 1,
        "source_unknown_app_count": 10 if supplemental else 0,
        "source_high_risk_app_count": 3 if supplemental else 0,
        "destination_repeat_count": 1,
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "rule_evidence": "possible_port_scan" if supplemental else "",
        "rule_evidence_score": 100 if supplemental else 0,
        "source_auth_deny_count": 10 if supplemental else 0,
        "bytes_sent": 4000 if supplemental else 1200,
        "external_to_internal": supplemental,
        "human_decision": "",
        "human_attack_type": "",
        "human_confidence": "",
        "human_rationale": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_must_confirm": True,
        "human_reviewed": False,
        "import_ready": False,
    }


def _review_rows(
    rows: list[dict[str, Any]],
    decisions: list[str],
) -> None:
    reviewed_at = datetime.now(UTC).isoformat()
    for row, decision in zip(rows, decisions, strict=True):
        row.update(
            {
                "human_decision": decision,
                "human_attack_type": (
                    "malware_c2"
                    if decision == "malicious"
                    else "port_scan"
                    if decision == "suspicious"
                    else ""
                ),
                "human_confidence": "90",
                "human_rationale": (
                    "Independent human decision based on approved evidence."
                ),
                "human_reviewer": "reviewer-one",
                "human_reviewed_at": reviewed_at,
                "human_must_confirm": True,
                "human_reviewed": True,
                "import_ready": False,
            }
        )


def _prepare_combined_workspace(root: Path) -> tuple[Path, Path]:
    original = root / "original"
    supplemental = root / "supplemental"
    roles = ["development_fit", "calibration", "threshold"]

    original_rows = [
        _row(index, role=roles[index % 3], supplemental=False)
        for index in range(v549b.EXPECTED_ORIGINAL_ROWS)
    ]
    v547._prepare_workspace(
        original_rows,
        {
            "selected_rows": len(original_rows),
            "target_rows": len(original_rows),
            "coverage_gate_passed": True,
            "coverage_counts": {"original_anchor": len(original_rows)},
        },
        output_dir=original,
    )
    v548.lock_fixed_protocol(original)
    original_working, _ = v547._read_csv(original / v547.V547_WORKING_COPY)
    _review_rows(
        original_working,
        ["benign"] * 92 + ["suspicious"] * 9 + ["needs_context"] * 19,
    )
    v547._atomic_write_csv(original / v547.V547_WORKING_COPY, original_working)
    v548._atomic_write_json(
        original / v548.V548_REVIEW_STATE,
        {
            "schema_version": v548.V548_VERSION,
            "revision": 120,
            "closed_at": datetime.now(UTC).isoformat(),
        },
    )

    supplemental_rows = [
        _row(index, role=roles[index % 3], supplemental=True)
        for index in range(v549b.EXPECTED_SUPPLEMENTAL_ROWS)
    ]
    v549a._prepare_workspace(
        supplemental_rows,
        {
            "selected_rows": len(supplemental_rows),
            "target_rows": len(supplemental_rows),
            "coverage_gate_passed": True,
            "coverage_counts": {
                "supplemental_rule_evidence": len(supplemental_rows)
            },
        },
        output_dir=supplemental,
        original_output_dir=original,
    )
    supplemental_working, _ = v547._read_csv(
        supplemental / v549a.V549A_WORKING_COPY
    )
    _review_rows(
        supplemental_working,
        ["benign"] * 3 + ["suspicious"] * 30 + ["malicious"] * 27,
    )
    v547._atomic_write_csv(
        supplemental / v549a.V549A_WORKING_COPY,
        supplemental_working,
    )
    v547._atomic_write_json(
        supplemental / v549a.V549A_REVIEW_STATE,
        {
            "schema_version": v549a.V549A_VERSION,
            "revision": 60,
            "closed_at": datetime.now(UTC).isoformat(),
        },
    )
    proposal = v549a.write_proposed_v549b_protocol(
        output_dir=supplemental,
        original_output_dir=original,
    )
    assert proposal is not None
    return original, supplemental


def _fake_comparison() -> dict[str, Any]:
    strategies = []
    for index, spec in enumerate(v548.FIXED_CANDIDATE_STRATEGIES):
        passed = index == 0
        strategies.append(
            {
                "name": spec["name"],
                "status": "evaluated",
                "model_type": spec["model_type"],
                "target_mode": spec["target_mode"],
                "queue_precision": 0.91,
                "queue_recall": 0.90,
                "queue_f1": 0.905,
                "threat_positive_precision": 0.91,
                "threat_positive_recall": 0.90,
                "threat_positive_f1": 0.905,
                "benign_like_false_positive_rate": 0.08,
                "suspicious_recall": 0.88,
                "malicious_recall": 0.92,
                "macro_f1": 0.86,
                "weighted_f1": 0.89,
                "review_queue_rate": 0.55,
                "false_positives": 2,
                "false_negatives": 2,
                "brier_score": 0.09,
                "expected_calibration_error": 0.07,
                "max_confidence_accuracy_gap": 0.10,
                "applied_calibration_method": "sigmoid_prefit",
                "fixed_gate_passed": passed,
                "gate_checks": {
                    "queue_precision": passed,
                    "queue_recall": passed,
                    "queue_f1": passed,
                },
                "gate_values": dict(v548.FIXED_QUALITY_GATES),
            }
        )
    return {
        "partition_rows": {
            "fit": 60,
            "calibration": 60,
            "threshold": 30,
            "evaluation": 30,
        },
        "strategy_count": 8,
        "evaluated_strategy_count": 8,
        "strategies": strategies,
        "passing_strategy_count": 1,
        "diagnostic_candidate": strategies[0]["name"],
        "diagnostic_candidate_qualified": True,
    }


def test_preflight_locks_immutable_combined_protocol(tmp_path: Path) -> None:
    original, supplemental = _prepare_combined_workspace(tmp_path)
    result = v549b.run_v549b_combined_fixed_revalidation(
        output_dir=supplemental,
        original_output_dir=original,
        preflight_only=True,
        use_temp_db=True,
    )
    assert result["ok"] is True
    assert result["status"] == "ready_for_combined_fixed_revalidation"
    assert result["custody"]["combined_class_support"] == {
        "benign_like": 95,
        "suspicious": 39,
        "malicious": 27,
    }
    assert result["protocol"]["locked"] is True
    assert result["protocol"]["contracts_unchanged"] is True
    assert result["evaluation_execution_count"] == 0
    assert not (original / v548.V548_EXECUTION_CLAIM).exists()
    assert not (original / v548.V548_RESULT).exists()
    assert not (supplemental / v549b.V549B_EXECUTION_CLAIM).exists()


def test_claim_precedes_label_loading_and_execution_is_at_most_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, supplemental = _prepare_combined_workspace(tmp_path)
    v549b.lock_combined_protocol(
        output_dir=supplemental,
        original_output_dir=original,
    )
    real_loader = v549b._load_combined_review_rows_after_claim

    def guarded_loader(**kwargs: Any) -> list[dict[str, Any]]:
        assert (supplemental / v549b.V549B_EXECUTION_CLAIM).is_file()
        return real_loader(**kwargs)

    monkeypatch.setattr(
        v549b,
        "_load_combined_review_rows_after_claim",
        guarded_loader,
    )
    monkeypatch.setattr(v549b, "_run_comparison", lambda rows: _fake_comparison())
    first = v549b.run_v549b_combined_fixed_revalidation(
        output_dir=supplemental,
        original_output_dir=original,
        confirmation=v549b.MEASURED_CONFIRMATION,
        use_temp_db=True,
    )
    assert first["ok"] is True
    assert first["executed_now"] is True
    assert first["evaluation_execution_count"] == 1
    assert first["evaluated_strategy_count"] == 8
    assert first["diagnostic_candidate_qualified"] is True
    second = v549b.run_v549b_combined_fixed_revalidation(
        output_dir=supplemental,
        original_output_dir=original,
        confirmation=v549b.MEASURED_CONFIRMATION,
        use_temp_db=True,
    )
    assert second["ok"] is True
    assert second["executed_now"] is False
    assert second["evaluation_execution_count"] == 1


def test_interruption_and_tampering_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, supplemental = _prepare_combined_workspace(tmp_path / "interrupted")
    v549b.lock_combined_protocol(
        output_dir=supplemental,
        original_output_dir=original,
    )

    def interrupt(**kwargs: Any) -> list[dict[str, Any]]:
        del kwargs
        assert (supplemental / v549b.V549B_EXECUTION_CLAIM).is_file()
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(v549b, "_load_combined_review_rows_after_claim", interrupt)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        v549b.run_v549b_combined_fixed_revalidation(
            output_dir=supplemental,
            original_output_dir=original,
            confirmation=v549b.MEASURED_CONFIRMATION,
            use_temp_db=True,
        )
    status = v549b.get_public_v549b_status(
        output_dir=supplemental,
        original_output_dir=original,
    )
    assert status["status"] == "combined_fixed_revalidation_failed_closed"
    assert status["evaluation_execution_count"] == 1
    assert status["metrics_available"] is False

    original_two, supplemental_two = _prepare_combined_workspace(tmp_path / "tampered")
    v549b.lock_combined_protocol(
        output_dir=supplemental_two,
        original_output_dir=original_two,
    )
    working = supplemental_two / v549a.V549A_WORKING_COPY
    working.write_text(working.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(v549b.V549BRevalidationError):
        v549b.run_v549b_combined_fixed_revalidation(
            output_dir=supplemental_two,
            original_output_dir=original_two,
            confirmation=v549b.MEASURED_CONFIRMATION,
            use_temp_db=True,
        )
    assert not (supplemental_two / v549b.V549B_EXECUTION_CLAIM).exists()


def test_strategy_projection_reports_all_metrics_and_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_strategies = []
    for index, spec in enumerate(v548.FIXED_CANDIDATE_STRATEGIES):
        raw_strategies.append(
            {
                "name": spec["name"],
                "status": "evaluated",
                "model_type": spec["model_type"],
                "target_mode": spec["target_mode"],
                "metrics": {
                    "queue_precision": 0.9,
                    "queue_recall": 0.9,
                    "queue_f1": 0.9,
                    "threat_positive_precision": 0.9,
                    "threat_positive_recall": 0.9,
                    "threat_positive_f1": 0.9,
                    "benign_like_false_positive_rate": 0.05,
                    "suspicious_recall": 0.9,
                    "malicious_recall": 0.9,
                    "macro_f1": 0.88,
                    "weighted_f1": 0.89,
                    "review_queue_rate": 0.55,
                    "false_positives": 1,
                    "false_negatives": 1,
                },
                "calibration": {
                    "brier_score": 0.08,
                    "expected_calibration_error": 0.07,
                    "max_confidence_accuracy_gap": 0.09,
                },
                "applied_calibration_method": "sigmoid_prefit",
                "fixed_freeze_gate": {
                    "passed": index == 0,
                    "checks": {"queue_f1": index == 0},
                    "gates": dict(v548.FIXED_QUALITY_GATES),
                },
            }
        )
    monkeypatch.setattr(
        v549b.v548,
        "_run_fixed_comparison",
        lambda rows: {
            "partition_rows": {},
            "strategies": raw_strategies,
        },
    )
    result = v549b._run_comparison([])
    assert result["strategy_count"] == 8
    assert result["evaluated_strategy_count"] == 8
    assert result["diagnostic_candidate"] == raw_strategies[0]["name"]
    projected = result["strategies"][0]
    assert {
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "threat_positive_precision",
        "threat_positive_recall",
        "threat_positive_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
        "review_queue_rate",
        "false_positives",
        "false_negatives",
        "brier_score",
        "expected_calibration_error",
        "max_confidence_accuracy_gap",
        "gate_checks",
        "gate_values",
    } <= set(projected)


def test_real_fixed_comparison_attempts_all_eight_strategies(
    tmp_path: Path,
) -> None:
    original, supplemental = _prepare_combined_workspace(tmp_path)
    original_rows, _ = v547._read_csv(original / v547.V547_WORKING_COPY)
    supplemental_rows, _ = v547._read_csv(
        supplemental / v549a.V549A_WORKING_COPY
    )
    result = v549b._run_comparison([*original_rows, *supplemental_rows])
    assert result["strategy_count"] == 8
    assert result["evaluated_strategy_count"] == 8
    assert len(result["strategies"]) == 8
    assert all("gate_checks" in row for row in result["strategies"])


@pytest.fixture()
def api_client(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, sessionmaker[Session]], None, None]:
    safe_status = {
        "version": v549b.V549B_VERSION,
        "status": "combined_fixed_revalidation_completed",
        "custody": {
            "original_reviewed": 120,
            "supplemental_reviewed": 60,
            "combined_reviewed": 180,
            "remaining": 0,
            "invalid": 0,
            "reviews_closed": True,
            "reviews_immutable": True,
            "combined_class_support": {
                "benign_like": 95,
                "suspicious": 39,
                "malicious": 27,
            },
            "minimum_class_support": {
                "benign_like": 20,
                "suspicious": 15,
                "malicious": 10,
            },
            "combined_support_passed": True,
            "old_evaluation_execution_count": 0,
        },
        "protocol": {
            "version": v549b.V549B_PROTOCOL_VERSION,
            "locked": True,
            "valid": True,
            "immutable": True,
            "strategy_count": 8,
            "combined_rows": 180,
            "contracts_unchanged": True,
            "supplemental_evidence_threat_enriched": True,
            "representative_of_production_prevalence": False,
            "digest_exposed": False,
        },
        "evaluation_attempted": True,
        "evaluation_execution_count": 1,
        "metrics_available": True,
        "strategy_count": 8,
        "evaluated_strategy_count": 8,
        "strategies": [],
        "diagnostic_candidate": None,
        "diagnostic_candidate_qualified": False,
        "selection_bias_notice": "Diagnostic only.",
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "labels_written": 0,
        "model_runs_written": 0,
        "detection_runs_written": 0,
        "alerts_written": 0,
        "response_actions_written": 0,
        "predictions_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "private_paths_exposed": False,
        "fingerprints_exposed": False,
        "digests_exposed": False,
        "secrets_exposed": False,
    }
    monkeypatch.setattr(review_router, "get_public_v549b_status", lambda: safe_status)
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    with factory() as db:
        create_user(
            db,
            username="reviewer-one",
            password="analyst123",
            role="analyst",
            full_name="Reviewer One",
        )

    def override_get_db() -> Generator[Session, None, None]:
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), factory
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_aggregate_status_requires_auth_and_has_no_authoritative_mutations(
    api_client,
) -> None:
    client, factory = api_client
    route = "/api/evidence-review/combined-manual-anchors/revalidation-status"
    assert client.get(route).status_code == 401
    login = client.post(
        "/api/auth/login",
        json={"username": "reviewer-one", "password": "analyst123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    response = client.get(route, headers=headers)
    assert response.status_code == 200
    payload = response.json()
    serialized = json.dumps(payload).casefold()
    assert payload["evaluation_execution_count"] == 1
    assert payload["rules_alert_authoritative"] is True
    assert payload["model_activated"] is False
    for forbidden in (
        "review_token",
        "reviewer-one",
        "source_ip",
        "destination_ip",
        "\"raw_log\":",
        "fingerprint_value",
        "protocol_digest",
    ):
        assert forbidden not in serialized
    with factory() as db:
        assert int(db.scalar(select(func.count(MLLabel.id))) or 0) == 0
        assert int(db.scalar(select(func.count(MLModelRun.id))) or 0) == 0
        assert int(db.scalar(select(func.count(DetectionRun.id))) or 0) == 0
        assert int(db.scalar(select(func.count(Alert.id))) or 0) == 0
        assert int(db.scalar(select(func.count(ResponseAction.id))) or 0) == 0
