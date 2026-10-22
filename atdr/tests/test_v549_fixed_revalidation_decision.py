from __future__ import annotations

from pathlib import Path

import pytest

from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548


def _strategy(name: str, *, passed: bool = False) -> dict[str, object]:
    checks = {
        "strategy_evaluated": True,
        "queue_precision": passed,
        "queue_recall": passed,
        "queue_f1": passed,
        "benign_like_false_positive_rate": passed,
        "suspicious_recall": passed,
        "malicious_recall": passed,
        "expected_calibration_error": passed,
        "max_confidence_accuracy_gap": passed,
        "calibration_applied": True,
        "duplicate_group_isolation": True,
        "post_prediction_guard_absent": True,
    }
    return {
        "status": "evaluated",
        "name": name,
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "applied_calibration_method": "sigmoid_prefit",
        "metrics": {
            "queue_precision": 0.90 if passed else 0.70,
            "queue_recall": 0.90 if passed else 0.70,
            "queue_f1": 0.90 if passed else 0.70,
            "threat_positive_precision": 0.90 if passed else 0.70,
            "threat_positive_recall": 0.90 if passed else 0.70,
            "threat_positive_f1": 0.90 if passed else 0.70,
            "benign_like_false_positive_rate": 0.05 if passed else 0.30,
            "suspicious_recall": 0.90 if passed else 0.60,
            "malicious_recall": 0.90 if passed else 0.60,
            "macro_f1": 0.88,
            "weighted_f1": 0.89,
            "review_queue_rate": 0.40,
            "false_positive": 1,
            "false_negative": 1,
        },
        "calibration": {
            "brier_score": 0.08,
            "expected_calibration_error": 0.05 if passed else 0.20,
            "max_confidence_accuracy_gap": 0.08 if passed else 0.20,
        },
        "fixed_freeze_gate": {
            "passed": passed,
            "checks": checks,
            "gates": dict(v548.FIXED_QUALITY_GATES),
        },
    }


def _result(*, leader_passed: bool = True) -> dict[str, object]:
    names = [str(spec["name"]) for spec in v548.FIXED_CANDIDATE_STRATEGIES]
    strategies = [
        _strategy(name, passed=leader_passed and index == 0)
        for index, name in enumerate(names)
    ]
    return {
        "schema_version": v548.V548_VERSION,
        "status": "fixed_development_revalidation_completed",
        "evaluation_execution_count": 1,
        "protocol_valid": True,
        "review_closed": True,
        "strategies": strategies,
        "diagnostic_leader": names[0],
        "leader_passed_fixed_gate": leader_passed,
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "response_automation_allowed": False,
        "automatic_import_performed": False,
        "labels_written": 0,
        "model_runs_written": 0,
        "detection_runs_written": 0,
        "alerts_written": 0,
        "response_actions_written": 0,
    }












def test_private_execution_claim_is_atomic_and_fail_closed(tmp_path: Path) -> None:
    claim = v548._claim_execution(tmp_path, protocol_digest="private-digest")

    assert claim["evaluation_execution_count"] == 1
    assert claim["evaluation_labels_accessed_before_claim"] is False
    with pytest.raises(v548.V548RevalidationError):
        v548._claim_execution(tmp_path, protocol_digest="private-digest")

    validated = v548._validate_execution_claim(
        tmp_path,
        protocol_digest="private-digest",
    )
    assert validated is not None
    assert validated["status"] == "fixed_revalidation_execution_claimed"


def test_fixed_runner_claims_before_evaluation_and_never_repeats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = {"protocol_digest": "private-protocol-digest"}
    status = {
        "review": {
            "closed": True,
            "ready_for_fixed_revalidation": True,
        },
        "evaluation_execution_count": 0,
        "model_activated": False,
        "response_automation_allowed": False,
    }
    calls = 0

    monkeypatch.setattr(v548, "lock_fixed_protocol", lambda _path: protocol)
    monkeypatch.setattr(v548, "validate_fixed_protocol", lambda _path: protocol)
    monkeypatch.setattr(v548, "get_public_v548_status", lambda _path: dict(status))
    monkeypatch.setattr(v548.v547, "_read_csv", lambda _path: ([{}], []))

    def compare(_rows):
        nonlocal calls
        calls += 1
        assert (tmp_path / v548.V548_EXECUTION_CLAIM).is_file()
        return {
            "partition_rows": {},
            "strategies": [],
            "evaluated_strategy_count": 0,
            "diagnostic_leader": None,
            "leader_metrics": {},
            "leader_calibration": {},
            "leader_passed_fixed_gate": False,
        }

    monkeypatch.setattr(v548, "_run_fixed_comparison", compare)

    first = v548.run_v548_manual_anchor_fixed_revalidation(
        output_dir=tmp_path,
        confirmation=v548.MEASURED_CONFIRMATION,
        use_temp_db=True,
    )
    second = v548.run_v548_manual_anchor_fixed_revalidation(
        output_dir=tmp_path,
        confirmation=v548.MEASURED_CONFIRMATION,
        use_temp_db=True,
    )

    assert first["executed_now"] is True
    assert second["executed_now"] is False
    assert calls == 1
    assert (tmp_path / v548.V548_RESULT).is_file()
