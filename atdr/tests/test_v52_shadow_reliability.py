from __future__ import annotations

import json

from atdr.app.detection import v52_shadow_reliability as reliability


def _summary(*, checks: int, f1: float, fpr: float, suspicious: float, malicious: float) -> dict:
    return {
        "strict_passing_splits": 0,
        "aggregate_gate_checks_passed": checks,
        "aggregate_gate_checks_total": 30,
        "calibration_passed_splits": 1,
        "metric_ranges": {
            "queue_f1": {"min": f1, "max": f1, "mean": f1},
            "benign_like_false_positive_rate": {"min": fpr, "max": fpr, "mean": fpr},
            "suspicious_recall": {"min": suspicious, "max": suspicious, "mean": suspicious},
            "malicious_recall": {"min": malicious, "max": malicious, "mean": malicious},
        },
    }


def test_diagnostic_selection_excludes_non_model_detection_baselines():
    comparison = {
        "hybrid_rule_anomaly_supervised_decision_support": _summary(
            checks=29,
            f1=0.99,
            fpr=0.01,
            suspicious=0.99,
            malicious=0.99,
        ),
        "calibrated_binary_hist_gradient_boosting_sigmoid": _summary(
            checks=12,
            f1=0.75,
            fpr=0.20,
            suspicious=0.70,
            malicious=0.85,
        ),
        "binary_extra_trees_balanced": _summary(
            checks=10,
            f1=0.80,
            fpr=0.12,
            suspicious=0.65,
            malicious=0.90,
        ),
    }

    selected = reliability._select_diagnostic(comparison)

    assert selected["name"] == "calibrated_binary_hist_gradient_boosting_sigmoid"
    assert selected["eligible_for_activation"] is False
    assert selected["candidate_selected"] is False
    assert selected["governance_outcome"] == "no_supervised_candidate_selected"
    assert "No candidate is selected" in selected["selection_rationale"]


def test_readiness_fails_closed_with_explicit_blocker_language():
    readiness = reliability._readiness(
        {"candidate": _summary(checks=12, f1=0.75, fpr=0.20, suspicious=0.70, malicious=0.85)},
        {"passed_v49_gates": False},
        {"available": True, "false_positive_count": 0, "false_negative_count": 0},
        {
            "database_counts_unchanged": True,
            "active_artifact_unchanged": True,
            "response_actions_created": 0,
        },
    )

    assert readiness["decision"] == "shadow_observation"
    assert readiness["model_activated"] is False
    assert readiness["production_promoted"] is False
    assert readiness["response_automation_allowed"] is False
    assert "No supervised strategy passes every required internal split" in readiness["blockers"]
    assert "Locked external benchmark does not pass strict gates" in readiness["blockers"]


def test_extra_strategy_matrix_includes_sigmoid_isotonic_and_no_artifact_write(monkeypatch):
    calls: list[dict] = []

    def fake_fit(*_args, **kwargs):
        calls.append(kwargs)
        return {
            "status": "evaluated",
            "final_scores": [0.2, 0.8],
            "threshold_selection": {"selected_threshold": 0.5},
            "calibration_method": kwargs["calibration_method"],
            "sample_weighting": kwargs["weight_strategy"],
            "training_seconds": 0.01,
        }

    def fake_evaluate(*_args, name, details, **_kwargs):
        return {
            "name": name,
            "status": "evaluated",
            "metrics": {},
            "calibration": {},
            "threshold_selection": {"selected_threshold": 0.5},
            "details": details,
        }

    monkeypatch.setattr(reliability.reliability, "_fit_candidate", fake_fit)
    monkeypatch.setattr(reliability.reliability, "_evaluate", fake_evaluate)

    rows = reliability._extra_strategies({"targets": []}, {}, seed=52)

    assert {call["calibration_method"] for call in calls} == {"sigmoid", "isotonic"}
    assert {row["name"] for row in rows} == {
        "calibrated_binary_extra_trees_isotonic",
        "binary_hist_gradient_boosting_weighted",
        "calibrated_binary_hist_gradient_boosting_sigmoid",
        "calibrated_binary_logistic_regression_isotonic",
    }
    assert all(row["details"]["diagnostic_only"] is True for row in rows)
    assert all(row["details"].get("active_artifact_written", False) is False for row in rows)


def test_private_shadow_summary_reads_v50_report_shape_without_private_evidence(tmp_path, monkeypatch):
    report = {
        "shadow_ingestion": {
            "raw_logs": 5000,
            "normalized_logs": 4998,
            "parse_failures": 2,
        },
        "ml_diagnostics": {
            "supervised_queue": {
                "sample_rows": 1000,
                "queue_rows": 47,
                "queue_rate_percent": 4.7,
            }
        },
        "current_database_unchanged": True,
        "model_artifacts_unchanged": True,
        "model_activated": False,
        "model_promoted": False,
        "response_actions_created": 0,
        "private_path_returned": False,
        "raw_evidence_returned": False,
        "secrets_exposed": False,
    }
    report_path = tmp_path / "v5_0_shadow_validation_20260722T000000Z.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(reliability, "PRIVATE_SHADOW_DIR", tmp_path)

    summary = reliability._safe_private_summary()

    assert summary["processed_rows"] == 5000
    assert summary["normalized_rows"] == 4998
    assert summary["parse_failures"] == 2
    assert summary["scored_rows"] == 1000
    assert summary["queued_rows"] == 47
    assert summary["database_counts_unchanged"] is True
    assert summary["active_artifact_unchanged"] is True
    assert summary["raw_logs_included"] is False
    assert summary["private_identifiers_included"] is False
    assert summary["secrets_exposed"] is False


def test_controlled_scenario_summary_uses_scenario_counts_not_layered_mode_counts(tmp_path):
    report_path = tmp_path / "detection_validation.json"
    summary = reliability._controlled_scenario_summary(
        {
            "ok": True,
            "scenario_count": 24,
            "passed_count": 24,
            "use_temp_db": True,
            "safety": {
                "automatic_response_enabled": False,
                "real_firewall_blocking_enabled": False,
                "production_readiness_claim": False,
            },
        },
        report_path,
    )

    assert summary["scenario_count"] == 24
    assert summary["passed_count"] == 24
    assert summary["failed_count"] == 0
    assert summary["temporary_database_used"] is True
    assert summary["automatic_response_enabled"] is False
