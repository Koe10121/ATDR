import json
from pathlib import Path

from atdr.app.benchmarks.readiness import (
    readiness_gate_v8_fresh_blind_validation,
)
from atdr.app.routers.dashboard import _latest_v20_ai_summary
from atdr.scripts import lock_v20_candidate as candidate_lock_module
from atdr.scripts import run_final_controlled_source_acceptance as acceptance_module
from atdr.scripts.build_fresh_blind_holdout import build_fresh_blind_holdout
from atdr.scripts.lock_v20_candidate import (
    CANDIDATE_NAME,
    FROZEN_CANDIDATE_CONFIG,
)
from atdr.scripts.run_v20_fresh_blind_revalidation import _fixed_calibration


def _metrics() -> dict:
    return {
        "threat_positive_precision": 0.89,
        "threat_positive_recall": 0.94,
        "threat_positive_f1": 0.91,
        "benign_false_positive_rate": 0.13,
        "macro_f1": 0.87,
        "weighted_f1": 0.88,
        "false_positives": 43,
        "false_negatives": 20,
        "confusion_matrix": [[287, 3, 40], [18, 171, 1], [2, 24, 154]],
        "per_class": {
            "suspicious": {"recall": 0.85},
            "malicious": {"recall": 0.9},
        },
    }


def test_candidate_lock_records_frozen_profile_and_safety(monkeypatch, tmp_path):
    monkeypatch.setattr(
        candidate_lock_module,
        "_load_json",
        lambda _path: {
            "best_profile": {
                "profile": CANDIDATE_NAME,
                "metrics": _metrics(),
            },
            "paths": {"json": "v1_9b_source.json"},
        },
    )

    result = candidate_lock_module.lock_v20_candidate(output_dir=tmp_path)

    assert result["ok"] is True
    assert result["candidate_name"] == CANDIDATE_NAME
    assert result["threshold_tuning_allowed"] is False
    assert result["holdout_tuning_allowed"] is False
    assert result["candidate_hash"]
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False
    assert Path(result["paths"]["json"]).exists()
    assert Path(result["paths"]["markdown"]).exists()


def test_fresh_blind_builder_is_large_diverse_separate_and_safe(tmp_path):
    result = build_fresh_blind_holdout(
        output_dir=tmp_path,
        csv_path=tmp_path / "fresh.csv",
    )

    assert result["ok"] is True
    assert result["row_count"] == 700
    assert result["source_count"] >= 6
    assert result["scenario_count"] >= 16
    assert result["previous_holdout_overlap"]["exact_overlap_rows"] == 0
    assert result["threshold_tuning_allowed"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert Path(result["snapshot_path"]).exists()


def test_fresh_blind_dry_run_writes_nothing(tmp_path):
    result = build_fresh_blind_holdout(
        output_dir=tmp_path,
        csv_path=tmp_path / "fresh.csv",
        dry_run=True,
    )

    assert result["row_count"] == 700
    assert result["csv_path"] is None
    assert result["snapshot_path"] is None
    assert not list(tmp_path.iterdir())


def test_locked_calibration_method_is_not_reselected(monkeypatch):
    monkeypatch.setattr(
        "atdr.scripts.run_v20_fresh_blind_revalidation._calibration_metrics",
        lambda **_kwargs: {
            "status": "limited",
            "expected_calibration_error": 0.04,
        },
    )

    result = _fixed_calibration(
        y_true=["benign_like", "suspicious"],
        predictions=["benign_like", "suspicious"],
        probabilities=[
            {"benign_like": 0.8, "suspicious": 0.1, "malicious": 0.1},
            {"benign_like": 0.1, "suspicious": 0.8, "malicious": 0.1},
        ],
    )

    assert result["locked_method"] == "raw_confidence"
    assert result["metrics"]["status"] == "limited"
    assert result["method_selection_performed"] is False
    assert result["external_labels_used_for_fit"] is False
    assert result["cross_fitted"] is False


def test_readiness_v8_requires_blind_and_final_controlled_passes():
    result = readiness_gate_v8_fresh_blind_validation(
        candidate_lock_valid=True,
        fresh_blind_label_count=700,
        fresh_blind_source_count=7,
        fresh_blind_scenario_count=16,
        fresh_blind_metrics=_metrics(),
        calibration_status="passed",
        exact_overlap_passed=True,
        threshold_tuning_performed=False,
        uses_source_or_scenario_identity=False,
        controlled_real_source_passed=True,
        final_controlled_acceptance_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
    )

    assert result["version"] == "v8"
    assert result["decision"] == "final_controlled_validation_candidate"
    assert result["fresh_blind_revalidated"] is True
    assert result["passed"] == result["total"]
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False


def test_readiness_v8_does_not_pass_blind_result_after_tuning():
    result = readiness_gate_v8_fresh_blind_validation(
        candidate_lock_valid=True,
        fresh_blind_label_count=700,
        fresh_blind_source_count=7,
        fresh_blind_scenario_count=16,
        fresh_blind_metrics=_metrics(),
        calibration_status="passed",
        exact_overlap_passed=True,
        threshold_tuning_performed=True,
        uses_source_or_scenario_identity=False,
        controlled_real_source_passed=True,
        final_controlled_acceptance_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
    )

    assert result["fresh_blind_revalidated"] is False
    assert result["decision"] == "controlled_real_source_validated_candidate"
    assert result["production_promoted"] is False


def test_final_controlled_acceptance_is_safe_and_audited(monkeypatch, tmp_path):
    monkeypatch.setattr(
        acceptance_module,
        "lock_v20_candidate",
        lambda **_kwargs: {
            "ok": True,
            "candidate_name": CANDIDATE_NAME,
            "candidate_hash": "abc123",
        },
    )
    monkeypatch.setattr(
        acceptance_module,
        "_latest_report_path",
        lambda _output_dir, pattern: Path(pattern),
    )
    monkeypatch.setattr(
        acceptance_module,
        "_load_json",
        lambda path: (
            {
                "fresh_blind_holdout": {
                    "row_count": 700,
                    "source_count": 7,
                    "scenario_count": 16,
                    "previous_holdout_overlap": {
                        "exact_overlap_passed": True
                    },
                },
                "metrics": _metrics(),
                "calibration": {"metrics": {"status": "passed"}},
                "threshold_tuning_performed": False,
                "uses_source_or_scenario_identity": False,
                "readiness_gate_v8": {"fresh_blind_revalidated": True},
            }
            if "fresh_blind" in str(path)
            else {"readiness_gate_v6": {"external_benchmark_validated": True}}
        ),
    )
    monkeypatch.setattr(
        acceptance_module,
        "run_controlled_real_source_validation",
        lambda **_kwargs: {
            "controlled_real_source_validated": True,
            "raw_logs": 28,
            "normalized_logs": 28,
            "parse_success": 25,
            "parse_failures": 3,
            "alert_count": 2,
            "case_count": 2,
            "alerts_deduplicated": 1,
            "scenarios": [
                {
                    "source_health": "healthy",
                    "why_flagged_available": True,
                }
            ],
            "response_and_audit_safety": {
                "protected_ip_denied": True,
                "audit_recorded": True,
                "approved_simulated": True,
                "real_firewall_changed": False,
                "automatic_response_actions": 0,
            },
        },
    )
    monkeypatch.setattr(
        acceptance_module,
        "run_performance_smoke",
        lambda **_kwargs: {"ok": True, "warnings": [], "timings": {}},
    )
    monkeypatch.setattr(
        acceptance_module,
        "_latest_validation_status",
        lambda: {"passed": True},
    )

    result = acceptance_module.run_final_controlled_source_acceptance(
        output_dir=tmp_path
    )

    assert result["ok"] is True
    assert result["final_controlled_validation_passed"] is True
    assert result["readiness_gate_v8"]["decision"] == (
        "final_controlled_validation_candidate"
    )
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
    assert Path(result["paths"]["final_markdown"]).exists()


def test_v20_dashboard_summary_is_concise_and_non_production(tmp_path):
    blind = {
        "ok": True,
        "generated_at": "2026-06-14T00:00:00Z",
        "candidate": {
            "name": CANDIDATE_NAME,
            "hash": "abc123",
        },
        "fresh_blind_holdout": {
            "row_count": 700,
            "source_count": 7,
            "scenario_count": 16,
            "previous_holdout_overlap": {
                "exact_overlap_rows": 0,
                "near_overlap_rows": 335,
            },
        },
        "metrics": _metrics(),
        "calibration": {
            "locked_method": "raw_confidence",
            "metrics": {
                "status": "passed",
                "expected_calibration_error": 0.0757,
                "brier_score_threat_positive": 0.0751,
                "max_confidence_accuracy_gap": 0.1878,
            },
        },
        "threshold_tuning_performed": False,
        "readiness_gate_v8": {
            "version": "v8",
            "decision": "fresh_blind_revalidated_candidate",
            "passed": 21,
            "total": 22,
            "fresh_blind_revalidated": True,
            "checks": [],
        },
    }
    final = {
        "generated_at": "2026-06-14T00:01:00Z",
        "controlled_real_source_validation": {
            "controlled_real_source_validated": True
        },
        "readiness_gate_v8": {
            "version": "v8",
            "decision": "final_controlled_validation_candidate",
            "passed": 22,
            "total": 22,
            "external_benchmark_validated": True,
            "fresh_blind_revalidated": True,
            "controlled_real_source_validated": True,
            "final_controlled_validation_passed": True,
            "checks": [],
        },
    }
    (
        tmp_path / "v2_0_fresh_blind_revalidation_20260614T000000Z.json"
    ).write_text(json.dumps(blind), encoding="utf-8")
    (
        tmp_path
        / "v2_0_final_controlled_source_acceptance_20260614T000100Z.json"
    ).write_text(json.dumps(final), encoding="utf-8")

    result = _latest_v20_ai_summary(tmp_path)

    assert result["independent_label_count"] == 700
    assert result["best_profile"] == CANDIDATE_NAME
    assert result["fresh_blind_revalidated"] is True
    assert result["final_controlled_validation_passed"] is True
    assert result["readiness_decision"] == "final_controlled_validation_candidate"
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False


def test_candidate_config_never_enables_automation_or_identity_inputs():
    assert FROZEN_CANDIDATE_CONFIG["identity_inputs_allowed"] is False
    assert FROZEN_CANDIDATE_CONFIG["production_promoted"] is False
    assert FROZEN_CANDIDATE_CONFIG["model_activated"] is False
    assert FROZEN_CANDIDATE_CONFIG["response_automation_allowed"] is False
    assert FROZEN_CANDIDATE_CONFIG["real_firewall_blocking_enabled"] is False
