import json
from pathlib import Path

from atdr.app.benchmarks.readiness import readiness_gate_v7_independent_validation
from atdr.app.routers.dashboard import _latest_v19_ai_summary
from atdr.scripts.build_independent_holdout import build_independent_holdout
from atdr.scripts.run_controlled_real_source_validation import (
    run_controlled_real_source_validation,
)
from atdr.scripts.run_v19_independent_revalidation import _best_profile


def _metrics(*, f1: float, recall: float, fpr: float) -> dict:
    return {
        "threat_positive_precision": 0.92,
        "threat_positive_recall": recall,
        "threat_positive_f1": f1,
        "benign_false_positive_rate": fpr,
        "macro_f1": 0.88,
        "weighted_f1": 0.89,
        "per_class": {
            "suspicious": {"recall": 0.84},
            "malicious": {"recall": 0.72},
        },
    }


def test_independent_holdout_builder_is_seeded_separate_and_safe(tmp_path):
    result = build_independent_holdout(
        output_dir=tmp_path,
        csv_path=tmp_path / "independent.csv",
    )

    assert result["row_count"] == 500
    assert result["source_count"] >= 5
    assert result["scenario_count"] >= 10
    assert result["duplicate_summary"]["exact_duplicate_rows"] == 0
    assert result["previous_holdout_overlap"]["exact_overlap_rows"] == 0
    assert Path(result["snapshot_path"]).exists()
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False


def test_independent_holdout_dry_run_writes_nothing(tmp_path):
    result = build_independent_holdout(
        output_dir=tmp_path,
        csv_path=tmp_path / "independent.csv",
        dry_run=True,
    )

    assert result["row_count"] == 500
    assert result["csv_path"] is None
    assert result["snapshot_path"] is None
    assert not list(tmp_path.iterdir())


def test_readiness_v7_can_validate_without_promotion_or_automation():
    result = readiness_gate_v7_independent_validation(
        independent_label_count=500,
        independent_metrics=_metrics(f1=0.9, recall=0.9, fpr=0.05),
        calibration_status="passed",
        external_benchmark_passed=True,
        independent_overlap_passed=True,
        controlled_real_source_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
    )

    assert result["decision"] == "controlled_real_source_validated_candidate"
    assert result["independent_holdout_validated"] is True
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False


def test_readiness_v7_stays_conservative_when_independent_fpr_fails():
    result = readiness_gate_v7_independent_validation(
        independent_label_count=500,
        independent_metrics=_metrics(f1=0.9, recall=0.9, fpr=0.22),
        calibration_status="passed",
        external_benchmark_passed=True,
        independent_overlap_passed=True,
        controlled_real_source_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
    )

    assert result["decision"] == "external_benchmark_validated_candidate"
    assert result["independent_holdout_validated"] is False
    assert result["production_promoted"] is False


def test_profile_selection_balances_f1_and_false_positive_budget():
    result = _best_profile(
        [
            {
                "profile": "external_recall_plus",
                "metrics": _metrics(f1=0.9, recall=0.93, fpr=0.154),
            },
            {
                "profile": "rules_only",
                "metrics": _metrics(f1=0.76, recall=0.67, fpr=0.08),
            },
        ]
    )

    assert result["profile"] == "external_recall_plus"


def test_controlled_real_source_validation_is_isolated_and_safe():
    result = run_controlled_real_source_validation(write_output=False)

    assert result["ok"] is True
    assert result["temporary_database_used"] is True
    assert result["current_database_modified"] is False
    assert result["raw_logs"] >= result["parse_success"]
    assert result["parse_failures"] >= 1
    assert result["alert_count"] >= 1
    assert result["case_count"] >= 1
    assert result["alerts_deduplicated"] >= 1
    assert result["response_and_audit_safety"]["protected_ip_denied"] is True
    assert result["response_and_audit_safety"]["audit_recorded"] is True
    assert (
        result["response_and_audit_safety"]["automatic_response_actions"] == 0
    )
    assert result["real_firewall_blocking_enabled"] is False


def test_v19_dashboard_summary_is_concise_and_safe(tmp_path):
    payload = {
        "ok": True,
        "generated_at": "2026-06-14T00:00:00Z",
        "independent_holdout": {
            "row_count": 500,
            "source_count": 6,
            "scenario_count": 16,
            "previous_holdout_overlap": {"exact_overlap_rows": 0},
        },
        "best_profile": {
            "profile": "external_recall_plus",
            "metrics": _metrics(f1=0.9, recall=0.93, fpr=0.154),
            "calibration": {
                "status": "passed",
                "expected_calibration_error": 0.02,
                "brier_score_threat_positive": 0.08,
                "max_confidence_accuracy_gap": 0.06,
            },
            "calibration_method": "isotonic",
        },
        "generalization_gap": {"status": "moderate_independent_gap"},
        "controlled_real_source_validation": {
            "available": True,
            "passed": True,
        },
        "readiness_gate_v7": {
            "version": "v7",
            "decision": "external_benchmark_validated_candidate",
            "passed": 16,
            "total": 17,
            "external_benchmark_validated": True,
            "independent_holdout_validated": False,
            "controlled_real_source_validated": True,
            "checks": [
                {
                    "name": "independent_benign_false_positive_rate",
                    "passed": False,
                }
            ],
        },
    }
    path = tmp_path / "v1_9_independent_revalidation_20260614T000000Z.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = _latest_v19_ai_summary(tmp_path)

    assert result["independent_label_count"] == 500
    assert result["best_profile"] == "external_recall_plus"
    assert result["controlled_real_source_validated"] is True
    assert result["independent_holdout_validated"] is False
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False


def test_generated_v19_outputs_are_ignored():
    gitignore = (Path(__file__).parents[2] / ".gitignore").read_text(
        encoding="utf-8"
    )

    assert "demo_exports/" in gitignore
    assert "ml_baseline_reviews/" in gitignore
