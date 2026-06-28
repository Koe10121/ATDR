import json

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v359_supervised_output_policy_contract import V359_LATEST
from atdr.app.detection.v362_supervised_training_target_contract import V362_LATEST
from atdr.app.detection.v372_unified_detection_ml_evaluation import run_v372_unified_detection_ml_evaluation
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _fake_v359() -> dict:
    return {
        "contract": {
            "decision": "decision_support_contract_ready",
            "checks_passed": 7,
            "checks_total": 7,
            "recommended_supervised_strategy": "binary_soc_review_queue",
            "exact_classification_policy": "explanation_or_ranking_only",
            "contract_ready_for_dashboard_guidance": True,
            "contract_ready_for_runtime_activation": False,
            "blocked_uses": ["automatic response from supervised ML output"],
        },
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "labels_written": False,
            "response_automation_allowed": False,
        },
    }


def _fake_v362() -> dict:
    return {
        "contract": {
            "decision": "safe_queue_target_adapter_ready",
            "checks_passed": 5,
            "checks_total": 5,
            "recommended_training_target": "binary_soc_review_queue",
            "exact_label_policy": "explanation_or_ranking_only",
            "runtime_activation_allowed": False,
            "production_promotion_allowed": False,
            "response_automation_allowed": False,
            "quality_warnings": ["exact label classes remain explanation/ranking only"],
        },
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "labels_written": False,
            "response_automation_allowed": False,
        },
    }


def test_v372_passes_required_checks_when_optional_ml_artifacts_are_missing(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=4)
        result = run_v372_unified_detection_ml_evaluation(db, output_dir=tmp_path)

    assert result["ok"] is True
    assert result["phase"] == "v3.72"
    assert result["read_only"] is True
    assert result["readiness"]["decision"] == "diagnostic_evaluation_passed_missing_optional_ml_artifacts"
    assert result["readiness"]["blockers"] == []
    assert "supervised output policy artifact available" in result["readiness"]["advisories"]
    assert "safe training target artifact available" in result["readiness"]["advisories"]
    assert result["rule_contract"]["ok"] is True
    assert result["supervised_output_policy"]["available"] is False
    assert result["training_target_contract"]["available"] is False
    assert result["safety"]["current_database_mutated"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert result["safety"]["real_firewall_blocking_enabled"] is False


def test_v372_reads_latest_policy_artifacts_without_side_effects(tmp_path):
    (tmp_path / V359_LATEST).write_text(json.dumps(_fake_v359()), encoding="utf-8")
    (tmp_path / V362_LATEST).write_text(json.dumps(_fake_v362()), encoding="utf-8")

    with _session() as db:
        _seed_labels(db, rows_per_class=4)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v372_unified_detection_ml_evaluation(db, output_dir=tmp_path)
        after_labels = db.scalar(select(func.count(MLLabel.id)))
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["readiness"]["decision"] == "diagnostic_evaluation_passed"
    assert result["supervised_output_policy"]["status"] == "decision_support_contract_ready"
    assert result["supervised_output_policy"]["runtime_activation_allowed"] is False
    assert result["training_target_contract"]["status"] == "safe_queue_target_adapter_ready"
    assert result["training_target_contract"]["production_promotion_allowed"] is False
    assert result["readiness"]["advisories"] == ["controlled scenario quality included"]
    assert before_labels == after_labels == result["safety"]["counts_after"]["ml_labels"]
    assert before_runs == after_runs == result["safety"]["counts_after"]["ml_model_runs"]
    assert before_responses == after_responses == result["safety"]["counts_after"]["response_actions"]


def test_v372_can_include_controlled_scenario_quality_without_current_db_side_effects(tmp_path):
    with _session() as db:
        result = run_v372_unified_detection_ml_evaluation(
            db,
            output_dir=tmp_path,
            include_scenarios=True,
            scenarios=["normal_allowed_traffic", "port_scan_like_traffic"],
        )

    assert result["ok"] is True
    assert result["scenario_quality"]["included"] is True
    assert result["scenario_quality"]["status"] == "passed"
    assert result["scenario_quality"]["scenario_count"] == 2
    assert result["scenario_quality"]["false_positive_scenario_count"] == 0
    assert result["scenario_quality"]["false_negative_scenario_count"] == 0
    assert result["scenario_quality"]["response_actions_created"] == 0
    assert result["safety"]["current_database_mutated"] is False
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["response_actions_created"] == 0
