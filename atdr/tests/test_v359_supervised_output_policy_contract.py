import json
from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v355_severity_target_policy_reframing import V355_LATEST
from atdr.app.detection.v357_queue_rule_hybrid_agreement import V357_LATEST
from atdr.app.detection.v359_supervised_output_policy_contract import (
    V359_LATEST,
    build_supervised_output_policy_contract,
    run_v359_supervised_output_policy_contract,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _fake_v355() -> dict:
    return {
        "ok": True,
        "phase": "v3.55",
        "strategy_comparison": {
            "binary_review_queue_queue_only": {
                "stability": {
                    "evaluated_splits": 5,
                    "passing_splits": 5,
                    "metric_ranges": {
                        "queue_f1": {"min": 0.9725, "max": 0.9962},
                        "queue_recall": {"min": 0.948, "max": 0.9925},
                        "queue_precision": {"min": 0.9907, "max": 1.0},
                        "benign_like_false_positive_rate": {"max": 0.04},
                    },
                },
                "best_calibration": {
                    "status": "passed",
                    "expected_calibration_error": 0.007,
                },
            },
            "current_three_severity_extra_trees": {
                "stability": {
                    "evaluated_splits": 5,
                    "passing_splits": 0,
                    "metric_ranges": {
                        "policy_positive_f1": {"min": 0.6277},
                        "benign_like_false_positive_rate": {"max": 0.7625},
                        "critical_recall_min": {"min": 0.4571},
                    },
                }
            },
        },
        "readiness": {
            "decision": "candidate_only",
            "passed": 10,
            "total": 10,
            "blockers": [],
        },
    }


def _fake_v357() -> dict:
    return {
        "ok": True,
        "phase": "v3.57",
        "policy_name": "binary_review_queue",
        "aggregate": {
            "evaluated_splits": 5,
            "passing_splits": 4,
            "queue_f1_min": 0.9725,
            "queue_false_positive_rate_max": 0.04,
            "agreement_rate_min": 0.884,
            "calibration_ece_max": 0.0137,
            "category_counts": {
                "queue_and_evidence_agree_review": 3376,
                "evidence_only_review": 310,
            },
            "top_evidence_only_patterns": [["app=quic-base|action=allow|port=443", 71]],
            "top_queue_only_patterns": [],
            "blockers": ["grouped_stratified: evidence-only review rate above 0.10"],
        },
        "readiness": {
            "decision": "diagnostic_only",
            "passed": 7,
            "total": 8,
            "blockers": ["evidence-only misses remain reviewable"],
        },
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "labels_written": False,
            "raw_logs_included": False,
            "response_automation_allowed": False,
        },
    }


def test_v359_contract_turns_label_semantics_into_safe_supervised_strategy():
    contract = build_supervised_output_policy_contract(
        v355=_fake_v355(),
        v357=_fake_v357(),
        training_diagnostics={"latest_trainable_rows": 100},
    )

    assert contract["decision"] == "decision_support_contract_ready"
    assert contract["contract_ready_for_runtime_activation"] is False
    assert contract["contract_ready_for_dashboard_guidance"] is True
    assert contract["recommended_supervised_strategy"] == "binary_soc_review_queue"
    assert contract["exact_classification_policy"] == "explanation_or_ranking_only"
    assert contract["queue"]["status"] == "stable"
    assert contract["queue_evidence_agreement"]["status"] == "usable_with_review"
    assert contract["exact_severity"]["status"] == "unstable"
    assert contract["allowed_outputs"]["soc_review_queue_score"]["status"] == "allowed_for_decision_support"
    assert "automatic response from supervised ML output" in contract["blocked_uses"]
    assert "marking AI-generated labels as human-reviewed" in contract["blocked_uses"]
    assert contract["checks_passed"] == contract["checks_total"]


def test_v359_contract_stays_diagnostic_when_upstream_reports_are_missing():
    contract = build_supervised_output_policy_contract(v355=None, v357=None)

    assert contract["decision"] == "diagnostic_contract_only"
    assert contract["contract_ready_for_dashboard_guidance"] is False
    assert contract["upstream_missing"]
    assert contract["allowed_outputs"]["soc_review_queue_score"]["status"] == "diagnostic_only"
    assert contract["exact_classification_policy"] == "explanation_or_ranking_only"


def test_v359_runner_writes_ignored_reports_without_side_effects(tmp_path):
    (tmp_path / V355_LATEST).write_text(json.dumps(_fake_v355()), encoding="utf-8")
    (tmp_path / V357_LATEST).write_text(json.dumps(_fake_v357()), encoding="utf-8")
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v359_supervised_output_policy_contract(db, output_dir=tmp_path)
        after_labels = db.scalar(select(func.count(MLLabel.id)))
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["phase"] == "v3.59"
    assert result["contract"]["decision"] == "decision_support_contract_ready"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["raw_logs_included"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).name == V359_LATEST
    assert "raw_line" not in Path(result["latest_summary_path"]).read_text(encoding="utf-8")
