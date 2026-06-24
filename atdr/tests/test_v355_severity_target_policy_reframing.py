from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split
from atdr.app.detection.v353_severity_feature_repair import enrich_v353_severity_features
from atdr.app.detection.v355_severity_target_policy_reframing import (
    POLICIES,
    _policy_targets,
    run_v355_severity_target_policy_reframing,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v355_policy_targets_map_to_expected_class_sets():
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)
        frame, _meta = enrich_v353_severity_features(prepared)

    for policy_name, policy in POLICIES.items():
        targets, queue_values, meta = _policy_targets(prepared, frame, policy_name=policy_name)
        assert targets
        assert queue_values
        assert set(targets).issubset(set(policy["labels_order"]))
        assert meta["policy_name"] == policy_name
        assert meta["target_distribution"]


def test_v355_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v355_severity_target_policy_reframing(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )
        after_labels = db.scalar(select(func.count(MLLabel.id)))
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["phase"] == "v3.55"
    assert result["strategy_comparison"]
    assert result["best_strategy"]
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert result["safety"]["labels_written"] is False
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()


def test_v355_includes_binary_and_two_tier_policy_candidates(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        result = run_v355_severity_target_policy_reframing(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )

    names = set(result["strategy_comparison"])
    assert any(name.startswith("binary_review_queue_") for name in names)
    assert any(name.startswith("review_needed_vs_malicious_") for name in names)
    assert any(name.startswith("unusual_vs_threat_evidence_") for name in names)
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["response_automation_allowed"] is False
