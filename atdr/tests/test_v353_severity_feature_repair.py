from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split
from atdr.app.detection.v353_severity_feature_repair import (
    V353_CATEGORICAL_FEATURES,
    V353_NUMERIC_FEATURES,
    enrich_v353_severity_features,
    run_v353_severity_feature_repair,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v353_feature_enrichment_adds_severity_specific_features():
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)
        frame, meta = enrich_v353_severity_features(prepared)

    for feature in V353_NUMERIC_FEATURES:
        assert feature in frame.columns
        assert feature in meta["numeric_features"]
    for feature in V353_CATEGORICAL_FEATURES:
        assert feature in frame.columns
        assert feature in meta["categorical_features"]
    assert set(frame["v353_service_family"].unique())


def test_v353_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v353_severity_feature_repair(
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
    assert result["readiness"]["decision"] == "candidate_only"
    assert "v337_current_features" in result["feature_sets"]
    assert "v353_severity_features" in result["feature_sets"]
    assert result["strategy_comparison"]
    assert any(name.startswith("v353_severity_features_") for name in result["strategy_comparison"])
    assert result["feature_support"]["numeric_separability"]
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


def test_v353_readiness_remains_conservative(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        result = run_v353_severity_feature_repair(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )

    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["model_artifact_written"] is False
    assert result["readiness"]["response_automation_allowed"] is False
