from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v352_repaired_interface_severity_model import (
    interface_severity_targets,
    run_v352_repaired_interface_severity_model,
)
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v352_best_interface_maps_queued_non_threat_to_unusual(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)
        frame, _meta = enrich_v337_features(prepared)

    baseline_targets, baseline_meta = interface_severity_targets(
        prepared,
        frame,
        variant="baseline_current_interface",
    )
    repaired_targets, repaired_meta = interface_severity_targets(
        prepared,
        frame,
        variant="map_non_threat_to_unusual",
    )

    assert baseline_targets
    assert repaired_targets
    assert baseline_meta["interface_variant"] == "baseline_current_interface"
    assert repaired_meta["interface_variant"] == "map_non_threat_to_unusual"
    assert repaired_meta["non_threat_mismatch_rows"] == 0
    assert repaired_meta["removed_review_rows"] == 0
    assert repaired_meta["changed_review_rows"] >= baseline_meta["non_threat_mismatch_rows"]


def test_v352_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v352_repaired_interface_severity_model(
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
    assert "baseline_current_interface" in result["interface_variants"]
    assert "map_non_threat_to_unusual" in result["interface_variants"]
    assert result["strategy_comparison"]
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


def test_v352_repaired_strategy_tracks_zero_mismatch(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        result = run_v352_repaired_interface_severity_model(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )

    repaired_rows = [
        item
        for name, item in result["strategy_comparison"].items()
        if name.startswith("map_non_threat_to_unusual_")
    ]
    assert repaired_rows
    assert all(row["interface_repair"]["max_non_threat_mismatch_rows"] == 0 for row in repaired_rows)
