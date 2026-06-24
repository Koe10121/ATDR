from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v354_severity_target_semantics_audit import (
    SEVERITY_TARGETS,
    _categorical_ambiguity,
    _policy_variant_summary,
    run_v354_severity_target_semantics_audit,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v354_categorical_ambiguity_finds_mixed_target_values():
    records = [
        {"target": "unusual_needs_review", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "unusual_needs_review", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "evidence_backed_suspicious", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "malicious_high_confidence", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "malicious_high_confidence", "pattern": "app=unknown|action=deny|port=22"},
    ]

    ambiguous = _categorical_ambiguity(records, "pattern", min_total=4)

    assert ambiguous
    assert ambiguous[0]["value"] == "app=ssl|action=allow|port=443"
    assert ambiguous[0]["target_counts"]["unusual_needs_review"] == 2
    assert ambiguous[0]["conflict_ratio"] > 0


def test_v354_policy_variant_summary_uses_policy_targets():
    records = [
        {"target": "unusual_needs_review", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "evidence_backed_suspicious", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "malicious_high_confidence", "pattern": "app=ssl|action=allow|port=443"},
        {"target": "malicious_high_confidence", "pattern": "app=ssl|action=allow|port=443"},
    ]

    summary = _policy_variant_summary(records)

    assert summary["merge_unusual_and_suspicious"]["target_distribution"] == {
        "review_needed": 2,
        "malicious_high_confidence": 2,
    }
    assert summary["binary_review_queue"]["target_distribution"] == {"needs_review": 4}
    assert summary["binary_review_queue"]["top_ambiguous_values"] == []


def test_v354_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v354_severity_target_semantics_audit(
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
    assert result["phase"] == "v3.54"
    assert set(result["target_distribution"]).issubset(set(SEVERITY_TARGETS))
    assert result["categorical_ambiguity"]["fields"]
    assert result["numeric_separability"]
    assert result["split_drift"]["splits"]
    assert result["policy_variants"]["current_three_severity"]
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["model_artifact_written"] is False
    assert result["readiness"]["response_automation_allowed"] is False
    assert result["safety"]["labels_written"] is False
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()
    if result["residual_sample"]["generated"]:
        assert result["residual_sample"]["import_ready"] is False
        assert Path(result["residual_sample"]["path"]).exists()


def test_v354_readiness_is_diagnostic_and_conservative(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        result = run_v354_severity_target_semantics_audit(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )

    assert result["readiness"]["decision"] in {"diagnostic_only", "candidate_only"}
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["response_automation_allowed"] is False
