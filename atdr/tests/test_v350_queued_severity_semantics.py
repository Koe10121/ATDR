from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v350_queued_severity_semantics import (
    _categorical_ambiguity,
    _numeric_separability,
    run_v350_queued_severity_semantics,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v350_categorical_ambiguity_finds_mixed_severity_patterns():
    rows = [
        {"pattern": "app=ssl|action=allow|port=443", "severity_target": "unusual_needs_review", "label_status": "manual|reviewed=True"},
        {
            "pattern": "app=ssl|action=allow|port=443",
            "severity_target": "evidence_backed_suspicious",
            "label_status": "assisted|reviewed=False",
        },
        {"pattern": "app=ssl|action=allow|port=443", "severity_target": "unusual_needs_review", "label_status": "manual|reviewed=True"},
        {
            "pattern": "app=ssl|action=allow|port=443",
            "severity_target": "malicious_high_confidence",
            "label_status": "manual|reviewed=True",
        },
    ]

    ambiguous = _categorical_ambiguity(rows, "pattern", min_count=4)

    assert ambiguous
    assert ambiguous[0]["value"] == "app=ssl|action=allow|port=443"
    assert ambiguous[0]["conflict_ratio"] == 0.5
    assert ambiguous[0]["target_counts"]["unusual_needs_review"] == 2


def test_v350_numeric_separability_reports_pairwise_effects():
    frame = pd.DataFrame(
        {
            "evidence_strength": [0, 0.2, 0.1, 2.0, 2.4, 2.2, 8.0, 8.4, 8.2],
            "weak_feature": [1, 1, 1, 1, 1, 1, 1, 1, 1],
        }
    )
    rows = []
    targets = [
        "unusual_needs_review",
        "unusual_needs_review",
        "unusual_needs_review",
        "evidence_backed_suspicious",
        "evidence_backed_suspicious",
        "evidence_backed_suspicious",
        "malicious_high_confidence",
        "malicious_high_confidence",
        "malicious_high_confidence",
    ]
    for index, target in enumerate(targets):
        rows.append({"index": index, "severity_target": target})

    separability = _numeric_separability(frame, rows, ["evidence_strength", "weak_feature"])

    assert separability[0]["feature"] == "evidence_strength"
    assert separability[0]["minimum_pairwise_effect_size"] > 1.0


def test_v350_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v350_queued_severity_semantics(
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
    assert result["assessment"]["decision"] == "diagnostic_only"
    assert result["queued_rows_audited"] > 0
    assert "severity_distribution" in result
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
