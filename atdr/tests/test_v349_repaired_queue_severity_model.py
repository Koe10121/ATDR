from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v349_repaired_queue_severity_model import (
    _final_predictions,
    severity_decision,
    run_v349_repaired_queue_severity_model,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v349_probability_only_severity_decision_prefers_malicious_when_confident():
    decision = severity_decision(
        pd.Series({"v337_behavior_evidence_strength": 4.5}),
        {
            "malicious_high_confidence": 0.82,
            "evidence_backed_suspicious": 0.10,
            "unusual_needs_review": 0.08,
        },
        {"malicious": 0.65, "threat": 0.45},
        mode="probability_only",
    )

    assert decision == "malicious_high_confidence"


def test_v349_evidence_guarded_severity_does_not_promote_low_signal_rows():
    decision = severity_decision(
        pd.Series(
            {
                "v337_behavior_evidence_strength": 0.5,
                "v337_low_signal_allow_flag": 1,
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
            }
        ),
        {
            "malicious_high_confidence": 0.10,
            "evidence_backed_suspicious": 0.80,
            "unusual_needs_review": 0.10,
        },
        {"malicious": 0.65, "threat": 0.45},
        mode="evidence_guarded",
    )

    assert decision == "unusual_needs_review"


def test_v349_final_predictions_keep_non_queued_rows_non_threat():
    predictions = _final_predictions(
        pd.DataFrame([{}, {}]),
        [0, 1],
        queue_predictions=["non_threat", "needs_review"],
        severity_rows=[
            {"malicious_high_confidence": 1.0},
            {"evidence_backed_suspicious": 0.9, "malicious_high_confidence": 0.0},
        ],
        thresholds={"malicious": 0.65, "threat": 0.45},
        mode="probability_only",
    )

    assert predictions == ["non_threat", "evidence_backed_suspicious"]


def test_v349_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v349_repaired_queue_severity_model(
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
