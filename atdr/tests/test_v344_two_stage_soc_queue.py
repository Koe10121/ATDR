from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v344_two_stage_soc_queue import (
    _queue_from_stage,
    _severity_decision,
    run_v344_two_stage_soc_queue,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _row(values: dict):
    return pd.Series(values)


def test_v344_keeps_queue_admission_separate_from_threat_severity():
    decision = _severity_decision(
        _row(
            {
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_web_low_signal_flag": 0,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 1.8,
                "v337_traffic_family": "unknown",
            }
        ),
        {
            "unusual_needs_review": 0.72,
            "evidence_backed_suspicious": 0.16,
            "malicious_high_confidence": 0.04,
        },
        {"queue": 0.45, "threat": 0.45, "malicious": 0.6},
    )

    assert decision == "unusual_needs_review"


def test_v344_hybrid_queue_does_not_admit_low_signal_web_from_probability_alone():
    decision = _queue_from_stage(
        _row(
            {
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_web_low_signal_flag": 1,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 0.3,
                "v337_traffic_family": "web_low_signal",
            }
        ),
        {"needs_review": 0.95},
        strategy="hybrid_queue_ml_severity",
        threshold=0.45,
    )

    assert decision == "non_threat"


def test_v344_hybrid_queue_admits_evidence_backed_scan_context():
    decision = _queue_from_stage(
        _row(
            {
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 1,
                "v337_web_low_signal_flag": 0,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 4.2,
                "v337_traffic_family": "unknown_scan_context",
            }
        ),
        {"needs_review": 0.05},
        strategy="hybrid_queue_ml_severity",
        threshold=0.45,
    )

    assert decision == "needs_review"


def test_v344_two_stage_soc_queue_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v344_two_stage_soc_queue(
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
    assert result["best_strategy"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.44 Two-Stage SOC Queue" in report_text
    assert "diagnostic only" in report_text
