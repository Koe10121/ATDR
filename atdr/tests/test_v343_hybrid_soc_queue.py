from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v343_hybrid_soc_queue import evidence_first_queue_decision, run_v343_hybrid_soc_queue
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _row(values: dict):
    return pd.Series(values)


def test_v343_evidence_first_keeps_low_signal_web_out_of_threat_queue():
    decision = evidence_first_queue_decision(
        _row(
            {
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_web_low_signal_flag": 1,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 0.2,
                "v337_traffic_family": "web_low_signal",
            }
        )
    )

    assert decision == "non_threat"


def test_v343_evidence_first_promotes_strong_scan_context():
    decision = evidence_first_queue_decision(
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
        )
    )

    assert decision == "malicious_high_confidence"


def test_v343_hybrid_soc_queue_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v343_hybrid_soc_queue(
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
    assert "v3.43 Hybrid Evidence-First SOC Queue Candidate" in report_text
    assert "diagnostic only" in report_text
