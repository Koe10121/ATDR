from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v342_label_policy_reframing import (
    behavior_aware_soc_target,
    run_v342_label_policy_reframing,
    soc_policy_target,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _row(values: dict):
    return pd.Series(values)


def test_v342_maps_low_signal_threat_to_review_not_human_reviewed_label():
    row = _row(
        {
            "v337_rule_backed_allow_flag": 0,
            "v337_anomaly_signal_flag": 0,
            "v337_web_scan_context_flag": 0,
            "v337_incomplete_scan_context_flag": 0,
            "v337_unknown_scan_context_flag": 0,
            "v337_web_low_signal_flag": 1,
            "v337_utility_low_signal_flag": 0,
            "v337_behavior_evidence_strength": 0.3,
            "v337_benign_web_likelihood_score": 3.0,
            "v337_traffic_family": "web_low_signal",
        }
    )

    assert soc_policy_target("suspicious", row) == "unusual_needs_review"
    assert behavior_aware_soc_target("suspicious", row) == "unusual_needs_review"


def test_v342_maps_strong_malicious_evidence_to_high_confidence_target():
    row = _row(
        {
            "v337_rule_backed_allow_flag": 1,
            "v337_anomaly_signal_flag": 1,
            "v337_web_scan_context_flag": 0,
            "v337_incomplete_scan_context_flag": 1,
            "v337_unknown_scan_context_flag": 0,
            "v337_web_low_signal_flag": 0,
            "v337_utility_low_signal_flag": 0,
            "v337_behavior_evidence_strength": 5.0,
            "v337_benign_web_likelihood_score": -2.0,
            "v337_traffic_family": "incomplete_probe",
        }
    )

    assert soc_policy_target("malicious", row) == "malicious_high_confidence"
    assert behavior_aware_soc_target("malicious", row) == "malicious_high_confidence"


def test_v342_label_policy_reframing_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v342_label_policy_reframing(
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
    assert "unusual_needs_review" in result["soc_targets"]["review_queue_targets"]
    assert result["best_strategy"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.42 Label Policy and SOC Target Reframing" in report_text
    assert "diagnostic only" in report_text
