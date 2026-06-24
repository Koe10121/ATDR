from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v357_queue_rule_hybrid_agreement import (
    agreement_category,
    evidence_snapshot,
    run_v357_queue_rule_hybrid_agreement,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _log(**kwargs):
    return type("Log", (), kwargs)()


def test_v357_evidence_snapshot_suppresses_normal_low_signal_web():
    row = pd.Series(
        {
            "v331_rule_score": 0,
            "v337_behavior_evidence_strength": 0,
            "v353_scan_pressure_score": 0,
            "v353_malicious_signal_score": 0,
            "v353_suspicious_signal_score": 0,
            "v353_evidence_margin_score": 0,
            "v337_source_diversity_pressure": 0,
            "scanning_like_behavior_score": 0,
            "v337_low_signal_allow_flag": 1,
            "v337_rule_backed_allow_flag": 0,
            "v337_anomaly_signal_flag": 0,
            "rare_dst_port_flag": 0,
            "unknown_app_flag": 0,
            "app_risk": 0,
        }
    )

    snapshot = evidence_snapshot(row, _log(app="quic-base", action="allow", dst_port=443))

    assert snapshot["decision"] == "non_threat"
    assert "low-signal allow traffic" in snapshot["reasons"]


def test_v357_evidence_snapshot_flags_rule_or_scan_context():
    row = pd.Series(
        {
            "v331_rule_score": 5,
            "v337_behavior_evidence_strength": 4,
            "v353_scan_pressure_score": 5,
            "v353_malicious_signal_score": 7,
            "v353_suspicious_signal_score": 6,
            "v353_evidence_margin_score": 5,
            "v337_source_diversity_pressure": 6,
            "scanning_like_behavior_score": 3,
            "src_ip_5min_unique_dst_ips": 5,
            "src_ip_5min_unique_dst_ports": 4,
            "v337_low_signal_allow_flag": 0,
            "v337_rule_backed_allow_flag": 1,
            "v337_anomaly_signal_flag": 1,
            "rare_dst_port_flag": 1,
            "unknown_app_flag": 1,
            "app_risk": 4,
        }
    )

    snapshot = evidence_snapshot(row, _log(app="unknown-tcp", action="alert", dst_port=80))

    assert snapshot["decision"] == "needs_review"
    assert snapshot["rule_backed"] is True
    assert snapshot["scan_like"] is True
    assert "rule evidence" in snapshot["reasons"]


def test_v357_agreement_categories_are_explicit():
    assert agreement_category("needs_review", "needs_review") == "queue_and_evidence_agree_review"
    assert agreement_category("needs_review", "non_threat") == "queue_only_review"
    assert agreement_category("non_threat", "needs_review") == "evidence_only_review"
    assert agreement_category("non_threat", "non_threat") == "queue_and_evidence_agree_non_review"


def test_v357_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v357_queue_rule_hybrid_agreement(
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
    assert result["phase"] == "v3.57"
    assert result["aggregate"]["evaluated_splits"] == 5
    assert result["aggregate"]["category_counts"]
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["response_automation_allowed"] is False
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["raw_logs_included"] is False
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    for split in result["split_results"]:
        if split["status"] != "evaluated":
            continue
        threshold = split["threshold_selection"]
        assert "fit_idx" not in threshold
        assert "calibration_idx" not in threshold
        assert threshold["used_test_for_threshold_selection"] is False
