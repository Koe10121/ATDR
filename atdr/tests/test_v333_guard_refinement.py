from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v333_guard_refinement import (
    _apply_evidence_aware_low_signal_guard,
    run_v333_guard_refinement,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _prepared_stub(log: SimpleNamespace | None = None) -> dict:
    return {
        "test_idx": [0],
        "test_logs": [log or SimpleNamespace(app="quic-base", action="allow", dst_port=443, is_anomaly=False, anomaly_score=0.0)],
    }


def _augmented_stub(row: dict, rule_codes: set[str] | None = None) -> dict:
    return {
        "frame": pd.DataFrame([row]),
        "rule_code_rows": [rule_codes or set()],
    }


def test_v333_refined_guard_suppresses_normal_quic_no_rule_low_signal():
    prepared = _prepared_stub()
    augmented = _augmented_stub(
        {
            "v331_quic_443_allow_no_rule_flag": 1,
            "v331_quic_443_allow_with_rule_flag": 0,
            "v331_benign_network_utility_no_rule_flag": 0,
            "src_ip_5min_unique_dst_ips": 1,
            "src_ip_5min_unique_dst_ports": 1,
            "src_ip_5min_log_count": 2,
            "v331_rule_score": 0,
        }
    )

    result = _apply_evidence_aware_low_signal_guard(
        prepared,
        augmented,
        ["suspicious"],
        [{"suspicious": 0.39, "malicious": 0.0, "benign": 0.4}],
    )

    assert result == ["benign"]


def test_v333_refined_guard_keeps_rule_bearing_quic_prediction():
    prepared = _prepared_stub()
    augmented = _augmented_stub(
        {
            "v331_quic_443_allow_no_rule_flag": 1,
            "v331_quic_443_allow_with_rule_flag": 1,
            "v331_benign_network_utility_no_rule_flag": 0,
            "src_ip_5min_unique_dst_ips": 1,
            "src_ip_5min_unique_dst_ports": 1,
            "v331_rule_score": 25,
        },
        {"possible_port_scan"},
    )

    result = _apply_evidence_aware_low_signal_guard(
        prepared,
        augmented,
        ["suspicious"],
        [{"suspicious": 0.39, "malicious": 0.0, "benign": 0.4}],
    )

    assert result == ["suspicious"]


def test_v333_refined_guard_keeps_scan_like_quic_prediction():
    prepared = _prepared_stub()
    augmented = _augmented_stub(
        {
            "v331_quic_443_allow_no_rule_flag": 1,
            "v331_quic_443_allow_with_rule_flag": 0,
            "v331_benign_network_utility_no_rule_flag": 0,
            "src_ip_5min_unique_dst_ips": 5,
            "src_ip_5min_unique_dst_ports": 3,
            "src_ip_5min_log_count": 12,
            "v331_rule_score": 0,
        }
    )

    result = _apply_evidence_aware_low_signal_guard(
        prepared,
        augmented,
        ["suspicious"],
        [{"suspicious": 0.39, "malicious": 0.0, "benign": 0.4}],
    )

    assert result == ["suspicious"]


def test_v333_refined_guard_suppresses_low_signal_ping_only():
    prepared = _prepared_stub(SimpleNamespace(app="ping", action="allow", dst_port=None, is_anomaly=False, anomaly_score=0.0))
    augmented = _augmented_stub(
        {
            "v331_quic_443_allow_no_rule_flag": 0,
            "v331_quic_443_allow_with_rule_flag": 0,
            "v331_benign_network_utility_no_rule_flag": 1,
            "src_ip_5min_unique_dst_ips": 1,
            "src_ip_5min_unique_dst_ports": 1,
            "src_ip_5min_log_count": 2,
            "v331_rule_score": 0,
        }
    )

    result = _apply_evidence_aware_low_signal_guard(
        prepared,
        augmented,
        ["malicious"],
        [{"suspicious": 0.2, "malicious": 0.19, "benign": 0.4}],
    )

    assert result == ["benign"]


def test_v333_guard_refinement_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=12)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v333_guard_refinement(
            db,
            test_size=0.3,
            min_samples=6,
            review_limit=8,
            output_dir=tmp_path,
        )
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["guard_report_path"]).exists()
    assert Path(result["stability_report_path"]).exists()
    assert Path(result["summary_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()
    assert result["review_sample"]["import_ready"] is False

    report_text = Path(result["guard_report_path"]).read_text(encoding="utf-8")
    assert "v3.33 Evidence-Aware Low-Signal Guard Refinement" in report_text
    assert "No model was activated" in report_text
