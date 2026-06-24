from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v335_split_stability_repair import (
    apply_evidence_aware_suspicious_recall_floor,
    run_v335_split_stability_repair,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _prepared_stub(log: SimpleNamespace | None = None) -> dict:
    return {
        "test_idx": [0],
        "test_logs": [
            log
            or SimpleNamespace(app="quic-base", action="allow", dst_port=443, is_anomaly=False, anomaly_score=0.0)
        ],
    }


def _augmented_stub(row: dict) -> dict:
    return {"frame": pd.DataFrame([row])}


def test_v335_recall_floor_does_not_raise_low_signal_quic():
    prepared = _prepared_stub()
    augmented = _augmented_stub(
        {
            "v331_quic_443_allow_no_rule_flag": 1,
            "v331_benign_network_utility_no_rule_flag": 0,
            "src_ip_5min_unique_dst_ips": 1,
            "src_ip_5min_unique_dst_ports": 1,
            "src_ip_5min_log_count": 2,
            "src_ip_5min_deny_count": 0,
            "src_ip_5min_unknown_app_count": 0,
            "src_ip_5min_high_risk_app_count": 0,
            "v331_unknown_udp_scan_context_flag": 0,
            "v331_rule_score": 0,
        }
    )

    result = apply_evidence_aware_suspicious_recall_floor(
        prepared,
        augmented,
        ["benign"],
        [{"suspicious": 0.45, "malicious": 0.02}],
        policy_name="evidence_floor_balanced",
    )

    assert result == ["benign"]


def test_v335_recall_floor_raises_scan_like_unknown_udp_to_suspicious():
    prepared = _prepared_stub(SimpleNamespace(app="unknown-udp", action="allow", dst_port=32100, is_anomaly=True, anomaly_score=-0.3))
    augmented = _augmented_stub(
        {
            "v331_quic_443_allow_no_rule_flag": 0,
            "v331_benign_network_utility_no_rule_flag": 0,
            "src_ip_5min_unique_dst_ips": 8,
            "src_ip_5min_unique_dst_ports": 4,
            "src_ip_5min_log_count": 14,
            "src_ip_5min_deny_count": 0,
            "src_ip_5min_unknown_app_count": 5,
            "src_ip_5min_high_risk_app_count": 2,
            "v331_unknown_udp_scan_context_flag": 1,
            "v331_rule_score": 0,
        }
    )

    result = apply_evidence_aware_suspicious_recall_floor(
        prepared,
        augmented,
        ["benign_like"],
        [{"suspicious": 0.12, "malicious": 0.05}],
        policy_name="evidence_floor_balanced",
    )

    assert result == ["suspicious"]


def test_v335_split_stability_repair_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v335_split_stability_repair(
            db,
            test_size=0.3,
            min_samples=6,
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
    assert result["best_strategy"]
    assert Path(result["repair_report_path"]).exists()
    assert Path(result["diagnosis_report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["repair_report_path"]).read_text(encoding="utf-8")
    assert "v3.35 Supervised ML Split-Stability Repair" in report_text
    assert "No model was activated" in report_text
