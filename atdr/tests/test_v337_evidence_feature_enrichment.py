from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v337_evidence_feature_enrichment import _enrichment_values, run_v337_evidence_feature_enrichment
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v337_web_no_rule_low_diversity_gets_low_signal_family():
    row = {
        "src_ip_5min_event_count": 2,
        "src_ip_5min_unique_dst_ips": 1,
        "src_ip_5min_unique_dst_ports": 1,
        "src_ip_5min_deny_drop_reset_count": 0,
        "src_ip_5min_unknown_app_count": 0,
        "src_ip_5min_high_risk_app_count": 0,
        "v331_rule_score": 0,
        "repeated_connection_attempts": 1,
    }
    log = SimpleNamespace(app="quic-base", action="allow", dst_port=443, anomaly_score=0.0, is_anomaly=False)

    values = _enrichment_values(row, log, rule_codes=set())

    assert values["v337_web_like_allow_flag"] == 1
    assert values["v337_web_low_signal_flag"] == 1
    assert values["v337_web_scan_context_flag"] == 0
    assert values["v337_traffic_family"] == "web_low_signal"


def test_v337_web_high_diversity_gets_scan_context_family():
    row = {
        "src_ip_5min_event_count": 12,
        "src_ip_5min_unique_dst_ips": 6,
        "src_ip_5min_unique_dst_ports": 4,
        "src_ip_5min_deny_drop_reset_count": 0,
        "src_ip_5min_unknown_app_count": 0,
        "src_ip_5min_high_risk_app_count": 0,
        "v331_rule_score": 0,
        "repeated_connection_attempts": 8,
    }
    log = SimpleNamespace(app="ssl", action="allow", dst_port=443, anomaly_score=0.0, is_anomaly=False)

    values = _enrichment_values(row, log, rule_codes=set())

    assert values["v337_web_like_allow_flag"] == 1
    assert values["v337_web_low_signal_flag"] == 0
    assert values["v337_web_scan_context_flag"] == 1
    assert values["v337_repeated_service_flag"] == 1
    assert values["v337_traffic_family"] == "web_scan_context"


def test_v337_rule_backed_web_gets_rule_backed_family():
    row = {
        "src_ip_5min_event_count": 2,
        "src_ip_5min_unique_dst_ips": 1,
        "src_ip_5min_unique_dst_ports": 1,
        "src_ip_5min_deny_drop_reset_count": 0,
        "src_ip_5min_unknown_app_count": 0,
        "src_ip_5min_high_risk_app_count": 0,
        "v331_rule_score": 20,
        "repeated_connection_attempts": 1,
    }
    log = SimpleNamespace(app="quic-base", action="allow", dst_port=443, anomaly_score=0.0, is_anomaly=False)

    values = _enrichment_values(row, log, rule_codes={"possible_port_scan"})

    assert values["v337_rule_backed_allow_flag"] == 1
    assert values["v337_web_low_signal_flag"] == 0
    assert values["v337_traffic_family"] == "web_rule_backed"


def test_v337_evidence_feature_enrichment_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v337_evidence_feature_enrichment(
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
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.37 Evidence Feature Enrichment" in report_text
    assert "No model was activated" in report_text
