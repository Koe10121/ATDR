import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from atdr.app.db.models import LogSource, NormalizedLog, RawLog
from atdr.scripts import (
    analyze_detection_errors,
    calibrate_detection_risk,
    monitor_detection_drift,
    run_detection_reliability_baseline,
    run_ml_reliability_report,
)
from atdr.scripts.run_detection_benchmark import run_detection_benchmark
from atdr.scripts.run_detection_stress_test import run_detection_stress_test
from atdr.scripts.run_source_scenario import _temp_session_factory


def test_reliability_baseline_aggregates_validation_layers(tmp_path, monkeypatch):
    scenario_report = {
        "ok": True,
        "scenario_count": 2,
        "passed_count": 2,
        "scenarios": [
            {
                "scenario": "normal_allowed_traffic",
                "expected": {"expected_alert_present": False, "expected_max_risk_score": 0},
                "alerts": [],
            },
            {
                "scenario": "port_scan_like_traffic",
                "expected": {"expected_alert_present": True, "expected_min_risk_score": 70, "expected_max_risk_score": 100},
                "alerts": [{"alert_type": "possible_port_scan", "severity": "Critical", "risk_score": 100}],
            },
        ],
    }
    monkeypatch.setattr(run_detection_reliability_baseline, "run_detection_validation_suite", lambda **_: scenario_report)
    monkeypatch.setattr(
        run_detection_reliability_baseline,
        "run_detection_generalization_suite",
        lambda **_: {
            "ok": True,
            "scenario_count": 2,
            "variant_count": 10,
            "passed_count": 10,
            "failed_count": 0,
            "false_positive_count": 0,
            "false_negative_count": 0,
            "families": [],
        },
    )
    monkeypatch.setattr(
        run_detection_reliability_baseline,
        "run_layered_detection_validation",
        lambda **_: {
            "ok": True,
            "scenario_count": 2,
            "variant_count": 6,
            "mode_run_count": 24,
            "passed_count": 24,
            "failed_count": 0,
            "false_positive_count": 0,
            "false_negative_count": 0,
            "mode_summary": [{"mode": "rules_only", "tests": 6, "passed_count": 6}],
        },
    )
    monkeypatch.setattr(
        run_detection_reliability_baseline,
        "run_e2e_workflow_validation",
        lambda **_: {"ok": True, "scenario_count": 1, "passed_count": 1, "failed_count": 0, "simulate_response": True, "scenarios": []},
    )

    report = run_detection_reliability_baseline.run_detection_reliability_baseline(output_dir=tmp_path)

    assert report["ok"] is True
    assert report["scenario_validation"]["passed_count"] == 2
    assert report["false_positive_count"] == 0
    assert report["false_negative_count"] == 0
    assert report["alert_volume"] == 1
    assert Path(report["paths"]["json"]).exists()
    assert report["safety"]["automatic_response_enabled"] is False


def test_benchmark_adapter_and_runner_detects_safe_port_scan(tmp_path):
    csv_path = tmp_path / "benchmark.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "app", "label", "attack_type"],
        )
        writer.writeheader()
        for offset in range(8):
            writer.writerow(
                {
                    "timestamp": f"2026-06-05T00:00:0{offset}+00:00",
                    "src_ip": "203.0.113.44",
                    "dst_ip": "10.20.30.44",
                    "dst_port": 20000 + offset,
                    "protocol": "tcp",
                    "action": "deny",
                    "app": "incomplete",
                    "label": "attack",
                    "attack_type": "port_scan",
                }
            )
        writer.writerow(
            {
                "timestamp": "2026-06-05T00:01:00+00:00",
                "src_ip": "10.20.30.10",
                "dst_ip": "198.51.100.10",
                "dst_port": 443,
                "protocol": "tcp",
                "action": "allow",
                "app": "ssl",
                "label": "benign",
                "attack_type": "normal",
            }
        )

    report = run_detection_benchmark(csv_path=csv_path, output_dir=tmp_path)

    assert report["ok"] is True
    assert report["total_rows"] == 9
    assert report["metrics"]["true_positives"] >= 1
    assert report["metrics"]["false_negatives"] < 8
    assert report["safety"]["response_actions_created"] == 0
    assert Path(report["paths"]["json"]).exists()


def test_internal_controlled_benchmark_manifest_is_safe_and_complete():
    manifest_path = Path("data/samples/benchmarks/internal_controlled_benchmark.json")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["production_readiness_claim"] is False
    assert payload["automatic_response_expected"] is False
    scenarios = {item["scenario"] for item in payload["entries"]}
    assert "normal_allowed_traffic" in scenarios
    assert "port_scan_like_traffic" in scenarios
    assert all(item["expected_no_automatic_response"] is True for item in payload["entries"])


def test_error_analysis_and_risk_calibration_reports(tmp_path):
    baseline = {
        "false_positive_count": 0,
        "false_negative_count": 0,
        "scenario_details": [
            {
                "scenario": "port_scan_like_traffic",
                "expected": {"expected_alert_present": True, "expected_min_risk_score": 70, "expected_max_risk_score": 100},
                "alerts": [{"alert_type": "possible_port_scan", "risk_score": 100, "severity": "Critical"}],
            }
        ],
    }
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    errors = analyze_detection_errors.analyze_detection_errors(baseline_path=baseline_path, output_dir=tmp_path)
    calibration = calibrate_detection_risk.calibrate_detection_risk(baseline_path=baseline_path, output_dir=tmp_path)

    assert errors["ok"] is True
    assert calibration["ok"] is True
    assert calibration["threshold_changes_applied"] is False
    assert Path(errors["paths"]["markdown"]).exists()
    assert Path(calibration["paths"]["markdown"]).exists()


def test_drift_report_generation_uses_read_only_session(tmp_path, monkeypatch):
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            source = LogSource(name="drift-test", source_type="sample", parser_profile="palo_alto")
            db.add(source)
            db.flush()
            for index in range(20):
                raw = RawLog(source_id=source.id, raw_line=f"line {index}")
                db.add(raw)
                db.flush()
                db.add(
                    NormalizedLog(
                        raw_log_id=raw.id,
                        generated_time=datetime.now(timezone.utc),
                        src_ip=f"203.0.113.{index % 3}",
                        dst_ip="10.0.0.5",
                        app="ssl" if index % 2 else "incomplete",
                        action="allow",
                        dst_port=443,
                        protocol="tcp",
                    )
                )
            source.logs_received_count = 20
            source.parse_success_count = 20
            db.commit()
        monkeypatch.setattr(monitor_detection_drift, "SessionLocal", SessionFactory)
        report = monitor_detection_drift.monitor_detection_drift(recent_limit=5, baseline_limit=10, output_dir=tmp_path)
        assert report["ok"] is True
        assert report["recent_rows"] == 5
        assert "unknown_app_rate" in report
        assert Path(report["paths"]["json"]).exists()
    finally:
        engine.dispose()


def test_ml_reliability_report_stays_decision_support(tmp_path, monkeypatch):
    class SessionContext:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(run_ml_reliability_report, "SessionLocal", lambda: SessionContext())
    monkeypatch.setattr(
        run_ml_reliability_report,
        "supervised_model_report",
        lambda _db: {
            "label_count": 10,
            "reviewed_label_count": 4,
            "reviewed_label_target": 20,
            "decision_support_only": True,
            "soc_triage_mode": "balanced",
        },
    )
    monkeypatch.setattr(run_ml_reliability_report, "evaluation_report", lambda _db: {"anomaly_rate": 1.2, "scored_log_count": 100})

    report = run_ml_reliability_report.run_ml_reliability_report(output_dir=tmp_path)

    assert report["decision_support_only"] is True
    assert report["production_promoted"] is False
    assert report["response_automation_allowed"] is False
    assert Path(report["paths"]["json"]).exists()


def test_detection_stress_test_uses_temp_db_and_safe_scenarios(tmp_path):
    report = run_detection_stress_test(
        scenarios=["port_scan_like_traffic"],
        iterations=1,
        output_dir=tmp_path,
    )

    assert report["use_temp_db"] is True
    assert report["rows_imported"] > 0
    assert report["safety"]["safe_synthetic_data_only"] is True
    assert report["safety"]["automatic_response_enabled"] is False
    assert Path(report["paths"]["markdown"]).exists()
