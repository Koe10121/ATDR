import json
from datetime import datetime, timezone

from atdr.app.benchmarks.adapter import BenchmarkRecord
from atdr.app.benchmarks.readiness import readiness_gate_v6_external_finalization
from atdr.app.routers.dashboard import _latest_v18_ai_summary


def _record(
    *,
    label: str = "suspicious",
    app: str = "incomplete",
    action: str = "allow",
    dst_port: int = 995,
    bytes_sent: int = 110,
    packets: int = 2,
) -> BenchmarkRecord:
    return BenchmarkRecord(
        row_number=2,
        raw={},
        normalized={
            "timestamp": datetime(2026, 4, 20, tzinfo=timezone.utc),
            "source_name": "external-holdout",
            "src_ip": "203.0.113.10",
            "dst_ip": "10.0.0.8",
            "src_port": 45000,
            "dst_port": dst_port,
            "protocol": "tcp",
            "action": action,
            "app": app,
            "bytes": bytes_sent,
            "packets": packets,
        },
        label=label,
        attack_type="port_scan",
    )


def test_v18_readiness_can_mark_external_candidate_without_activation():
    result = readiness_gate_v6_external_finalization(
        external_label_count=320,
        external_metrics={
            "threat_positive_precision": 0.9568,
            "threat_positive_recall": 0.9118,
            "threat_positive_f1": 0.9338,
            "benign_false_positive_rate": 0.0467,
            "per_class": {
                "suspicious": {"recall": 0.9375},
                "malicious": {"recall": 0.8556},
            },
        },
        calibration_status="passed",
        controlled_validations_passed=True,
        internal_benchmark_validated=True,
        overfitting_status="moderate_generalization_gap",
    )

    assert result["decision"] == "external_benchmark_validated_candidate"
    assert result["external_benchmark_validated"] is True
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False


def test_v18_readiness_rejects_noisy_profile():
    result = readiness_gate_v6_external_finalization(
        external_label_count=320,
        external_metrics={
            "threat_positive_precision": 0.82,
            "threat_positive_recall": 0.94,
            "threat_positive_f1": 0.87,
            "benign_false_positive_rate": 0.23,
            "per_class": {
                "suspicious": {"recall": 0.93},
                "malicious": {"recall": 0.88},
            },
        },
        calibration_status="passed",
        controlled_validations_passed=True,
        internal_benchmark_validated=True,
        overfitting_status="moderate_generalization_gap",
        profile_rejected=True,
    )

    assert result["external_benchmark_validated"] is False
    failed = {item["name"] for item in result["checks"] if not item["passed"]}
    assert "external_benign_like_false_positive_rate" in failed
    assert "profile_safety_filter" in failed










def test_v18_dashboard_summary_is_concise_and_safe(tmp_path):
    payload = {
        "ok": True,
        "generated_at": "2026-06-14T00:00:00Z",
        "external_label_count": 320,
        "best_profile": {
            "profile": "external_recall_plus",
            "metrics": {
                "threat_positive_precision": 0.9568,
                "threat_positive_recall": 0.9118,
                "threat_positive_f1": 0.9338,
                "benign_false_positive_rate": 0.0467,
                "macro_f1": 0.9201,
                "weighted_f1": 0.9215,
                "per_class": {
                    "suspicious": {"recall": 0.9375},
                    "malicious": {"recall": 0.8556},
                },
            },
            "calibration": {
                "status": "passed",
                "expected_calibration_error": 0.0118,
                "brier_score_threat_positive": 0.0607,
                "max_confidence_accuracy_gap": 0.0418,
            },
            "calibration_readiness_status": "passed",
            "calibration_method": "bucket_smoothing",
            "generalization": {"status": "moderate_generalization_gap"},
        },
        "readiness_gate_v6": {
            "version": "v6",
            "decision": "external_benchmark_validated_candidate",
            "passed": 12,
            "total": 12,
            "external_benchmark_validated": True,
            "checks": [],
        },
        "miss_analysis": {
            "before_threat_false_negatives": 27,
            "after_threat_false_negatives": 15,
            "recovered_threat_false_negatives": 12,
        },
        "independent_revalidation_recommended": True,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
    }
    report = tmp_path / "v1_8_external_benchmark_finalization_20260614T000000Z.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = _latest_v18_ai_summary(tmp_path)

    assert result["best_profile"] == "external_recall_plus"
    assert result["external_benchmark_validated"] is True
    assert result["calibration_method"] == "bucket_smoothing"
    assert result["recovered_false_negatives"] == 12
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
