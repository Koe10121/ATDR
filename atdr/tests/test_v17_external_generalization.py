from datetime import datetime, timezone

from atdr.app.benchmarks.adapter import BenchmarkRecord
from atdr.app.benchmarks.readiness import readiness_gate_v6_external_generalization


def _record(
    *,
    row_number: int = 2,
    label: str = "suspicious",
    attack_type: str = "policy_violation",
    app: str = "bittorrent",
    action: str = "allow",
    dst_port: int = 6881,
    scenario: str = "peer_to_peer_policy_violation",
) -> BenchmarkRecord:
    return BenchmarkRecord(
        row_number=row_number,
        raw={},
        normalized={
            "timestamp": datetime(2026, 4, 20, tzinfo=timezone.utc),
            "source_name": "holdout-edge-firewall",
            "scenario": scenario,
            "src_ip": "198.51.100.10",
            "dst_ip": "10.0.0.5",
            "src_port": 50000,
            "dst_port": dst_port,
            "protocol": "tcp",
            "action": action,
            "app": app,
            "bytes": 900,
            "packets": 5,
        },
        label=label,
        attack_type=attack_type,
    )


def test_v17_readiness_gate_blocks_external_validation_on_boundary_gaps():
    result = readiness_gate_v6_external_generalization(
        external_label_count=320,
        external_metrics={
            "threat_positive_f1": 0.8937,
            "threat_positive_recall": 0.8412,
            "benign_false_positive_rate": 0.0467,
            "per_class": {
                "suspicious": {"recall": 0.7875},
                "malicious": {"recall": 0.7222},
            },
        },
        calibration_status="weak",
        controlled_validations_passed=True,
        internal_benchmark_validated=True,
        overfitting_status="significant_generalization_gap",
    )

    assert result["decision"] == "internal_benchmark_validated_candidate"
    assert result["external_benchmark_validated"] is False
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    failed = {item["name"] for item in result["checks"] if not item["passed"]}
    assert "external_suspicious_recall" in failed
    assert "confidence_calibration" in failed
    assert "overfitting_gap_limited" in failed








