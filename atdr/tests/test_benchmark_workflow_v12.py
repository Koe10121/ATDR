import csv
from pathlib import Path

from atdr.app.benchmarks.readiness import readiness_gate_v2


def _benchmark_csv(path: Path) -> Path:
    rows = []
    for index in range(5):
        rows.append(
            {
                "event_time": f"2026-06-05T00:00:0{index}+00:00",
                "source_ip": "10.0.0.10",
                "destination_ip": f"198.51.100.{index}",
                "source_port": 50000 + index,
                "destination_port": 443,
                "protocol": "tcp",
                "firewall_action": "allow",
                "application": "ssl",
                "bytes_total": 1200,
                "packet_count": 12,
                "label": "BENIGN",
                "attack_type": "normal",
            }
        )
    for index in range(5):
        rows.append(
            {
                "event_time": f"2026-06-05T00:01:0{index}+00:00",
                "source_ip": "203.0.113.45",
                "destination_ip": "10.0.0.5",
                "source_port": 41000 + index,
                "destination_port": 20000 + index,
                "protocol": "tcp",
                "firewall_action": "deny",
                "application": "incomplete",
                "bytes_total": 100,
                "packet_count": 1,
                "label": "Attack",
                "attack_type": "scan",
            }
        )
    for index in range(5):
        rows.append(
            {
                "event_time": f"2026-06-05T00:02:0{index}+00:00",
                "source_ip": "203.0.113.55",
                "destination_ip": "10.0.0.22",
                "source_port": 42000 + index,
                "destination_port": 22,
                "protocol": "tcp",
                "firewall_action": "deny",
                "application": "ssh",
                "bytes_total": 80,
                "packet_count": 1,
                "label": "Malicious",
                "attack_type": "bruteforce",
            }
        )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path












def test_readiness_gate_v2_remains_conservative():
    result = readiness_gate_v2(
        label_count=15,
        label_distribution={"benign": 5, "threat": 10},
        metrics={"threat_positive_f1": 1.0, "threat_positive_recall": 1.0, "macro_f1": 1.0, "weighted_f1": 1.0},
        benchmark_metrics={"threat_positive_f1": 1.0, "threat_positive_recall": 1.0, "benign_false_positive_rate": 0.0},
        response_automation_allowed=False,
    )

    assert result["decision"] in {"candidate_only", "analyst_review_eligible"}
    assert result["production_status"] == "not_production_promoted"
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
