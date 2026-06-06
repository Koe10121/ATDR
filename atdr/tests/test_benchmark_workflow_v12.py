import csv
import json
from pathlib import Path

from atdr.app.benchmarks.readiness import readiness_gate_v2
from atdr.scripts.compare_layered_benchmark_reliability import compare_layered_benchmark_reliability
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.run_benchmark_ml_experiment import run_benchmark_ml_experiment
from atdr.scripts.run_detection_benchmark import run_detection_benchmark


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


def test_prepare_benchmark_dataset_writes_sanitized_snapshot(tmp_path):
    csv_path = _benchmark_csv(tmp_path / "benchmark.csv")
    snapshot = prepare_benchmark_dataset(
        input_csv=csv_path,
        mapping_config=Path("data/samples/benchmarks/example_firewall_mapping.json"),
        label_config=Path("data/samples/benchmarks/example_label_mapping.json"),
        limit=12,
        sample_strategy="balanced",
        output_dir=tmp_path,
    )

    assert snapshot["ok"] is True
    assert snapshot["rows_selected"] == 12
    assert snapshot["profile"]["label_distribution"]["benign"] > 0
    assert snapshot["profile"]["label_distribution"]["threat"] > 0
    assert snapshot["private_raw_payloads_excluded"] is True
    assert Path(snapshot["snapshot_path"]).exists()
    payload = json.loads(Path(snapshot["snapshot_path"]).read_text(encoding="utf-8"))
    assert all("raw" not in row for row in payload["records"])


def test_detection_benchmark_uses_prepared_snapshot_and_readiness_gate(tmp_path):
    csv_path = _benchmark_csv(tmp_path / "benchmark.csv")
    snapshot = prepare_benchmark_dataset(
        input_csv=csv_path,
        mapping_config=Path("data/samples/benchmarks/example_firewall_mapping.json"),
        label_config=Path("data/samples/benchmarks/example_label_mapping.json"),
        output_dir=tmp_path,
    )

    report = run_detection_benchmark(
        prepared_snapshot=Path(snapshot["snapshot_path"]),
        detection_mode="hybrid",
        output_dir=tmp_path,
    )

    assert report["ok"] is True
    assert report["detection_mode"] == "hybrid"
    assert report["metrics"]["threat_positive_recall"] > 0
    assert "per_class_metrics" in report["metrics"]
    assert "confusion_matrix" in report["metrics"]
    assert report["readiness_gate_v2"]["production_promoted"] is False
    assert report["safety"]["response_actions_created"] == 0


def test_benchmark_ml_experiment_does_not_activate_model(tmp_path):
    csv_path = _benchmark_csv(tmp_path / "benchmark.csv")
    snapshot = prepare_benchmark_dataset(
        input_csv=csv_path,
        mapping_config=Path("data/samples/benchmarks/example_firewall_mapping.json"),
        label_config=Path("data/samples/benchmarks/example_label_mapping.json"),
        output_dir=tmp_path,
    )

    report = run_benchmark_ml_experiment(
        snapshot_path=Path(snapshot["snapshot_path"]),
        split="random",
        output_dir=tmp_path,
    )

    assert report["ok"] is True
    assert report["best_candidate"] is not None
    assert report["safety"]["model_artifact_written"] is False
    assert report["safety"]["model_activated"] is False
    assert report["safety"]["automatic_response_enabled"] is False
    assert Path(report["paths"]["json"]).exists()


def test_layered_benchmark_comparison_report_and_ignored_output_policy(tmp_path):
    csv_path = _benchmark_csv(tmp_path / "benchmark.csv")
    snapshot = prepare_benchmark_dataset(
        input_csv=csv_path,
        mapping_config=Path("data/samples/benchmarks/example_firewall_mapping.json"),
        label_config=Path("data/samples/benchmarks/example_label_mapping.json"),
        output_dir=tmp_path,
    )

    report = compare_layered_benchmark_reliability(
        prepared_snapshot=Path(snapshot["snapshot_path"]),
        output_dir=tmp_path,
    )

    assert report["ok"] is True
    assert {row["mode"] for row in report["mode_results"]} == {"rules_only", "anomaly_only", "supervised_only", "hybrid"}
    assert report["safety"]["automatic_response_enabled"] is False
    assert Path(report["paths"]["markdown"]).exists()
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "demo_exports/" in gitignore
    assert "ml_baseline_reviews/" in gitignore


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
