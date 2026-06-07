import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT


DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "data"
    / "samples"
    / "benchmarks"
    / "internal_ai_readiness_benchmark_manifest.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "demo_exports"
    / "benchmarks"
    / "internal_ai_readiness_benchmark.csv"
)
FIELDS = [
    "timestamp",
    "source_name",
    "scenario",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "app",
    "bytes",
    "packets",
    "label",
    "attack_type",
]


def _base_row(entry: dict[str, Any], index: int, row_number: int) -> dict[str, Any]:
    timestamp = datetime(2026, 1, 15, tzinfo=timezone.utc) + timedelta(
        seconds=row_number * 7
    )
    scenario = str(entry["name"])
    row = {
        "timestamp": timestamp.isoformat(),
        "source_name": entry["source_name"],
        "scenario": scenario,
        "src_ip": f"10.20.{(row_number // 240) % 20}.{10 + row_number % 200}",
        "dst_ip": f"198.51.100.{10 + row_number % 200}",
        "src_port": 40000 + row_number % 20000,
        "dst_port": 443,
        "protocol": "tcp",
        "action": "allow",
        "app": "ssl",
        "bytes": 1200 + index * 17,
        "packets": 12 + index % 8,
        "label": entry["label"],
        "attack_type": entry["attack_type"],
    }
    if scenario == "normal_quic_443":
        row.update(protocol="udp", dst_port=443, app="quic", bytes=1800 + index * 23)
    elif scenario == "normal_web_dns":
        if index % 3 == 0:
            row.update(protocol="udp", dst_port=53, app="dns", bytes=320)
        else:
            row.update(dst_port=443 if index % 2 else 80, app="ssl" if index % 2 else "web-browsing")
    elif scenario == "benign_near_threat_boundary":
        row.update(dst_port=80, app="incomplete", action="allow", bytes=640, packets=7)
    elif scenario == "port_scan_like":
        row.update(
            src_ip=f"203.0.113.{20 + index // 12}",
            dst_ip=f"10.30.{index // 20}.{10 + index % 20}",
            dst_port=20 + (index * 97) % 10000,
            action="deny",
            app="incomplete",
            bytes=80,
            packets=1,
        )
    elif scenario == "policy_violation":
        row.update(
            src_ip=f"10.40.1.{20 + index % 15}",
            dst_port=8080 if index % 2 else 23,
            action="deny" if index % 3 else "allow",
            app="unknown-tcp",
            bytes=500,
            packets=5,
        )
    elif scenario == "brute_force_like":
        row.update(
            src_ip=f"203.0.113.{80 + index // 10}",
            dst_ip=f"10.50.0.{20 + index % 3}",
            dst_port=22 if index % 2 else 3389,
            action="deny",
            app="ssh" if index % 2 else "ms-rdp",
            bytes=90,
            packets=1,
        )
    elif scenario == "malware_c2_beaconing":
        row.update(
            src_ip=f"10.60.0.{30 + index % 4}",
            dst_ip=f"192.0.2.{80 + index % 3}",
            dst_port=4444 if index % 2 else 8081,
            app="unknown-tcp",
            bytes=180 + index % 5,
            packets=3,
        )
    elif scenario == "data_exfiltration_suspicion":
        row.update(
            src_ip=f"10.70.0.{40 + index % 5}",
            dst_ip=f"192.0.2.{120 + index % 4}",
            dst_port=443,
            app="ssl",
            bytes=15_000_000 + index * 500_000,
            packets=20_000 + index * 100,
        )
    elif scenario == "connection_flood_like":
        row.update(
            src_ip=f"203.0.113.{140 + index // 8}",
            dst_ip="10.80.0.10",
            dst_port=443,
            action="deny",
            app="incomplete",
            bytes=60,
            packets=1,
        )
    elif scenario == "malformed_or_limited_context":
        row.update(
            timestamp="" if index % 3 == 0 else row["timestamp"],
            src_ip="" if index % 5 == 0 else row["src_ip"],
            dst_ip="" if index % 7 == 0 else row["dst_ip"],
            dst_port="" if index % 2 else 0,
            action="",
            app="unknown",
            bytes=0,
            packets=0,
        )
    return row


def build_internal_ai_readiness_benchmark(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    output_path: Path = DEFAULT_OUTPUT,
    dry_run: bool = False,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for entry in manifest.get("scenarios") or []:
        for index in range(int(entry.get("count") or 0)):
            rows.append(_base_row(entry, index, len(rows)))
    target_rows = int(manifest.get("target_rows") or 0)
    if len(rows) < 100 or len(rows) != target_rows:
        raise ValueError(
            f"Manifest must generate its declared target and at least 100 rows; "
            f"target={target_rows}, generated={len(rows)}."
        )
    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    return {
        "ok": True,
        "dry_run": dry_run,
        "manifest_name": manifest.get("name"),
        "manifest_version": manifest.get("version"),
        "manifest_path": str(manifest_path),
        "output_path": None if dry_run else str(output_path),
        "row_count": len(rows),
        "target_rows": target_rows,
        "target_met": len(rows) >= 100,
        "label_distribution": dict(sorted(Counter(row["label"] for row in rows).items())),
        "attack_type_distribution": dict(
            sorted(Counter(row["attack_type"] for row in rows).items())
        ),
        "source_distribution": dict(
            sorted(Counter(row["source_name"] for row in rows).items())
        ),
        "scenario_count": len(manifest.get("scenarios") or []),
        "private_raw_payloads_included": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "production_readiness_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the safe synthetic v1.5 internal AI readiness benchmark CSV."
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = build_internal_ai_readiness_benchmark(
        manifest_path=Path(args.manifest),
        output_path=Path(args.output),
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
