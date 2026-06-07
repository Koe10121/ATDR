import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.build_internal_ai_readiness_benchmark import FIELDS


DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "data"
    / "samples"
    / "benchmarks"
    / "external_unseen_holdout_manifest.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "demo_exports" / "benchmarks" / "external_unseen_holdout.csv"
)


def _row(entry: dict[str, Any], index: int, row_number: int) -> dict[str, Any]:
    timestamp = datetime(2026, 4, 20, tzinfo=timezone.utc) + timedelta(
        seconds=row_number * 19
    )
    scenario = str(entry["name"])
    row = {
        "timestamp": timestamp.isoformat(),
        "source_name": entry["source_name"],
        "scenario": scenario,
        "src_ip": f"10.110.{row_number % 8}.{20 + row_number % 180}",
        "dst_ip": f"192.0.2.{20 + (row_number * 7) % 200}",
        "src_port": 30000 + (row_number * 31) % 30000,
        "dst_port": 443,
        "protocol": "tcp",
        "action": "allow",
        "app": "ssl",
        "bytes": 2400 + index * 41,
        "packets": 18 + index % 11,
        "label": entry["label"],
        "attack_type": entry["attack_type"],
    }
    if scenario == "normal_saas_tls":
        row.update(
            dst_port=443,
            app=("office365" if index % 2 else "ssl"),
            bytes=4000 + index * 83,
            packets=30 + index % 10,
        )
    elif scenario == "normal_quic_video":
        row.update(
            protocol="udp",
            dst_port=443,
            app="quic",
            bytes=25_000 + index * 900,
            packets=80 + index * 4,
        )
    elif scenario == "normal_incomplete_allow_boundary":
        row.update(
            dst_port=80 if index % 3 else 443,
            app="incomplete",
            action="allow",
            bytes=450 + index * 5,
            packets=4 + index % 3,
        )
    elif scenario == "normal_backup_transfer":
        row.update(
            src_ip=f"10.111.20.{10 + index % 4}",
            dst_ip=f"10.112.30.{20 + index % 3}",
            dst_port=445,
            app="ms-ds-smb",
            bytes=80_000_000 + index * 2_000_000,
            packets=90_000 + index * 1500,
        )
    elif scenario == "normal_blocked_background_noise":
        row.update(
            src_ip=f"198.51.100.{40 + index}",
            dst_ip=f"10.113.0.{30 + index % 5}",
            dst_port=1900 if index % 2 else 137,
            protocol="udp",
            action="deny",
            app="unknown-udp",
            bytes=120,
            packets=2,
        )
    elif scenario == "slow_horizontal_scan":
        row.update(
            src_ip=f"203.0.113.{170 + index // 10}",
            dst_ip=f"10.114.{index // 15}.{10 + index % 15}",
            dst_port=[21, 25, 110, 143, 587, 993, 995][index % 7],
            action="deny" if index % 4 else "allow",
            app="incomplete",
            bytes=110,
            packets=2,
        )
    elif scenario == "peer_to_peer_policy_violation":
        row.update(
            src_ip=f"10.115.0.{40 + index % 8}",
            dst_port=6881 + index % 8,
            protocol="udp" if index % 2 else "tcp",
            app="bittorrent",
            action="allow" if index % 3 else "deny",
            bytes=18_000 + index * 700,
            packets=90 + index,
        )
    elif scenario == "unknown_service_boundary":
        row.update(
            dst_port=7000 + index * 37,
            app="unknown-tcp",
            action="allow",
            bytes=900 + index * 60,
            packets=7 + index % 5,
        )
    elif scenario == "credential_probe_boundary":
        row.update(
            src_ip=f"198.51.100.{90 + index // 5}",
            dst_ip=f"10.116.0.{50 + index % 4}",
            dst_port=22 if index % 3 else 5900,
            app="ssh" if index % 3 else "vnc",
            action="deny",
            bytes=140,
            packets=2,
        )
    elif scenario == "distributed_brute_force":
        row.update(
            src_ip=f"203.0.113.{30 + index}",
            dst_ip=f"10.117.0.{20 + index % 2}",
            dst_port=22 if index % 2 else 3389,
            app="ssh" if index % 2 else "ms-rdp",
            action="deny",
            bytes=75,
            packets=1,
        )
    elif scenario == "dns_c2_beaconing":
        row.update(
            src_ip=f"10.118.0.{60 + index % 5}",
            dst_ip=f"192.0.2.{150 + index % 6}",
            dst_port=53,
            protocol="udp",
            app="dns",
            action="allow",
            bytes=220 + index % 9,
            packets=2,
        )
    elif scenario == "gradual_exfiltration":
        row.update(
            src_ip=f"10.119.0.{70 + index % 4}",
            dst_ip=f"198.51.100.{130 + index % 5}",
            dst_port=8443 if index % 2 else 443,
            app="ssl",
            action="allow",
            bytes=3_000_000 + index * 350_000,
            packets=4000 + index * 120,
        )
    elif scenario == "distributed_connection_flood":
        row.update(
            src_ip=f"198.51.100.{160 + index}",
            dst_ip="10.120.0.10",
            dst_port=8080,
            app="web-browsing",
            action="deny",
            bytes=65,
            packets=1,
        )
    elif scenario == "limited_generic_context":
        row.update(
            timestamp="" if index % 4 == 0 else row["timestamp"],
            src_ip="" if index % 6 == 0 else row["src_ip"],
            dst_ip="" if index % 9 == 0 else row["dst_ip"],
            dst_port="" if index % 3 else 0,
            action="" if index % 2 else "allow",
            app="unknown",
            bytes=0,
            packets=0,
        )
    return row


def build_fixed_unseen_holdout(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    output_path: Path = DEFAULT_OUTPUT,
    dry_run: bool = False,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for entry in manifest.get("scenarios") or []:
        for index in range(int(entry.get("count") or 0)):
            rows.append(_row(entry, index, len(rows)))
    target = int(manifest.get("target_rows") or 0)
    if len(rows) != target or len(rows) < 300:
        raise ValueError(
            f"Holdout must generate its declared target and at least 300 rows; "
            f"target={target}, generated={len(rows)}."
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
        "output_path": None if dry_run else str(output_path),
        "row_count": len(rows),
        "target_rows": target,
        "target_met": len(rows) >= 300,
        "label_distribution": dict(
            sorted(Counter(row["label"] for row in rows).items())
        ),
        "attack_type_distribution": dict(
            sorted(Counter(row["attack_type"] for row in rows).items())
        ),
        "source_distribution": dict(
            sorted(Counter(row["source_name"] for row in rows).items())
        ),
        "scenario_count": len(manifest.get("scenarios") or []),
        "training_contamination": False,
        "private_raw_payloads_included": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "production_readiness_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the fixed safe v1.6 unseen holdout benchmark."
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = build_fixed_unseen_holdout(
        manifest_path=Path(args.manifest),
        output_path=Path(args.output),
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
