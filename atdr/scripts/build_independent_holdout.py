import argparse
import csv
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import (
    BenchmarkRecord,
    load_prepared_benchmark_snapshot,
    write_benchmark_snapshot,
)
from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.build_internal_ai_readiness_benchmark import FIELDS


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
DEFAULT_CSV = DEFAULT_OUTPUT_DIR / "v1_9_independent_holdout.csv"
DEFAULT_SEED = 1909
MINIMUM_ROWS = 300
PREFERRED_ROWS = 500

SCENARIOS = (
    ("campus_sso_tls", 45, "benign_like", "normal", "independent-campus-edge"),
    ("software_update_cdn", 35, "benign_like", "normal", "independent-campus-edge"),
    ("resolver_dns_normal", 25, "benign_like", "normal", "independent-core-router"),
    ("internal_file_sync", 25, "benign_like", "normal", "independent-datacenter-fw"),
    ("near_threat_web_retry", 30, "benign_like", "normal", "independent-branch-fw"),
    ("low_slow_mail_port_sweep", 55, "suspicious", "port_scan", "independent-remote-edge"),
    ("sparse_credential_probes", 30, "suspicious", "brute_force", "independent-remote-edge"),
    ("rare_admin_service_boundary", 25, "suspicious", "unknown_anomaly", "independent-branch-fw"),
    ("policy_tunnel_boundary", 20, "suspicious", "policy_violation", "independent-campus-edge"),
    ("delayed_dns_beacon", 35, "malicious", "malware_c2", "independent-core-router"),
    ("gradual_cloud_exfil", 35, "malicious", "data_exfiltration_suspicion", "independent-datacenter-fw"),
    ("distributed_auth_abuse", 30, "malicious", "brute_force", "independent-remote-edge"),
    ("staged_service_flood", 30, "malicious", "dos_ddos", "independent-campus-edge"),
    ("partial_router_events", 35, "needs_context", "unknown", "independent-generic-sensor"),
    ("unknown_encrypted_service", 25, "needs_context", "unknown", "independent-branch-fw"),
    ("ambiguous_external_sessions", 20, "needs_context", "unknown", "independent-generic-sensor"),
)


def _fingerprint(row: dict[str, Any], *, near: bool = False) -> str:
    if near:
        values = (
            row.get("label"),
            row.get("attack_type"),
            row.get("app"),
            row.get("action"),
            row.get("protocol"),
            row.get("dst_port"),
            int(float(row.get("bytes") or 0)) // 1000,
            int(float(row.get("packets") or 0)) // 10,
        )
    else:
        values = tuple(row.get(field) for field in FIELDS)
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _record_fingerprint(record: BenchmarkRecord, *, near: bool = False) -> str:
    row = {
        **record.normalized,
        "label": record.label,
        "attack_type": record.attack_type,
    }
    timestamp = row.get("timestamp")
    if isinstance(timestamp, datetime):
        row["timestamp"] = timestamp.isoformat()
    return _fingerprint(row, near=near)


def _base_row(
    *,
    scenario: str,
    label: str,
    attack_type: str,
    source_name: str,
    index: int,
    row_number: int,
    rng: random.Random,
) -> dict[str, Any]:
    timestamp = datetime(2026, 5, 18, tzinfo=timezone.utc) + timedelta(
        seconds=row_number * 31 + rng.randint(0, 11)
    )
    row: dict[str, Any] = {
        "timestamp": timestamp.isoformat(),
        "source_name": source_name,
        "scenario": scenario,
        "src_ip": f"10.{130 + row_number % 8}.{row_number % 31}.{20 + row_number % 180}",
        "dst_ip": f"192.0.2.{10 + (row_number * 11) % 230}",
        "src_port": 20000 + (row_number * 67) % 44000,
        "dst_port": 443,
        "protocol": "tcp",
        "action": "allow",
        "app": "ssl",
        "bytes": 2500 + rng.randint(0, 3000),
        "packets": 15 + rng.randint(0, 20),
        "label": label,
        "attack_type": attack_type,
    }
    if scenario == "campus_sso_tls":
        row.update(
            app=("ssl" if index % 2 else "office365"),
            dst_port=443,
            bytes=3500 + rng.randint(0, 9000),
            packets=20 + rng.randint(0, 35),
        )
    elif scenario == "software_update_cdn":
        row.update(
            app=("ssl" if index % 3 else "web-browsing"),
            dst_port=443,
            bytes=150_000 + rng.randint(0, 900_000),
            packets=180 + rng.randint(0, 500),
        )
    elif scenario == "resolver_dns_normal":
        row.update(
            protocol="udp",
            app="dns",
            dst_port=53,
            bytes=800 + rng.randint(0, 900),
            packets=5 + rng.randint(0, 5),
        )
    elif scenario == "internal_file_sync":
        row.update(
            src_ip=f"10.141.10.{10 + index % 6}",
            dst_ip=f"10.142.20.{20 + index % 4}",
            app="ms-ds-smb",
            dst_port=445,
            bytes=2_000_000 + rng.randint(0, 8_000_000),
            packets=2000 + rng.randint(0, 6000),
        )
    elif scenario == "near_threat_web_retry":
        row.update(
            src_ip=f"10.143.0.{30 + index % 10}",
            dst_port=80 if index % 2 else 443,
            app="incomplete",
            action="allow",
            bytes=300 + rng.randint(0, 500),
            packets=3 + rng.randint(0, 4),
        )
    elif scenario == "low_slow_mail_port_sweep":
        row.update(
            src_ip=f"203.0.113.{90 + index // 12}",
            dst_ip=f"10.144.{index // 18}.{10 + index % 18}",
            dst_port=[25, 110, 143, 465, 587, 993, 995][index % 7],
            app="incomplete",
            action="allow" if index % 5 == 0 else "deny",
            bytes=90 + rng.randint(0, 80),
            packets=1 + rng.randint(0, 2),
        )
    elif scenario == "sparse_credential_probes":
        row.update(
            src_ip=f"198.51.100.{40 + index // 6}",
            dst_ip=f"10.145.0.{20 + index % 6}",
            dst_port=22 if index % 3 else 5900,
            app="ssh" if index % 3 else "vnc",
            action="deny",
            bytes=100 + rng.randint(0, 90),
            packets=1 + rng.randint(0, 2),
        )
    elif scenario == "rare_admin_service_boundary":
        row.update(
            dst_port=7001 + (index * 53) % 1800,
            app="unknown-tcp",
            action="allow",
            bytes=700 + rng.randint(0, 2500),
            packets=5 + rng.randint(0, 12),
        )
    elif scenario == "policy_tunnel_boundary":
        row.update(
            dst_port=6881 + index % 12,
            protocol="udp" if index % 2 else "tcp",
            app="bittorrent",
            action="allow" if index % 4 else "deny",
            bytes=12_000 + rng.randint(0, 25_000),
            packets=70 + rng.randint(0, 100),
        )
    elif scenario == "delayed_dns_beacon":
        row.update(
            src_ip=f"10.146.0.{50 + index % 5}",
            dst_ip=f"192.0.2.{170 + index % 7}",
            protocol="udp",
            app="dns",
            dst_port=53,
            bytes=190 + rng.randint(0, 170),
            packets=2,
        )
    elif scenario == "gradual_cloud_exfil":
        row.update(
            src_ip=f"10.147.0.{60 + index % 5}",
            dst_ip=f"198.51.100.{150 + index % 8}",
            app=("ssl" if index % 3 else "quic"),
            protocol="udp" if index % 3 == 0 else "tcp",
            dst_port=443 if index % 2 else 8443,
            bytes=3_200_000 + rng.randint(0, 2_800_000),
            packets=3500 + rng.randint(0, 2500),
        )
    elif scenario == "distributed_auth_abuse":
        row.update(
            src_ip=f"203.0.113.{20 + index}",
            dst_ip=f"10.148.0.{10 + index % 3}",
            dst_port=22 if index % 2 else 3389,
            app="ssh" if index % 2 else "ms-rdp",
            action="deny",
            bytes=60 + rng.randint(0, 50),
            packets=1,
        )
    elif scenario == "staged_service_flood":
        row.update(
            src_ip=f"198.51.100.{180 + index % 40}",
            dst_ip="10.149.0.10",
            dst_port=8080,
            app="web-browsing",
            action="deny",
            bytes=50 + rng.randint(0, 40),
            packets=1,
        )
    elif scenario == "partial_router_events":
        row.update(
            timestamp="" if index % 5 == 0 else row["timestamp"],
            src_ip="" if index % 7 == 0 else row["src_ip"],
            dst_ip="" if index % 9 == 0 else row["dst_ip"],
            dst_port="" if index % 4 == 0 else 0,
            app="unknown",
            action="" if index % 3 else "allow",
            bytes=0,
            packets=0,
        )
    elif scenario == "unknown_encrypted_service":
        row.update(
            app="unknown-tcp",
            dst_port=5000 + (index * 71) % 3500,
            bytes=1000 + rng.randint(0, 7000),
            packets=7 + rng.randint(0, 15),
        )
    elif scenario == "ambiguous_external_sessions":
        row.update(
            app="incomplete",
            dst_port=[80, 443, 8080, 8443][index % 4],
            action="allow" if index % 2 else "reset",
            bytes=200 + rng.randint(0, 1200),
            packets=2 + rng.randint(0, 7),
        )
    return row


def _load_previous_fingerprints(
    output_dir: Path,
    *,
    excluded_path: Path | None = None,
    excluded_input_name: str | None = None,
) -> tuple[set[str], set[str], int]:
    exact: set[str] = set()
    near: set[str] = set()
    snapshots = 0
    for path in sorted(output_dir.glob("benchmark_snapshot_*.json")):
        if excluded_path is not None and path.resolve() == excluded_path.resolve():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if (
                excluded_input_name
                and str(payload.get("input_name") or "") == excluded_input_name
            ):
                continue
            records, _summary = load_prepared_benchmark_snapshot(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        snapshots += 1
        exact.update(_record_fingerprint(record) for record in records)
        near.update(_record_fingerprint(record, near=True) for record in records)
    return exact, near, snapshots


def build_independent_holdout(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    csv_path: Path = DEFAULT_CSV,
    seed: int = DEFAULT_SEED,
    row_limit: int = PREFERRED_ROWS,
    dry_run: bool = False,
) -> dict[str, Any]:
    if row_limit < MINIMUM_ROWS:
        raise ValueError(f"Independent holdout requires at least {MINIMUM_ROWS} rows.")
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    for scenario, count, label, attack_type, source_name in SCENARIOS:
        for index in range(count):
            rows.append(
                _base_row(
                    scenario=scenario,
                    label=label,
                    attack_type=attack_type,
                    source_name=source_name,
                    index=index,
                    row_number=len(rows),
                    rng=rng,
                )
            )
    if row_limit != PREFERRED_ROWS:
        rng.shuffle(rows)
        rows = rows[:row_limit]
    rng.shuffle(rows)
    exact_counts = Counter(_fingerprint(row) for row in rows)
    near_counts = Counter(_fingerprint(row, near=True) for row in rows)
    previous_exact, previous_near, previous_snapshot_count = (
        _load_previous_fingerprints(
            output_dir,
            excluded_input_name=csv_path.name,
        )
    )
    overlap_exact = sum(1 for row in rows if _fingerprint(row) in previous_exact)
    overlap_near = sum(1 for row in rows if _fingerprint(row, near=True) in previous_near)
    snapshot = None
    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        records = [
            BenchmarkRecord(
                row_number=index + 2,
                raw={field: str(row.get(field, "")) for field in FIELDS},
                normalized={
                    "timestamp": (
                        datetime.fromisoformat(str(row["timestamp"]))
                        if row.get("timestamp")
                        else None
                    ),
                    "source_name": row.get("source_name"),
                    "scenario": row.get("scenario"),
                    "src_ip": row.get("src_ip") or None,
                    "dst_ip": row.get("dst_ip") or None,
                    "src_port": int(row["src_port"]) if row.get("src_port") else None,
                    "dst_port": int(row["dst_port"]) if row.get("dst_port") not in ("", None) else None,
                    "protocol": row.get("protocol"),
                    "action": row.get("action") or None,
                    "app": row.get("app"),
                    "bytes": int(row["bytes"]) if row.get("bytes") not in ("", None) else None,
                    "packets": int(row["packets"]) if row.get("packets") not in ("", None) else None,
                },
                label=str(row["label"]),
                attack_type=str(row["attack_type"]),
            )
            for index, row in enumerate(rows)
        ]
        snapshot = write_benchmark_snapshot(
            records,
            input_name=csv_path.name,
            mapping_summary={
                "generator": "atdr.scripts.build_independent_holdout",
                "seed": seed,
                "mapping_errors": [],
            },
            output_dir=output_dir,
            sample_strategy="independent_seeded",
            requested_limit=row_limit,
        )
    return {
        "ok": True,
        "dry_run": dry_run,
        "seed": seed,
        "version": "v1.9",
        "row_count": len(rows),
        "minimum_rows_met": len(rows) >= MINIMUM_ROWS,
        "preferred_rows_met": len(rows) >= PREFERRED_ROWS,
        "source_count": len({str(row["source_name"]) for row in rows}),
        "scenario_count": len({str(row["scenario"]) for row in rows}),
        "label_distribution": dict(sorted(Counter(str(row["label"]) for row in rows).items())),
        "source_distribution": dict(sorted(Counter(str(row["source_name"]) for row in rows).items())),
        "scenario_distribution": dict(sorted(Counter(str(row["scenario"]) for row in rows).items())),
        "duplicate_summary": {
            "exact_duplicate_rows": sum(count - 1 for count in exact_counts.values() if count > 1),
            "near_duplicate_rows": sum(count - 1 for count in near_counts.values() if count > 1),
            "near_duplicate_groups": sum(1 for count in near_counts.values() if count > 1),
        },
        "previous_holdout_overlap": {
            "snapshots_checked": previous_snapshot_count,
            "exact_overlap_rows": overlap_exact,
            "near_overlap_rows": overlap_near,
            "exact_overlap_passed": overlap_exact == 0,
        },
        "csv_path": None if dry_run else str(csv_path),
        "snapshot_path": None if snapshot is None else str(snapshot["snapshot_path"]),
        "snapshot_id": None if snapshot is None else snapshot["snapshot_id"],
        "synthetic_only": True,
        "real_attacks_executed": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "production_promoted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the safe independent v1.9 benchmark holdout."
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--output-csv", default=str(DEFAULT_CSV))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--rows", type=int, default=PREFERRED_ROWS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = build_independent_holdout(
        output_dir=Path(args.output_dir),
        csv_path=Path(args.output_csv),
        seed=args.seed,
        row_limit=args.rows,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
