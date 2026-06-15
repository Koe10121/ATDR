import argparse
import csv
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import BenchmarkRecord, write_benchmark_snapshot
from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.build_independent_holdout import (
    _fingerprint,
    _load_previous_fingerprints,
)
from atdr.scripts.build_internal_ai_readiness_benchmark import FIELDS


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
DEFAULT_CSV = DEFAULT_OUTPUT_DIR / "v2_0_fresh_blind_holdout.csv"
DEFAULT_SEED = 20200614
MINIMUM_ROWS = 500
PREFERRED_ROWS = 700
SCENARIOS = (
    ("student_portal_tls", 70, "benign_like", "normal", "blind-campus-fw-a"),
    ("backup_replication", 55, "benign_like", "normal", "blind-datacenter-fw"),
    ("recursive_dns_normal", 40, "benign_like", "normal", "blind-core-router"),
    ("video_conference_quic", 40, "benign_like", "normal", "blind-campus-fw-b"),
    ("transient_web_retries", 35, "benign_like", "normal", "blind-branch-fw"),
    ("slow_service_discovery", 60, "suspicious", "port_scan", "blind-remote-edge"),
    ("credential_probe_boundary", 50, "suspicious", "brute_force", "blind-remote-edge"),
    ("uncommon_admin_service", 35, "suspicious", "unknown_anomaly", "blind-branch-fw"),
    ("unauthorized_tunnel_use", 35, "suspicious", "policy_violation", "blind-campus-fw-b"),
    ("periodic_dns_callback", 55, "malicious", "malware_c2", "blind-core-router"),
    ("incremental_archive_upload", 50, "malicious", "data_exfiltration_suspicion", "blind-datacenter-fw"),
    ("distributed_remote_login_abuse", 45, "malicious", "brute_force", "blind-remote-edge"),
    ("application_exhaustion_wave", 40, "malicious", "dos_ddos", "blind-campus-fw-a"),
    ("malformed_router_fallback", 30, "needs_context", "unknown", "blind-generic-sensor"),
    ("unresolved_high_port_service", 35, "needs_context", "unknown", "blind-branch-fw"),
    ("ambiguous_reset_sessions", 25, "needs_context", "unknown", "blind-generic-sensor"),
)


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
    timestamp = datetime(2026, 6, 7, tzinfo=timezone.utc) + timedelta(
        seconds=row_number * 47 + rng.randint(0, 19)
    )
    row: dict[str, Any] = {
        "timestamp": timestamp.isoformat(),
        "source_name": source_name,
        "scenario": scenario,
        "src_ip": f"10.{170 + row_number % 12}.{3 + row_number % 40}.{10 + row_number % 220}",
        "dst_ip": f"198.51.100.{10 + (row_number * 17) % 230}",
        "src_port": 18000 + (row_number * 83) % 46000,
        "dst_port": 443,
        "protocol": "tcp",
        "action": "allow",
        "app": "ssl",
        "bytes": 3000 + rng.randint(0, 7000),
        "packets": 15 + rng.randint(0, 30),
        "label": label,
        "attack_type": attack_type,
    }
    if scenario == "student_portal_tls":
        row.update(
            app=("ssl" if index % 3 else "office365"),
            bytes=4500 + rng.randint(0, 16_000),
            packets=22 + rng.randint(0, 50),
        )
    elif scenario == "backup_replication":
        row.update(
            src_ip=f"10.181.20.{10 + index % 8}",
            dst_ip=f"10.182.30.{20 + index % 5}",
            app="ms-ds-smb",
            dst_port=445,
            bytes=1_500_000 + rng.randint(0, 7_000_000),
            packets=1800 + rng.randint(0, 5200),
        )
    elif scenario == "recursive_dns_normal":
        row.update(
            protocol="udp",
            app="dns",
            dst_port=53,
            bytes=950 + rng.randint(0, 1100),
            packets=5 + rng.randint(0, 7),
        )
    elif scenario == "video_conference_quic":
        row.update(
            protocol="udp",
            app="quic",
            dst_port=443,
            bytes=80_000 + rng.randint(0, 500_000),
            packets=120 + rng.randint(0, 480),
        )
    elif scenario == "transient_web_retries":
        row.update(
            src_ip=f"10.183.0.{25 + index % 12}",
            app="incomplete",
            dst_port=[80, 443, 8080, 8443][index % 4],
            bytes=280 + rng.randint(0, 650),
            packets=3 + rng.randint(0, 5),
        )
    elif scenario == "slow_service_discovery":
        row.update(
            src_ip=f"203.0.113.{80 + index // 10}",
            dst_ip=f"10.184.{index // 20}.{20 + index % 20}",
            dst_port=[21, 25, 110, 143, 465, 587, 993, 995][index % 8],
            app="incomplete",
            action="allow" if index % 6 == 0 else "deny",
            bytes=70 + rng.randint(0, 120),
            packets=1 + rng.randint(0, 2),
        )
    elif scenario == "credential_probe_boundary":
        row.update(
            src_ip=f"192.0.2.{35 + index // 5}",
            dst_ip=f"10.185.0.{12 + index % 8}",
            dst_port=[22, 3389, 5900][index % 3],
            app=["ssh", "ms-rdp", "vnc"][index % 3],
            action="deny",
            bytes=85 + rng.randint(0, 100),
            packets=1 + rng.randint(0, 2),
        )
    elif scenario == "uncommon_admin_service":
        row.update(
            dst_port=7103 + (index * 59) % 1700,
            app="unknown-tcp",
            action="allow",
            bytes=900 + rng.randint(0, 3500),
            packets=6 + rng.randint(0, 14),
        )
    elif scenario == "unauthorized_tunnel_use":
        row.update(
            protocol="udp" if index % 2 else "tcp",
            app="bittorrent",
            dst_port=6900 + index % 17,
            action="deny" if index % 5 == 0 else "allow",
            bytes=9000 + rng.randint(0, 34_000),
            packets=55 + rng.randint(0, 130),
        )
    elif scenario == "periodic_dns_callback":
        row.update(
            src_ip=f"10.186.0.{40 + index % 6}",
            dst_ip=f"203.0.113.{160 + index % 9}",
            protocol="udp",
            app="dns",
            dst_port=53,
            bytes=170 + rng.randint(0, 180),
            packets=2,
        )
    elif scenario == "incremental_archive_upload":
        row.update(
            src_ip=f"10.187.0.{50 + index % 6}",
            dst_ip=f"192.0.2.{140 + index % 10}",
            protocol="udp" if index % 4 == 0 else "tcp",
            app="quic" if index % 4 == 0 else "ssl",
            dst_port=8443 if index % 3 == 0 else 443,
            bytes=3_400_000 + rng.randint(0, 3_100_000),
            packets=3300 + rng.randint(0, 3000),
        )
    elif scenario == "distributed_remote_login_abuse":
        row.update(
            src_ip=f"198.51.100.{30 + index}",
            dst_ip=f"10.188.0.{20 + index % 4}",
            dst_port=22 if index % 2 else 3389,
            app="ssh" if index % 2 else "ms-rdp",
            action="deny",
            bytes=55 + rng.randint(0, 60),
            packets=1,
        )
    elif scenario == "application_exhaustion_wave":
        row.update(
            src_ip=f"203.0.113.{170 + index % 50}",
            dst_ip="10.189.0.15",
            dst_port=8080,
            app="web-browsing",
            action="deny",
            bytes=45 + rng.randint(0, 55),
            packets=1,
        )
    elif scenario == "malformed_router_fallback":
        row.update(
            timestamp="" if index % 4 == 0 else row["timestamp"],
            src_ip="" if index % 6 == 0 else row["src_ip"],
            dst_ip="" if index % 8 == 0 else row["dst_ip"],
            dst_port="" if index % 3 == 0 else 0,
            app="unknown",
            action="" if index % 2 else "allow",
            bytes=0,
            packets=0,
        )
    elif scenario == "unresolved_high_port_service":
        row.update(
            app="unknown-tcp",
            action="allow",
            dst_port=5100 + (index * 89) % 3300,
            bytes=1200 + rng.randint(0, 8500),
            packets=8 + rng.randint(0, 18),
        )
    elif scenario == "ambiguous_reset_sessions":
        row.update(
            app="incomplete",
            action="reset" if index % 2 == 0 else "allow",
            dst_port=[80, 443, 8080, 8443][index % 4],
            bytes=220 + rng.randint(0, 1400),
            packets=2 + rng.randint(0, 8),
        )
    return row


def _to_record(row: dict[str, Any], index: int) -> BenchmarkRecord:
    return BenchmarkRecord(
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
            "dst_port": (
                int(row["dst_port"])
                if row.get("dst_port") not in ("", None)
                else None
            ),
            "protocol": row.get("protocol"),
            "action": row.get("action") or None,
            "app": row.get("app"),
            "bytes": (
                int(row["bytes"]) if row.get("bytes") not in ("", None) else None
            ),
            "packets": (
                int(row["packets"])
                if row.get("packets") not in ("", None)
                else None
            ),
        },
        label=str(row["label"]),
        attack_type=str(row["attack_type"]),
    )


def build_fresh_blind_holdout(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    csv_path: Path = DEFAULT_CSV,
    seed: int = DEFAULT_SEED,
    row_limit: int = PREFERRED_ROWS,
    dry_run: bool = False,
) -> dict[str, Any]:
    if row_limit < MINIMUM_ROWS:
        raise ValueError(
            f"Fresh blind holdout requires at least {MINIMUM_ROWS} rows."
        )
    if row_limit > PREFERRED_ROWS:
        raise ValueError(
            f"Fresh blind holdout currently supports at most {PREFERRED_ROWS} rows."
        )
    rng = random.Random(seed)
    rows = []
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
    rng.shuffle(rows)
    rows = rows[:row_limit]
    exact_counts = Counter(_fingerprint(row) for row in rows)
    near_counts = Counter(_fingerprint(row, near=True) for row in rows)
    previous_exact, previous_near, snapshots_checked = (
        _load_previous_fingerprints(
            output_dir,
            excluded_input_name=csv_path.name,
        )
    )
    exact_overlap = sum(
        1 for row in rows if _fingerprint(row) in previous_exact
    )
    near_overlap = sum(
        1 for row in rows if _fingerprint(row, near=True) in previous_near
    )
    snapshot = None
    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        snapshot = write_benchmark_snapshot(
            [_to_record(row, index) for index, row in enumerate(rows)],
            input_name=csv_path.name,
            mapping_summary={
                "generator": "atdr.scripts.build_fresh_blind_holdout",
                "seed": seed,
                "mapping_errors": [],
                "blind_validation_only": True,
            },
            output_dir=output_dir,
            sample_strategy="fresh_blind_seeded",
            requested_limit=row_limit,
        )
    return {
        "ok": exact_overlap == 0,
        "status": "ready" if exact_overlap == 0 else "overlap_detected",
        "dry_run": dry_run,
        "version": "v2.0",
        "seed": seed,
        "row_count": len(rows),
        "minimum_rows_met": len(rows) >= MINIMUM_ROWS,
        "preferred_rows_met": len(rows) >= PREFERRED_ROWS,
        "source_count": len({str(row["source_name"]) for row in rows}),
        "scenario_count": len({str(row["scenario"]) for row in rows}),
        "label_distribution": dict(
            sorted(Counter(str(row["label"]) for row in rows).items())
        ),
        "source_distribution": dict(
            sorted(Counter(str(row["source_name"]) for row in rows).items())
        ),
        "scenario_distribution": dict(
            sorted(Counter(str(row["scenario"]) for row in rows).items())
        ),
        "duplicate_summary": {
            "exact_duplicate_rows": sum(
                count - 1 for count in exact_counts.values() if count > 1
            ),
            "near_duplicate_rows": sum(
                count - 1 for count in near_counts.values() if count > 1
            ),
            "near_duplicate_groups": sum(
                1 for count in near_counts.values() if count > 1
            ),
        },
        "previous_holdout_overlap": {
            "snapshots_checked": snapshots_checked,
            "exact_overlap_rows": exact_overlap,
            "near_overlap_rows": near_overlap,
            "exact_overlap_passed": exact_overlap == 0,
        },
        "csv_path": None if dry_run else str(csv_path),
        "snapshot_path": (
            None if snapshot is None else str(snapshot["snapshot_path"])
        ),
        "snapshot_id": None if snapshot is None else snapshot["snapshot_id"],
        "blind_validation_only": True,
        "threshold_tuning_allowed": False,
        "synthetic_only": True,
        "real_attacks_executed": False,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the safe v2.0 fresh blind holdout."
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--output-csv", default=str(DEFAULT_CSV))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--rows", type=int, default=PREFERRED_ROWS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = build_fresh_blind_holdout(
        output_dir=Path(args.output_dir),
        csv_path=Path(args.output_csv),
        seed=args.seed,
        row_limit=args.rows,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
