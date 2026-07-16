from __future__ import annotations

import csv
import hashlib
import json
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base
from atdr.app.db.models import LogSource, NormalizedLog, RawLog
from atdr.app.detection import v398_independent_holdout_validation as v398
from atdr.app.detection.v331_noise_reduction import _classes


V399_VERSION = "v3.99"
V399_LATEST = "v3_99_validation_latest.json"
V399_SPLITS = (
    "source_holdout",
    "temporal_holdout",
    "random_seed_7",
    "random_seed_17",
    "random_seed_42",
)
V399_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
INTERNAL_FREEZE_SPLIT = "random_seed_42"
PRIMARY_CANDIDATE = "v362_repaired_queue_extra_trees_sigmoid"
DEFAULT_ROWS_PER_SOURCE = 240
MIN_ACCEPTED_ROWS = 300
MIN_SOURCE_COUNT = 3
MIN_COLLECTION_WINDOWS = 4


SOURCE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "source_name": "v399-campus-router-normal",
        "source_type": "router",
        "parser_profile": "generic_syslog",
        "category": "normal_workstation_router_traffic",
        "scenario_cycle": (
            "normal_dns",
            "normal_dns",
            "normal_dns",
            "normal_web",
            "normal_web",
            "normal_quic",
            "normal_quic",
            "software_update",
            "software_update",
            "incomplete_retry",
            "partial_router",
            "dns_beacon",
        ),
    },
    {
        "source_name": "v399-edge-firewall-probing",
        "source_type": "firewall",
        "parser_profile": "palo_alto",
        "category": "firewall_scan_and_probing_traffic",
        "scenario_cycle": (
            "normal_web",
            "incomplete_retry",
            "port_scan",
            "port_scan",
            "port_scan",
            "ssh_probe",
            "ssh_probe",
            "service_flood",
            "service_flood",
            "unknown_service",
            "c2_beacon",
            "c2_beacon",
        ),
    },
    {
        "source_name": "v399-mixed-workstation",
        "source_type": "sample",
        "parser_profile": "generic_syslog",
        "category": "mixed_suspicious_and_malicious_like_traffic",
        "scenario_cycle": (
            "normal_web",
            "normal_web",
            "normal_quic",
            "software_update",
            "policy_tunnel",
            "policy_tunnel",
            "unknown_service",
            "partial_router",
            "c2_beacon",
            "c2_beacon",
            "gradual_exfiltration",
            "gradual_exfiltration",
        ),
    },
)


SCENARIO_EXPECTATIONS: dict[str, dict[str, str]] = {
    "normal_dns": {"label": "benign", "attack_type": "normal"},
    "normal_web": {"label": "benign", "attack_type": "normal"},
    "normal_quic": {"label": "benign", "attack_type": "normal"},
    "software_update": {"label": "benign", "attack_type": "normal"},
    "incomplete_retry": {"label": "benign_unusual", "attack_type": "normal"},
    "partial_router": {"label": "needs_context", "attack_type": "unknown"},
    "port_scan": {"label": "suspicious", "attack_type": "port_scan"},
    "ssh_probe": {"label": "suspicious", "attack_type": "brute_force"},
    "policy_tunnel": {"label": "suspicious", "attack_type": "policy_violation"},
    "unknown_service": {"label": "needs_context", "attack_type": "unknown_anomaly"},
    "dns_beacon": {"label": "malicious", "attack_type": "malware_c2"},
    "c2_beacon": {"label": "malicious", "attack_type": "malware_c2"},
    "service_flood": {"label": "malicious", "attack_type": "dos_ddos"},
    "gradual_exfiltration": {"label": "malicious", "attack_type": "data_exfiltration_suspicion"},
}


EVIDENCE_CSV_FIELDS = (
    "evidence_id",
    "source_name",
    "source_type",
    "parser_profile",
    "collection_window",
    "timestamp",
    "scenario",
    "category",
    "expected_label",
    "expected_attack_type",
    "label_provenance",
    "evidence_kind",
    "human_reviewed",
    "import_ready",
    "independence_status",
    "quarantine_reasons",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "app",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "elapsed_time",
    "src_zone",
    "dst_zone",
    "app_risk",
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _base_time(internal_dataset: dict[str, Any]) -> datetime:
    timestamps = [_utc(row.get("timestamp")) for row in internal_dataset.get("rows") or []]
    available = [value for value in timestamps if value is not None]
    anchor = max(available, default=datetime(2026, 1, 1, tzinfo=timezone.utc))
    return (anchor + timedelta(days=30)).replace(hour=8, minute=0, second=0, microsecond=0)


def _directional_addresses(source_number: int, row_number: int, scenario: str) -> tuple[str, str, str, str]:
    internal = f"10.{40 + source_number}.{1 + (row_number // 220) % 20}.{10 + row_number % 220}"
    internal_dst = f"10.{70 + source_number}.{1 + (row_number // 210) % 20}.{20 + (row_number * 7) % 210}"
    external_a = f"192.0.2.{10 + (row_number * 11 + source_number * 17) % 230}"
    external_b = f"198.51.100.{10 + (row_number * 13 + source_number * 19) % 230}"
    inbound = scenario in {"port_scan", "ssh_probe", "service_flood"}
    internal_only = scenario in {"partial_router"}
    if inbound:
        return external_b, internal_dst, "outside", "inside"
    if internal_only:
        return internal, internal_dst, "inside", "inside"
    return internal, external_a, "inside", "outside"


def _scenario_values(
    *,
    scenario: str,
    source_number: int,
    row_number: int,
    scenario_number: int,
    rng: random.Random,
) -> dict[str, Any]:
    src_ip, dst_ip, src_zone, dst_zone = _directional_addresses(source_number, row_number, scenario)
    values: dict[str, Any] = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 20000 + ((row_number * 97) + source_number * 701) % 44000,
        "dst_port": 443,
        "protocol": "tcp",
        "action": "allow",
        "app": "ssl",
        "bytes": 2500 + rng.randint(0, 5000),
        "packets": 15 + rng.randint(0, 25),
        "elapsed_time": 1 + rng.randint(0, 20),
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "app_risk": 1,
    }
    if scenario == "normal_dns":
        values.update(protocol="udp", app="dns", dst_port=53, bytes=600 + rng.randint(0, 1000), packets=3 + rng.randint(0, 5))
    elif scenario == "normal_web":
        values.update(app="web-browsing" if scenario_number % 3 == 0 else "ssl", dst_port=443, app_risk=1)
    elif scenario == "normal_quic":
        values.update(protocol="udp", app="quic-base", dst_port=443, bytes=1800 + rng.randint(0, 6000), app_risk=1)
    elif scenario == "software_update":
        values.update(app="ssl", dst_port=443, bytes=150_000 + rng.randint(0, 900_000), packets=180 + rng.randint(0, 500))
    elif scenario == "incomplete_retry":
        values.update(app="incomplete", dst_port=80 if scenario_number % 2 else 443, bytes=180 + rng.randint(0, 700), packets=2 + rng.randint(0, 5), app_risk=2)
    elif scenario == "partial_router":
        values.update(app="unknown", dst_port=0 if scenario_number % 2 else None, bytes=0, packets=0, app_risk=2)
        if scenario_number % 5 == 0:
            values["action"] = "unknown"
    elif scenario == "port_scan":
        values.update(
            src_ip=f"198.51.100.{80 + (scenario_number // 20) % 80}",
            dst_ip=f"10.{70 + source_number}.{1 + scenario_number // 40}.{20 + scenario_number % 40}",
            dst_port=1000 + (scenario_number * 137) % 8000,
            app="unknown-tcp",
            action="deny" if scenario_number % 5 else "allow",
            bytes=70 + rng.randint(0, 100),
            packets=1 + scenario_number % 2,
            app_risk=4,
        )
    elif scenario == "ssh_probe":
        values.update(
            src_ip=f"203.0.113.{40 + (scenario_number // 8) % 120}",
            dst_ip=f"10.{70 + source_number}.5.{20 + scenario_number % 8}",
            dst_port=22 if scenario_number % 3 else 3389,
            app="ssh" if scenario_number % 3 else "ms-rdp",
            action="deny",
            bytes=80 + rng.randint(0, 100),
            packets=1 + scenario_number % 2,
            app_risk=4,
        )
    elif scenario == "policy_tunnel":
        values.update(protocol="udp" if scenario_number % 2 else "tcp", app="bittorrent", dst_port=6881 + scenario_number % 12, app_risk=4)
    elif scenario == "unknown_service":
        values.update(app="unknown-udp" if scenario_number % 2 else "unknown-tcp", dst_port=5000 + (scenario_number * 71) % 3500, app_risk=3)
    elif scenario in {"dns_beacon", "c2_beacon"}:
        if scenario == "dns_beacon":
            values.update(protocol="udp", app="dns", dst_port=53, bytes=150 + rng.randint(0, 180), packets=2, app_risk=5)
        else:
            values.update(app="ssl", dst_port=443, bytes=220 + rng.randint(0, 260), packets=3 + scenario_number % 3, app_risk=5)
        values["src_ip"] = f"10.{40 + source_number}.9.{50 + scenario_number % 5}"
        values["dst_ip"] = f"192.0.2.{170 + scenario_number % 7}"
    elif scenario == "service_flood":
        values.update(
            src_ip=f"198.51.100.{120 + scenario_number % 100}",
            dst_ip=f"10.{70 + source_number}.8.10",
            dst_port=8080,
            app="web-browsing",
            action="deny",
            bytes=40 + rng.randint(0, 50),
            packets=1,
            app_risk=5,
        )
    elif scenario == "gradual_exfiltration":
        values.update(
            app="ssl" if scenario_number % 3 else "quic-base",
            protocol="udp" if scenario_number % 3 == 0 else "tcp",
            dst_port=443 if scenario_number % 2 else 8443,
            bytes=3_200_000 + rng.randint(0, 2_800_000),
            packets=3500 + rng.randint(0, 2500),
            app_risk=5,
        )
    byte_count = int(values.get("bytes") or 0)
    values["bytes_sent"] = int(byte_count * 0.62)
    values["bytes_received"] = byte_count - values["bytes_sent"]
    return values


def build_evidence_records(
    *,
    base_time: datetime,
    seed: int = 399,
    rows_per_source: int = DEFAULT_ROWS_PER_SOURCE,
) -> list[dict[str, Any]]:
    if rows_per_source < 16:
        raise ValueError("v3.99 requires at least 16 rows per source so all collection windows are represented.")
    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    for source_number, source in enumerate(SOURCE_SPECS, start=1):
        scenario_counts: Counter[str] = Counter()
        cycle = tuple(source["scenario_cycle"])
        for source_row in range(rows_per_source):
            collection_window = (source_row % MIN_COLLECTION_WINDOWS) + 1
            scenario = cycle[(source_row // MIN_COLLECTION_WINDOWS) % len(cycle)]
            scenario_number = scenario_counts[scenario]
            scenario_counts[scenario] += 1
            timestamp = base_time + timedelta(
                days=(collection_window - 1) * 7,
                seconds=(source_row // MIN_COLLECTION_WINDOWS) * 47 + source_number * 5,
            )
            values = _scenario_values(
                scenario=scenario,
                source_number=source_number,
                row_number=len(records),
                scenario_number=scenario_number,
                rng=rng,
            )
            expectation = SCENARIO_EXPECTATIONS[scenario]
            evidence_id = f"v399-{source_number}-{source_row + 1:04d}"
            records.append(
                {
                    "evidence_id": evidence_id,
                    "source_name": source["source_name"],
                    "source_type": source["source_type"],
                    "parser_profile": source["parser_profile"],
                    "collection_window": f"window_{collection_window}",
                    "timestamp": timestamp,
                    "scenario": scenario,
                    "category": source["category"],
                    "expected_label": expectation["label"],
                    "expected_attack_type": expectation["attack_type"],
                    "label_provenance": "deterministic_synthetic_scenario_expectation",
                    "evidence_kind": "synthetic",
                    "human_reviewed": False,
                    "import_ready": False,
                    "independence_status": "pending_audit",
                    "quarantine_reasons": [],
                    **values,
                }
            )
    return records


def _raw_line_for_record(record: dict[str, Any]) -> str:
    public_fields = {
        key: value.isoformat() if isinstance(value, datetime) else value
        for key, value in record.items()
        if key
        not in {
            "expected_label",
            "expected_attack_type",
            "label_provenance",
            "human_reviewed",
            "import_ready",
            "independence_status",
            "quarantine_reasons",
        }
    }
    return json.dumps(public_fields, sort_keys=True, separators=(",", ":"), default=str)


def _external_feature_dataset(records: list[dict[str, Any]]) -> dict[str, Any]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine, tables=[LogSource.__table__, RawLog.__table__, NormalizedLog.__table__])
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)
    session = factory()
    try:
        sources: dict[str, LogSource] = {}
        for spec in SOURCE_SPECS:
            source = LogSource(
                name=str(spec["source_name"]),
                source_type=str(spec["source_type"]),
                parser_profile=str(spec["parser_profile"]),
                enabled=True,
            )
            session.add(source)
            sources[source.name] = source
        session.flush()

        logs: list[NormalizedLog] = []
        for record in records:
            source = sources[str(record["source_name"])]
            raw = RawLog(
                source_id=source.id,
                raw_line=_raw_line_for_record(record),
                syslog_timestamp=record["timestamp"],
                device_hostname=source.name,
            )
            log = NormalizedLog(
                raw_log=raw,
                generated_time=record["timestamp"],
                receive_time=record["timestamp"] + timedelta(milliseconds=50),
                log_type="TRAFFIC",
                subtype="end",
                serial=f"V399-{source.id}",
                src_ip=record["src_ip"],
                dst_ip=record["dst_ip"],
                src_port=record["src_port"],
                dst_port=record["dst_port"],
                protocol=record["protocol"],
                action=record["action"],
                app=record["app"],
                bytes=record["bytes"],
                bytes_sent=record["bytes_sent"],
                bytes_received=record["bytes_received"],
                packets=record["packets"],
                elapsed_time=record["elapsed_time"],
                src_zone=record["src_zone"],
                dst_zone=record["dst_zone"],
                app_risk=record["app_risk"],
                device_name=source.name,
                parsed_json={"synthetic_validation": True, "scenario": record["scenario"]},
            )
            session.add(raw)
            logs.append(log)
        session.commit()

        imports = v398._optional_imports()
        if imports is None:
            return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
        pd = imports[1]
        started = time.perf_counter()
        from atdr.app.ml.features import build_feature_rows

        base_frame = pd.DataFrame(build_feature_rows(session, logs))
        frame, feature_meta = v398._local_evidence_frame(base_frame, logs)
        used_columns = [*feature_meta["numeric_features"], *feature_meta["categorical_features"]]
        rows: list[dict[str, Any]] = []
        targets: list[str] = []
        for index, (record, log) in enumerate(zip(records, logs, strict=True)):
            target, reason = v398._safe_queue_target(str(record["expected_label"]), frame.iloc[index])
            targets.append(target)
            rows.append(
                {
                    "index": index,
                    "evidence_id": record["evidence_id"],
                    "log_id": int(log.id),
                    "original_label": record["expected_label"],
                    "safe_queue_target": target,
                    "original_queue_target": v398._original_queue_target(str(record["expected_label"])),
                    "reviewed": False,
                    "human_reviewed": False,
                    "label_source": record["label_provenance"],
                    "source_id": int(log.raw_log.source_id),
                    "source_name": record["source_name"],
                    "source_type": record["source_type"],
                    "parser_profile": record["parser_profile"],
                    "collection_window": record["collection_window"],
                    "timestamp": v398._timestamp(log),
                    "scenario": record["scenario"],
                    "category": record["category"],
                    "expected_attack_type": record["expected_attack_type"],
                    "app": str(log.app or "unknown"),
                    "action": str(log.action or "unknown"),
                    "dst_port": log.dst_port,
                    "exact_fingerprint": v398._raw_fingerprint(log),
                    "near_fingerprint": v398._near_fingerprint(log),
                    "feature_fingerprint": v398._feature_fingerprint(frame, index, used_columns),
                    "target_reason": reason,
                }
            )
        return {
            "ok": True,
            "imports": imports,
            "records": records,
            "logs": logs,
            "frame": frame,
            "rows": rows,
            "targets": targets,
            "original_labels": [str(record["expected_label"]) for record in records],
            "feature_meta": feature_meta,
            "feature_generation_seconds": round(time.perf_counter() - started, 4),
            "_session": session,
            "_engine": engine,
        }
    except Exception:
        session.close()
        engine.dispose()
        raise


def _close_external_dataset(dataset: dict[str, Any]) -> None:
    session = dataset.pop("_session", None)
    engine = dataset.pop("_engine", None)
    if session is not None:
        session.close()
    if engine is not None:
        engine.dispose()


def audit_and_quarantine_independence(
    internal_dataset: dict[str, Any],
    external_dataset: dict[str, Any],
) -> dict[str, Any]:
    fingerprint_fields = ("exact_fingerprint", "near_fingerprint", "feature_fingerprint")
    internal_tokens = {
        field: {str(row[field]) for row in internal_dataset["rows"]}
        for field in fingerprint_fields
    }
    overlap_before: Counter[str] = Counter()
    quarantined: list[int] = []
    accepted: list[int] = []
    reasons_by_index: dict[int, list[str]] = {}
    seen_external_exact: set[str] = set()
    for position, row in enumerate(external_dataset["rows"]):
        reasons: list[str] = []
        for field in fingerprint_fields:
            if str(row[field]) in internal_tokens[field]:
                reason = f"internal_{field}_overlap"
                reasons.append(reason)
                overlap_before[field] += 1
        exact = str(row["exact_fingerprint"])
        if exact in seen_external_exact:
            reasons.append("duplicate_external_exact_fingerprint")
        seen_external_exact.add(exact)
        if reasons:
            quarantined.append(position)
            reasons_by_index[position] = reasons
        else:
            accepted.append(position)

    for position, record in enumerate(external_dataset["records"]):
        reasons = reasons_by_index.get(position, [])
        record["independence_status"] = "quarantined" if reasons else "accepted"
        record["quarantine_reasons"] = list(reasons)

    accepted_rows = [external_dataset["rows"][index] for index in accepted]
    group_summary = v398.assign_leakage_groups(accepted_rows)
    accepted_sources = {str(row["source_name"]) for row in accepted_rows}
    accepted_windows = {str(row["collection_window"]) for row in accepted_rows}
    remaining_overlap = {
        field: sum(1 for row in accepted_rows if str(row[field]) in internal_tokens[field])
        for field in fingerprint_fields
    }
    return {
        "passed": (
            len(accepted) >= MIN_ACCEPTED_ROWS
            and len(accepted_sources) >= MIN_SOURCE_COUNT
            and len(accepted_windows) >= MIN_COLLECTION_WINDOWS
            and all(value == 0 for value in remaining_overlap.values())
        ),
        "attempted_rows": len(external_dataset["rows"]),
        "accepted_rows": len(accepted),
        "quarantined_rows": len(quarantined),
        "accepted_indices": accepted,
        "quarantined_indices": quarantined,
        "quarantine_reason_counts": dict(sorted(Counter(reason for reasons in reasons_by_index.values() for reason in reasons).items())),
        "internal_overlap_before_quarantine": dict(sorted(overlap_before.items())),
        "internal_overlap_after_quarantine": remaining_overlap,
        "accepted_source_count": len(accepted_sources),
        "accepted_collection_window_count": len(accepted_windows),
        "accepted_sources": sorted(accepted_sources),
        "accepted_collection_windows": sorted(accepted_windows),
        "external_leakage_group_summary": group_summary,
        "minimum_rows_required": MIN_ACCEPTED_ROWS,
        "minimum_sources_required": MIN_SOURCE_COUNT,
        "minimum_collection_windows_required": MIN_COLLECTION_WINDOWS,
    }


def _internal_freeze(internal_dataset: dict[str, Any]) -> dict[str, Any]:
    partition = v398.build_frozen_partition(internal_dataset["rows"], split_mode=INTERNAL_FREEZE_SPLIT)
    leakage = v398.audit_partition_leakage(internal_dataset["rows"], partition)
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "The frozen internal fit/calibration/threshold partition failed leakage checks.",
            "partition": partition,
            "leakage_audit": leakage,
        }
    role_ids = {
        "fit": [internal_dataset["rows"][index]["log_id"] for index in partition["fit_idx"]],
        "calibration": [internal_dataset["rows"][index]["log_id"] for index in partition["calibration_idx"]],
        "threshold": [internal_dataset["rows"][index]["log_id"] for index in partition["threshold_idx"]],
        "reserved_internal_final": [internal_dataset["rows"][index]["log_id"] for index in partition["final_test_idx"]],
    }
    return {
        "ok": True,
        "status": "frozen",
        "split_mode": INTERNAL_FREEZE_SPLIT,
        "partition": partition,
        "leakage_audit": leakage,
        "partition_hash": _stable_hash(role_ids),
        "partition_sizes": {name: len(values) for name, values in role_ids.items()},
        "external_rows_used_for_fit": 0,
        "external_rows_used_for_calibration": 0,
        "external_rows_used_for_threshold_selection": 0,
        "internal_reserved_final_used_for_fit_or_tuning": False,
        "final_test_labels_used_for_fit_calibration_or_threshold": False,
    }


def _fit_anomaly_model(internal_dataset: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder

    numeric = internal_dataset["feature_meta"]["numeric_features"]
    categorical = internal_dataset["feature_meta"]["categorical_features"]
    preprocess = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), numeric),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical,
            ),
        ]
    )
    model = Pipeline(
        steps=[
            ("preprocess", preprocess),
            ("model", IsolationForest(n_estimators=150, contamination="auto", random_state=399, n_jobs=-1)),
        ]
    )
    frame = internal_dataset["frame"]
    model.fit(frame.iloc[partition["fit_idx"]])
    calibration_raw = [-float(value) for value in model.decision_function(frame.iloc[partition["calibration_idx"]])]

    def percentile(values: Iterable[float]) -> list[float]:
        reference = sorted(calibration_raw)
        if not reference:
            return [0.5 for _ in values]
        return [sum(1 for item in reference if item <= value) / len(reference) for value in values]

    threshold_raw = [-float(value) for value in model.decision_function(frame.iloc[partition["threshold_idx"]])]
    threshold_scores = percentile(threshold_raw)
    threshold_selection = v398.select_threshold(
        [internal_dataset["targets"][index] for index in partition["threshold_idx"]],
        threshold_scores,
    )
    return {
        "model": model,
        "calibration_reference": calibration_raw,
        "threshold_scores": threshold_scores,
        "threshold_selection": threshold_selection,
        "score_external": lambda external_frame, indices: percentile(
            [-float(value) for value in model.decision_function(external_frame.iloc[indices])]
        ),
    }


def _fit_frozen_candidates(internal_dataset: dict[str, Any], freeze: dict[str, Any]) -> dict[str, Any]:
    partition = freeze["partition"]
    primary = v398._fit_supervised_candidate(internal_dataset, partition, model_type="extra_trees", calibrate=True)
    logistic = v398._fit_supervised_candidate(internal_dataset, partition, model_type="logistic_regression", calibrate=False)
    anomaly = _fit_anomaly_model(internal_dataset, partition)
    threshold_indices = partition["threshold_idx"]
    threshold_rule_scores = v398._rule_scores(internal_dataset["logs"], threshold_indices)
    threshold_hybrid_scores = [
        (0.55 * rule_score) + (0.20 * anomaly_score) + (0.20 * supervised_score)
        for rule_score, anomaly_score, supervised_score in zip(
            threshold_rule_scores,
            anomaly["threshold_scores"],
            primary["threshold_scores"],
            strict=True,
        )
    ]
    hybrid_threshold = v398.select_threshold(
        [internal_dataset["targets"][index] for index in threshold_indices],
        threshold_hybrid_scores,
    )
    fit_targets = [internal_dataset["targets"][index] for index in partition["fit_idx"]]
    majority = Counter(fit_targets).most_common(1)[0][0]
    return {
        "primary": primary,
        "logistic": logistic,
        "anomaly": anomaly,
        "hybrid_threshold": hybrid_threshold,
        "majority_class": majority,
        "thresholds_frozen_before_external_scoring": True,
        "external_labels_used_during_fit_calibration_threshold": False,
    }


def _grouped_random_indices(rows: list[dict[str, Any]], indices: list[int], *, seed: int) -> list[int]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index in indices:
        groups[str(rows[index]["leakage_group"])].append(index)
    ordered = sorted(groups)
    random.Random(seed).shuffle(ordered)
    desired = max(1, round(len(indices) * 0.75))
    selected: list[int] = []
    for group in ordered:
        if len(selected) >= desired:
            break
        selected.extend(groups[group])
    selected = sorted(selected)
    targets = {rows[index]["safe_queue_target"] for index in selected}
    if targets != set(v398.QUEUE_LABELS):
        return sorted(indices)
    return selected


def build_external_final_splits(external_dataset: dict[str, Any], independence: dict[str, Any]) -> dict[str, list[int]]:
    accepted = list(independence["accepted_indices"])
    rows = external_dataset["rows"]
    latest_window = max(str(rows[index]["collection_window"]) for index in accepted)
    return {
        "source_holdout": sorted(accepted),
        "temporal_holdout": sorted(index for index in accepted if str(rows[index]["collection_window"]) == latest_window),
        "random_seed_7": _grouped_random_indices(rows, accepted, seed=7),
        "random_seed_17": _grouped_random_indices(rows, accepted, seed=17),
        "random_seed_42": _grouped_random_indices(rows, accepted, seed=42),
    }


def _split_leakage_audit(
    internal_dataset: dict[str, Any],
    external_dataset: dict[str, Any],
    final_indices: list[int],
    *,
    split_mode: str,
) -> dict[str, Any]:
    internal_rows = internal_dataset["rows"]
    final_rows = [external_dataset["rows"][index] for index in final_indices]
    fingerprint_overlap = {
        field: len({str(row[field]) for row in internal_rows} & {str(row[field]) for row in final_rows})
        for field in ("exact_fingerprint", "near_fingerprint", "feature_fingerprint")
    }
    internal_sources = {str(row["source_name"]) for row in internal_rows}
    final_sources = {str(row["source_name"]) for row in final_rows}
    internal_times = [_utc(row.get("timestamp")) for row in internal_rows]
    final_times = [_utc(row.get("timestamp")) for row in final_rows]
    internal_available = [value for value in internal_times if value is not None]
    final_available = [value for value in final_times if value is not None]
    chronology_passed = bool(internal_available and final_available and min(final_available) > max(internal_available))
    source_disjoint = internal_sources.isdisjoint(final_sources)
    class_diversity = len({str(row["safe_queue_target"]) for row in final_rows}) == len(v398.QUEUE_LABELS)
    passed = (
        bool(final_rows)
        and all(value == 0 for value in fingerprint_overlap.values())
        and source_disjoint
        and chronology_passed
        and class_diversity
    )
    return {
        "passed": passed,
        "split_mode": split_mode,
        "final_rows": len(final_rows),
        "fingerprint_overlap": fingerprint_overlap,
        "source_disjoint_from_internal": source_disjoint,
        "internal_source_count": len(internal_sources),
        "final_source_count": len(final_sources),
        "chronology_passed": chronology_passed,
        "internal_time_end": max(internal_available).isoformat() if internal_available else None,
        "final_time_start": min(final_available).isoformat() if final_available else None,
        "final_time_end": max(final_available).isoformat() if final_available else None,
        "final_target_class_diversity_passed": class_diversity,
        "final_labels_used_for_fit_calibration_or_threshold": False,
        "external_fit_rows": 0,
        "external_calibration_rows": 0,
        "external_threshold_rows": 0,
    }


def _score_external(model: Any, frame: Any, indices: list[int]) -> list[float]:
    classes = _classes(model)
    if "needs_review" not in classes:
        return [0.0 for _ in indices]
    position = classes.index("needs_review")
    probabilities = model.predict_proba(frame.iloc[indices])
    return [float(row[position]) for row in probabilities]


def _source_breakdown(
    dataset: dict[str, Any],
    indices: list[int],
    predictions: list[str],
) -> dict[str, Any]:
    grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for index, prediction in zip(indices, predictions, strict=True):
        grouped[str(dataset["rows"][index]["source_name"])].append((index, prediction))
    result: dict[str, Any] = {}
    for source, items in sorted(grouped.items()):
        source_indices = [index for index, _prediction in items]
        source_predictions = [prediction for _index, prediction in items]
        truth = [dataset["targets"][index] for index in source_indices]
        metrics = v398._binary_metrics(truth, source_predictions)
        metrics.update(v398._diagnostic_original_recall(dataset["rows"], source_indices, source_predictions))
        result[source] = metrics
    return result


def _evaluate_external_split(
    internal_dataset: dict[str, Any],
    external_dataset: dict[str, Any],
    candidates: dict[str, Any],
    *,
    split_mode: str,
    final_indices: list[int],
) -> dict[str, Any]:
    leakage = _split_leakage_audit(internal_dataset, external_dataset, final_indices, split_mode=split_mode)
    if not leakage["passed"]:
        return {"split_mode": split_mode, "status": "failed_closed", "leakage_audit": leakage, "strategies": []}
    seed = 399 if split_mode in {"source_holdout", "temporal_holdout"} else int(split_mode.rsplit("_", 1)[-1])
    frame = external_dataset["frame"]
    primary_scores = _score_external(candidates["primary"]["model"], frame, final_indices)
    logistic_scores = _score_external(candidates["logistic"]["model"], frame, final_indices)
    anomaly_scores = candidates["anomaly"]["score_external"](frame, final_indices)
    rule_scores = v398._rule_scores(external_dataset["logs"], final_indices)
    hybrid_scores = [
        (0.55 * rule_score) + (0.20 * anomaly_score) + (0.20 * supervised_score)
        for rule_score, anomaly_score, supervised_score in zip(rule_scores, anomaly_scores, primary_scores, strict=True)
    ]
    partition = {"final_test_idx": final_indices}
    primary = v398._evaluate_scores(
        external_dataset,
        partition,
        name=PRIMARY_CANDIDATE,
        scores=primary_scores,
        threshold_selection=candidates["primary"]["threshold_selection"],
        seed=seed,
        details={
            "training_evidence": "existing_reviewed_internal_only",
            "final_evidence": "synthetic_scenario_expectations_only",
            "calibration_method": candidates["primary"]["calibration_method"],
            "decision_support_only": True,
        },
    )
    logistic = v398._evaluate_scores(
        external_dataset,
        partition,
        name="balanced_logistic_regression_baseline",
        scores=logistic_scores,
        threshold_selection=candidates["logistic"]["threshold_selection"],
        seed=seed + 1,
        details={"training_evidence": "existing_reviewed_internal_only"},
    )
    rules = v398._evaluate_scores(
        external_dataset,
        partition,
        name="deterministic_rules_baseline",
        scores=rule_scores,
        threshold_selection=v398._fixed_threshold(v398.RULE_QUEUE_THRESHOLD, policy="existing_minimum_rule_alert_score"),
        seed=seed + 2,
        details={"context_scope": "external_final_partition_only", "ml_anomaly_rule_excluded": True},
    )
    anomaly = v398._evaluate_scores(
        external_dataset,
        partition,
        name="isolation_forest_baseline",
        scores=anomaly_scores,
        threshold_selection=candidates["anomaly"]["threshold_selection"],
        seed=seed + 3,
        details={"model_artifact_written": False, "scaling": "internal_calibration_empirical_percentile"},
    )
    hybrid = v398._evaluate_scores(
        external_dataset,
        partition,
        name="hybrid_rule_anomaly_supervised_decision_support",
        scores=hybrid_scores,
        threshold_selection=candidates["hybrid_threshold"],
        seed=seed + 4,
        details={"weights": {"rule": 0.55, "anomaly": 0.20, "supervised_queue": 0.20, "asset_context": 0.05}},
    )
    majority_scores = [1.0 if candidates["majority_class"] == "needs_review" else 0.0 for _ in final_indices]
    majority = v398._evaluate_scores(
        external_dataset,
        partition,
        name="majority_class_baseline",
        scores=majority_scores,
        threshold_selection=v398._fixed_threshold(0.5, policy="internal_fit_partition_majority_only"),
        seed=seed + 5,
        details={"fit_majority_class": candidates["majority_class"]},
    )
    primary["source_breakdown"] = _source_breakdown(external_dataset, final_indices, primary["_predictions"])
    public = [v398._public_strategy(item) for item in (primary, logistic, rules, anomaly, hybrid, majority)]
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition": {
            "fit": "frozen_internal_reviewed_partition",
            "calibration": "frozen_internal_reviewed_partition",
            "threshold": "frozen_internal_reviewed_partition",
            "final_test": "accepted_v399_synthetic_evidence_only",
        },
        "partition_sizes": {
            "fit": len(candidates["internal_partition"]["fit_idx"]),
            "calibration": len(candidates["internal_partition"]["calibration_idx"]),
            "threshold": len(candidates["internal_partition"]["threshold_idx"]),
            "final_test": len(final_indices),
        },
        "final_target_distribution": dict(Counter(external_dataset["targets"][index] for index in final_indices)),
        "final_original_label_distribution": dict(Counter(external_dataset["original_labels"][index] for index in final_indices)),
        "leakage_audit": leakage,
        "strategies": public,
    }


def _readiness(split_results: list[dict[str, Any]], comparison: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    evaluated = [item for item in split_results if item.get("status") == "evaluated"]
    primary = comparison.get(PRIMARY_CANDIDATE) or {}
    ranges = primary.get("metric_ranges") or {}
    min_f1 = (ranges.get("queue_f1") or {}).get("min")
    max_fpr = (ranges.get("benign_like_false_positive_rate") or {}).get("max")
    min_recall = (ranges.get("queue_recall") or {}).get("min")
    min_suspicious = (ranges.get("suspicious_recall") or {}).get("min")
    min_malicious = (ranges.get("malicious_recall") or {}).get("min")
    calibration_passes = int(primary.get("calibration_passed_splits") or 0)
    checks = [
        {
            "name": "synthetic evidence pack has required sources windows and rows",
            "passed": bool(evidence.get("passed")),
            "value": {
                "rows": evidence.get("accepted_rows"),
                "sources": evidence.get("accepted_source_count"),
                "windows": evidence.get("accepted_collection_window_count"),
            },
        },
        {
            "name": "all required frozen final splits evaluated",
            "passed": len(evaluated) == len(V399_SPLITS),
            "value": f"{len(evaluated)}/{len(V399_SPLITS)}",
        },
        {
            "name": "all internal-to-final leakage audits pass",
            "passed": len(evaluated) == len(V399_SPLITS) and all(item["leakage_audit"]["passed"] for item in evaluated),
            "value": sum(1 for item in evaluated if item["leakage_audit"]["passed"]),
        },
        {
            "name": "final labels never used for fit calibration or threshold selection",
            "passed": all(not item["leakage_audit"]["final_labels_used_for_fit_calibration_or_threshold"] for item in evaluated),
            "value": False,
        },
        {"name": "primary queue F1 stable", "passed": min_f1 is not None and min_f1 >= 0.80, "value": min_f1},
        {"name": "primary benign-like FPR controlled", "passed": max_fpr is not None and max_fpr <= 0.15, "value": max_fpr},
        {"name": "primary queue recall stable", "passed": min_recall is not None and min_recall >= 0.80, "value": min_recall},
        {"name": "primary suspicious recall stable", "passed": min_suspicious is not None and min_suspicious >= 0.80, "value": min_suspicious},
        {"name": "primary malicious recall stable", "passed": min_malicious is not None and min_malicious >= 0.65, "value": min_malicious},
        {
            "name": "primary confidence calibration acceptable",
            "passed": calibration_passes == len(V399_SPLITS),
            "value": f"{calibration_passes}/{len(V399_SPLITS)}",
        },
        {
            "name": "provider-blinded or real-source independent evidence available",
            "passed": False,
            "value": "v3.99 evidence is safe deterministic synthetic data",
        },
    ]
    return {
        "decision": "candidate_only",
        "checks_passed": sum(1 for item in checks if item["passed"]),
        "checks_total": len(checks),
        "checks": checks,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "synthetic_independence_passed": bool(evidence.get("passed")),
        "external_independent_validation_passed": False,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "primary_candidate": primary,
    }


def _source_manifest(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record["source_name"])].append(record)
    sources: list[dict[str, Any]] = []
    for source_name, items in sorted(grouped.items()):
        timestamps = [_utc(item["timestamp"]) for item in items]
        available = [value for value in timestamps if value is not None]
        sources.append(
            {
                "source_identity": source_name,
                "source_type": items[0]["source_type"],
                "parser_profile": items[0]["parser_profile"],
                "collection_windows": sorted({str(item["collection_window"]) for item in items}),
                "collection_start": min(available).isoformat() if available else None,
                "collection_end": max(available).isoformat() if available else None,
                "provenance": "atdr_v399_seeded_synthetic_generator",
                "category": items[0]["category"],
                "scenario_distribution": dict(sorted(Counter(str(item["scenario"]) for item in items).items())),
                "expected_label_distribution": dict(sorted(Counter(str(item["expected_label"]) for item in items).items())),
                "expected_label_provenance": "deterministic_synthetic_scenario_expectation",
                "evidence_kind": "synthetic",
                "human_reviewed": False,
                "import_ready": False,
                "row_count": len(items),
                "accepted_rows": sum(1 for item in items if item["independence_status"] == "accepted"),
                "quarantined_rows": sum(1 for item in items if item["independence_status"] == "quarantined"),
            }
        )
    return sources


def _write_evidence_pack(
    records: list[dict[str, Any]],
    audit: dict[str, Any],
    *,
    output_dir: Path,
    stamp: str,
) -> dict[str, Any]:
    evidence_dir = output_dir / "v3_99_evidence" / stamp
    evidence_dir.mkdir(parents=True, exist_ok=True)
    csv_paths: list[str] = []
    for source in SOURCE_SPECS:
        source_name = str(source["source_name"])
        path = evidence_dir / f"{source_name}.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=EVIDENCE_CSV_FIELDS)
            writer.writeheader()
            for record in records:
                if record["source_name"] != source_name:
                    continue
                serialized = {field: record.get(field) for field in EVIDENCE_CSV_FIELDS}
                serialized["timestamp"] = _utc(record["timestamp"]).isoformat()
                serialized["quarantine_reasons"] = ";".join(record["quarantine_reasons"])
                writer.writerow(serialized)
        csv_paths.append(str(path))

    manifest = {
        "schema": "atdr_v399_independent_evidence_manifest_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "atdr.app.detection.v399_multisource_frozen_revalidation",
        "seeded_and_reproducible": True,
        "safe_synthetic_only": True,
        "provider_blinded": False,
        "real_source": False,
        "human_reviewed": False,
        "import_ready": False,
        "labels_are_scenario_expectations_only": True,
        "sources": _source_manifest(records),
        "duplicate_and_overlap_audit": {
            key: value
            for key, value in audit.items()
            if key not in {"accepted_indices", "quarantined_indices"}
        },
        "privacy": {
            "only_documentation_range_and_private_synthetic_addresses": True,
            "raw_private_logs_included": False,
            "secrets_included": False,
        },
    }
    manifest_path = evidence_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    return {"directory": str(evidence_dir), "manifest_path": str(manifest_path), "source_csv_paths": csv_paths, "manifest": manifest}


def _render_report(result: dict[str, Any]) -> str:
    readiness = result["readiness"]
    lines = [
        "# v3.99 Independent Multi-Source Evidence And Frozen Revalidation",
        "",
        "## Safety Boundary",
        "",
        "This is diagnostic decision-support evidence only. The generated corpus is deterministic synthetic evidence, not human-reviewed, provider-blinded, real-device, or production evidence. No model was activated, no artifact was written, no labels were imported, and no response action was created.",
        "",
        "## Evidence Pack",
        "",
        f"- Attempted rows: `{result['evidence_audit']['attempted_rows']}`",
        f"- Accepted rows: `{result['evidence_audit']['accepted_rows']}`",
        f"- Quarantined rows: `{result['evidence_audit']['quarantined_rows']}`",
        f"- Accepted sources: `{result['evidence_audit']['accepted_source_count']}`",
        f"- Collection windows: `{result['evidence_audit']['accepted_collection_window_count']}`",
        f"- Internal overlap after quarantine: `{result['evidence_audit']['internal_overlap_after_quarantine']}`",
        "",
        "## Frozen Protocol",
        "",
        f"- Internal freeze split: `{result['frozen_protocol']['split_mode']}`",
        f"- Internal partition hash: `{result['frozen_protocol']['partition_hash']}`",
        f"- Partition sizes: `{result['frozen_protocol']['partition_sizes']}`",
        "- External rows used for fitting/calibration/threshold selection: `0/0/0`",
        "- Final labels used before scoring: `false`",
        "",
        "## Split Results",
        "",
        "| Split | Status | Rows | Queue precision | Queue recall | Queue F1 | Benign FPR | Suspicious recall | Malicious recall | Brier | ECE |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for split in result["split_results"]:
        primary = next((item for item in split.get("strategies") or [] if item.get("name") == PRIMARY_CANDIDATE), None)
        metrics = (primary or {}).get("metrics") or {}
        calibration = (primary or {}).get("calibration") or {}
        lines.append(
            "| {mode} | {status} | {rows} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {brier} | {ece} |".format(
                mode=split["split_mode"],
                status=split["status"],
                rows=(split.get("partition_sizes") or {}).get("final_test", 0),
                precision=metrics.get("queue_precision", "-"),
                recall=metrics.get("queue_recall", "-"),
                f1=metrics.get("queue_f1", "-"),
                fpr=metrics.get("benign_like_false_positive_rate", "-"),
                suspicious=metrics.get("suspicious_recall", "-"),
                malicious=metrics.get("malicious_recall", "-"),
                brier=calibration.get("brier_score", "-"),
                ece=calibration.get("expected_calibration_error", "-"),
            )
        )
    lines.extend(
        [
            "",
            "## Readiness",
            "",
            f"- Decision: `{readiness['decision']}`",
            f"- Checks passed: `{readiness['checks_passed']}/{readiness['checks_total']}`",
            f"- Synthetic independence passed: `{readiness['synthetic_independence_passed']}`",
            f"- External real/provider independence passed: `{readiness['external_independent_validation_passed']}`",
            f"- Blockers: `{readiness['blockers']}`",
            "- Production promoted: `false`",
            "- Model activated: `false`",
            "- Response automation allowed: `false`",
            "",
            "## Interpretation",
            "",
            "This phase closes the repository-side source/time evidence harness. Its synthetic results may reveal regressions and blind spots, but they cannot establish real-world accuracy. The next promotion discussion still requires independently reviewed real or provider-blinded multi-source evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_leakage_report(result: dict[str, Any]) -> str:
    audit = result["evidence_audit"]
    lines = [
        "# v3.99 Evidence Independence And Leakage Audit",
        "",
        f"- Passed: `{audit['passed']}`",
        f"- Attempted / accepted / quarantined: `{audit['attempted_rows']} / {audit['accepted_rows']} / {audit['quarantined_rows']}`",
        f"- Overlap before quarantine: `{audit['internal_overlap_before_quarantine']}`",
        f"- Overlap after quarantine: `{audit['internal_overlap_after_quarantine']}`",
        f"- Quarantine reasons: `{audit['quarantine_reason_counts']}`",
        f"- External leakage groups: `{audit['external_leakage_group_summary']}`",
        "",
        "## Per-Split Isolation",
        "",
    ]
    for split in result["split_results"]:
        leakage = split["leakage_audit"]
        lines.extend(
            [
                f"### {split['split_mode']}",
                "",
                f"- Passed: `{leakage['passed']}`",
                f"- Fingerprint overlap: `{leakage['fingerprint_overlap']}`",
                f"- Source-disjoint: `{leakage['source_disjoint_from_internal']}`",
                f"- Chronology passed: `{leakage['chronology_passed']}`",
                f"- Final class diversity passed: `{leakage['final_target_class_diversity_passed']}`",
                f"- Final labels used for tuning: `{leakage['final_labels_used_for_fit_calibration_or_threshold']}`",
                "",
            ]
        )
    lines.extend(
        [
            "No raw line, private path, IP address, API key, or model artifact is written to this report.",
            "",
        ]
    )
    return "\n".join(lines)


def _public_result(result: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(result, default=str))


def run_v399_multisource_frozen_revalidation(
    db: Session,
    *,
    output_dir: Path = V399_OUTPUT_DIR,
    rows_per_source: int = DEFAULT_ROWS_PER_SOURCE,
    seed: int = 399,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    before_counts = v398._database_counts(db)
    before_artifact = v398._artifact_state()
    internal_dataset = v398._build_dataset(db, min_samples=100)
    if not internal_dataset.get("ok"):
        return {
            "ok": False,
            "status": internal_dataset.get("status", "failed_closed"),
            "message": internal_dataset.get("message"),
            "readiness": {"decision": "candidate_only"},
        }
    internal_group_summary = v398.assign_leakage_groups(internal_dataset["rows"])
    freeze = _internal_freeze(internal_dataset)
    if not freeze.get("ok"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": freeze.get("message"),
            "frozen_protocol": freeze,
            "readiness": {"decision": "candidate_only"},
        }

    records = build_evidence_records(base_time=_base_time(internal_dataset), seed=seed, rows_per_source=rows_per_source)
    external_dataset = _external_feature_dataset(records)
    if not external_dataset.get("ok"):
        return {
            "ok": False,
            "status": external_dataset.get("status", "failed_closed"),
            "message": external_dataset.get("message"),
            "readiness": {"decision": "candidate_only"},
        }
    try:
        independence = audit_and_quarantine_independence(internal_dataset, external_dataset)
        if not independence["passed"]:
            return {
                "ok": False,
                "status": "failed_closed",
                "message": "Independent evidence did not meet overlap/source/window/row requirements after quarantine.",
                "evidence_audit": {key: value for key, value in independence.items() if not key.endswith("_indices")},
                "readiness": {"decision": "candidate_only"},
            }

        candidates = _fit_frozen_candidates(internal_dataset, freeze)
        candidates["internal_partition"] = freeze["partition"]
        final_splits = build_external_final_splits(external_dataset, independence)
        split_results = [
            _evaluate_external_split(
                internal_dataset,
                external_dataset,
                candidates,
                split_mode=split_mode,
                final_indices=final_splits[split_mode],
            )
            for split_mode in V399_SPLITS
        ]
        comparison = v398._strategy_comparison(split_results)
        readiness = _readiness(split_results, comparison, independence)
        after_counts = v398._database_counts(db)
        after_artifact = v398._artifact_state()
        stamp = _stamp()
        public_audit = {key: value for key, value in independence.items() if not key.endswith("_indices")}
        result: dict[str, Any] = {
            "ok": True,
            "status": "completed",
            "version": V399_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "runtime_seconds": round(time.perf_counter() - started, 4),
            "protocol": {
                "training_evidence": "existing latest reviewed labels only",
                "final_evidence": "separate deterministic synthetic scenario expectations only",
                "fit_calibration_threshold_final_roles_separate": True,
                "external_final_labels_used_for_tuning": False,
                "exact_near_feature_overlap_quarantined": True,
                "split_modes": list(V399_SPLITS),
                "threshold_policy_frozen_before_external_scoring": True,
                "synthetic_only": True,
                "provider_blinded_or_real_source": False,
            },
            "current_corpus_limitations": {
                "reviewed_latest_rows": internal_dataset["label_provenance"]["reviewed_latest_rows"],
                "reviewed_source_distribution": dict(Counter(str(row["source_name"]) for row in internal_dataset["rows"])),
                "reviewed_time_start": min(_utc(row["timestamp"]) for row in internal_dataset["rows"] if row["timestamp"]).isoformat(),
                "reviewed_time_end": max(_utc(row["timestamp"]) for row in internal_dataset["rows"] if row["timestamp"]).isoformat(),
                "v398_random_fpr_range": [0.0303, 0.3939],
                "v398_calibration": "weak",
            },
            "label_integrity": {
                "human_reviewed_external_rows": 0,
                "ai_generated_human_labels": 0,
                "labels_imported": 0,
                "external_label_provenance": "deterministic_synthetic_scenario_expectation",
                "import_ready": False,
            },
            "frozen_protocol": {
                key: value
                for key, value in freeze.items()
                if key not in {"partition", "leakage_audit"}
            }
            | {
                "internal_leakage_audit_passed": freeze["leakage_audit"]["passed"],
                "primary_threshold": candidates["primary"]["threshold_selection"],
                "logistic_threshold": candidates["logistic"]["threshold_selection"],
                "anomaly_threshold": candidates["anomaly"]["threshold_selection"],
                "hybrid_threshold": candidates["hybrid_threshold"],
            },
            "internal_leakage_group_summary": internal_group_summary,
            "evidence_audit": public_audit,
            "split_results": split_results,
            "strategy_comparison": comparison,
            "worst_primary_split": v398._worst_primary_split(split_results),
            "readiness": readiness,
            "safety": {
                "database_counts_before": before_counts,
                "database_counts_after": after_counts,
                "database_counts_unchanged": before_counts == after_counts,
                "active_artifact_before": before_artifact,
                "active_artifact_after": after_artifact,
                "active_artifact_unchanged": before_artifact == after_artifact,
                "session_new_objects": len(db.new),
                "session_dirty_objects": len(db.dirty),
                "session_deleted_objects": len(db.deleted),
                "labels_written": False,
                "model_activated": False,
                "model_artifact_written": False,
                "production_promoted": False,
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
                "configured_database_mutated": False,
                "raw_logs_written_to_reports": False,
            },
        }
        if write_output:
            output_dir.mkdir(parents=True, exist_ok=True)
            evidence_pack = _write_evidence_pack(records, independence, output_dir=output_dir, stamp=stamp)
            report_path = output_dir / f"v3_99_independent_multisource_validation_{stamp}.md"
            leakage_path = output_dir / f"v3_99_leakage_audit_{stamp}.md"
            latest_path = output_dir / V399_LATEST
            result["evidence_pack"] = {
                "directory": evidence_pack["directory"],
                "manifest_path": evidence_pack["manifest_path"],
                "source_csv_paths": evidence_pack["source_csv_paths"],
            }
            result["reports"] = {
                "validation_report": str(report_path),
                "leakage_report": str(leakage_path),
                "latest_json": str(latest_path),
            }
            public = _public_result(result)
            report_path.write_text(_render_report(public), encoding="utf-8")
            leakage_path.write_text(_render_leakage_report(public), encoding="utf-8")
            latest_path.write_text(json.dumps(public, indent=2, default=str), encoding="utf-8")
        return _public_result(result)
    finally:
        _close_external_dataset(external_dataset)
