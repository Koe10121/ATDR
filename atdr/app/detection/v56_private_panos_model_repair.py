from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.models import NormalizedLog
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v54_temporal_evidence as v54
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection.rules import (
    CorrelationSnapshot,
    DetectionContext,
    evaluate_rules,
)
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services.private_log_preflight_service import _configured_sqlite_path


V56_VERSION = "v5.6-private-panos-assisted-model-repair-v1"
V56_POLICY_VERSION = "v5.6-conservative-assisted-label-policy-v1"
V56_LATEST = "v5_6_private_panos_model_repair_latest.json"
V55_BASELINE = {
    "queue_f1": 0.4925,
    "benign_like_false_positive_rate": 0.0773,
    "suspicious_recall": 0.3824,
    "malicious_recall": 0.4143,
    "expected_calibration_error": 0.5405,
    "isolation_forest_false_positive_rate": 0.2773,
    "isolation_forest_threat_capture": 0.0818,
}
ROLE_NAMES = {
    0: "development_fit",
    1: "calibration",
    2: "threshold",
    3: "untouched_future_validation",
    4: "quarantine",
}
ROLE_KEYS = {
    "development_fit": "fit_idx",
    "calibration": "calibration_idx",
    "threshold": "threshold_idx",
}
ASSISTED_WEIGHTS = {
    "vendor_threat_assisted": 0.55,
    "rule_assisted": 0.45,
    "codex_assisted": 0.30,
    "weak_supervision": 0.20,
}
UNKNOWN_APPS = {
    "",
    "unknown",
    "unknown-tcp",
    "unknown-udp",
    "unknown-p2p",
    "incomplete",
    "not-applicable",
}
DENY_ACTION_TOKENS = ("deny", "drop", "reset", "block")
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 3389, 5900}
WEB_APPS = {
    "dns",
    "google-base",
    "ms-update",
    "ping",
    "quic-base",
    "ssl",
    "web-browsing",
}
V56_NUMERIC_FEATURES = [
    "src_port",
    "dst_port",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "elapsed_time",
    "app_risk",
    "repeat_count_effective",
    "parser_warning_count",
    "required_field_missing_count",
    "parser_confidence_score",
    "unknown_app_flag",
    "external_to_internal_flag",
    "internal_to_external_flag",
    "hour_of_day",
    "is_after_hours",
    "src_ip_5min_log_count",
    "src_ip_5min_deny_count",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "src_ip_5min_total_bytes",
    "src_ip_5min_avg_packets",
    "src_ip_5min_unknown_app_count",
    "src_ip_5min_high_risk_app_count",
    "deny_rate_5min",
    "v56_threat_record_flag",
    "v56_vendor_severity_score",
    "v56_rule_evidence_score",
    "v56_destination_repeat_count",
    "v56_schema_field_count",
    "v56_scan_pressure",
]
V56_CATEGORICAL_FEATURES = [
    "protocol",
    "action",
    "app",
    "src_zone",
    "dst_zone",
    "v56_log_type",
    "v56_subtype",
    "v56_schema_bucket",
]
V56_CANDIDATE_SPECS = (
    {
        "name": "calibrated_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "class_weight": "balanced",
        "weight_variant": "provenance_limited",
    },
    {
        "name": "calibrated_extra_trees_assisted_weighted",
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "class_weight": None,
        "weight_variant": "class_and_provenance",
    },
    {
        "name": "calibrated_hist_gradient_boosting",
        "model_type": "hist_gradient_boosting",
        "target_mode": "binary_soc_queue",
        "class_weight": None,
        "weight_variant": "class_and_provenance",
    },
    {
        "name": "calibrated_logistic_regression",
        "model_type": "logistic_regression",
        "target_mode": "binary_soc_queue",
        "class_weight": "balanced",
        "weight_variant": "provenance_limited",
    },
    {
        "name": "three_class_soc_queue_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "three_class_soc_queue",
        "class_weight": "balanced",
        "weight_variant": "class_and_provenance",
    },
    {
        "name": "hierarchical_two_stage_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "class_weight": "balanced",
        "weight_variant": "class_and_provenance",
    },
)
DEVELOPMENT_GATES = {
    "queue_f1_min": 0.80,
    "benign_like_false_positive_rate_max": 0.10,
    "suspicious_recall_min": 0.70,
    "malicious_recall_min": 0.70,
    "expected_calibration_error_max": 0.15,
    "max_confidence_accuracy_gap_max": 0.20,
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _magnitude_bucket(value: Any) -> int:
    numeric = abs(_number(value))
    return 0 if numeric < 1 else int(math.log10(numeric)) + 1


def _event_time(parsed: Any) -> datetime | None:
    normalized = parsed.normalized
    value = (
        normalized.get("generated_time")
        or normalized.get("receive_time")
        or normalized.get("high_res_timestamp")
        or parsed.syslog_timestamp
    )
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _minute_bucket(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.replace(second=0, microsecond=0).isoformat()


def _schema_bucket(log_type: str, field_count: int) -> str:
    if log_type == "TRAFFIC":
        return "traffic_complete" if field_count >= 47 else "traffic_limited"
    if log_type == "THREAT":
        return "threat_complete" if field_count >= 40 else "threat_limited"
    return "unrecognized"


def _direction_flags(src_zone: str, dst_zone: str) -> tuple[int, int]:
    source = _lower(src_zone)
    destination = _lower(dst_zone)
    outside = ("outside", "untrust", "internet", "wan")
    inside = ("inside", "trust", "lan", "wlan", "corp")
    external_to_internal = int(
        any(token in source for token in outside)
        and any(token in destination for token in inside)
    )
    internal_to_external = int(
        any(token in source for token in inside)
        and any(token in destination for token in outside)
    )
    return external_to_internal, internal_to_external


def _is_deny(action: str, subtype: str, session_end_reason: str) -> bool:
    values = (_lower(action), _lower(subtype), _lower(session_end_reason))
    return any(
        token in value
        for value in values
        for token in DENY_ACTION_TOKENS
    )


def _safe_token(namespace: str, value: Any) -> str:
    return hashlib.sha256(
        f"v56-disposable:{namespace}:{value or 'missing'}".encode("utf-8")
    ).hexdigest()


def _near_fingerprint(normalized: dict[str, Any], *, minute: str | None) -> str:
    return _stable_hash(
        {
            "minute_regime": minute,
            "log_type": _lower(normalized.get("log_type")),
            "subtype": _lower(normalized.get("subtype")),
            "app": _lower(normalized.get("app")),
            "action": _lower(normalized.get("action")),
            "protocol": _lower(normalized.get("protocol")),
            "src_port": normalized.get("src_port"),
            "dst_port": normalized.get("dst_port"),
            "src_zone": _lower(normalized.get("src_zone")),
            "dst_zone": _lower(normalized.get("dst_zone")),
            "app_risk": normalized.get("app_risk"),
            "bytes_bucket": _magnitude_bucket(normalized.get("bytes")),
            "packets_bucket": _magnitude_bucket(normalized.get("packets")),
        }
    )


def _create_disposable_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = FILE;
        CREATE TABLE db_hashes (
            exact_hash TEXT PRIMARY KEY,
            row_count INTEGER NOT NULL
        );
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            exact_hash TEXT NOT NULL,
            propagation_hash TEXT NOT NULL,
            event_time TEXT,
            minute_bucket TEXT,
            role_rank INTEGER NOT NULL DEFAULT 4,
            quarantine_reason TEXT,
            source_token TEXT NOT NULL,
            destination_token TEXT NOT NULL,
            log_type TEXT NOT NULL,
            subtype TEXT NOT NULL,
            app TEXT NOT NULL,
            action TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            src_zone TEXT NOT NULL,
            dst_zone TEXT NOT NULL,
            bytes INTEGER,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            packets INTEGER,
            elapsed_time INTEGER,
            app_risk INTEGER,
            repeat_count INTEGER,
            parser_error INTEGER NOT NULL,
            parser_warning_count INTEGER NOT NULL,
            required_missing_count INTEGER NOT NULL,
            field_count INTEGER NOT NULL,
            schema_bucket TEXT NOT NULL,
            threat_severity TEXT NOT NULL,
            app_characteristic TEXT NOT NULL,
            session_end_reason TEXT NOT NULL,
            deny_flag INTEGER NOT NULL,
            auth_deny_flag INTEGER NOT NULL,
            unknown_app_flag INTEGER NOT NULL,
            high_risk_app_flag INTEGER NOT NULL,
            external_to_internal_flag INTEGER NOT NULL,
            internal_to_external_flag INTEGER NOT NULL
        );
        """
    )


def _load_configured_hashes(
    connection: sqlite3.Connection,
    *,
    database_url: str | None,
) -> dict[str, Any]:
    path = _configured_sqlite_path(database_url)
    if path is None:
        return {
            "status": "not_compared_non_sqlite_or_memory_database",
            "configured_rows": None,
            "hash_rows_loaded": 0,
            "read_only": True,
            "path_returned": False,
        }
    if not path.exists():
        return {
            "status": "not_compared_database_missing",
            "configured_rows": 0,
            "hash_rows_loaded": 0,
            "read_only": True,
            "path_returned": False,
        }
    try:
        source = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        source.execute("PRAGMA query_only = ON")
        table = source.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='raw_logs'"
        ).fetchone()
        if table is None:
            source.close()
            return {
                "status": "not_compared_raw_logs_table_missing",
                "configured_rows": 0,
                "hash_rows_loaded": 0,
                "read_only": True,
                "path_returned": False,
            }
        configured_rows = int(
            source.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
        )
        cursor = source.execute(
            "SELECT raw_line_hash, COUNT(*) FROM raw_logs "
            "WHERE raw_line_hash IS NOT NULL GROUP BY raw_line_hash"
        )
        loaded = 0
        while True:
            batch = cursor.fetchmany(5000)
            if not batch:
                break
            connection.executemany(
                "INSERT OR REPLACE INTO db_hashes(exact_hash, row_count) "
                "VALUES (?, ?)",
                [(str(value), int(count)) for value, count in batch],
            )
            loaded += len(batch)
        source.close()
        connection.commit()
        return {
            "status": "loaded_read_only_fingerprint_index",
            "configured_rows": configured_rows,
            "hash_rows_loaded": loaded,
            "read_only": True,
            "path_returned": False,
        }
    except sqlite3.Error as exc:
        return {
            "status": "comparison_failed",
            "error_type": exc.__class__.__name__,
            "configured_rows": None,
            "hash_rows_loaded": 0,
            "read_only": True,
            "path_returned": False,
        }


def _event_record(raw_text: str) -> tuple[Any, ...]:
    parsed = parse_log_line(raw_text)
    normalized = parsed.normalized
    value = _event_time(parsed)
    minute = _minute_bucket(value)
    log_type = str(normalized.get("log_type") or "missing").upper()
    subtype = _lower(normalized.get("subtype")) or "missing"
    app = _lower(normalized.get("app")) or "unknown"
    action = _lower(normalized.get("action")) or "unknown"
    protocol = _lower(normalized.get("protocol")) or "unknown"
    src_zone = _lower(normalized.get("src_zone")) or "unknown"
    dst_zone = _lower(normalized.get("dst_zone")) or "unknown"
    session_end_reason = _lower(normalized.get("session_end_reason"))
    deny = int(_is_deny(action, subtype, session_end_reason))
    dst_port = normalized.get("dst_port")
    external_to_internal, internal_to_external = _direction_flags(
        src_zone,
        dst_zone,
    )
    warnings = parsed.parsed_json.get("parser_warnings") or []
    required = (
        normalized.get("generated_time"),
        normalized.get("src_ip"),
        normalized.get("dst_ip"),
        normalized.get("action"),
        normalized.get("app"),
    )
    missing = sum(
        1
        for item in required
        if item is None or (isinstance(item, str) and not item.strip())
    )
    field_count = _integer(parsed.parsed_json.get("field_count"))
    return (
        raw_line_fingerprint(raw_text),
        _stable_hash(
            {
                "source": _safe_token("source", normalized.get("src_ip")),
                "pattern": _near_fingerprint(normalized, minute=minute),
            }
        ),
        value.isoformat() if value else None,
        minute,
        4,
        "parser_error_or_missing_time" if parsed.error or value is None else None,
        _safe_token("source", normalized.get("src_ip")),
        _safe_token("destination", normalized.get("dst_ip")),
        log_type,
        subtype,
        app,
        action,
        protocol,
        normalized.get("src_port"),
        dst_port,
        src_zone,
        dst_zone,
        normalized.get("bytes"),
        normalized.get("bytes_sent"),
        normalized.get("bytes_received"),
        normalized.get("packets"),
        normalized.get("elapsed_time"),
        normalized.get("app_risk"),
        normalized.get("repeat_count"),
        int(bool(parsed.error)),
        len(warnings),
        missing,
        field_count,
        _schema_bucket(log_type, field_count),
        _lower(parsed.parsed_json.get("parsed_threat_severity")) or "none",
        str(normalized.get("app_characteristic") or ""),
        session_end_reason,
        deny,
        int(deny and dst_port in AUTH_PORTS),
        int(app in UNKNOWN_APPS),
        int(_integer(normalized.get("app_risk")) >= 4),
        external_to_internal,
        internal_to_external,
    )


EVENT_INSERT = """
INSERT INTO events(
    exact_hash, propagation_hash, event_time, minute_bucket, role_rank,
    quarantine_reason, source_token, destination_token, log_type, subtype,
    app, action, protocol, src_port, dst_port, src_zone, dst_zone, bytes,
    bytes_sent, bytes_received, packets, elapsed_time, app_risk, repeat_count,
    parser_error, parser_warning_count, required_missing_count, field_count,
    schema_bucket, threat_severity, app_characteristic, session_end_reason,
    deny_flag, auth_deny_flag, unknown_app_flag, high_risk_app_flag,
    external_to_internal_flag, internal_to_external_flag
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
"""


def stream_private_file_to_disposable_index(
    sample_path: Path,
    connection: sqlite3.Connection,
    *,
    database_url: str | None = None,
    chunk_size: int = 2000,
) -> dict[str, Any]:
    """Stream private evidence into a disposable derived-feature index."""

    if not sample_path.exists() or not sample_path.is_file():
        return {
            "ok": False,
            "status": "private_evidence_unavailable",
            "path_returned": False,
            "raw_evidence_returned": False,
        }
    _create_disposable_schema(connection)
    overlap_index = _load_configured_hashes(
        connection,
        database_url=database_url,
    )
    counters: dict[str, Counter[Any]] = {
        "log_type": Counter(),
        "app": Counter(),
        "action": Counter(),
        "dst_port": Counter(),
        "zone": Counter(),
        "schema": Counter(),
        "parser_warning_count": Counter(),
        "threat_severity": Counter(),
    }
    parser_errors = 0
    nonblank = 0
    blank = 0
    batch: list[tuple[Any, ...]] = []
    started = time.perf_counter()
    with sample_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline="",
    ) as stream:
        for line in stream:
            if not line.strip():
                blank += 1
                continue
            raw_text = line.rstrip("\r\n")
            record = _event_record(raw_text)
            nonblank += 1
            parser_errors += int(record[24])
            counters["log_type"][record[8]] += 1
            counters["app"][record[10]] += 1
            counters["action"][record[11]] += 1
            counters["dst_port"][record[14] if record[14] is not None else "missing"] += 1
            counters["zone"][f"{record[15]}->{record[16]}"] += 1
            counters["schema"][record[28]] += 1
            counters["parser_warning_count"][record[25]] += 1
            counters["threat_severity"][record[29]] += 1
            batch.append(record)
            if len(batch) >= max(100, int(chunk_size)):
                connection.executemany(EVENT_INSERT, batch)
                connection.commit()
                batch.clear()
    if batch:
        connection.executemany(EVENT_INSERT, batch)
        connection.commit()

    connection.executescript(
        """
        CREATE INDEX ix_v56_events_exact ON events(exact_hash);
        CREATE INDEX ix_v56_events_propagation ON events(propagation_hash);
        CREATE INDEX ix_v56_events_minute ON events(minute_bucket);
        CREATE INDEX ix_v56_events_source_minute
            ON events(source_token, minute_bucket);
        CREATE INDEX ix_v56_events_role ON events(role_rank);
        CREATE INDEX ix_v56_db_hashes ON db_hashes(exact_hash);
        UPDATE events
        SET role_rank = 4, quarantine_reason = 'configured_database_overlap'
        WHERE exact_hash IN (SELECT exact_hash FROM db_hashes);
        """
    )
    connection.commit()
    overlap_rows = int(
        connection.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE quarantine_reason='configured_database_overlap'"
        ).fetchone()[0]
    )
    unique_exact = int(
        connection.execute(
            "SELECT COUNT(DISTINCT exact_hash) FROM events"
        ).fetchone()[0]
    )
    unique_near = int(
        connection.execute(
            "SELECT COUNT(DISTINCT propagation_hash) FROM events"
        ).fetchone()[0]
    )
    time_range = connection.execute(
        "SELECT MIN(event_time), MAX(event_time) FROM events "
        "WHERE event_time IS NOT NULL"
    ).fetchone()
    return {
        "ok": nonblank > 0,
        "status": "complete_file_streamed" if nonblank else "empty_evidence",
        "rows_processed": nonblank,
        "blank_rows": blank,
        "parser_successes": nonblank - parser_errors,
        "parser_failures": parser_errors,
        "parser_success_rate": round((nonblank - parser_errors) / max(1, nonblank), 6),
        "time_range": {
            "earliest": time_range[0],
            "latest": time_range[1],
        },
        "top_log_types": _safe_top(counters["log_type"]),
        "top_applications": _safe_top(counters["app"]),
        "top_actions": _safe_top(counters["action"]),
        "top_destination_ports": _safe_top(counters["dst_port"]),
        "top_zone_directions": _safe_top(counters["zone"]),
        "schema_profiles": _safe_top(counters["schema"]),
        "parser_warning_distribution": _safe_top(
            counters["parser_warning_count"]
        ),
        "threat_severities": _safe_top(counters["threat_severity"]),
        "exact_duplicate_rows": max(0, nonblank - unique_exact),
        "near_duplicate_rows": max(0, nonblank - unique_near),
        "unique_exact_families": unique_exact,
        "unique_near_families": unique_near,
        "configured_database_overlap_rows": overlap_rows,
        "configured_database_overlap": overlap_index,
        "streaming": {
            "bounded_chunk_size": max(100, int(chunk_size)),
            "entire_file_loaded_in_memory": False,
            "disposable_sqlite_index_used": True,
            "elapsed_seconds": round(time.perf_counter() - started, 4),
        },
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "reusable_row_fingerprints_returned": False,
        "secrets_exposed": False,
    }


def _safe_top(counter: Counter[Any], *, limit: int = 15) -> list[dict[str, Any]]:
    return [
        {"value": str(value), "count": int(count)}
        for value, count in counter.most_common(limit)
    ]


def predeclare_chronological_roles(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Assign evidence roles before any assisted decision is calculated."""

    minutes = [
        str(row[0])
        for row in connection.execute(
            "SELECT DISTINCT minute_bucket FROM events "
            "WHERE minute_bucket IS NOT NULL "
            "AND quarantine_reason IS NULL ORDER BY minute_bucket"
        )
    ]
    if len(minutes) < 8:
        return {
            "ok": False,
            "status": "failed_closed_insufficient_chronological_windows",
            "distinct_time_windows": len(minutes),
            "labels_inspected": False,
        }
    fit_end = max(1, int(len(minutes) * 0.55))
    calibration_end = max(fit_end + 1, int(len(minutes) * 0.70))
    threshold_end = max(calibration_end + 1, int(len(minutes) * 0.82))
    threshold_end = min(threshold_end, len(minutes) - 1)
    role_minutes = {
        0: minutes[:fit_end],
        1: minutes[fit_end:calibration_end],
        2: minutes[calibration_end:threshold_end],
        3: minutes[threshold_end:],
    }
    for role_rank, values in role_minutes.items():
        connection.executemany(
            "UPDATE events SET role_rank=? "
            "WHERE minute_bucket=? AND quarantine_reason IS NULL",
            [(role_rank, value) for value in values],
        )

    # Any exact or tightly equivalent family that straddles a boundary is
    # moved wholly to its latest role. This prevents family leakage backward.
    connection.executescript(
        """
        DROP TABLE IF EXISTS exact_family_roles;
        CREATE TEMP TABLE exact_family_roles AS
        SELECT exact_hash, MAX(role_rank) AS role_rank
        FROM events
        GROUP BY exact_hash;
        CREATE INDEX ix_v56_exact_family_roles
            ON exact_family_roles(exact_hash);
        UPDATE events
        SET role_rank = (
            SELECT role_rank FROM exact_family_roles
            WHERE exact_family_roles.exact_hash = events.exact_hash
        );

        DROP TABLE IF EXISTS propagation_family_roles;
        CREATE TEMP TABLE propagation_family_roles AS
        SELECT propagation_hash, MAX(role_rank) AS role_rank
        FROM events
        GROUP BY propagation_hash;
        CREATE INDEX ix_v56_propagation_family_roles
            ON propagation_family_roles(propagation_hash);
        UPDATE events
        SET role_rank = (
            SELECT role_rank FROM propagation_family_roles
            WHERE propagation_family_roles.propagation_hash =
                events.propagation_hash
        );

        UPDATE events
        SET quarantine_reason = COALESCE(
            quarantine_reason,
            'family_contained_with_quarantine'
        )
        WHERE role_rank = 4;
        """
    )
    connection.commit()

    role_counts = {
        ROLE_NAMES[int(role)]: int(count)
        for role, count in connection.execute(
            "SELECT role_rank, COUNT(*) FROM events GROUP BY role_rank"
        )
    }
    group_counts = {
        ROLE_NAMES[int(role)]: int(count)
        for role, count in connection.execute(
            "SELECT role_rank, COUNT(DISTINCT propagation_hash) "
            "FROM events GROUP BY role_rank"
        )
    }
    exact_leakage = int(
        connection.execute(
            "SELECT COUNT(*) FROM ("
            "SELECT exact_hash FROM events GROUP BY exact_hash "
            "HAVING COUNT(DISTINCT role_rank) > 1)"
        ).fetchone()[0]
    )
    near_leakage = int(
        connection.execute(
            "SELECT COUNT(*) FROM ("
            "SELECT propagation_hash FROM events GROUP BY propagation_hash "
            "HAVING COUNT(DISTINCT role_rank) > 1)"
        ).fetchone()[0]
    )
    summaries: dict[str, Any] = {}
    for role_rank, name in ROLE_NAMES.items():
        time_range = connection.execute(
            "SELECT MIN(event_time), MAX(event_time), "
            "COUNT(DISTINCT minute_bucket) FROM events WHERE role_rank=?",
            (role_rank,),
        ).fetchone()
        summaries[name] = {
            "rows": role_counts.get(name, 0),
            "representative_families": group_counts.get(name, 0),
            "time_windows": int(time_range[2] or 0),
            "time_range": {
                "earliest": time_range[0],
                "latest": time_range[1],
            },
            "aggregate_fingerprint": _stable_hash(
                {
                    "role": name,
                    "rows": role_counts.get(name, 0),
                    "groups": group_counts.get(name, 0),
                    "earliest": time_range[0],
                    "latest": time_range[1],
                }
            ),
            "row_fingerprints_returned": False,
        }
    return {
        "ok": exact_leakage == 0 and near_leakage == 0,
        "status": "chronological_roles_predeclared",
        "policy": {
            "fit_share": 0.55,
            "calibration_share": 0.15,
            "threshold_share": 0.12,
            "future_validation_share": 0.18,
            "latest_windows_reserved": True,
            "labels_inspected_during_partitioning": False,
        },
        "distinct_time_windows": len(minutes),
        "roles": summaries,
        "exact_family_cross_role_count": exact_leakage,
        "near_family_cross_role_count": near_leakage,
        "duplicate_families_contained": exact_leakage == 0 and near_leakage == 0,
        "future_validation_labels_opened": False,
    }


def build_disposable_behavior_aggregates(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    connection.executescript(
        """
        DROP TABLE IF EXISTS source_minute_stats;
        CREATE TABLE source_minute_stats AS
        SELECT
            source_token,
            minute_bucket,
            role_rank,
            SUM(CASE WHEN repeat_count IS NULL OR repeat_count < 1
                THEN 1 ELSE MIN(repeat_count, 10000) END) AS event_count,
            SUM(deny_flag) AS deny_count,
            SUM(auth_deny_flag) AS auth_deny_count,
            COUNT(DISTINCT destination_token) AS unique_destinations,
            COUNT(DISTINCT dst_port) AS unique_ports,
            SUM(COALESCE(bytes, 0)) AS total_bytes,
            AVG(COALESCE(packets, 0)) AS average_packets,
            SUM(unknown_app_flag) AS unknown_app_count,
            SUM(high_risk_app_flag) AS high_risk_app_count
        FROM events
        WHERE role_rank < 4
        GROUP BY source_token, minute_bucket, role_rank;
        CREATE INDEX ix_v56_source_minute_stats
            ON source_minute_stats(source_token, minute_bucket, role_rank);

        DROP TABLE IF EXISTS destination_repeat_stats;
        CREATE TABLE destination_repeat_stats AS
        SELECT
            source_token,
            minute_bucket,
            role_rank,
            destination_token,
            dst_port,
            SUM(CASE WHEN repeat_count IS NULL OR repeat_count < 1
                THEN 1 ELSE MIN(repeat_count, 10000) END) AS repeat_count
        FROM events
        WHERE role_rank < 4
        GROUP BY source_token, minute_bucket, role_rank,
            destination_token, dst_port;
        CREATE INDEX ix_v56_destination_repeat_stats
            ON destination_repeat_stats(
                source_token, minute_bucket, role_rank,
                destination_token, dst_port
            );

        DROP TABLE IF EXISTS representative_groups;
        CREATE TABLE representative_groups AS
        SELECT
            (
                CAST(e.role_rank AS TEXT) || '|' ||
                COALESCE(e.minute_bucket, 'missing') || '|' ||
                e.log_type || '|' || e.subtype || '|' || e.app || '|' ||
                e.action || '|' || e.protocol || '|' ||
                COALESCE(CAST(e.src_port AS TEXT), 'missing') || '|' ||
                COALESCE(CAST(e.dst_port AS TEXT), 'missing') || '|' ||
                e.src_zone || '|' || e.dst_zone || '|' ||
                COALESCE(CAST(e.app_risk AS TEXT), 'missing') || '|' ||
                e.schema_bucket || '|' || e.threat_severity || '|' ||
                CAST(e.external_to_internal_flag AS TEXT) || '|' ||
                CAST(e.internal_to_external_flag AS TEXT) || '|' ||
                CASE
                    WHEN COALESCE(e.bytes, 0) < 1 THEN '0'
                    WHEN ABS(e.bytes) < 100 THEN '1'
                    WHEN ABS(e.bytes) < 1000 THEN '2'
                    WHEN ABS(e.bytes) < 10000 THEN '3'
                    WHEN ABS(e.bytes) < 100000 THEN '4'
                    WHEN ABS(e.bytes) < 1000000 THEN '5'
                    ELSE '6'
                END || '|' ||
                CASE
                    WHEN COALESCE(e.packets, 0) < 1 THEN '0'
                    WHEN ABS(e.packets) < 10 THEN '1'
                    WHEN ABS(e.packets) < 100 THEN '2'
                    WHEN ABS(e.packets) < 1000 THEN '3'
                    ELSE '4'
                END || '|' ||
                CASE
                    WHEN s.event_count < 5 THEN 'low'
                    WHEN s.event_count < 25 THEN 'medium'
                    WHEN s.event_count < 100 THEN 'high'
                    ELSE 'very_high'
                END || '|' ||
                CASE
                    WHEN s.unique_destinations < 3 THEN 'low'
                    WHEN s.unique_destinations < 8 THEN 'medium'
                    ELSE 'high'
                END || '|' ||
                CASE
                    WHEN s.unique_ports < 3 THEN 'low'
                    WHEN s.unique_ports < 10 THEN 'medium'
                    ELSE 'high'
                END || '|' ||
                CASE
                    WHEN s.deny_count = 0 THEN 'none'
                    WHEN s.deny_count < 5 THEN 'low'
                    ELSE 'high'
                END || '|' ||
                CASE
                    WHEN COALESCE(d.repeat_count, 0) < 3 THEN 'low'
                    WHEN d.repeat_count < 10 THEN 'medium'
                    ELSE 'high'
                END
            ) AS propagation_hash,
            e.role_rank AS role_rank,
            MIN(e.id) AS representative_id,
            COUNT(*) AS group_size
        FROM events AS e
        JOIN source_minute_stats AS s
            ON s.source_token = e.source_token
            AND s.minute_bucket = e.minute_bucket
            AND s.role_rank = e.role_rank
        LEFT JOIN destination_repeat_stats AS d
            ON d.source_token = e.source_token
            AND d.minute_bucket = e.minute_bucket
            AND d.role_rank = e.role_rank
            AND d.destination_token = e.destination_token
            AND (
                d.dst_port = e.dst_port
                OR (d.dst_port IS NULL AND e.dst_port IS NULL)
            )
        WHERE e.role_rank < 4
        GROUP BY
            e.role_rank, e.minute_bucket, e.log_type, e.subtype, e.app,
            e.action, e.protocol, e.src_port, e.dst_port, e.src_zone,
            e.dst_zone, e.app_risk, e.schema_bucket, e.threat_severity,
            e.external_to_internal_flag, e.internal_to_external_flag,
            CASE
                WHEN COALESCE(e.bytes, 0) < 1 THEN '0'
                WHEN ABS(e.bytes) < 100 THEN '1'
                WHEN ABS(e.bytes) < 1000 THEN '2'
                WHEN ABS(e.bytes) < 10000 THEN '3'
                WHEN ABS(e.bytes) < 100000 THEN '4'
                WHEN ABS(e.bytes) < 1000000 THEN '5'
                ELSE '6'
            END,
            CASE
                WHEN COALESCE(e.packets, 0) < 1 THEN '0'
                WHEN ABS(e.packets) < 10 THEN '1'
                WHEN ABS(e.packets) < 100 THEN '2'
                WHEN ABS(e.packets) < 1000 THEN '3'
                ELSE '4'
            END,
            CASE
                WHEN s.event_count < 5 THEN 'low'
                WHEN s.event_count < 25 THEN 'medium'
                WHEN s.event_count < 100 THEN 'high'
                ELSE 'very_high'
            END,
            CASE
                WHEN s.unique_destinations < 3 THEN 'low'
                WHEN s.unique_destinations < 8 THEN 'medium'
                ELSE 'high'
            END,
            CASE
                WHEN s.unique_ports < 3 THEN 'low'
                WHEN s.unique_ports < 10 THEN 'medium'
                ELSE 'high'
            END,
            CASE
                WHEN s.deny_count = 0 THEN 'none'
                WHEN s.deny_count < 5 THEN 'low'
                ELSE 'high'
            END,
            CASE
                WHEN COALESCE(d.repeat_count, 0) < 3 THEN 'low'
                WHEN d.repeat_count < 10 THEN 'medium'
                ELSE 'high'
            END;
        CREATE UNIQUE INDEX ix_v56_representative_groups
            ON representative_groups(propagation_hash, role_rank);
        """
    )
    connection.commit()
    source_windows = int(
        connection.execute(
            "SELECT COUNT(*) FROM source_minute_stats"
        ).fetchone()[0]
    )
    representative_groups = int(
        connection.execute(
            "SELECT COUNT(*) FROM representative_groups"
        ).fetchone()[0]
    )
    return {
        "status": "disposable_behavior_aggregates_ready",
        "source_time_windows": source_windows,
        "representative_groups": representative_groups,
        "raw_evidence_included": False,
        "private_identifiers_returned": False,
    }


REPRESENTATIVE_QUERY = """
SELECT
    e.id, e.event_time, e.minute_bucket, e.role_rank,
    e.log_type, e.subtype, e.app, e.action, e.protocol,
    e.src_port, e.dst_port, e.src_zone, e.dst_zone,
    e.bytes, e.bytes_sent, e.bytes_received, e.packets,
    e.elapsed_time, e.app_risk, e.repeat_count,
    e.parser_error, e.parser_warning_count, e.required_missing_count,
    e.field_count, e.schema_bucket, e.threat_severity,
    e.app_characteristic, e.session_end_reason,
    e.deny_flag, e.unknown_app_flag,
    e.external_to_internal_flag, e.internal_to_external_flag,
    g.group_size, g.propagation_hash,
    s.event_count, s.deny_count, s.auth_deny_count,
    s.unique_destinations, s.unique_ports, s.total_bytes,
    s.average_packets, s.unknown_app_count, s.high_risk_app_count,
    d.repeat_count
FROM representative_groups AS g
JOIN events AS e ON e.id = g.representative_id
JOIN source_minute_stats AS s
    ON s.source_token = e.source_token
    AND s.minute_bucket = e.minute_bucket
    AND s.role_rank = e.role_rank
LEFT JOIN destination_repeat_stats AS d
    ON d.source_token = e.source_token
    AND d.minute_bucket = e.minute_bucket
    AND d.role_rank = e.role_rank
    AND d.destination_token = e.destination_token
    AND (
        d.dst_port = e.dst_port
        OR (d.dst_port IS NULL AND e.dst_port IS NULL)
    )
ORDER BY e.id
"""


REPRESENTATIVE_COLUMNS = [
    "id",
    "event_time",
    "minute_bucket",
    "role_rank",
    "log_type",
    "subtype",
    "app",
    "action",
    "protocol",
    "src_port",
    "dst_port",
    "src_zone",
    "dst_zone",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "elapsed_time",
    "app_risk",
    "repeat_count",
    "parser_error",
    "parser_warning_count",
    "required_missing_count",
    "field_count",
    "schema_bucket",
    "threat_severity",
    "app_characteristic",
    "session_end_reason",
    "deny_flag",
    "unknown_app_flag",
    "external_to_internal_flag",
    "internal_to_external_flag",
    "group_size",
    "propagation_hash",
    "source_event_count",
    "source_deny_count",
    "source_auth_deny_count",
    "source_unique_destinations",
    "source_unique_ports",
    "source_total_bytes",
    "source_average_packets",
    "source_unknown_app_count",
    "source_high_risk_app_count",
    "destination_repeat_count",
]


def _row_mapping(values: Iterable[Any]) -> dict[str, Any]:
    return dict(zip(REPRESENTATIVE_COLUMNS, values, strict=True))


def _representative_log(row: dict[str, Any]) -> NormalizedLog:
    timestamp = (
        datetime.fromisoformat(str(row["event_time"]))
        if row.get("event_time")
        else None
    )
    return NormalizedLog(
        id=int(row["id"]),
        raw_log_id=0,
        generated_time=timestamp,
        receive_time=timestamp,
        log_type=str(row["log_type"]),
        subtype=str(row["subtype"]),
        src_ip="private-source",
        dst_ip="private-destination",
        app=str(row["app"]),
        action=str(row["action"]),
        protocol=str(row["protocol"]),
        src_port=row.get("src_port"),
        dst_port=row.get("dst_port"),
        src_zone=str(row["src_zone"]),
        dst_zone=str(row["dst_zone"]),
        bytes=row.get("bytes"),
        bytes_sent=row.get("bytes_sent"),
        bytes_received=row.get("bytes_received"),
        packets=row.get("packets"),
        elapsed_time=row.get("elapsed_time"),
        app_risk=row.get("app_risk"),
        repeat_count=row.get("repeat_count"),
        app_characteristic=str(row.get("app_characteristic") or ""),
        session_end_reason=str(row.get("session_end_reason") or ""),
        parsed_json={
            "parser_warnings": [
                "redacted_parser_warning"
                for _ in range(_integer(row.get("parser_warning_count")))
            ]
        },
    )


def _rule_evidence(row: dict[str, Any]) -> tuple[list[str], int]:
    log = _representative_log(row)
    unique_ports = max(0, _integer(row.get("source_unique_ports")))
    unique_destinations = max(0, _integer(row.get("source_unique_destinations")))
    source_auth_denies = _integer(row.get("source_auth_deny_count"))
    source_denies = _integer(row.get("source_deny_count"))
    destination_repeats = _integer(row.get("destination_repeat_count"))

    # The historical disposable aggregate does not retain per-port cadence or
    # target counters. Preserve evidence only when its one-target/one-port
    # shape makes that attribution unambiguous; otherwise fail closed.
    single_target_service = unique_destinations == 1 and unique_ports == 1
    correlation = CorrelationSnapshot(
        source_count=_integer(row.get("source_event_count")),
        deny_drop_count=source_denies,
        distinct_ports=frozenset(range(unique_ports)),
        auth_deny_count=source_auth_denies,
        auth_target_deny_count=(source_auth_denies if single_target_service else 0),
        destination_repeat_count=destination_repeats,
        destination_event_count=destination_repeats,
        distinct_destinations_for_port=(
            unique_destinations if unique_ports <= 1 else 0
        ),
        deny_drop_count_for_port=(source_denies if unique_ports <= 1 else 0),
        cadence_interval_count=0,
        cadence_mean_seconds=None,
        cadence_jitter_ratio=None,
        source_scope="source:private-disposable",
        window_label=str(row.get("minute_bucket") or "missing"),
    )
    context = DetectionContext(
        source_counts=Counter(),
        source_deny_drop_counts=Counter(),
        source_distinct_ports=defaultdict(set),
        source_auth_deny_counts=Counter(),
        source_destination_counts=Counter(),
        source_auth_destination_counts=Counter(),
        byte_outlier_threshold=10_000_000,
        packet_outlier_threshold=50_000,
        event_correlations={int(log.id): correlation},
    )
    matches = [
        item
        for item in evaluate_rules(log, context)
        if item.code != "ml_anomaly_detected"
    ]
    return sorted({item.code for item in matches}), min(
        100,
        sum(int(item.score) for item in matches),
    )


def assisted_decision(
    row: dict[str, Any],
    *,
    rule_codes: list[str],
    rule_score: int,
) -> dict[str, Any]:
    """Apply the fixed v5.6 weak-label policy without claiming human review."""

    log_type = str(row.get("log_type") or "").upper()
    severity = _lower(row.get("threat_severity"))
    app = _lower(row.get("app"))
    action = _lower(row.get("action"))
    risk = _integer(row.get("app_risk"))
    source_events = _integer(row.get("source_event_count"))
    unique_destinations = _integer(row.get("source_unique_destinations"))
    unique_ports = _integer(row.get("source_unique_ports"))
    deny_count = _integer(row.get("source_deny_count"))
    destination_repeat = _integer(row.get("destination_repeat_count"))
    external_to_internal = bool(row.get("external_to_internal_flag"))
    parser_limited = bool(
        row.get("parser_error")
        or _integer(row.get("required_missing_count")) >= 2
    )
    scan_like = (
        unique_ports >= 10
        or (source_events >= 20 and unique_destinations >= 8)
        or "possible_port_scan" in rule_codes
    )
    brute_force = "brute_force_like_attempts" in rule_codes
    beacon_like = "beaconing_like_outbound" in rule_codes
    flood_like = "connection_flood_suspicion" in rule_codes
    strong_behavior = scan_like or brute_force or beacon_like or flood_like
    multi_signal = sum(
        (
            int(strong_behavior),
            int(external_to_internal),
            int(deny_count >= 5),
            int(risk >= 4),
            int(rule_score >= 50),
            int(log_type == "THREAT"),
        )
    )
    routine_web = (
        action == "allow"
        and app in WEB_APPS
        and row.get("dst_port") in {53, 80, 443, None}
        and not strong_behavior
        and rule_score < 30
        and risk < 4
    )

    if log_type == "THREAT" and severity in {"critical", "high"}:
        decision = "malicious"
        provenance = "vendor_threat_assisted"
        confidence = 0.96
        reason = "explicit high-severity PAN-OS THREAT record"
    elif log_type == "THREAT" and severity in {"medium", "low", "informational"}:
        decision = "suspicious"
        provenance = "vendor_threat_assisted"
        confidence = 0.90 if severity == "medium" else 0.82
        reason = "explicit PAN-OS THREAT record with non-high severity"
    elif strong_behavior and multi_signal >= 4:
        decision = "malicious"
        provenance = "rule_assisted"
        confidence = 0.90
        reason = "strong deterministic behavior with multiple corroborating signals"
    elif strong_behavior or rule_score >= 50:
        decision = "suspicious"
        provenance = "rule_assisted"
        confidence = 0.86
        reason = "deterministic scan, brute-force, beacon, flood, or rule evidence"
    elif routine_web and not parser_limited:
        decision = "benign"
        provenance = "weak_supervision"
        confidence = 0.90
        reason = "routine allowed web or utility traffic with no strong behavior evidence"
    elif (
        action == "allow"
        and app not in UNKNOWN_APPS
        and risk <= 2
        and not strong_behavior
        and rule_score < 30
    ):
        decision = "benign"
        provenance = "codex_assisted"
        confidence = 0.84
        reason = "known low-risk allowed application without corroborating threat evidence"
    elif app in UNKNOWN_APPS and not strong_behavior and rule_score < 30:
        decision = "benign_unusual" if not parser_limited else "needs_context"
        provenance = "weak_supervision"
        confidence = 0.78 if decision == "benign_unusual" else 0.55
        reason = "unknown or incomplete application without strong behavior evidence"
    elif destination_repeat >= 6 or source_events >= 25 or risk >= 4:
        decision = "needs_context"
        provenance = "codex_assisted"
        confidence = 0.60
        reason = "activity is unusual but lacks enough independent evidence for threat labeling"
    else:
        decision = "needs_context"
        provenance = "codex_assisted"
        confidence = 0.50
        reason = "evidence is ambiguous under the conservative policy"

    training_eligible = bool(
        decision != "needs_context"
        and confidence >= 0.75
        and not row.get("parser_error")
    )
    return {
        "decision": decision,
        "provenance": provenance,
        "confidence": round(confidence, 4),
        "evidence_summary": reason,
        "rule_codes": rule_codes,
        "rule_score": int(rule_score),
        "policy_version": V56_POLICY_VERSION,
        "human_reviewed": False,
        "training_eligible": training_eligible,
        "ambiguous": not training_eligible,
    }


def apply_assisted_policy(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    connection.executescript(
        """
        DROP TABLE IF EXISTS assisted_groups;
        CREATE TABLE assisted_groups (
            representative_id INTEGER PRIMARY KEY,
            propagation_hash TEXT NOT NULL,
            role_rank INTEGER NOT NULL,
            group_size INTEGER NOT NULL,
            decision TEXT NOT NULL,
            provenance TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence_summary TEXT NOT NULL,
            rule_codes_json TEXT NOT NULL,
            rule_score INTEGER NOT NULL,
            policy_version TEXT NOT NULL,
            human_reviewed INTEGER NOT NULL,
            training_eligible INTEGER NOT NULL,
            ambiguous INTEGER NOT NULL
        );
        """
    )
    decision_counts: Counter[str] = Counter()
    provenance_counts: Counter[str] = Counter()
    training_rows = 0
    ambiguous_rows = 0
    cursor = connection.execute(REPRESENTATIVE_QUERY)
    batch: list[tuple[Any, ...]] = []
    for values in cursor:
        row = _row_mapping(values)
        codes, score = _rule_evidence(row)
        decision = assisted_decision(
            row,
            rule_codes=codes,
            rule_score=score,
        )
        group_size = _integer(row["group_size"], 1)
        if _integer(row["role_rank"]) != 3:
            decision_counts[decision["decision"]] += group_size
            provenance_counts[decision["provenance"]] += group_size
            if decision["training_eligible"]:
                training_rows += group_size
            else:
                ambiguous_rows += group_size
        batch.append(
            (
                int(row["id"]),
                str(row["propagation_hash"]),
                int(row["role_rank"]),
                group_size,
                decision["decision"],
                decision["provenance"],
                decision["confidence"],
                decision["evidence_summary"],
                json.dumps(decision["rule_codes"], separators=(",", ":")),
                decision["rule_score"],
                decision["policy_version"],
                0,
                int(decision["training_eligible"]),
                int(decision["ambiguous"]),
            )
        )
        if len(batch) >= 2000:
            connection.executemany(
                "INSERT INTO assisted_groups VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
            connection.commit()
            batch.clear()
    if batch:
        connection.executemany(
            "INSERT INTO assisted_groups VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            batch,
        )
        connection.commit()
    connection.executescript(
        """
        CREATE INDEX ix_v56_assisted_role
            ON assisted_groups(role_rank, training_eligible);
        CREATE INDEX ix_v56_assisted_decision
            ON assisted_groups(decision, provenance);
        """
    )
    connection.commit()

    future_summary = {
        "status": "sealed_until_candidate_freeze",
        "labels_opened_for_feature_or_candidate_design": False,
        "counts_returned_before_freeze": False,
    }
    return {
        "status": "assisted_policy_applied",
        "policy_version": V56_POLICY_VERSION,
        "decisions_by_event_count": dict(sorted(decision_counts.items())),
        "provenance_by_event_count": dict(sorted(provenance_counts.items())),
        "high_confidence_training_event_count": training_rows,
        "ambiguous_or_quarantined_event_count": ambiguous_rows,
        "representative_group_count": int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups"
            ).fetchone()[0]
        ),
        "human_reviewed_true_count": int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups WHERE human_reviewed=1"
            ).fetchone()[0]
        ),
        "configured_database_labels_written": 0,
        "import_ready_human_review_file_created": False,
        "future_validation": future_summary,
    }


def open_future_assisted_summary_after_freeze(
    connection: sqlite3.Connection,
    *,
    candidate_frozen: bool,
) -> dict[str, Any]:
    if not candidate_frozen:
        raise ValueError(
            "Future assisted-label aggregates remain sealed until candidate freeze."
        )
    decision_counts = {
        str(value): int(count)
        for value, count in connection.execute(
            "SELECT decision, SUM(group_size) FROM assisted_groups "
            "WHERE role_rank=3 GROUP BY decision"
        )
    }
    provenance_counts = {
        str(value): int(count)
        for value, count in connection.execute(
            "SELECT provenance, SUM(group_size) FROM assisted_groups "
            "WHERE role_rank=3 GROUP BY provenance"
        )
    }
    return {
        "status": "opened_once_after_candidate_freeze",
        "decisions_by_event_count": dict(sorted(decision_counts.items())),
        "provenance_by_event_count": dict(sorted(provenance_counts.items())),
        "representative_groups": int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups WHERE role_rank=3"
            ).fetchone()[0]
        ),
        "training_eligible_groups": int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups "
                "WHERE role_rank=3 AND training_eligible=1"
            ).fetchone()[0]
        ),
        "future_labels_used_for_candidate_selection": False,
        "human_reviewed_true_count": int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups "
                "WHERE role_rank=3 AND human_reviewed=1"
            ).fetchone()[0]
        ),
    }


MODEL_ROW_QUERY = """
SELECT
    e.id, e.event_time, e.minute_bucket, e.role_rank,
    e.log_type, e.subtype, e.app, e.action, e.protocol,
    e.src_port, e.dst_port, e.src_zone, e.dst_zone,
    e.bytes, e.bytes_sent, e.bytes_received, e.packets,
    e.elapsed_time, e.app_risk, e.repeat_count,
    e.parser_error, e.parser_warning_count, e.required_missing_count,
    e.field_count, e.schema_bucket, e.threat_severity,
    e.app_characteristic, e.session_end_reason,
    e.deny_flag, e.unknown_app_flag,
    e.external_to_internal_flag, e.internal_to_external_flag,
    a.group_size, a.propagation_hash,
    s.event_count, s.deny_count, s.auth_deny_count,
    s.unique_destinations, s.unique_ports, s.total_bytes,
    s.average_packets, s.unknown_app_count, s.high_risk_app_count,
    d.repeat_count,
    a.decision, a.provenance, a.confidence, a.rule_score,
    a.human_reviewed, a.training_eligible, a.ambiguous
FROM assisted_groups AS a
JOIN events AS e ON e.id = a.representative_id
JOIN source_minute_stats AS s
    ON s.source_token = e.source_token
    AND s.minute_bucket = e.minute_bucket
    AND s.role_rank = e.role_rank
LEFT JOIN destination_repeat_stats AS d
    ON d.source_token = e.source_token
    AND d.minute_bucket = e.minute_bucket
    AND d.role_rank = e.role_rank
    AND d.destination_token = e.destination_token
    AND (
        d.dst_port = e.dst_port
        OR (d.dst_port IS NULL AND e.dst_port IS NULL)
    )
JOIN selected_representatives AS selected
    ON selected.representative_id = a.representative_id
ORDER BY e.event_time, a.propagation_hash
"""


MODEL_ROW_COLUMNS = [
    *REPRESENTATIVE_COLUMNS,
    "decision",
    "provenance",
    "confidence",
    "rule_score",
    "human_reviewed",
    "training_eligible",
    "ambiguous",
]


def _private_feature_row(row: dict[str, Any]) -> dict[str, Any]:
    event_time = (
        datetime.fromisoformat(str(row["event_time"]))
        if row.get("event_time")
        else None
    )
    source_events = max(1, _integer(row.get("source_event_count"), 1))
    deny_count = _integer(row.get("source_deny_count"))
    unique_ports = _integer(row.get("source_unique_ports"))
    unique_destinations = _integer(row.get("source_unique_destinations"))
    severity_score = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }.get(_lower(row.get("threat_severity")), 0)
    parser_confidence = max(
        0.0,
        1.0
        - (0.20 * _integer(row.get("required_missing_count")))
        - (0.08 * _integer(row.get("parser_warning_count")))
        - (0.50 * int(bool(row.get("parser_error")))),
    )
    scan_pressure = min(
        1.0,
        (unique_ports / 10.0)
        + (unique_destinations / 12.0)
        + (deny_count / 25.0),
    )
    return {
        "src_port": row.get("src_port"),
        "dst_port": row.get("dst_port"),
        "bytes": row.get("bytes"),
        "bytes_sent": row.get("bytes_sent"),
        "bytes_received": row.get("bytes_received"),
        "packets": row.get("packets"),
        "elapsed_time": row.get("elapsed_time"),
        "app_risk": row.get("app_risk"),
        "repeat_count_effective": max(
            1,
            min(_integer(row.get("repeat_count"), 1), 10_000),
        ),
        "parser_warning_count": _integer(row.get("parser_warning_count")),
        "required_field_missing_count": _integer(
            row.get("required_missing_count")
        ),
        "parser_confidence_score": round(parser_confidence, 4),
        "unknown_app_flag": _integer(row.get("unknown_app_flag")),
        "external_to_internal_flag": _integer(
            row.get("external_to_internal_flag")
        ),
        "internal_to_external_flag": _integer(
            row.get("internal_to_external_flag")
        ),
        "hour_of_day": event_time.hour if event_time else None,
        "is_after_hours": (
            int(event_time.hour < 7 or event_time.hour >= 18)
            if event_time
            else None
        ),
        "src_ip_5min_log_count": source_events,
        "src_ip_5min_deny_count": deny_count,
        "src_ip_5min_unique_dst_ports": unique_ports,
        "src_ip_5min_unique_dst_ips": unique_destinations,
        "src_ip_5min_total_bytes": _integer(row.get("source_total_bytes")),
        "src_ip_5min_avg_packets": _number(
            row.get("source_average_packets")
        ),
        "src_ip_5min_unknown_app_count": _integer(
            row.get("source_unknown_app_count")
        ),
        "src_ip_5min_high_risk_app_count": _integer(
            row.get("source_high_risk_app_count")
        ),
        "deny_rate_5min": round(deny_count / source_events, 6),
        "v56_threat_record_flag": int(
            str(row.get("log_type") or "").upper() == "THREAT"
        ),
        "v56_vendor_severity_score": severity_score,
        "v56_rule_evidence_score": _integer(row.get("rule_score")),
        "v56_destination_repeat_count": _integer(
            row.get("destination_repeat_count")
        ),
        "v56_schema_field_count": _integer(row.get("field_count")),
        "v56_scan_pressure": round(scan_pressure, 6),
        "protocol": str(row.get("protocol") or "unknown"),
        "action": str(row.get("action") or "unknown"),
        "app": str(row.get("app") or "unknown"),
        "src_zone": str(row.get("src_zone") or "unknown"),
        "dst_zone": str(row.get("dst_zone") or "unknown"),
        "v56_log_type": str(row.get("log_type") or "missing"),
        "v56_subtype": str(row.get("subtype") or "missing"),
        "v56_schema_bucket": str(row.get("schema_bucket") or "unrecognized"),
    }


def _empty_bundle(imports: Any) -> dict[str, Any]:
    pd = imports[1]
    return {
        "frame": pd.DataFrame(
            columns=[*V56_NUMERIC_FEATURES, *V56_CATEGORICAL_FEATURES]
        ),
        "rows": [],
        "original_labels": [],
        "targets": [],
        "base_weights": [],
    }


def _queue_target(label: str) -> str:
    return (
        "needs_review"
        if label in {"needs_context", "suspicious", "malicious"}
        else "non_threat"
    )


def _bundle_from_private_rows(
    imports: Any,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    pd = imports[1]
    frames = [_private_feature_row(row) for row in rows]
    originals = [str(row["decision"]) for row in rows]
    metadata = [
        {
            "timestamp": (
                datetime.fromisoformat(str(row["event_time"]))
                if row.get("event_time")
                else None
            ),
            "app": str(row.get("app") or "unknown"),
            "action": str(row.get("action") or "unknown"),
            "dst_port": row.get("dst_port"),
            "schema": str(row.get("schema_bucket") or "unknown"),
            "provenance": str(row.get("provenance") or "unknown"),
            "human_reviewed": False,
            "group_size": _integer(row.get("group_size"), 1),
            "evidence_role": ROLE_NAMES[_integer(row.get("role_rank"), 4)],
            "original_label": str(row["decision"]),
            "private_source": True,
            "source_name": "private-single-device",
        }
        for row in rows
    ]
    weights = [
        min(
            0.65,
            ASSISTED_WEIGHTS.get(str(row.get("provenance")), 0.20)
            * min(1.35, max(1.0, math.sqrt(_integer(row.get("group_size"), 1)) / 3)),
        )
        for row in rows
    ]
    return {
        "frame": pd.DataFrame(frames).reindex(
            columns=[*V56_NUMERIC_FEATURES, *V56_CATEGORICAL_FEATURES]
        ),
        "rows": metadata,
        "original_labels": originals,
        "targets": [_queue_target(value) for value in originals],
        "base_weights": weights,
    }


def load_private_role_bundle(
    connection: sqlite3.Connection,
    imports: Any,
    *,
    role_rank: int,
    max_rows: int,
    open_future_labels: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if role_rank == 3 and not open_future_labels:
        raise ValueError(
            "Untouched future labels may be opened only after candidate freeze."
        )
    connection.execute("DROP TABLE IF EXISTS selected_representatives")
    connection.execute(
        "CREATE TEMP TABLE selected_representatives("
        "representative_id INTEGER PRIMARY KEY)"
    )
    labels = ("benign", "benign_unusual", "suspicious", "malicious")
    quota = max(1, int(max_rows) // len(labels))
    selected: list[int] = []
    available_by_label: dict[str, int] = {}
    for label in labels:
        available_by_label[label] = int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups "
                "WHERE role_rank=? AND training_eligible=1 AND decision=?",
                (role_rank, label),
            ).fetchone()[0]
        )
        selected.extend(
            int(row[0])
            for row in connection.execute(
                "SELECT representative_id FROM assisted_groups "
                "WHERE role_rank=? AND training_eligible=1 AND decision=? "
                "ORDER BY propagation_hash LIMIT ?",
                (role_rank, label, quota),
            )
        )
    connection.executemany(
        "INSERT OR IGNORE INTO selected_representatives VALUES (?)",
        [(value,) for value in selected],
    )
    values = [
        dict(zip(MODEL_ROW_COLUMNS, row, strict=True))
        for row in connection.execute(MODEL_ROW_QUERY)
    ]
    return _bundle_from_private_rows(imports, values), {
        "role": ROLE_NAMES[role_rank],
        "available_training_groups_by_label": available_by_label,
        "selected_representative_rows": len(values),
        "selection_cap": int(max_rows),
        "selection": "deterministic_stratified_representatives",
        "duplicate_rows_replicated": False,
        "future_labels_opened": bool(role_rank == 3 and open_future_labels),
    }


def _human_feature_row(
    frame_row: Any,
    log: Any,
) -> dict[str, Any]:
    parsed = getattr(log, "parsed_json", {}) or {}
    severity = _lower(parsed.get("parsed_threat_severity"))
    severity_score = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }.get(severity, 0)
    unique_ports = _number(frame_row.get("src_ip_5min_unique_dst_ports"))
    unique_destinations = _number(frame_row.get("src_ip_5min_unique_dst_ips"))
    deny_count = _number(frame_row.get("src_ip_5min_deny_count"))
    output: dict[str, Any] = {}
    for field in V56_NUMERIC_FEATURES:
        output[field] = frame_row.get(field)
    for field in V56_CATEGORICAL_FEATURES:
        output[field] = frame_row.get(field)
    output.update(
        {
            "v56_threat_record_flag": int(
                str(getattr(log, "log_type", "") or "").upper() == "THREAT"
            ),
            "v56_vendor_severity_score": severity_score,
            "v56_rule_evidence_score": _number(
                frame_row.get("v398_local_rule_score")
            ),
            "v56_destination_repeat_count": _number(
                frame_row.get("repeated_connection_attempts")
            ),
            "v56_schema_field_count": _integer(parsed.get("field_count")),
            "v56_scan_pressure": round(
                min(
                    1.0,
                    (unique_ports / 10.0)
                    + (unique_destinations / 12.0)
                    + (deny_count / 25.0),
                ),
                6,
            ),
            "v56_log_type": str(
                getattr(log, "log_type", None) or "missing"
            ),
            "v56_subtype": str(
                getattr(log, "subtype", None) or "missing"
            ),
            "v56_schema_bucket": (
                "parser_limited"
                if _integer(frame_row.get("parser_warning_count")) > 0
                else "parsed"
            ),
        }
    )
    return output


def build_human_role_bundles(
    dataset: dict[str, Any],
    partition: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    imports = dataset["imports"]
    pd = imports[1]
    bundles: dict[str, dict[str, Any]] = {}
    for role_name, key in ROLE_KEYS.items():
        indices = [int(value) for value in partition.get(key, [])]
        frames = [
            _human_feature_row(
                dataset["frame"].iloc[index],
                dataset["logs"][index],
            )
            for index in indices
        ]
        originals = [dataset["original_labels"][index] for index in indices]
        rows = []
        for index in indices:
            source = dataset["rows"][index]
            rows.append(
                {
                    "timestamp": source.get("timestamp"),
                    "app": source.get("app"),
                    "action": source.get("action"),
                    "dst_port": source.get("dst_port"),
                    "schema": "governed_database",
                    "provenance": source.get("label_source") or "reviewed",
                    "human_reviewed": True,
                    "group_size": 1,
                    "evidence_role": role_name,
                    "original_label": source.get("original_label"),
                    "private_source": False,
                    "source_name": "governed-development-evidence",
                }
            )
        bundles[role_name] = {
            "frame": pd.DataFrame(frames).reindex(
                columns=[*V56_NUMERIC_FEATURES, *V56_CATEGORICAL_FEATURES]
            ),
            "rows": rows,
            "original_labels": originals,
            "targets": [_queue_target(value) for value in originals],
            "base_weights": [1.0 for _ in originals],
        }
    return bundles


def _concat_bundles(imports: Any, *bundles: dict[str, Any]) -> dict[str, Any]:
    pd = imports[1]
    materialized = [bundle for bundle in bundles if len(bundle["rows"])]
    if not materialized:
        return _empty_bundle(imports)
    return {
        "frame": pd.concat(
            [bundle["frame"] for bundle in materialized],
            ignore_index=True,
        ),
        "rows": [
            row for bundle in materialized for row in bundle["rows"]
        ],
        "original_labels": [
            value
            for bundle in materialized
            for value in bundle["original_labels"]
        ],
        "targets": [
            value for bundle in materialized for value in bundle["targets"]
        ],
        "base_weights": [
            value
            for bundle in materialized
            for value in bundle["base_weights"]
        ],
    }


def _slice_bundle(
    imports: Any,
    bundle: dict[str, Any],
    indices: list[int],
) -> dict[str, Any]:
    ordered = sorted(set(int(value) for value in indices))
    if not ordered:
        return _empty_bundle(imports)
    return {
        "frame": bundle["frame"].iloc[ordered].reset_index(drop=True),
        "rows": [bundle["rows"][index] for index in ordered],
        "original_labels": [
            bundle["original_labels"][index] for index in ordered
        ],
        "targets": [bundle["targets"][index] for index in ordered],
        "base_weights": [
            bundle["base_weights"][index] for index in ordered
        ],
    }


def _chronological_slices(
    imports: Any,
    bundle: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    ordered = sorted(
        range(len(bundle["rows"])),
        key=lambda index: (
            bundle["rows"][index].get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc),
            index,
        ),
    )
    size = len(ordered)
    fit_end = max(1, int(size * 0.58))
    calibration_end = max(fit_end + 1, int(size * 0.72))
    threshold_end = max(calibration_end + 1, int(size * 0.84))
    threshold_end = min(threshold_end, max(calibration_end + 1, size - 1))
    return (
        _slice_bundle(imports, bundle, ordered[:fit_end]),
        _slice_bundle(imports, bundle, ordered[fit_end:calibration_end]),
        _slice_bundle(imports, bundle, ordered[calibration_end:threshold_end]),
        _slice_bundle(imports, bundle, ordered[threshold_end:]),
    )


def _three_class_targets(labels: list[str]) -> list[str]:
    mapping = {
        "benign": "benign_like",
        "benign_unusual": "benign_like",
        "needs_context": "suspicious",
        "suspicious": "suspicious",
        "malicious": "malicious",
    }
    return [mapping[value] for value in labels]


def _targets_for_mode(bundle: dict[str, Any], mode: str) -> list[str]:
    if mode == "three_class_soc_queue":
        return _three_class_targets(bundle["original_labels"])
    return list(bundle["targets"])


def _positive_classes(mode: str) -> set[str]:
    if mode == "three_class_soc_queue":
        return {"suspicious", "malicious"}
    return {"needs_review"}


def _fit_weights(
    bundle: dict[str, Any],
    targets: list[str],
    *,
    variant: str,
) -> tuple[list[float], dict[str, Any]]:
    counts = Counter(targets)
    total = max(1, len(targets))
    class_count = max(1, len(counts))
    weights: list[float] = []
    human_weights: list[float] = []
    assisted_weights: list[float] = []
    for index, target in enumerate(targets):
        base = float(bundle["base_weights"][index])
        class_factor = 1.0
        if variant == "class_and_provenance":
            class_factor = min(
                2.0,
                max(0.65, total / (class_count * max(1, counts[target]))),
            )
        if bool(bundle["rows"][index].get("human_reviewed")):
            value = min(3.0, max(1.0, base * class_factor))
            human_weights.append(value)
        else:
            value = min(0.65, max(0.10, base * class_factor))
            assisted_weights.append(value)
        weights.append(value)
    return weights, {
        "strategy": variant,
        "target_distribution": dict(sorted(counts.items())),
        "human_reviewed_rows": len(human_weights),
        "assisted_rows": len(assisted_weights),
        "human_weight_range": {
            "minimum": round(min(human_weights), 4)
            if human_weights
            else None,
            "maximum": round(max(human_weights), 4)
            if human_weights
            else None,
        },
        "assisted_weight_range": {
            "minimum": round(min(assisted_weights), 4)
            if assisted_weights
            else None,
            "maximum": round(max(assisted_weights), 4)
            if assisted_weights
            else None,
        },
        "assisted_weights_lower_than_human": bool(
            not assisted_weights
            or not human_weights
            or max(assisted_weights) < min(human_weights)
        ),
    }


def _error_pattern_summary(
    bundle: dict[str, Any],
    y_true: list[str],
    predictions: list[str],
) -> dict[str, Any]:
    false_positive: list[dict[str, Any]] = []
    false_negative: list[dict[str, Any]] = []
    for row, actual, predicted in zip(
        bundle["rows"],
        y_true,
        predictions,
        strict=True,
    ):
        if actual == predicted:
            continue
        item = {
            "app": str(row.get("app") or "unknown"),
            "action": str(row.get("action") or "unknown"),
            "port": str(row.get("dst_port")),
            "schema": str(row.get("schema") or "unknown"),
            "provenance": str(row.get("provenance") or "unknown"),
            "time_window": (
                row["timestamp"].replace(second=0, microsecond=0).isoformat()
                if isinstance(row.get("timestamp"), datetime)
                else "missing"
            ),
            "original_label": str(row.get("original_label") or "unknown"),
        }
        if actual == "non_threat":
            false_positive.append(item)
        else:
            false_negative.append(item)

    def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "rows": len(rows),
            "top_applications": _safe_top(
                Counter(item["app"] for item in rows),
                limit=10,
            ),
            "top_actions": _safe_top(
                Counter(item["action"] for item in rows),
                limit=10,
            ),
            "top_ports": _safe_top(
                Counter(item["port"] for item in rows),
                limit=10,
            ),
            "top_schema_profiles": _safe_top(
                Counter(item["schema"] for item in rows),
                limit=10,
            ),
            "top_provenance": _safe_top(
                Counter(item["provenance"] for item in rows),
                limit=10,
            ),
            "top_time_windows": _safe_top(
                Counter(item["time_window"] for item in rows),
                limit=10,
            ),
            "top_original_labels": _safe_top(
                Counter(item["original_label"] for item in rows),
                limit=10,
            ),
        }

    return {
        "false_positives": summarize(false_positive),
        "false_negatives": summarize(false_negative),
        "private_identifiers_included": False,
    }


def _development_gate(
    metrics: dict[str, Any],
    calibration: dict[str, Any],
) -> dict[str, Any]:
    suspicious = metrics.get("suspicious_recall")
    malicious = metrics.get("malicious_recall")
    checks = {
        "queue_f1": _number(metrics.get("queue_f1"))
        >= DEVELOPMENT_GATES["queue_f1_min"],
        "benign_like_false_positive_rate": _number(
            metrics.get("benign_like_false_positive_rate"),
            1.0,
        )
        <= DEVELOPMENT_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": suspicious is not None
        and _number(suspicious) >= DEVELOPMENT_GATES["suspicious_recall_min"],
        "malicious_recall": malicious is not None
        and _number(malicious) >= DEVELOPMENT_GATES["malicious_recall_min"],
        "expected_calibration_error": _number(
            calibration.get("expected_calibration_error"),
            1.0,
        )
        <= DEVELOPMENT_GATES["expected_calibration_error_max"],
        "max_confidence_accuracy_gap": _number(
            calibration.get("max_confidence_accuracy_gap"),
            1.0,
        )
        <= DEVELOPMENT_GATES["max_confidence_accuracy_gap_max"],
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "gates": DEVELOPMENT_GATES,
    }


def _fit_candidate(
    imports: Any,
    *,
    fit: dict[str, Any],
    calibration: dict[str, Any],
    threshold: dict[str, Any],
    evaluation: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    mode = str(spec["target_mode"])
    fit_targets = _targets_for_mode(fit, mode)
    if len(fit_targets) < 20 or len(set(fit_targets)) < 2:
        return {
            "status": "failed_closed",
            "reason": "fit evidence has insufficient target support",
            "name": spec["name"],
        }
    if not len(calibration["rows"]) or not len(threshold["rows"]) or not len(
        evaluation["rows"]
    ):
        return {
            "status": "failed_closed",
            "reason": "a dedicated development role is empty",
            "name": spec["name"],
        }
    pipeline = _build_pipeline_for_columns(
        imports,
        model_type=str(spec["model_type"]),
        class_weight=spec.get("class_weight"),
        numeric_features=V56_NUMERIC_FEATURES,
        categorical_features=V56_CATEGORICAL_FEATURES,
    )
    weights, weight_summary = _fit_weights(
        fit,
        fit_targets,
        variant=str(spec["weight_variant"]),
    )
    started = time.perf_counter()
    pipeline.fit(
        fit["frame"],
        fit_targets,
        model__sample_weight=weights,
    )
    combined = _concat_bundles(imports, fit, calibration)
    combined_targets = _targets_for_mode(combined, mode)
    calibration_indices = list(
        range(len(fit["rows"]), len(combined["rows"]))
    )
    model, calibration_method = reliability._fit_frozen_calibrator(
        pipeline,
        combined["frame"],
        calibration_indices,
        combined_targets,
        method="sigmoid",
    )
    positive_classes = _positive_classes(mode)
    threshold_scores = reliability._queue_scores(
        model,
        threshold["frame"],
        list(range(len(threshold["rows"]))),
        positive_classes,
    )
    threshold_selection = reliability.select_v49_threshold(
        threshold["targets"],
        threshold_scores,
    )
    selected_threshold = _number(
        threshold_selection.get("selected_threshold"),
        0.5,
    )
    evaluation_scores = reliability._queue_scores(
        model,
        evaluation["frame"],
        list(range(len(evaluation["rows"]))),
        positive_classes,
    )
    predictions = [
        "needs_review" if score >= selected_threshold else "non_threat"
        for score in evaluation_scores
    ]
    metrics = frozen._binary_metrics(evaluation["targets"], predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            evaluation["rows"],
            list(range(len(evaluation["rows"]))),
            predictions,
        )
    )
    calibration_report = frozen._calibration_report(
        evaluation["targets"],
        evaluation_scores,
    )
    classification_diagnostics = None
    severity_model = None
    if mode == "three_class_soc_queue":
        direct = [
            str(value)
            for value in model.predict(evaluation["frame"])
        ]
        classification_diagnostics = reliability._classification_diagnostics(
            _three_class_targets(evaluation["original_labels"]),
            direct,
        )
    elif mode == "hierarchical_two_stage":
        severity_indices = [
            index
            for index, value in enumerate(fit["original_labels"])
            if value in {"suspicious", "malicious"}
        ]
        severity_targets = [
            fit["original_labels"][index] for index in severity_indices
        ]
        if len(set(severity_targets)) >= 2:
            severity_fit = _slice_bundle(
                imports,
                fit,
                severity_indices,
            )
            severity_model = _build_pipeline_for_columns(
                imports,
                model_type="extra_trees",
                class_weight="balanced",
                numeric_features=V56_NUMERIC_FEATURES,
                categorical_features=V56_CATEGORICAL_FEATURES,
            )
            severity_weights, _ = _fit_weights(
                severity_fit,
                severity_targets,
                variant=str(spec["weight_variant"]),
            )
            severity_model.fit(
                severity_fit["frame"],
                severity_targets,
                model__sample_weight=severity_weights,
            )
            severity_predictions = [
                str(value)
                for value in severity_model.predict(evaluation["frame"])
            ]
            combined_predictions = [
                severity if queue == "needs_review" else "benign_like"
                for queue, severity in zip(
                    predictions,
                    severity_predictions,
                    strict=True,
                )
            ]
            classification_diagnostics = (
                reliability._classification_diagnostics(
                    _three_class_targets(evaluation["original_labels"]),
                    combined_predictions,
                )
            )
    result = {
        "status": "evaluated",
        "name": spec["name"],
        "model_type": spec["model_type"],
        "target_mode": mode,
        "fit_rows": len(fit["rows"]),
        "calibration_rows": len(calibration["rows"]),
        "threshold_rows": len(threshold["rows"]),
        "evaluation_rows": len(evaluation["rows"]),
        "metrics": metrics,
        "calibration": calibration_report,
        "calibration_method": calibration_method,
        "threshold_selection": threshold_selection,
        "sample_weighting": weight_summary,
        "error_patterns": _error_pattern_summary(
            evaluation,
            evaluation["targets"],
            predictions,
        ),
        "classification_diagnostics": classification_diagnostics,
        "development_gate": _development_gate(
            metrics,
            calibration_report,
        ),
        "training_seconds": round(time.perf_counter() - started, 4),
        "locked_v53_labels_used": False,
        "future_validation_labels_used": False,
        "active_artifact_written": False,
        "_model": model,
        "_threshold": selected_threshold,
        "_positive_classes": positive_classes,
        "_severity_model": severity_model,
    }
    return result


def _public_candidate(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in result.items()
        if not key.startswith("_")
    }


def build_development_views(
    imports: Any,
    *,
    human: dict[str, dict[str, Any]],
    private: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    views: list[dict[str, Any]] = []
    private_fit = private["development_fit"]
    if len(private_fit["rows"]) >= 80:
        ordered = sorted(
            range(len(private_fit["rows"])),
            key=lambda index: (
                private_fit["rows"][index].get("timestamp")
                or datetime.min.replace(tzinfo=timezone.utc),
                index,
            ),
        )
        for fold_index, share in enumerate((0.75, 1.0), start=1):
            prefix = ordered[: max(40, int(len(ordered) * share))]
            subset = _slice_bundle(imports, private_fit, prefix)
            fit, calibration, threshold, evaluation = _chronological_slices(
                imports,
                subset,
            )
            fit = _concat_bundles(
                imports,
                human["development_fit"],
                fit,
            )
            views.append(
                {
                    "name": f"nested_private_chronological_{fold_index}",
                    "fit": fit,
                    "calibration": calibration,
                    "threshold": threshold,
                    "evaluation": evaluation,
                    "uses_future_validation": False,
                    "uses_locked_v53": False,
                }
            )

    combined_threshold = _concat_bundles(
        imports,
        human["threshold"],
        private["threshold"],
    )
    threshold_order = sorted(
        range(len(combined_threshold["rows"])),
        key=lambda index: (
            combined_threshold["rows"][index].get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc),
            index,
        ),
    )
    split = max(1, int(len(threshold_order) * 0.55))
    threshold_selection = _slice_bundle(
        imports,
        combined_threshold,
        threshold_order[:split],
    )
    development_evaluation = _slice_bundle(
        imports,
        combined_threshold,
        threshold_order[split:],
    )
    if len(development_evaluation["rows"]):
        views.append(
            {
                "name": "predeclared_role_development",
                "fit": _concat_bundles(
                    imports,
                    human["development_fit"],
                    private["development_fit"],
                ),
                "calibration": _concat_bundles(
                    imports,
                    human["calibration"],
                    private["calibration"],
                ),
                "threshold": threshold_selection,
                "evaluation": development_evaluation,
                "uses_future_validation": False,
                "uses_locked_v53": False,
            }
        )
    return views


def run_supervised_development_comparison(
    imports: Any,
    views: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    public_views: list[dict[str, Any]] = []
    by_candidate: dict[str, list[dict[str, Any]]] = defaultdict(list)
    internal_by_candidate: dict[str, dict[str, Any]] = {}
    for view in views:
        strategies = []
        for spec in V56_CANDIDATE_SPECS:
            result = _fit_candidate(
                imports,
                fit=view["fit"],
                calibration=view["calibration"],
                threshold=view["threshold"],
                evaluation=view["evaluation"],
                spec=spec,
            )
            public = _public_candidate(result)
            strategies.append(public)
            if result.get("status") == "evaluated":
                by_candidate[str(spec["name"])].append(
                    {"view": view["name"], **public}
                )
                internal_by_candidate[str(spec["name"])] = result
        public_views.append(
            {
                "name": view["name"],
                "uses_future_validation": False,
                "uses_locked_v53": False,
                "partition_sizes": {
                    key: len(view[key]["rows"])
                    for key in ("fit", "calibration", "threshold", "evaluation")
                },
                "strategies": strategies,
            }
        )

    summaries: dict[str, Any] = {}
    ranked: list[tuple[Any, ...]] = []
    for name, evaluations in by_candidate.items():
        metrics = [item["metrics"] for item in evaluations]
        calibrations = [item["calibration"] for item in evaluations]

        def metric_values(field: str) -> list[float]:
            return [
                float(item[field])
                for item in metrics
                if item.get(field) is not None
            ]

        def calibration_values(field: str) -> list[float]:
            return [
                float(item[field])
                for item in calibrations
                if item.get(field) is not None
            ]

        ranges = {
            field: {
                "minimum": round(min(values), 4),
                "maximum": round(max(values), 4),
                "mean": round(mean(values), 4),
            }
            for field in (
                "queue_precision",
                "queue_recall",
                "queue_f1",
                "benign_like_false_positive_rate",
                "suspicious_recall",
                "malicious_recall",
                "macro_f1",
                "weighted_f1",
                "review_queue_rate",
            )
            if (values := metric_values(field))
        }
        calibration_ranges = {
            field: {
                "minimum": round(min(values), 4),
                "maximum": round(max(values), 4),
                "mean": round(mean(values), 4),
            }
            for field in (
                "brier_score",
                "expected_calibration_error",
                "max_confidence_accuracy_gap",
            )
            if (values := calibration_values(field))
        }
        passing = sum(
            1
            for item in evaluations
            if (item.get("development_gate") or {}).get("passed")
        )
        summary = {
            "evaluated_views": len(evaluations),
            "passing_views": passing,
            "all_views_passed": bool(evaluations)
            and passing == len(evaluations),
            "metric_ranges": ranges,
            "calibration_ranges": calibration_ranges,
        }
        summaries[name] = summary
        minimum_f1 = _number(
            (ranges.get("queue_f1") or {}).get("minimum")
        )
        maximum_fpr = _number(
            (ranges.get("benign_like_false_positive_rate") or {}).get(
                "maximum"
            ),
            1.0,
        )
        minimum_suspicious = _number(
            (ranges.get("suspicious_recall") or {}).get("minimum")
        )
        minimum_malicious = _number(
            (ranges.get("malicious_recall") or {}).get("minimum")
        )
        maximum_ece = _number(
            (
                calibration_ranges.get("expected_calibration_error") or {}
            ).get("maximum"),
            1.0,
        )
        score = (
            minimum_f1
            + (0.20 * minimum_suspicious)
            + (0.20 * minimum_malicious)
            - (0.80 * maximum_fpr)
            - (0.20 * maximum_ece)
        )
        ranked.append(
            (
                passing,
                len(evaluations),
                round(score, 6),
                -maximum_fpr,
                minimum_f1,
                name,
            )
        )
    leader: dict[str, Any] | None = None
    if ranked:
        selected = max(ranked)
        name = str(selected[-1])
        leader = {
            "name": name,
            "selection_basis": "development_roles_and_nested_chronology_only",
            "locked_v53_labels_used": False,
            "future_validation_labels_used": False,
            "summary": summaries[name],
            "passed_all_development_gates": bool(
                summaries[name]["all_views_passed"]
            ),
            "_latest_fitted": internal_by_candidate[name],
        }
    return {
        "status": "evaluated" if views else "failed_closed_no_views",
        "views": public_views,
        "candidate_summaries": summaries,
        "locked_v53_labels_used_for_selection": False,
        "future_validation_labels_used_for_selection": False,
        "provenance_balanced_sampling": True,
        "ambiguous_rows_used_for_training": False,
    }, leader


def freeze_diagnostic_candidate(
    leader: dict[str, Any] | None,
    *,
    role_manifest: dict[str, Any],
    evidence_lock: dict[str, Any],
) -> dict[str, Any] | None:
    if not leader:
        return None
    fitted = leader.get("_latest_fitted") or {}
    if fitted.get("status") != "evaluated":
        return None
    return {
        "name": leader["name"],
        "selection_basis": leader["selection_basis"],
        "freeze_fingerprint": _stable_hash(
            {
                "candidate": leader["name"],
                "policy": V56_POLICY_VERSION,
                "roles": role_manifest.get("roles"),
                "governed_lock": (
                    evidence_lock.get("overall_fingerprint")
                    or evidence_lock.get("lock_fingerprint")
                ),
                "threshold": fitted.get("_threshold"),
            }
        ),
        "threshold": fitted.get("_threshold"),
        "frozen_before_future_label_access": True,
        "locked_v53_labels_used": False,
        "future_validation_labels_used_for_selection": False,
        "eligible_for_activation": False,
        "active_artifact_written": False,
        "_model": fitted.get("_model"),
        "_severity_model": fitted.get("_severity_model"),
        "_positive_classes": fitted.get("_positive_classes"),
    }


def evaluate_untouched_future_once(
    candidate: dict[str, Any],
    future: dict[str, Any],
) -> dict[str, Any]:
    if not candidate.get("frozen_before_future_label_access"):
        raise ValueError(
            "Candidate must be frozen before future labels are opened."
        )
    model = candidate.get("_model")
    if model is None:
        return {
            "status": "failed_closed_missing_frozen_model",
            "future_labels_opened_after_freeze": True,
        }
    if not len(future["rows"]):
        return {
            "status": "failed_closed_no_training_eligible_future_rows",
            "future_labels_opened_after_freeze": True,
            "future_labels_used_for_candidate_selection": False,
        }
    scores = reliability._queue_scores(
        model,
        future["frame"],
        list(range(len(future["rows"]))),
        set(candidate.get("_positive_classes") or {"needs_review"}),
    )
    threshold = _number(candidate.get("threshold"), 0.5)
    predictions = [
        "needs_review" if score >= threshold else "non_threat"
        for score in scores
    ]
    metrics = frozen._binary_metrics(future["targets"], predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            future["rows"],
            list(range(len(future["rows"]))),
            predictions,
        )
    )
    calibration = frozen._calibration_report(future["targets"], scores)
    return {
        "status": "evaluated_once_after_candidate_freeze",
        "rows": len(future["rows"]),
        "metrics": metrics,
        "calibration": calibration,
        "error_patterns": _error_pattern_summary(
            future,
            future["targets"],
            predictions,
        ),
        "development_gate": _development_gate(metrics, calibration),
        "future_labels_opened_after_freeze": True,
        "future_labels_used_for_candidate_selection": False,
        "locked_v53_labels_used": False,
        "single_private_device": True,
        "independent_validation_claimed": False,
    }


def _isolation_predictions(
    pipeline: Any,
    bundle: dict[str, Any],
) -> tuple[list[str], list[float]]:
    predictions = pipeline.predict(bundle["frame"])
    scores = [
        float(value)
        for value in pipeline.decision_function(bundle["frame"])
    ]
    queue = [
        "needs_review" if int(value) == -1 else "non_threat"
        for value in predictions
    ]
    return queue, scores


def _anomaly_regime_summary(
    bundle: dict[str, Any],
    predictions: list[str],
) -> dict[str, Any]:
    counters: dict[str, Counter[str]] = {
        "app": Counter(),
        "schema": Counter(),
        "time_window": Counter(),
        "provenance": Counter(),
    }
    totals: dict[str, Counter[str]] = {
        "app": Counter(),
        "schema": Counter(),
        "time_window": Counter(),
        "provenance": Counter(),
    }
    for row, prediction in zip(bundle["rows"], predictions, strict=True):
        values = {
            "app": str(row.get("app") or "unknown"),
            "schema": str(row.get("schema") or "unknown"),
            "time_window": (
                row["timestamp"].replace(second=0, microsecond=0).isoformat()
                if isinstance(row.get("timestamp"), datetime)
                else "missing"
            ),
            "provenance": str(row.get("provenance") or "unknown"),
        }
        for field, value in values.items():
            totals[field][value] += 1
            if prediction == "needs_review":
                counters[field][value] += 1
    output: dict[str, Any] = {}
    for field in counters:
        rows = [
            {
                "value": value,
                "rows": int(total),
                "anomaly_rows": int(counters[field][value]),
                "anomaly_rate": round(
                    counters[field][value] / max(1, total),
                    4,
                ),
            }
            for value, total in totals[field].items()
        ]
        rows.sort(
            key=lambda item: (
                item["anomaly_rate"],
                item["rows"],
            ),
            reverse=True,
        )
        output[field] = rows[:12]
    output["private_identifiers_included"] = False
    return output


def run_isolation_forest_diagnostics(
    imports: Any,
    *,
    fit: dict[str, Any],
    development_evaluation: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import IsolationForest
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError:
        return {
            "status": "skipped_dependencies_unavailable",
            "active_artifact_written": False,
        }, None
    benign_indices = [
        index
        for index, label in enumerate(fit["original_labels"])
        if label == "benign"
    ]
    if len(benign_indices) < 50:
        return {
            "status": "failed_closed_insufficient_confident_benign",
            "confident_benign_rows": len(benign_indices),
            "active_artifact_written": False,
        }, None
    benign_fit = _slice_bundle(
        imports,
        fit,
        benign_indices[: min(6000, len(benign_indices))],
    )
    results = []
    internal: dict[float, Any] = {}
    for contamination in (0.01, 0.02, 0.05, 0.08):
        try:
            encoder = OneHotEncoder(
                handle_unknown="ignore",
                sparse_output=False,
            )
        except TypeError:  # pragma: no cover - older supported sklearn
            encoder = OneHotEncoder(handle_unknown="ignore", sparse=False)
        preprocess = ColumnTransformer(
            [
                (
                    "numeric",
                    SimpleImputer(strategy="median"),
                    V56_NUMERIC_FEATURES,
                ),
                (
                    "categorical",
                    Pipeline(
                        [
                            (
                                "imputer",
                                SimpleImputer(strategy="most_frequent"),
                            ),
                            ("onehot", encoder),
                        ]
                    ),
                    V56_CATEGORICAL_FEATURES,
                ),
            ]
        )
        pipeline = Pipeline(
            [
                ("preprocess", preprocess),
                (
                    "model",
                    IsolationForest(
                        n_estimators=180,
                        contamination=contamination,
                        random_state=42,
                        n_jobs=-1,
                    ),
                ),
            ]
        )
        started = time.perf_counter()
        pipeline.fit(benign_fit["frame"])
        predictions, scores = _isolation_predictions(
            pipeline,
            development_evaluation,
        )
        metrics = frozen._binary_metrics(
            development_evaluation["targets"],
            predictions,
        )
        metrics.update(
            frozen._diagnostic_original_recall(
                development_evaluation["rows"],
                list(range(len(development_evaluation["rows"]))),
                predictions,
            )
        )
        result = {
            "contamination": contamination,
            "confident_benign_fit_rows": len(benign_fit["rows"]),
            "evaluation_rows": len(development_evaluation["rows"]),
            "metrics": metrics,
            "score_distribution": {
                "minimum": round(min(scores), 6) if scores else None,
                "maximum": round(max(scores), 6) if scores else None,
                "mean": round(mean(scores), 6) if scores else None,
            },
            "regime_summary": _anomaly_regime_summary(
                development_evaluation,
                predictions,
            ),
            "training_seconds": round(time.perf_counter() - started, 4),
            "development_only": True,
            "active_artifact_written": False,
        }
        results.append(result)
        internal[contamination] = pipeline
    selected = max(
        results,
        key=lambda item: (
            _number(item["metrics"].get("queue_recall"))
            - (
                2.0
                * _number(
                    item["metrics"].get(
                        "benign_like_false_positive_rate"
                    )
                )
            ),
            _number(item["metrics"].get("queue_f1")),
            -float(item["contamination"]),
        ),
    )
    frozen_candidate = {
        "contamination": selected["contamination"],
        "selection_basis": "development_weak_label_agreement_only",
        "frozen_before_future_label_access": True,
        "active_artifact_written": False,
        "_pipeline": internal[float(selected["contamination"])],
    }
    return {
        "status": "evaluated",
        "baseline_training_policy": "high_confidence_benign_only",
        "strategies": results,
        "selected_development_strategy": {
            key: value
            for key, value in selected.items()
            if key != "regime_summary"
        },
        "active_artifact_written": False,
    }, frozen_candidate


def evaluate_isolation_future_once(
    candidate: dict[str, Any] | None,
    future: dict[str, Any],
) -> dict[str, Any]:
    if not candidate:
        return {"status": "not_evaluated_no_diagnostic_candidate"}
    if not candidate.get("frozen_before_future_label_access"):
        raise ValueError(
            "IsolationForest candidate must be frozen before future access."
        )
    if not len(future["rows"]):
        return {
            "status": "failed_closed_no_training_eligible_future_rows",
            "future_labels_used_for_selection": False,
            "active_artifact_written": False,
        }
    predictions, scores = _isolation_predictions(
        candidate["_pipeline"],
        future,
    )
    metrics = frozen._binary_metrics(future["targets"], predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            future["rows"],
            list(range(len(future["rows"]))),
            predictions,
        )
    )
    return {
        "status": "evaluated_once_after_freeze",
        "rows": len(future["rows"]),
        "contamination": candidate["contamination"],
        "metrics": metrics,
        "score_distribution": {
            "minimum": round(min(scores), 6) if scores else None,
            "maximum": round(max(scores), 6) if scores else None,
            "mean": round(mean(scores), 6) if scores else None,
        },
        "regime_summary": _anomaly_regime_summary(future, predictions),
        "future_labels_used_for_selection": False,
        "active_artifact_written": False,
        "independent_validation_claimed": False,
    }


def audit_current_isolation_on_development(
    imports: Any,
    development_evaluation: dict[str, Any],
) -> dict[str, Any]:
    path = get_settings().resolved_model_path
    state_before = v55._file_state(path)
    if not state_before.get("exists"):
        return {
            "status": "active_artifact_unavailable",
            "artifact": state_before,
            "active_artifact_written": False,
        }
    try:
        model = imports[0].load(path)
        predictions = model.predict(development_evaluation["frame"])
        scores = [
            float(value)
            for value in model.decision_function(
                development_evaluation["frame"]
            )
        ]
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "status": "active_artifact_incompatible_with_v56_features",
            "error_type": exc.__class__.__name__,
            "artifact": state_before,
            "active_artifact_written": False,
        }
    queue = [
        "needs_review" if int(value) == -1 else "non_threat"
        for value in predictions
    ]
    metrics = frozen._binary_metrics(
        development_evaluation["targets"],
        queue,
    )
    metrics.update(
        frozen._diagnostic_original_recall(
            development_evaluation["rows"],
            list(range(len(development_evaluation["rows"]))),
            queue,
        )
    )
    state_after = v55._file_state(path)
    return {
        "status": "evaluated_on_development_roles",
        "artifact": state_before,
        "artifact_unchanged": state_before == state_after,
        "rows": len(development_evaluation["rows"]),
        "metrics": metrics,
        "score_distribution": {
            "minimum": round(min(scores), 6) if scores else None,
            "maximum": round(max(scores), 6) if scores else None,
            "mean": round(mean(scores), 6) if scores else None,
        },
        "regime_summary": _anomaly_regime_summary(
            development_evaluation,
            queue,
        ),
        "future_validation_scored": False,
        "active_artifact_written": False,
    }


def build_private_drift_profile(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    fields = {
        "application": "app",
        "action": "action",
        "schema": "schema_bucket",
        "log_type": "log_type",
    }
    role_distributions: dict[str, Any] = {}
    normalized: dict[int, dict[str, dict[str, float]]] = {}
    for role_rank, role_name in ROLE_NAMES.items():
        if role_rank == 4:
            continue
        role_distributions[role_name] = {}
        normalized[role_rank] = {}
        for label, column in fields.items():
            values = Counter(
                {
                    str(value): int(count)
                    for value, count in connection.execute(
                        f"SELECT {column}, COUNT(*) FROM events "  # noqa: S608
                        "WHERE role_rank=? GROUP BY "
                        f"{column}",  # noqa: S608
                        (role_rank,),
                    )
                }
            )
            total = max(1, sum(values.values()))
            normalized[role_rank][label] = {
                key: count / total for key, count in values.items()
            }
            role_distributions[role_name][label] = _safe_top(
                values,
                limit=10,
            )
        quality = connection.execute(
            "SELECT COUNT(*), SUM(parser_error), "
            "SUM(parser_warning_count), SUM(required_missing_count), "
            "SUM(unknown_app_flag) FROM events WHERE role_rank=?",
            (role_rank,),
        ).fetchone()
        total = max(1, int(quality[0] or 0))
        role_distributions[role_name]["quality"] = {
            "rows": int(quality[0] or 0),
            "parser_error_rate": round(_integer(quality[1]) / total, 6),
            "parser_warning_per_row": round(
                _integer(quality[2]) / total,
                6,
            ),
            "required_missing_per_row": round(
                _integer(quality[3]) / total,
                6,
            ),
            "unknown_app_rate": round(_integer(quality[4]) / total, 6),
        }

    def total_variation(
        left: dict[str, float],
        right: dict[str, float],
    ) -> float:
        keys = set(left) | set(right)
        return round(
            0.5
            * sum(abs(left.get(key, 0.0) - right.get(key, 0.0)) for key in keys),
            6,
        )

    fit_to_future = {
        field: total_variation(
            normalized.get(0, {}).get(field, {}),
            normalized.get(3, {}).get(field, {}),
        )
        for field in fields
    }
    maximum = max(fit_to_future.values(), default=0.0)
    status = (
        "OOD Warning"
        if maximum >= 0.50
        else "Drift Warning"
        if maximum >= 0.25
        else "Stable"
    )
    return {
        "status": status,
        "fit_to_future_total_variation": fit_to_future,
        "role_distributions": role_distributions,
        "future_labels_inspected": False,
        "private_identifiers_included": False,
        "raw_logs_included": False,
    }


def _serialize_candidate(
    imports: Any,
    candidate: dict[str, Any] | None,
    *,
    output_dir: Path,
    stamp: str,
) -> dict[str, Any]:
    if not candidate or candidate.get("_model") is None:
        return {
            "written": False,
            "reason": "no_frozen_supervised_candidate",
            "active_artifact_written": False,
        }
    path = output_dir / f"v5_6_diagnostic_candidate_{stamp}.joblib"
    imports[0].dump(
        {
            "pipeline": candidate["_model"],
            "severity_pipeline": candidate.get("_severity_model"),
            "threshold": candidate.get("threshold"),
            "candidate_name": candidate.get("name"),
            "version": V56_VERSION,
            "lifecycle": "shadow_observation",
            "active": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "label_policy": V56_POLICY_VERSION,
        },
        path,
    )
    state = v55._file_state(path)
    return {
        "written": True,
        "artifact_name": path.name,
        "size_bytes": state.get("size_bytes"),
        "sha256": state.get("sha256"),
        "ignored_output": True,
        "active_artifact_written": False,
        "active_artifact_replaced": False,
        "path_returned": False,
    }


def _readiness(
    *,
    lock_validation: dict[str, Any],
    future_supervised: dict[str, Any] | None,
    future_isolation: dict[str, Any] | None,
    safety: dict[str, Any],
) -> dict[str, Any]:
    supervised_gate = bool(
        future_supervised
        and (future_supervised.get("development_gate") or {}).get("passed")
    )
    isolation_metrics = (
        (future_isolation or {}).get("metrics") or {}
    )
    isolation_gate = bool(
        future_isolation
        and _number(
            isolation_metrics.get("benign_like_false_positive_rate"),
            1.0,
        )
        <= 0.10
        and _number(isolation_metrics.get("queue_recall")) >= 0.60
    )
    checks = {
        "v5_4_evidence_lock_matched": bool(lock_validation.get("passed")),
        "configured_database_unchanged": bool(
            safety.get("database_counts_unchanged")
        ),
        "active_model_artifacts_unchanged": bool(
            safety.get("model_artifacts_unchanged")
        ),
        "untouched_private_future_supervised_gate": supervised_gate,
        "untouched_private_future_isolation_gate": isolation_gate,
        "independent_multi_device_evidence": False,
        "genuine_human_ground_truth_for_private_evidence": False,
    }
    blockers = [
        name.replace("_", " ")
        for name, passed in checks.items()
        if not passed
    ]
    return {
        "decision": "shadow_observation",
        "checks": checks,
        "blockers": blockers,
        "candidate_selected": bool(future_supervised),
        "eligible_for_activation": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "independent_validation_claimed": False,
        "single_private_device_limitation": True,
        "weak_label_agreement_not_ground_truth_accuracy": True,
    }


def _public_freeze(candidate: dict[str, Any] | None) -> dict[str, Any] | None:
    if not candidate:
        return None
    return {
        key: value
        for key, value in candidate.items()
        if not key.startswith("_")
    }


def _comparison_to_v55(
    future_supervised: dict[str, Any] | None,
    future_isolation: dict[str, Any] | None,
) -> dict[str, Any]:
    supervised = (future_supervised or {}).get("metrics") or {}
    calibration = (future_supervised or {}).get("calibration") or {}
    isolation = (future_isolation or {}).get("metrics") or {}

    def comparison(
        baseline: float,
        current: Any,
        *,
        lower_is_better: bool,
    ) -> dict[str, Any]:
        value = None if current is None else _number(current)
        delta = None if value is None else round(value - baseline, 4)
        improved = (
            None
            if delta is None
            else delta < 0
            if lower_is_better
            else delta > 0
        )
        return {
            "v5_5": baseline,
            "v5_6_private_future": value,
            "delta": delta,
            "direction_improved": improved,
        }

    return {
        "queue_f1": comparison(
            V55_BASELINE["queue_f1"],
            supervised.get("queue_f1"),
            lower_is_better=False,
        ),
        "benign_like_false_positive_rate": comparison(
            V55_BASELINE["benign_like_false_positive_rate"],
            supervised.get("benign_like_false_positive_rate"),
            lower_is_better=True,
        ),
        "suspicious_recall": comparison(
            V55_BASELINE["suspicious_recall"],
            supervised.get("suspicious_recall"),
            lower_is_better=False,
        ),
        "malicious_recall": comparison(
            V55_BASELINE["malicious_recall"],
            supervised.get("malicious_recall"),
            lower_is_better=False,
        ),
        "expected_calibration_error": comparison(
            V55_BASELINE["expected_calibration_error"],
            calibration.get("expected_calibration_error"),
            lower_is_better=True,
        ),
        "isolation_forest_false_positive_rate": comparison(
            V55_BASELINE["isolation_forest_false_positive_rate"],
            isolation.get("benign_like_false_positive_rate"),
            lower_is_better=True,
        ),
        "isolation_forest_threat_capture": comparison(
            V55_BASELINE["isolation_forest_threat_capture"],
            isolation.get("queue_recall"),
            lower_is_better=False,
        ),
        "comparison_is_source_specific": True,
        "weak_label_agreement_only": True,
        "production_accuracy_claimed": False,
    }


def _render_report(result: dict[str, Any]) -> str:
    profile = result.get("private_profile") or {}
    roles = result.get("chronological_protocol") or {}
    labels = result.get("assisted_labeling") or {}
    future = result.get("untouched_future_validation") or {}
    future_supervised = future.get("supervised") or {}
    future_metrics = future_supervised.get("metrics") or {}
    readiness = result.get("readiness") or {}
    safety = result.get("safety") or {}
    lines = [
        "# v5.6 Private PAN-OS Evidence and Assisted Model Repair",
        "",
        "## Integrity Boundary",
        "",
        f"- v5.4 evidence lock: `{result.get('evidence_lock_validation', {}).get('status')}`",
        "- v5.3 final, rolling, external, and quarantine labels used for selection: `false`",
        "- Private file imported into configured database: `false`",
        "- Assisted decisions marked human-reviewed: `false`",
        "- Rules remain alert-authoritative: `true`",
        "- Automatic response enabled: `false`",
        "- Real firewall blocking enabled: `false`",
        "",
        "## Private Evidence Profile",
        "",
        f"- Rows streamed: `{profile.get('rows_processed')}`",
        f"- Parser successes: `{profile.get('parser_successes')}`",
        f"- Parser failures: `{profile.get('parser_failures')}`",
        f"- Configured-database overlap rows: `{profile.get('configured_database_overlap_rows')}`",
        f"- Exact duplicate rows: `{profile.get('exact_duplicate_rows')}`",
        f"- Near-duplicate rows: `{profile.get('near_duplicate_rows')}`",
        f"- Bounded chunk size: `{(profile.get('streaming') or {}).get('bounded_chunk_size')}`",
        "",
        "## Chronological Protocol",
        "",
        f"- Status: `{roles.get('status')}`",
        f"- Distinct time windows: `{roles.get('distinct_time_windows')}`",
        f"- Duplicate families contained: `{roles.get('duplicate_families_contained')}`",
    ]
    for role, summary in (roles.get("roles") or {}).items():
        lines.append(
            f"- {role}: `{summary.get('rows')}` events / "
            f"`{summary.get('representative_families')}` representative families"
        )
    lines.extend(
        [
            "",
            "## Assisted Evidence",
            "",
            f"- Policy: `{labels.get('policy_version')}`",
            f"- Development decisions: `{labels.get('decisions_by_event_count')}`",
            f"- Provenance: `{labels.get('provenance_by_event_count')}`",
            f"- High-confidence training events: `{labels.get('high_confidence_training_event_count')}`",
            f"- Ambiguous/quarantined events: `{labels.get('ambiguous_or_quarantined_event_count')}`",
            "- Human review claimed: `false`",
            "",
            "## Diagnostic Candidate",
            "",
            f"- Selected strategy: `{(result.get('frozen_diagnostic_candidate') or {}).get('name')}`",
            "- Candidate activated: `false`",
            "- Candidate production-promoted: `false`",
            f"- Future queue F1: `{future_metrics.get('queue_f1')}`",
            f"- Future benign-like FPR: `{future_metrics.get('benign_like_false_positive_rate')}`",
            f"- Future suspicious recall: `{future_metrics.get('suspicious_recall')}`",
            f"- Future malicious recall: `{future_metrics.get('malicious_recall')}`",
            f"- Future calibration ECE: `{(future_supervised.get('calibration') or {}).get('expected_calibration_error')}`",
            "",
            "## Readiness",
            "",
            f"- Lifecycle: `{readiness.get('decision')}`",
            "- Independent validation claimed: `false`",
            "- Single-private-device limitation: `true`",
            "- Weak-label agreement is not ground-truth accuracy.",
            "",
            "## Safety",
            "",
            f"- Configured database unchanged: `{safety.get('database_counts_unchanged')}`",
            f"- Active model artifacts unchanged: `{safety.get('model_artifacts_unchanged')}`",
            f"- Labels created in configured DB: `{safety.get('labels_created')}`",
            f"- Detection runs created: `{safety.get('detection_runs_created')}`",
            f"- Response actions created: `{safety.get('response_actions_created')}`",
            "",
            "## Remaining Blockers",
            "",
        ]
    )
    lines.extend(
        f"- {blocker}" for blocker in readiness.get("blockers") or []
    )
    return "\n".join(lines) + "\n"


def run_v56_private_panos_model_repair(
    db: Session,
    *,
    sample_path: str | Path,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    lock_path: str | Path = v54.V53_LOCK_PATH,
    chunk_size: int = 2000,
    max_fit_rows: int = 8000,
    max_calibration_rows: int = 3000,
    max_threshold_rows: int = 3500,
    max_future_rows: int = 4500,
    preflight_only: bool = False,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    path = Path(sample_path)
    output = Path(output_dir)
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    imports = _optional_imports()
    if imports is None:
        return {
            "ok": False,
            "status": "dependencies_unavailable",
            "version": V56_VERSION,
            "lifecycle_state": "shadow_observation",
        }

    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "message": dataset.get("message"),
            "version": V56_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    canonical_partition = frozen.build_frozen_partition(
        dataset["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(
        dataset["rows"],
        canonical_partition,
    )
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed_governed_partition_leakage",
            "version": V56_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    evidence_lock = v54.build_evidence_lock(dataset, output_dir=output)
    lock_validation = v54.validate_evidence_lock(
        evidence_lock,
        lock_path=Path(lock_path),
    )
    if not lock_validation.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed_evidence_lock_mismatch",
            "message": "v5.4 evidence lock mismatch; private processing refused.",
            "version": V56_VERSION,
            "lifecycle_state": "shadow_observation",
            "evidence_lock_validation": lock_validation,
        }

    with tempfile.TemporaryDirectory(prefix="atdr-v56-") as directory:
        disposable_path = Path(directory) / "derived-evidence.sqlite3"
        connection = sqlite3.connect(disposable_path)
        try:
            profile = stream_private_file_to_disposable_index(
                path,
                connection,
                database_url=get_settings().database_url,
                chunk_size=chunk_size,
            )
            if not profile.get("ok"):
                return {
                    "ok": False,
                    "status": profile.get("status"),
                    "version": V56_VERSION,
                    "private_profile": profile,
                    "lifecycle_state": "shadow_observation",
                }
            roles = predeclare_chronological_roles(connection)
            if not roles.get("ok"):
                return {
                    "ok": False,
                    "status": roles.get("status"),
                    "version": V56_VERSION,
                    "private_profile": profile,
                    "chronological_protocol": roles,
                    "lifecycle_state": "shadow_observation",
                }
            aggregates = build_disposable_behavior_aggregates(connection)
            drift = build_private_drift_profile(connection)
            if preflight_only:
                counts_after = frozen._database_counts(db)
                artifacts_after = v55._model_artifact_states()
                return {
                    "ok": bool(
                        counts_before == counts_after
                        and artifacts_before == artifacts_after
                    ),
                    "status": "preflight_complete",
                    "version": V56_VERSION,
                    "lifecycle_state": "shadow_observation",
                    "evidence_lock_validation": lock_validation,
                    "private_profile": profile,
                    "chronological_protocol": roles,
                    "behavior_aggregates": aggregates,
                    "drift_profile": drift,
                    "safety": {
                        "database_counts_unchanged": counts_before
                        == counts_after,
                        "model_artifacts_unchanged": artifacts_before
                        == artifacts_after,
                        "private_file_imported": False,
                        "temporary_storage_disposed": True,
                    },
                    "path_returned": False,
                    "raw_evidence_returned": False,
                }

            labeling = apply_assisted_policy(connection)
            human = build_human_role_bundles(
                dataset,
                canonical_partition,
            )
            private: dict[str, dict[str, Any]] = {}
            private_selection: dict[str, Any] = {}
            for role_rank, role_name, cap in (
                (0, "development_fit", max_fit_rows),
                (1, "calibration", max_calibration_rows),
                (2, "threshold", max_threshold_rows),
            ):
                private[role_name], private_selection[role_name] = (
                    load_private_role_bundle(
                        connection,
                        imports,
                        role_rank=role_rank,
                        max_rows=cap,
                    )
                )
            views = build_development_views(
                imports,
                human=human,
                private=private,
            )
            comparison, leader = run_supervised_development_comparison(
                imports,
                views,
            )
            candidate = freeze_diagnostic_candidate(
                leader,
                role_manifest=roles,
                evidence_lock=evidence_lock,
            )
            development_fit = _concat_bundles(
                imports,
                human["development_fit"],
                private["development_fit"],
            )
            development_evaluation = (
                views[-1]["evaluation"]
                if views
                else _empty_bundle(imports)
            )
            current_isolation = audit_current_isolation_on_development(
                imports,
                development_evaluation,
            )
            isolation_diagnostics, isolation_candidate = (
                run_isolation_forest_diagnostics(
                    imports,
                    fit=development_fit,
                    development_evaluation=development_evaluation,
                )
            )
            any_candidate_frozen = bool(candidate or isolation_candidate)
            future_summary = (
                open_future_assisted_summary_after_freeze(
                    connection,
                    candidate_frozen=True,
                )
                if any_candidate_frozen
                else {
                    "status": "sealed_no_candidate_frozen",
                    "future_labels_used_for_candidate_selection": False,
                }
            )
            future_bundle = _empty_bundle(imports)
            future_selection: dict[str, Any] = {
                "role": "untouched_future_validation",
                "selected_representative_rows": 0,
                "future_labels_opened": False,
            }
            if any_candidate_frozen:
                future_bundle, future_selection = load_private_role_bundle(
                    connection,
                    imports,
                    role_rank=3,
                    max_rows=max_future_rows,
                    open_future_labels=True,
                )
            future_supervised = (
                evaluate_untouched_future_once(candidate, future_bundle)
                if candidate
                else {
                    "status": "not_evaluated_no_supervised_candidate",
                    "future_labels_used_for_candidate_selection": False,
                }
            )
            future_isolation = evaluate_isolation_future_once(
                isolation_candidate,
                future_bundle,
            )
            candidate_artifact = {
                "written": False,
                "reason": "output_disabled",
                "active_artifact_written": False,
            }
            stamp = _stamp()
            if write_output:
                output.mkdir(parents=True, exist_ok=True)
                candidate_artifact = _serialize_candidate(
                    imports,
                    candidate,
                    output_dir=output,
                    stamp=stamp,
                )
        finally:
            connection.close()

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    safety = {
        "database_counts_before": counts_before,
        "database_counts_after": counts_after,
        "database_counts_unchanged": counts_before == counts_after,
        "model_artifacts_before": artifacts_before,
        "model_artifacts_after": artifacts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "private_file_imported_into_configured_database": False,
        "temporary_storage_disposed": True,
        "active_model_artifact_written": False,
        "active_model_artifact_replaced": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "ml_changed_authoritative_alerts": False,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        lock_validation=lock_validation,
        future_supervised=future_supervised,
        future_isolation=future_isolation,
        safety=safety,
    )
    comparison_v55 = _comparison_to_v55(
        future_supervised,
        future_isolation,
    )
    public_leader = None
    if leader:
        public_leader = {
            key: value
            for key, value in leader.items()
            if not key.startswith("_")
        }
    result = {
        "ok": bool(
            lock_validation.get("passed")
            and safety["database_counts_unchanged"]
            and safety["model_artifacts_unchanged"]
            and safety["labels_created"] == 0
            and safety["response_actions_created"] == 0
        ),
        "status": "evaluated",
        "version": V56_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lifecycle_state": "shadow_observation",
        "evidence_lock_validation": lock_validation,
        "governed_evidence": {
            "development_roles": list(v54.DEVELOPMENT_ROLES),
            "locked_v53_final_rows": len(
                canonical_partition["final_test_idx"]
            ),
            "quarantined_rows": len(
                canonical_partition["quarantined_idx"]
            ),
            "locked_v53_labels_used_for_selection": False,
            "external_labels_used_for_selection": False,
            "duplicate_group_isolation": bool(leakage.get("passed")),
        },
        "private_profile": profile,
        "chronological_protocol": roles,
        "behavior_aggregates": aggregates,
        "drift_profile": drift,
        "assisted_labeling": {
            **labeling,
            "future_validation": future_summary,
        },
        "model_sampling": {
            "development_roles": private_selection,
            "future_validation": future_selection,
            "human_reviewed_development_rows": sum(
                len(value["rows"]) for value in human.values()
            ),
            "assisted_rows_have_lower_weight": True,
            "ambiguous_rows_used_for_training": False,
        },
        "supervised_development_comparison": comparison,
        "selected_development_leader": public_leader,
        "frozen_diagnostic_candidate": _public_freeze(candidate),
        "diagnostic_candidate_artifact": candidate_artifact,
        "isolation_forest": {
            "active_artifact_development_audit": current_isolation,
            "diagnostic_alternatives": isolation_diagnostics,
            "frozen_diagnostic_candidate": _public_freeze(
                isolation_candidate
            ),
        },
        "untouched_future_validation": {
            "opened_after_candidate_freeze": any_candidate_frozen,
            "supervised": future_supervised,
            "isolation_forest": future_isolation,
            "used_for_candidate_selection": False,
            "independent_validation_claimed": False,
        },
        "v5_5_comparison": comparison_v55,
        "readiness": readiness,
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "privacy": {
            "private_path_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "reusable_row_fingerprints_returned": False,
            "secrets_exposed": False,
        },
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        report_path = output / f"v5_6_private_panos_model_repair_{stamp}.md"
        latest_path = output / V56_LATEST
        manifest_path = output / "v5_6_private_evidence_manifest_latest.json"
        report_path.write_text(_render_report(result), encoding="utf-8")
        latest_path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        manifest_path.write_text(
            json.dumps(
                {
                    "version": V56_VERSION,
                    "policy_version": V56_POLICY_VERSION,
                    "chronological_protocol": roles,
                    "private_profile": profile,
                    "drift_profile": drift,
                    "path_returned": False,
                    "raw_evidence_returned": False,
                    "private_identifiers_returned": False,
                    "reusable_row_fingerprints_returned": False,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        result["reports"] = {
            "markdown_file_name": report_path.name,
            "latest_json_file_name": latest_path.name,
            "private_manifest_file_name": manifest_path.name,
            "ignored_output": True,
            "private_paths_returned": False,
            "raw_logs_returned": False,
        }
    return result
