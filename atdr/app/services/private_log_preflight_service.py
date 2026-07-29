from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any

from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.parsers.paloalto_parser import parse_log_line


UNKNOWN_APPS = {
    "",
    "unknown",
    "unknown-tcp",
    "unknown-udp",
    "unknown-p2p",
    "incomplete",
    "not-applicable",
}
KEY_NORMALIZED_FIELDS = (
    "generated_time",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "action",
    "app",
    "src_zone",
    "dst_zone",
    "bytes",
    "packets",
    "app_risk",
)


def _top(counter: Counter[Any], *, limit: int = 20) -> list[dict[str, Any]]:
    return [
        {"value": str(value), "count": int(count)}
        for value, count in counter.most_common(limit)
    ]


def _ranked_counts(counter: Counter[str], *, limit: int = 10) -> list[dict[str, int]]:
    return [
        {"rank": index, "event_count": int(count)}
        for index, (_value, count) in enumerate(counter.most_common(limit), start=1)
    ]


def _configured_sqlite_path(database_url: str | None = None) -> Path | None:
    value = database_url or get_settings().database_url
    try:
        url = make_url(value)
    except Exception:
        return None
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None
    path = Path(url.database)
    return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()


def configured_database_marker(database_url: str | None = None) -> tuple[int, int] | None:
    path = _configured_sqlite_path(database_url)
    if path is None or not path.exists():
        return None
    stat = path.stat()
    return int(stat.st_size), int(stat.st_mtime_ns)


def _database_overlap(
    file_fingerprints: Counter[str],
    *,
    database_url: str | None,
) -> dict[str, Any]:
    path = _configured_sqlite_path(database_url)
    if path is None:
        return {
            "status": "not_compared_non_sqlite_or_memory_database",
            "already_imported_by_fingerprint": None,
            "secrets_exposed": False,
        }
    if not path.exists():
        return {
            "status": "not_compared_database_missing",
            "already_imported_by_fingerprint": False,
            "secrets_exposed": False,
        }

    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            table_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='raw_logs'"
            ).fetchone()
            if table_exists is None:
                return {
                    "status": "not_compared_raw_logs_table_missing",
                    "already_imported_by_fingerprint": False,
                    "secrets_exposed": False,
                }
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(raw_logs)").fetchall()
            }
            if "raw_line_hash" not in columns:
                return {
                    "status": "not_compared_fingerprint_column_missing",
                    "already_imported_by_fingerprint": None,
                    "secrets_exposed": False,
                }
            current_raw_rows = int(
                connection.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
            )
            null_hash_rows = int(
                connection.execute(
                    "SELECT COUNT(*) FROM raw_logs WHERE raw_line_hash IS NULL"
                ).fetchone()[0]
            )
            db_fingerprints = Counter(
                {
                    str(fingerprint): int(count)
                    for fingerprint, count in connection.execute(
                        "SELECT raw_line_hash, COUNT(*) FROM raw_logs "
                        "WHERE raw_line_hash IS NOT NULL GROUP BY raw_line_hash"
                    )
                }
            )
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return {
            "status": "comparison_failed",
            "error_type": exc.__class__.__name__,
            "already_imported_by_fingerprint": None,
            "secrets_exposed": False,
        }

    file_rows = sum(file_fingerprints.values())
    file_unique = len(file_fingerprints)
    matched_rows = sum(
        min(count, int(db_fingerprints.get(fingerprint, 0)))
        for fingerprint, count in file_fingerprints.items()
    )
    matched_unique = sum(
        1 for fingerprint in file_fingerprints if db_fingerprints.get(fingerprint, 0)
    )
    full_multiplicity_coverage = bool(file_rows) and matched_rows == file_rows
    return {
        "status": "compared_read_only",
        "current_raw_rows": current_raw_rows,
        "current_hash_backed_rows": current_raw_rows - null_hash_rows,
        "current_null_hash_rows": null_hash_rows,
        "file_rows_matched_by_multiplicity": matched_rows,
        "file_unique_fingerprints": file_unique,
        "file_unique_fingerprints_matched": matched_unique,
        "file_row_overlap_percent": round((matched_rows / file_rows) * 100, 4)
        if file_rows
        else 0.0,
        "file_unique_overlap_percent": round((matched_unique / file_unique) * 100, 4)
        if file_unique
        else 0.0,
        "already_imported_by_fingerprint": full_multiplicity_coverage,
        "comparison_basis": "SHA-256 multiplicity comparison; fingerprint values are not returned",
        "read_only": True,
        "secrets_exposed": False,
    }


def preflight_private_paloalto_file(
    path: Path,
    *,
    current_database_url: str | None = None,
    max_lines: int | None = None,
) -> dict[str, Any]:
    """Inspect private PAN-OS evidence without returning raw identifiers or content."""

    if not path.exists() or not path.is_file():
        return {
            "ok": False,
            "status": "private_evidence_unavailable",
            "file_readable": False,
            "evidence_label": "private-paloalto-evidence",
            "path_returned": False,
            "raw_evidence_returned": False,
            "private_identifiers_returned": False,
        }

    size_bytes = int(path.stat().st_size)
    nonblank_lines = 0
    blank_lines = 0
    parser_errors = 0
    line_bytes = 0
    min_line_bytes: int | None = None
    max_line_bytes = 0
    fingerprints: Counter[str] = Counter()
    log_types: Counter[str] = Counter()
    subtypes: Counter[str] = Counter()
    schema_variants: Counter[tuple[str, int]] = Counter()
    parser_warnings: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    apps: Counter[str] = Counter()
    destination_ports: Counter[int] = Counter()
    threat_severities: Counter[str] = Counter()
    source_frequency: Counter[str] = Counter()
    missing_fields: Counter[str] = Counter()
    unknown_app_count = 0
    hostname_values: set[str] = set()
    serial_values: set[str] = set()
    device_values: set[str] = set()
    source_zone_values: set[str] = set()
    destination_zone_values: set[str] = set()
    source_user_present = 0
    destination_user_present = 0
    earliest_event: datetime | None = None
    latest_event: datetime | None = None
    limited = False

    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for physical_line, line in enumerate(stream, start=1):
            if max_lines is not None and nonblank_lines >= max(0, int(max_lines)):
                limited = True
                break
            if not line.strip():
                blank_lines += 1
                continue
            nonblank_lines += 1
            raw_text = line.rstrip("\r\n")
            encoded_length = len(raw_text.encode("utf-8", errors="replace"))
            line_bytes += encoded_length
            min_line_bytes = encoded_length if min_line_bytes is None else min(min_line_bytes, encoded_length)
            max_line_bytes = max(max_line_bytes, encoded_length)
            fingerprints[raw_line_fingerprint(raw_text)] += 1

            parsed = parse_log_line(raw_text)
            if parsed.error:
                parser_errors += 1
            normalized = parsed.normalized
            log_type = str(normalized.get("log_type") or "missing").upper()
            subtype = str(normalized.get("subtype") or "missing").lower()
            field_count = int(parsed.parsed_json.get("field_count") or 0)
            log_types[log_type] += 1
            subtypes[subtype] += 1
            schema_variants[(log_type, field_count)] += 1
            parser_warnings.update(
                str(item) for item in parsed.parsed_json.get("parser_warnings", [])
            )
            if parsed.device_hostname:
                hostname_values.add(str(parsed.device_hostname))
            if normalized.get("serial"):
                serial_values.add(str(normalized["serial"]))
            if normalized.get("device_name"):
                device_values.add(str(normalized["device_name"]))
            if normalized.get("src_zone"):
                source_zone_values.add(str(normalized["src_zone"]))
            if normalized.get("dst_zone"):
                destination_zone_values.add(str(normalized["dst_zone"]))
            if normalized.get("src_user"):
                source_user_present += 1
            if normalized.get("dst_user"):
                destination_user_present += 1
            if normalized.get("src_ip"):
                source_frequency[str(normalized["src_ip"])] += 1
            if normalized.get("action"):
                actions[str(normalized["action"]).lower()] += 1
            if normalized.get("app"):
                apps[str(normalized["app"]).lower()] += 1
            if normalized.get("dst_port") is not None:
                destination_ports[int(normalized["dst_port"])] += 1
            if parsed.parsed_json.get("parsed_threat_severity"):
                threat_severities[
                    str(parsed.parsed_json["parsed_threat_severity"]).lower()
                ] += 1
            app_name = str(normalized.get("app") or "").strip().lower()
            if app_name in UNKNOWN_APPS:
                unknown_app_count += 1
            for field in KEY_NORMALIZED_FIELDS:
                value = normalized.get(field)
                if value is None or (isinstance(value, str) and not value.strip()):
                    missing_fields[field] += 1
            event_time = (
                normalized.get("generated_time")
                or normalized.get("receive_time")
                or normalized.get("high_res_timestamp")
                or parsed.syslog_timestamp
            )
            if isinstance(event_time, datetime):
                comparable = event_time.replace(tzinfo=None)
                earliest_event = comparable if earliest_event is None else min(earliest_event, comparable)
                latest_event = comparable if latest_event is None else max(latest_event, comparable)

    duplicate_rows = nonblank_lines - len(fingerprints)
    recognized = sum(log_types.get(item, 0) for item in ("TRAFFIC", "THREAT"))
    format_name = (
        "palo_alto_syslog_csv"
        if nonblank_lines and recognized / nonblank_lines >= 0.95
        else "mixed_or_unrecognized"
    )
    overlap = _database_overlap(
        fingerprints,
        database_url=current_database_url,
    )
    return {
        "ok": nonblank_lines > 0,
        "status": "preflight_complete" if nonblank_lines else "empty_evidence_file",
        "evidence_label": "private-paloalto-evidence",
        "file_readable": True,
        "file_size_bytes": size_bytes,
        "physical_lines_observed": nonblank_lines + blank_lines,
        "nonblank_lines": nonblank_lines,
        "blank_lines": blank_lines,
        "limited_preflight": limited,
        "format": format_name,
        "time_range": {
            "earliest": earliest_event.isoformat() if earliest_event else None,
            "latest": latest_event.isoformat() if latest_event else None,
        },
        "log_types": _top(log_types),
        "subtypes": _top(subtypes),
        "schema_variants": [
            {"log_type": log_type, "field_count": field_count, "count": count}
            for (log_type, field_count), count in sorted(schema_variants.items())
        ],
        "parser": {
            "errors": parser_errors,
            "error_rate_percent": round((parser_errors / nonblank_lines) * 100, 4)
            if nonblank_lines
            else 0.0,
            "warnings": _top(parser_warnings),
        },
        "duplicates": {
            "exact_duplicate_rows": duplicate_rows,
            "unique_rows": len(fingerprints),
            "duplicate_rate_percent": round((duplicate_rows / nonblank_lines) * 100, 4)
            if nonblank_lines
            else 0.0,
            "fingerprints_returned": False,
        },
        "field_quality": {
            "missing": {field: int(missing_fields[field]) for field in KEY_NORMALIZED_FIELDS},
            "unknown_app_count": unknown_app_count,
            "unknown_app_rate_percent": round((unknown_app_count / nonblank_lines) * 100, 4)
            if nonblank_lines
            else 0.0,
            "source_user_present": source_user_present,
            "destination_user_present": destination_user_present,
        },
        "safe_aggregates": {
            "actions": _top(actions),
            "applications": _top(apps),
            "destination_ports": _top(destination_ports),
            "threat_severities": _top(threat_severities),
            "unique_source_count": len(source_frequency),
            "top_source_event_counts": _ranked_counts(source_frequency),
            "unique_syslog_hostname_count": len(hostname_values),
            "unique_serial_count": len(serial_values),
            "unique_device_name_count": len(device_values),
            "unique_source_zone_count": len(source_zone_values),
            "unique_destination_zone_count": len(destination_zone_values),
            "average_line_bytes": round(line_bytes / nonblank_lines, 2)
            if nonblank_lines
            else 0.0,
            "minimum_line_bytes": min_line_bytes or 0,
            "maximum_line_bytes": max_line_bytes,
        },
        "current_database_overlap": overlap,
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "secrets_exposed": False,
    }
