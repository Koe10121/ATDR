from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v543_temporal_stability_repair as v543
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection.supervised_detector import _optional_imports


V544_VERSION = "v5.44-chronological-evidence-expansion-v1"
V544_OUTPUT_DIR = (
    PROJECT_ROOT / "ml_baseline_reviews" / "v5_44_chronological_evidence"
)
V544_LATEST = "v5_44_chronological_evidence_latest.json"
V544_PRIVATE_STATE = "v5_44_private_development_state.json"
V544_PRIVATE_LOCK = "v5_44_private_development_lock.sqlite3"
V544_REVIEW_PACK = "v5_44_assisted_pattern_review_pack.csv"
V544_REPORT_PREFIX = "v5_44_chronological_evidence_expansion"

DEVELOPMENT_ROLE_RANKS = (0, 1, 2)
RESERVED_ROLE_RANK = 3
MAX_REVIEW_ROWS = 200
MIN_DISTINCT_TIME_WINDOWS = 12
MIN_REPRESENTATIVE_GROUPS_PER_ROLE = 75
MIN_TRAINING_GROUPS = 600
MIN_BENIGN_LIKE_GROUPS = 300
MIN_SUSPICIOUS_GROUPS = 75
MIN_MALICIOUS_GROUPS = 25
MIN_EXISTING_MANUAL_ANCHORS = 500

PATTERN_ORDER = (
    "benign_quic_443",
    "incomplete_allow_80",
    "unknown_udp_tcp",
    "scan_like_behavior",
    "denied_high_risk_service",
    "c2_or_exfiltration_evidence",
    "vendor_threat_record",
    "suspicious_malicious_boundary",
    "routine_known_application",
    "other_ambiguous",
)


class V544EvidenceError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V544EvidenceError(
            "Private v5.44 custody state failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V544EvidenceError(
            "Private v5.44 custody state failed integrity validation."
        )
    return payload


def _private_file_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"exists": False, "size": None, "sha256": None}
    return {
        "exists": True,
        "size": int(path.stat().st_size),
        "sha256": _file_sha256(path),
    }


def _protected_workspace_state(
    *,
    state_path: Path,
    pack_path: Path,
    blind_output_dir: Path,
    v542_output_dir: Path,
    v543_output_dir: Path,
) -> dict[str, Any]:
    return {
        "v539_state": v55._file_state(state_path),
        "v539_pack": v55._file_state(pack_path),
        "v541_workspace": v543._workspace_state(blind_output_dir),
        "v542_workspace": v543._workspace_state(v542_output_dir),
        "v543_workspace": v543._workspace_state(v543_output_dir),
    }


def revalidate_v544_custody(
    db: Session,
    *,
    min_samples: int = 100,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    state = v543.build_v543_development_state(
        db,
        min_samples=min_samples,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
    )
    v542_manifest = v542._validate_freeze_manifest(v542_output_dir)
    v543_manifest = v543._validate_freeze_manifest(v543_output_dir)
    checks = {
        **{
            f"v543_{key}": bool(value)
            for key, value in state["v543_boundary_checks"].items()
        },
        "v539_consumed_boundary_locked": (
            state["v539_boundary"].get("status")
            == "consumed_boundary_locked"
        ),
        "v541_development_boundary_locked": (
            state["v541_boundary"].get("status")
            == "v5_41_development_boundary_locked"
        ),
        "v542_freeze_integrity_valid": (
            v542_manifest is None
            or v542_manifest.get("status")
            == "diagnostic_candidate_frozen"
        ),
        "v543_freeze_integrity_valid": (
            v543_manifest is None
            or v543_manifest.get("status")
            == "diagnostic_candidate_frozen"
        ),
        "fixed_gates_unchanged": (
            v543.FIXED_FREEZE_GATES == v542.FIXED_FREEZE_GATES
        ),
    }
    if not all(checks.values()):
        raise V544EvidenceError(
            "The v5.39-v5.43 evidence custody boundary does not match."
        )
    return {
        "state": state,
        "checks": checks,
        "all_checks_passed": True,
        "development_rows": len(state["development"]["rows"]),
        "v542_candidate_frozen": v542_manifest is not None,
        "v543_candidate_frozen": v543_manifest is not None,
    }


def _public_custody(custody: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "v5_39_to_v5_43_boundaries_revalidated",
        "checks": dict(custody["checks"]),
        "all_checks_passed": bool(custody["all_checks_passed"]),
        "existing_development_rows": int(custody["development_rows"]),
        "v542_candidate_frozen": bool(custody["v542_candidate_frozen"]),
        "v543_candidate_frozen": bool(custody["v543_candidate_frozen"]),
        "protected_labels_opened": False,
        "protected_predictions_opened": False,
        "private_digests_returned": False,
        "private_identifiers_returned": False,
    }


def _load_v541_candidate_boundaries(
    output_dir: Path,
) -> dict[str, Any]:
    paths = (
        output_dir / v541.V541_MANIFEST,
        output_dir / v541.V541_PRIVATE_STATE,
        output_dir / v541.V541_CANDIDATES,
    )
    existing = [path.is_file() for path in paths]
    if not any(existing):
        return {
            "status": "no_v541_candidate_rows",
            "exact_hashes": frozenset(),
            "near_hashes": frozenset(),
            "candidate_rows": 0,
        }
    if not all(existing):
        raise V544EvidenceError(
            "The private v5.41 candidate custody workspace is incomplete."
        )
    manifest = v541._read_json(paths[0], default=v541._manifest_default())
    private_state = v541._read_json(
        paths[1],
        default=v541._private_state_default(),
    )
    candidate_store = v541._read_json(
        paths[2],
        default=v541._candidate_store_default(),
    )
    v541._validate_workspace_integrity(
        manifest,
        private_state,
        candidate_store=candidate_store,
    )
    rows = [
        row
        for row in candidate_store.get("rows") or []
        if isinstance(row, dict)
    ]
    return {
        "status": "v541_candidate_boundary_locked",
        "exact_hashes": frozenset(
            str(row.get("exact_hash") or "")
            for row in rows
            if row.get("exact_hash")
        ),
        "near_hashes": frozenset(
            str(row.get("near_hash") or "")
            for row in rows
            if row.get("near_hash")
        ),
        "candidate_rows": len(rows),
    }


def _install_hash_boundary(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    values: Iterable[str],
    event_column: str,
    reason: str,
) -> int:
    if table_name not in {
        "v544_v539_protected",
        "v544_v541_exact",
        "v544_v541_near",
    }:
        raise V544EvidenceError("Unsupported private boundary table.")
    if event_column not in {
        "propagation_hash",
        "exact_hash",
        "candidate_near_hash",
    }:
        raise V544EvidenceError("Unsupported private boundary field.")
    connection.execute(
        f"CREATE TEMP TABLE {table_name}(value TEXT PRIMARY KEY)"  # noqa: S608
    )
    connection.executemany(
        f"INSERT OR IGNORE INTO {table_name}(value) VALUES (?)",  # noqa: S608
        ((value,) for value in values if value),
    )
    matched = int(
        connection.execute(
            f"SELECT COUNT(*) FROM events WHERE {event_column} "  # noqa: S608
            f"IN (SELECT value FROM {table_name})"  # noqa: S608
        ).fetchone()[0]
    )
    connection.execute(
        "UPDATE events SET quarantine_reason=COALESCE(quarantine_reason, ?) "
        f"WHERE {event_column} IN "  # noqa: S608
        f"(SELECT value FROM {table_name})",  # noqa: S608
        (reason,),
    )
    connection.commit()
    return matched


def _install_protected_boundaries(
    connection: sqlite3.Connection,
    *,
    custody: dict[str, Any],
    blind_output_dir: Path,
) -> dict[str, Any]:
    state = custody["state"]
    v541_boundary = state["v541_boundary"]
    prior = v541._install_prior_hashes(
        connection,
        exact_hashes=v541_boundary["development_exact_hashes"],
        propagation_hashes=v541_boundary[
            "development_propagation_hashes"
        ],
    )
    protected_tokens = state["v539_boundary"]["_protected_tokens"]
    protected_propagation = []
    for (value,) in connection.execute(
        "SELECT DISTINCT propagation_hash FROM events"
    ):
        if v521._review_token(str(value)) in protected_tokens:
            protected_propagation.append(str(value))
    v539_overlap = _install_hash_boundary(
        connection,
        table_name="v544_v539_protected",
        values=protected_propagation,
        event_column="propagation_hash",
        reason="v539_protected_evidence_overlap",
    )
    blind = _load_v541_candidate_boundaries(blind_output_dir)
    v541_exact = _install_hash_boundary(
        connection,
        table_name="v544_v541_exact",
        values=blind["exact_hashes"],
        event_column="exact_hash",
        reason="v541_candidate_exact_overlap",
    )
    v541_near = _install_hash_boundary(
        connection,
        table_name="v544_v541_near",
        values=blind["near_hashes"],
        event_column="candidate_near_hash",
        reason="v541_candidate_near_overlap",
    )
    cutoff = v541._apply_cutoff(
        connection,
        cutoff=v541_boundary["cutoff"],
    )
    return {
        "v540_exact_overlap_rows": int(prior["exact_overlap_rows"]),
        "v540_near_overlap_rows": int(prior["near_overlap_rows"]),
        "v539_protected_overlap_rows": v539_overlap,
        "v541_candidate_exact_overlap_rows": v541_exact,
        "v541_candidate_near_overlap_rows": v541_near,
        "v541_protected_candidate_rows": int(blind["candidate_rows"]),
        "missing_time_rows": int(cutoff["missing_time_rows"]),
        "at_or_before_development_cutoff_rows": int(
            cutoff["at_or_before_cutoff_rows"]
        ),
        "strictly_after_development_cutoff_rows": int(
            cutoff["strictly_after_cutoff_rows"]
        ),
        "eligible_after_boundary_exclusions": int(
            cutoff["eligible_after_all_exclusions"]
        ),
        "protected_hashes_returned": False,
        "protected_labels_opened": False,
        "protected_predictions_opened": False,
    }


def _duration_seconds(earliest: str | None, latest: str | None) -> float:
    if not earliest or not latest:
        return 0.0
    try:
        start = datetime.fromisoformat(earliest)
        end = datetime.fromisoformat(latest)
    except ValueError:
        return 0.0
    return max(0.0, (end - start).total_seconds())


def _chronology_summary(
    connection: sqlite3.Connection,
    stream_profile: dict[str, Any],
) -> dict[str, Any]:
    full = stream_profile.get("time_range") or {}
    duration = _duration_seconds(full.get("earliest"), full.get("latest"))
    distinct_minutes = int(
        connection.execute(
            "SELECT COUNT(DISTINCT minute_bucket) FROM events "
            "WHERE minute_bucket IS NOT NULL"
        ).fetchone()[0]
    )
    distinct_days = int(
        connection.execute(
            "SELECT COUNT(DISTINCT substr(event_time, 1, 10)) "
            "FROM events WHERE event_time IS NOT NULL"
        ).fetchone()[0]
    )
    eligible_minutes = int(
        connection.execute(
            "SELECT COUNT(DISTINCT minute_bucket) FROM events "
            "WHERE quarantine_reason IS NULL AND role_rank < 4"
        ).fetchone()[0]
    )
    return {
        "timestamped_rows": int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_time IS NOT NULL"
            ).fetchone()[0]
        ),
        "missing_timestamp_rows": int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_time IS NULL"
            ).fetchone()[0]
        ),
        "observed_span_seconds": round(duration, 3),
        "observed_span_hours": round(duration / 3600.0, 3),
        "observed_span_days": round(duration / 86400.0, 3),
        "distinct_minute_windows": distinct_minutes,
        "distinct_calendar_days": distinct_days,
        "eligible_minute_windows": eligible_minutes,
        "chronological_order_available": distinct_minutes > 0,
        "exact_timestamps_returned": False,
    }


def _safe_stream_profile(
    connection: sqlite3.Connection,
    profile: dict[str, Any],
) -> dict[str, Any]:
    direction = connection.execute(
        "SELECT SUM(external_to_internal_flag), "
        "SUM(internal_to_external_flag), COUNT(*) FROM events"
    ).fetchone()
    return {
        "status": profile.get("status"),
        "rows_processed": int(profile.get("rows_processed") or 0),
        "blank_rows": int(profile.get("blank_rows") or 0),
        "parser_successes": int(profile.get("parser_successes") or 0),
        "parser_failures": int(profile.get("parser_failures") or 0),
        "parser_success_rate": profile.get("parser_success_rate"),
        "top_log_types": list(profile.get("top_log_types") or []),
        "top_applications": list(profile.get("top_applications") or []),
        "top_actions": list(profile.get("top_actions") or []),
        "top_destination_ports": list(
            profile.get("top_destination_ports") or []
        ),
        "schema_profiles": list(profile.get("schema_profiles") or []),
        "threat_severities": list(profile.get("threat_severities") or []),
        "exact_duplicate_rows": int(
            profile.get("exact_duplicate_rows") or 0
        ),
        "near_duplicate_rows": int(
            profile.get("near_duplicate_rows") or 0
        ),
        "unique_exact_families": int(
            profile.get("unique_exact_families") or 0
        ),
        "unique_near_families": int(
            profile.get("unique_near_families") or 0
        ),
        "configured_database_overlap_rows": int(
            profile.get("configured_database_overlap_rows") or 0
        ),
        "device_sources": dict(profile.get("device_sources") or {}),
        "direction_counts": {
            "external_to_internal": int(direction[0] or 0),
            "internal_to_external": int(direction[1] or 0),
            "other_or_unknown": max(
                0,
                int(direction[2] or 0)
                - int(direction[0] or 0)
                - int(direction[1] or 0),
            ),
        },
        "streaming": dict(profile.get("streaming") or {}),
        "raw_evidence_returned": False,
        "private_paths_returned": False,
        "private_identifiers_returned": False,
        "reusable_fingerprints_returned": False,
        "exact_timestamps_returned": False,
        "secrets_exposed": False,
    }


def _cohort_summary(
    connection: sqlite3.Connection,
    roles: dict[str, Any],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for role_rank, role_name in v56.ROLE_NAMES.items():
        if role_rank == 4:
            continue
        values = connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT propagation_hash), "
            "COUNT(DISTINCT minute_bucket), "
            "COUNT(DISTINCT CASE WHEN device_identity_present=1 "
            "THEN device_token END) FROM events WHERE role_rank=? "
            "AND quarantine_reason IS NULL",
            (role_rank,),
        ).fetchone()
        output[role_name] = {
            "rows": int(values[0] or 0),
            "representative_families": int(values[1] or 0),
            "time_windows": int(values[2] or 0),
            "identified_device_sources": int(values[3] or 0),
            "development_eligible": role_rank in DEVELOPMENT_ROLE_RANKS,
            "labels_opened": False,
            "source_tokens_returned": False,
            "exact_time_range_returned": False,
            "aggregate_fingerprint_returned": False,
        }
    return {
        "status": roles.get("status"),
        "policy": dict(roles.get("policy") or {}),
        "distinct_time_windows": int(
            roles.get("distinct_time_windows") or 0
        ),
        "cohorts": output,
        "exact_family_cross_role_count": int(
            roles.get("exact_family_cross_role_count") or 0
        ),
        "near_family_cross_role_count": int(
            roles.get("near_family_cross_role_count") or 0
        ),
        "duplicate_families_contained": bool(
            roles.get("duplicate_families_contained")
        ),
        "reserved_future_labels_opened": False,
        "row_fingerprints_returned": False,
    }


def _pattern_for_row(
    row: dict[str, Any],
    rule_codes: list[str],
) -> str:
    app = str(row.get("app") or "").strip().lower()
    action = str(row.get("action") or "").strip().lower()
    protocol = str(row.get("protocol") or "").strip().lower()
    dst_port = v56._integer(row.get("dst_port"), -1)
    risk = v56._integer(row.get("app_risk"))
    log_type = str(row.get("log_type") or "").upper()
    unique_ports = v56._integer(row.get("source_unique_ports"))
    unique_destinations = v56._integer(
        row.get("source_unique_destinations")
    )
    deny_count = v56._integer(row.get("source_deny_count"))
    codes = " ".join(rule_codes).lower()
    if any(value in codes for value in ("c2", "beacon", "exfil")):
        return "c2_or_exfiltration_evidence"
    if (
        "port_scan" in codes
        or unique_ports >= 10
        or unique_destinations >= 8
    ):
        return "scan_like_behavior"
    if action != "allow" and (risk >= 4 or deny_count >= 5):
        return "denied_high_risk_service"
    if log_type == "THREAT":
        return "vendor_threat_record"
    if app in {"quic", "quic-base"} and action == "allow" and dst_port == 443:
        return "benign_quic_443"
    if app == "incomplete" and action == "allow" and dst_port == 80:
        return "incomplete_allow_80"
    if app in v56.UNKNOWN_APPS and protocol in {"udp", "tcp"}:
        return "unknown_udp_tcp"
    if rule_codes or risk >= 4:
        return "suspicious_malicious_boundary"
    if action == "allow" and app not in v56.UNKNOWN_APPS:
        return "routine_known_application"
    return "other_ambiguous"


def _bucket(value: Any, boundaries: tuple[int, ...]) -> str:
    number = max(0, v56._integer(value))
    for boundary in boundaries:
        if number < boundary:
            return f"lt_{boundary}"
    return f"gte_{boundaries[-1]}"


def _review_projection(
    row: dict[str, Any],
    *,
    pattern: str,
    decision: dict[str, Any],
) -> dict[str, Any]:
    return {
        "cohort": v56.ROLE_NAMES[v56._integer(row.get("role_rank"), 4)],
        "pattern": pattern,
        "log_type": row.get("log_type"),
        "subtype": row.get("subtype"),
        "application": row.get("app"),
        "action": row.get("action"),
        "protocol": row.get("protocol"),
        "destination_port": row.get("dst_port"),
        "source_zone_class": row.get("src_zone"),
        "destination_zone_class": row.get("dst_zone"),
        "schema_bucket": row.get("schema_bucket"),
        "threat_severity": row.get("threat_severity"),
        "application_risk": row.get("app_risk"),
        "source_event_count_bucket": _bucket(
            row.get("source_event_count"),
            (5, 25, 100),
        ),
        "destination_diversity_bucket": _bucket(
            row.get("source_unique_destinations"),
            (3, 8, 20),
        ),
        "port_diversity_bucket": _bucket(
            row.get("source_unique_ports"),
            (3, 10, 25),
        ),
        "rule_codes": ";".join(decision["rule_codes"]),
        "assisted_suggested_decision": decision["decision"],
        "assisted_suggested_confidence": decision["confidence"],
        "assisted_provenance": decision["provenance"],
        "assisted_reason": decision["evidence_summary"],
        "human_must_confirm": True,
        "human_reviewed": False,
        "import_ready": False,
        "raw_log_included": False,
        "ip_addresses_included": False,
    }


def _review_priority(
    *,
    pattern: str,
    decision: dict[str, Any],
) -> int:
    score = {
        "needs_context": 100,
        "suspicious": 85,
        "malicious": 75,
        "benign_unusual": 65,
        "benign": 40,
    }.get(str(decision.get("decision")), 50)
    if pattern in {
        "unknown_udp_tcp",
        "suspicious_malicious_boundary",
        "scan_like_behavior",
        "denied_high_risk_service",
    }:
        score += 20
    if float(decision.get("confidence") or 0.0) < 0.8:
        score += 10
    return score


def _apply_development_assisted_policy(
    connection: sqlite3.Connection,
    *,
    review_limit: int,
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
    event_decisions: Counter[str] = Counter()
    group_decisions: Counter[str] = Counter()
    event_provenance: Counter[str] = Counter()
    group_provenance: Counter[str] = Counter()
    event_patterns: Counter[str] = Counter()
    group_patterns: Counter[str] = Counter()
    event_rules: Counter[str] = Counter()
    group_rules: Counter[str] = Counter()
    by_role: dict[str, dict[str, Counter[str]]] = defaultdict(
        lambda: {
            "decisions": Counter(),
            "provenance": Counter(),
            "patterns": Counter(),
        }
    )
    review_candidates: dict[str, list[tuple[int, dict[str, Any]]]] = (
        defaultdict(list)
    )
    training_events = 0
    training_groups = 0
    ambiguous_events = 0
    batch: list[tuple[Any, ...]] = []
    per_pattern_cap = max(8, max(1, review_limit) // 2)

    for values in connection.execute(v56.REPRESENTATIVE_QUERY):
        row = v56._row_mapping(values)
        role_rank = v56._integer(row.get("role_rank"), 4)
        if role_rank not in DEVELOPMENT_ROLE_RANKS:
            continue
        rule_codes, rule_score = v56._rule_evidence(row)
        decision = v56.assisted_decision(
            row,
            rule_codes=rule_codes,
            rule_score=rule_score,
        )
        pattern = _pattern_for_row(row, rule_codes)
        group_size = max(1, v56._integer(row.get("group_size"), 1))
        role_name = v56.ROLE_NAMES[role_rank]
        event_decisions[decision["decision"]] += group_size
        group_decisions[decision["decision"]] += 1
        event_provenance[decision["provenance"]] += group_size
        group_provenance[decision["provenance"]] += 1
        event_patterns[pattern] += group_size
        group_patterns[pattern] += 1
        by_role[role_name]["decisions"][decision["decision"]] += 1
        by_role[role_name]["provenance"][decision["provenance"]] += 1
        by_role[role_name]["patterns"][pattern] += 1
        for code in rule_codes:
            event_rules[code] += group_size
            group_rules[code] += 1
        if decision["training_eligible"]:
            training_events += group_size
            training_groups += 1
        else:
            ambiguous_events += group_size
        candidate = _review_projection(
            row,
            pattern=pattern,
            decision=decision,
        )
        priority = _review_priority(pattern=pattern, decision=decision)
        if len(review_candidates[pattern]) < per_pattern_cap:
            review_candidates[pattern].append((priority, candidate))
        batch.append(
            (
                int(row["id"]),
                str(row["propagation_hash"]),
                role_rank,
                group_size,
                decision["decision"],
                decision["provenance"],
                decision["confidence"],
                decision["evidence_summary"],
                json.dumps(rule_codes, separators=(",", ":")),
                int(rule_score),
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
        CREATE INDEX ix_v544_assisted_role
            ON assisted_groups(role_rank, training_eligible);
        CREATE INDEX ix_v544_assisted_decision
            ON assisted_groups(decision, provenance);
        """
    )
    connection.commit()

    ordered_candidates: list[dict[str, Any]] = []
    buckets = {
        pattern: sorted(
            review_candidates.get(pattern, []),
            key=lambda item: item[0],
            reverse=True,
        )
        for pattern in PATTERN_ORDER
    }
    while len(ordered_candidates) < max(0, review_limit):
        added = False
        for pattern in PATTERN_ORDER:
            values = buckets[pattern]
            if values and len(ordered_candidates) < review_limit:
                _, row = values.pop(0)
                ordered_candidates.append(row)
                added = True
        if not added:
            break
    for index, row in enumerate(ordered_candidates, start=1):
        row["review_row_number"] = index

    return {
        "status": "development_only_assisted_coverage_complete",
        "policy_version": v56.V56_POLICY_VERSION,
        "decision_event_counts": dict(sorted(event_decisions.items())),
        "decision_group_counts": dict(sorted(group_decisions.items())),
        "provenance_event_counts": dict(sorted(event_provenance.items())),
        "provenance_group_counts": dict(sorted(group_provenance.items())),
        "pattern_event_counts": dict(sorted(event_patterns.items())),
        "pattern_group_counts": dict(sorted(group_patterns.items())),
        "rule_event_counts": dict(event_rules.most_common(15)),
        "rule_group_counts": dict(group_rules.most_common(15)),
        "cohort_coverage": {
            role: {
                key: dict(sorted(counter.items()))
                for key, counter in values.items()
            }
            for role, values in sorted(by_role.items())
        },
        "high_confidence_training_event_count": training_events,
        "high_confidence_training_group_count": training_groups,
        "ambiguous_or_quarantined_event_count": ambiguous_events,
        "human_reviewed_true_count": 0,
        "human_labels_created": 0,
        "configured_database_labels_written": 0,
        "reserved_future_labels_opened": False,
        "import_ready_human_review_file_created": False,
        "review_pack_rows": len(ordered_candidates),
        "_review_rows": ordered_candidates,
    }


def _existing_label_coverage(custody: dict[str, Any]) -> dict[str, Any]:
    development = custody["state"]["development"]
    labels = [str(value) for value in development["original_labels"]]
    provenance = Counter(
        str(row.get("label_source") or "unknown")
        for row in development["rows"]
    )
    manual_sources = {"manual", "reviewed_import"}
    manual_rows = sum(
        count for source, count in provenance.items() if source in manual_sources
    )
    cohorts = v543._temporal_cohorts(
        development,
        list(range(len(development["rows"]))),
    )
    by_cohort: dict[str, Counter[str]] = defaultdict(Counter)
    for index, label in enumerate(labels):
        by_cohort[cohorts[index]][label] += 1
    return {
        "rows": len(labels),
        "decision_counts": dict(sorted(Counter(labels).items())),
        "provenance_counts": dict(sorted(provenance.items())),
        "manual_or_reviewed_anchor_rows": manual_rows,
        "assisted_or_weak_rows": len(labels) - manual_rows,
        "temporal_cohort_counts": {
            name: dict(sorted(values.items()))
            for name, values in sorted(by_cohort.items())
        },
        "protected_v539_rows_included": 0,
        "labels_rewritten": False,
        "private_identifiers_returned": False,
    }


def _safe_anomaly_audit(connection: sqlite3.Connection) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {
            "status": "dependencies_unavailable",
            "rows": 0,
            "future_rows_scored": 0,
            "active_artifact_written": False,
        }
    bundles = []
    selections = []
    for role_rank in DEVELOPMENT_ROLE_RANKS:
        bundle, selection = v56.load_private_role_bundle(
            connection,
            imports,
            role_rank=role_rank,
            max_rows=600,
        )
        bundles.append(bundle)
        selections.append(selection)
    combined = v56._concat_bundles(imports, *bundles)
    if not combined["rows"]:
        return {
            "status": "no_training_eligible_development_rows",
            "rows": 0,
            "future_rows_scored": 0,
            "active_artifact_written": False,
        }
    result = v56.audit_current_isolation_on_development(imports, combined)
    metrics = result.get("metrics") or {}
    return {
        "status": result.get("status"),
        "rows": int(result.get("rows") or len(combined["rows"])),
        "selection": [
            {
                "cohort": value.get("role"),
                "selected_representative_rows": int(
                    value.get("selected_representative_rows") or 0
                ),
            }
            for value in selections
        ],
        "queue_metrics": {
            name: metrics.get(name)
            for name in (
                "queue_precision",
                "queue_recall",
                "queue_f1",
                "benign_like_false_positive_rate",
                "suspicious_recall",
                "malicious_recall",
                "review_queue_rate",
            )
            if name in metrics
        },
        "score_distribution": dict(result.get("score_distribution") or {}),
        "artifact_unchanged": bool(result.get("artifact_unchanged", True)),
        "future_rows_scored": 0,
        "reserved_future_labels_opened": False,
        "regime_identifiers_returned": False,
        "active_artifact_written": False,
    }


def _quarantine_summary(
    connection: sqlite3.Connection,
    boundary_matches: dict[str, Any],
) -> dict[str, Any]:
    final_reasons = {
        str(reason or "none"): int(count)
        for reason, count in connection.execute(
            "SELECT quarantine_reason, COUNT(*) FROM events "
            "WHERE quarantine_reason IS NOT NULL GROUP BY quarantine_reason"
        )
    }
    selected_rows = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE quarantine_reason IS NULL "
            "AND role_rank IN (0, 1, 2)"
        ).fetchone()[0]
    )
    reserved_rows = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE quarantine_reason IS NULL "
            "AND role_rank=3"
        ).fetchone()[0]
    )
    selected_groups = int(
        connection.execute(
            "SELECT COUNT(DISTINCT propagation_hash) FROM events "
            "WHERE quarantine_reason IS NULL AND role_rank IN (0, 1, 2)"
        ).fetchone()[0]
    )
    selected_exact = int(
        connection.execute(
            "SELECT COUNT(DISTINCT exact_hash) FROM events "
            "WHERE quarantine_reason IS NULL AND role_rank IN (0, 1, 2)"
        ).fetchone()[0]
    )
    return {
        "boundary_match_counts": {
            key: value
            for key, value in boundary_matches.items()
            if key.endswith("_rows")
            and isinstance(value, int)
        },
        "final_quarantine_reason_counts": dict(sorted(final_reasons.items())),
        "usable_development_event_rows": selected_rows,
        "usable_development_exact_families": selected_exact,
        "usable_development_near_families": selected_groups,
        "reserved_future_event_rows": reserved_rows,
        "excluded_or_quarantined_rows": sum(final_reasons.values()),
        "reserved_future_labels_opened": False,
        "fingerprints_returned": False,
    }


def _development_sufficiency(
    *,
    custody: dict[str, Any],
    stream: dict[str, Any],
    chronology: dict[str, Any],
    cohorts: dict[str, Any],
    policy: dict[str, Any],
    existing_labels: dict[str, Any],
) -> dict[str, Any]:
    decision_groups = policy.get("decision_group_counts") or {}
    benign_like = int(decision_groups.get("benign") or 0) + int(
        decision_groups.get("benign_unusual") or 0
    )
    suspicious = int(decision_groups.get("suspicious") or 0)
    malicious = int(decision_groups.get("malicious") or 0)
    role_groups = [
        int(
            (cohorts.get("cohorts") or {})
            .get(v56.ROLE_NAMES[role], {})
            .get("representative_families")
            or 0
        )
        for role in DEVELOPMENT_ROLE_RANKS
    ]
    checks = {
        "custody_revalidated": bool(custody["all_checks_passed"]),
        "parser_success_rate_acceptable": float(
            stream.get("parser_success_rate") or 0.0
        )
        >= 0.99,
        "chronological_windows_sufficient": int(
            chronology.get("eligible_minute_windows") or 0
        )
        >= MIN_DISTINCT_TIME_WINDOWS,
        "three_development_cohorts_populated": all(
            count >= MIN_REPRESENTATIVE_GROUPS_PER_ROLE
            for count in role_groups
        ),
        "duplicate_families_isolated": bool(
            cohorts.get("duplicate_families_contained")
        ),
        "training_group_volume_sufficient": int(
            policy.get("high_confidence_training_group_count") or 0
        )
        >= MIN_TRAINING_GROUPS,
        "benign_like_assisted_support_sufficient": (
            benign_like >= MIN_BENIGN_LIKE_GROUPS
        ),
        "suspicious_assisted_support_sufficient": (
            suspicious >= MIN_SUSPICIOUS_GROUPS
        ),
        "malicious_assisted_support_sufficient": (
            malicious >= MIN_MALICIOUS_GROUPS
        ),
        "existing_manual_anchor_sufficient": int(
            existing_labels.get("manual_or_reviewed_anchor_rows") or 0
        )
        >= MIN_EXISTING_MANUAL_ANCHORS,
        "private_labels_remain_assisted_only": int(
            policy.get("human_reviewed_true_count") or 0
        )
        == 0,
        "reserved_future_labels_unopened": not bool(
            policy.get("reserved_future_labels_opened")
        ),
    }
    development_ready = all(checks.values())
    source_count = int(
        (stream.get("device_sources") or {}).get("identified_source_count")
        or 0
    )
    blockers = [
        name.replace("_", " ")
        for name, passed in checks.items()
        if not passed
    ]
    if source_count < 2:
        blockers.append(
            "independent validation still requires a second genuine device source"
        )
    blockers.extend(
        (
            "new private labels are assisted evidence, not human ground truth",
            "no supervised candidate has passed the unchanged temporal gates",
        )
    )
    return {
        "status": (
            "development_only_repair_evidence_available"
            if development_ready
            else "development_evidence_insufficient"
        ),
        "checks": checks,
        "development_only_model_repair_ready": development_ready,
        "rerun_model_repair_recommended": development_ready,
        "candidate_freeze_ready": False,
        "independent_validation_ready": False,
        "independent_labeled_evidence_sufficient": False,
        "identified_device_source_count": source_count,
        "new_human_reviewed_rows": 0,
        "new_assisted_label_groups": int(
            policy.get("high_confidence_training_group_count") or 0
        ),
        "blockers": blockers,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "supervised_phases_remaining": 5,
    }


def _collection_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    cursor = connection.execute(
        "SELECT exact_hash, COUNT(*) FROM events "
        "GROUP BY exact_hash ORDER BY exact_hash"
    )
    while True:
        batch = cursor.fetchmany(5000)
        if not batch:
            break
        for value, count in batch:
            digest.update(str(value).encode("ascii"))
            digest.update(b":")
            digest.update(str(int(count)).encode("ascii"))
            digest.update(b"\n")
    return digest.hexdigest()


def _boundary_contract_digest(custody: dict[str, Any]) -> str:
    state = custody["state"]
    boundary = state["v541_boundary"]
    return _stable_hash(
        {
            "version": V544_VERSION,
            "development_contract": state["development_contract"],
            "protected_v539_tokens": sorted(
                state["v539_boundary"]["_protected_tokens"]
            ),
            "v540_exact": sorted(boundary["development_exact_hashes"]),
            "v540_propagation": sorted(
                boundary["development_propagation_hashes"]
            ),
            "v543_checks": custody["checks"],
        }
    )


def _assisted_summary_digest(connection: sqlite3.Connection) -> str:
    rows = [
        (
            int(role),
            str(decision),
            str(provenance),
            int(eligible),
            int(groups),
            int(events),
        )
        for role, decision, provenance, eligible, groups, events in (
            connection.execute(
                "SELECT role_rank, decision, provenance, training_eligible, "
                "COUNT(*), SUM(group_size) FROM assisted_groups GROUP BY "
                "role_rank, decision, provenance, training_eligible ORDER BY "
                "role_rank, decision, provenance, training_eligible"
            )
        )
    ]
    return _stable_hash(
        {
            "policy_version": v56.V56_POLICY_VERSION,
            "summary": rows,
        }
    )


def _write_private_lock(
    connection: sqlite3.Connection,
    *,
    output_dir: Path,
    custody: dict[str, Any],
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    state_path = output_dir / V544_PRIVATE_STATE
    lock_path = output_dir / V544_PRIVATE_LOCK
    collection_digest = _collection_digest(connection)
    boundary_digest = _boundary_contract_digest(custody)
    assisted_digest = _assisted_summary_digest(connection)
    if state_path.is_file() or lock_path.is_file():
        if not state_path.is_file() or not lock_path.is_file():
            raise V544EvidenceError(
                "The private v5.44 development lock is incomplete."
            )
        state = _read_json(state_path)
        valid = bool(
            state.get("schema_version") == V544_VERSION
            and state.get("status") == "development_evidence_locked"
            and state.get("collection_digest") == collection_digest
            and state.get("boundary_contract_digest") == boundary_digest
            and state.get("assisted_summary_digest") == assisted_digest
            and state.get("lock_sha256") == _file_sha256(lock_path)
        )
        if not valid:
            raise V544EvidenceError(
                "A different or damaged private v5.44 development lock exists."
            )
        return {
            "status": "existing_private_lock_reused",
            "lock_valid": True,
            "private_path_returned": False,
            "private_digest_returned": False,
        }

    temporary = lock_path.with_name(f".{lock_path.name}.{os.getpid()}.tmp")
    if temporary.exists():
        temporary.unlink()
    target = sqlite3.connect(temporary)
    try:
        target.executescript(
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            CREATE TABLE exact_rows (
                exact_hash TEXT PRIMARY KEY,
                role_rank INTEGER NOT NULL
            );
            CREATE TABLE development_families (
                propagation_hash TEXT NOT NULL,
                candidate_near_hash TEXT NOT NULL,
                device_token TEXT NOT NULL,
                role_rank INTEGER NOT NULL,
                event_count INTEGER NOT NULL,
                PRIMARY KEY (
                    propagation_hash,
                    candidate_near_hash,
                    device_token,
                    role_rank
                )
            );
            CREATE TABLE assisted_summary (
                role_rank INTEGER NOT NULL,
                decision TEXT NOT NULL,
                provenance TEXT NOT NULL,
                training_eligible INTEGER NOT NULL,
                representative_groups INTEGER NOT NULL,
                represented_events INTEGER NOT NULL,
                PRIMARY KEY (
                    role_rank,
                    decision,
                    provenance,
                    training_eligible
                )
            );
            """
        )
        cursor = connection.execute(
            "SELECT DISTINCT exact_hash, role_rank FROM events "
            "WHERE quarantine_reason IS NULL AND role_rank IN (0, 1, 2) "
            "ORDER BY exact_hash"
        )
        while True:
            batch = cursor.fetchmany(5000)
            if not batch:
                break
            target.executemany(
                "INSERT INTO exact_rows VALUES (?, ?)",
                [(str(value), int(role)) for value, role in batch],
            )
        cursor = connection.execute(
            "SELECT propagation_hash, candidate_near_hash, device_token, "
            "role_rank, COUNT(*) FROM events WHERE quarantine_reason IS NULL "
            "AND role_rank IN (0, 1, 2) GROUP BY propagation_hash, "
            "candidate_near_hash, device_token, role_rank"
        )
        while True:
            batch = cursor.fetchmany(5000)
            if not batch:
                break
            target.executemany(
                "INSERT INTO development_families VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        str(propagation),
                        str(near),
                        str(device),
                        int(role),
                        int(count),
                    )
                    for propagation, near, device, role, count in batch
                ],
            )
        target.executemany(
            "INSERT INTO assisted_summary VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    int(role),
                    str(decision),
                    str(provenance),
                    int(eligible),
                    int(groups),
                    int(events),
                )
                for role, decision, provenance, eligible, groups, events in (
                    connection.execute(
                        "SELECT role_rank, decision, provenance, "
                        "training_eligible, COUNT(*), SUM(group_size) "
                        "FROM assisted_groups GROUP BY role_rank, decision, "
                        "provenance, training_eligible"
                    )
                )
            ],
        )
        target.commit()
    finally:
        target.close()
    os.replace(temporary, lock_path)
    state = {
        "schema_version": V544_VERSION,
        "status": "development_evidence_locked",
        "created_at": _now(),
        "collection_digest": collection_digest,
        "boundary_contract_digest": boundary_digest,
        "assisted_summary_digest": assisted_digest,
        "lock_sha256": _file_sha256(lock_path),
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "exact_timestamps_included": False,
        "human_reviewed_labels_created": 0,
        "private_paths_recorded": False,
    }
    _atomic_write_json(state_path, state)
    return {
        "status": "private_development_evidence_locked",
        "lock_valid": True,
        "private_path_returned": False,
        "private_digest_returned": False,
    }


def _write_review_pack(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["review_row_number"] + [
        name for name in rows[0] if name != "review_row_number"
    ]
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def _render_report(result: dict[str, Any]) -> str:
    chronology = result.get("chronology") or {}
    exclusions = result.get("exclusions") or {}
    coverage = result.get("assisted_label_coverage") or {}
    sufficiency = result.get("sufficiency") or {}
    stream = result.get("private_evidence") or {}
    lines = [
        "# v5.44 Chronological Evidence Expansion",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "This report contains aggregate development-only evidence. It contains "
        "no private path, raw log, IP address, source identity, reusable "
        "fingerprint, model activation, or human-label claim.",
        "",
        "## Result",
        "",
        f"- Status: `{result.get('status')}`",
        f"- Rows streamed: `{stream.get('rows_processed')}`",
        f"- Parser success rate: `{stream.get('parser_success_rate')}`",
        f"- Observed span days: `{chronology.get('observed_span_days')}`",
        f"- Eligible minute windows: `{chronology.get('eligible_minute_windows')}`",
        f"- Usable development events: "
        f"`{exclusions.get('usable_development_event_rows')}`",
        f"- Usable near families: "
        f"`{exclusions.get('usable_development_near_families')}`",
        f"- Reserved future events: "
        f"`{exclusions.get('reserved_future_event_rows')}`",
        f"- High-confidence assisted groups: "
        f"`{coverage.get('high_confidence_training_group_count')}`",
        f"- Human-reviewed labels created: "
        f"`{coverage.get('human_reviewed_true_count')}`",
        f"- Development repair ready: "
        f"`{sufficiency.get('development_only_model_repair_ready')}`",
        f"- Independent validation ready: "
        f"`{sufficiency.get('independent_validation_ready')}`",
        f"- Lifecycle: `{sufficiency.get('lifecycle_state')}`",
        "",
        "## Assisted Decision Coverage",
        "",
    ]
    for name, count in sorted(
        (coverage.get("decision_group_counts") or {}).items()
    ):
        lines.append(f"- {name}: `{count}` representative groups")
    lines.extend(("", "## Remaining Blockers", ""))
    for blocker in sufficiency.get("blockers") or []:
        lines.append(f"- {blocker}")
    lines.extend(
        (
            "",
            "Rules remain alert-authoritative. Supervised ML remains in "
            "`shadow_observation`; automatic response and real blocking remain "
            "disabled.",
        )
    )
    return "\n".join(lines).rstrip() + "\n"


def _safe_failure(status: str, *, error_type: str | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V544_VERSION,
        "status": status,
        "generated_at": _now(),
        "error_type": error_type,
        "message": (
            "The chronological evidence workflow failed closed. Review local "
            "diagnostics without exposing private evidence."
        ),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }


def run_v544_chronological_evidence_expansion(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = False,
    min_samples: int = 100,
    review_limit: int = MAX_REVIEW_ROWS,
    output_dir: Path = V544_OUTPUT_DIR,
    write_output: bool = True,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    protected_before = _protected_workspace_state(
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    try:
        custody = revalidate_v544_custody(
            db,
            min_samples=min_samples,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
    except (
        V544EvidenceError,
        v540.V540EvidenceBoundaryError,
        v541.V541EvidenceError,
        v542.V542FreezeError,
        v543.V543RepairError,
    ) as exc:
        return _safe_failure(
            "failed_closed_custody",
            error_type=exc.__class__.__name__,
        )

    supplied = sample_path is not None
    available = bool(sample_path and sample_path.is_file())
    private_file = {
        "supplied": supplied,
        "available": available,
        "size_bytes": (
            int(sample_path.stat().st_size) if available and sample_path else None
        ),
        "path_returned": False,
        "file_name_returned": False,
        "digest_returned": False,
    }
    if preflight_only:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        protected_after = _protected_workspace_state(
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
        safety = {
            "configured_database_counts_unchanged": counts_before
            == counts_after,
            "active_model_artifacts_unchanged": artifacts_before
            == artifacts_after,
            "protected_workspaces_unchanged": protected_before
            == protected_after,
            "labels_created": 0,
            "model_runs_created": 0,
            "detection_runs_created": 0,
            "alerts_created": 0,
            "response_actions_created": 0,
            "active_model_artifact_written": False,
            "reserved_future_labels_opened": False,
        }
        safety_passed = bool(
            safety["configured_database_counts_unchanged"]
            and safety["active_model_artifacts_unchanged"]
            and safety["protected_workspaces_unchanged"]
            and safety["labels_created"] == 0
            and safety["model_runs_created"] == 0
            and safety["detection_runs_created"] == 0
            and safety["alerts_created"] == 0
            and safety["response_actions_created"] == 0
            and not safety["active_model_artifact_written"]
            and not safety["reserved_future_labels_opened"]
        )
        return {
            "ok": bool(available and safety_passed),
            "version": V544_VERSION,
            "status": "preflight_complete" if available else "private_file_unavailable",
            "generated_at": _now(),
            "preflight_only": True,
            "custody": _public_custody(custody),
            "private_file": private_file,
            "safety": {**safety, "all_invariants_passed": safety_passed},
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "private_paths_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "source_identities_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    if not supplied or not available:
        return _safe_failure("private_file_unavailable")
    if not use_temp_db:
        return _safe_failure("temporary_storage_acknowledgement_required")

    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v544-") as directory:
            disposable_path = Path(directory) / "derived-evidence.sqlite3"
            connection = sqlite3.connect(disposable_path)
            try:
                profile_private = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile_private.get("ok"):
                    raise V544EvidenceError(
                        "Private evidence could not be parsed in disposable storage."
                    )
                boundary_matches = _install_protected_boundaries(
                    connection,
                    custody=custody,
                    blind_output_dir=blind_output_dir,
                )
                roles_private = v56.predeclare_chronological_roles(connection)
                if not roles_private.get("ok"):
                    raise V544EvidenceError(
                        "Private evidence has insufficient isolated chronological windows."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                policy_private = _apply_development_assisted_policy(
                    connection,
                    review_limit=max(0, min(MAX_REVIEW_ROWS, int(review_limit))),
                )
                review_rows = list(policy_private.pop("_review_rows"))
                anomaly = _safe_anomaly_audit(connection)
                stream = _safe_stream_profile(connection, profile_private)
                chronology = _chronology_summary(connection, profile_private)
                cohorts = _cohort_summary(connection, roles_private)
                exclusions = _quarantine_summary(
                    connection,
                    boundary_matches,
                )
                existing_labels = _existing_label_coverage(custody)
                sufficiency = _development_sufficiency(
                    custody=custody,
                    stream=stream,
                    chronology=chronology,
                    cohorts=cohorts,
                    policy=policy_private,
                    existing_labels=existing_labels,
                )
                private_lock = (
                    _write_private_lock(
                        connection,
                        output_dir=output_dir,
                        custody=custody,
                    )
                    if write_output
                    else {
                        "status": "not_written_by_request",
                        "lock_valid": False,
                        "private_path_returned": False,
                        "private_digest_returned": False,
                    }
                )
            finally:
                connection.close()
    except (V544EvidenceError, sqlite3.Error, OSError, ValueError) as exc:
        return _safe_failure(
            "failed_closed_private_evidence",
            error_type=exc.__class__.__name__,
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    protected_after = _protected_workspace_state(
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    deltas = {
        key: int(counts_after[key]) - int(counts_before[key])
        for key in counts_before
    }
    safety = {
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "protected_workspaces_unchanged": protected_before == protected_after,
        "labels_created": deltas.get("ml_labels", 0),
        "model_runs_created": deltas.get("ml_model_runs", 0),
        "detection_runs_created": deltas.get("detection_runs", 0),
        "alerts_created": deltas.get("alerts", 0),
        "response_actions_created": deltas.get("response_actions", 0),
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
        "reserved_future_labels_opened": False,
        "human_reviewed_labels_created": 0,
    }
    safety_passed = bool(
        safety["configured_database_counts_unchanged"]
        and safety["active_model_artifacts_unchanged"]
        and safety["protected_workspaces_unchanged"]
        and all(value == 0 for value in deltas.values())
    )
    review_generated = bool(write_output and review_rows)
    result = {
        "ok": bool(custody["all_checks_passed"] and safety_passed),
        "version": V544_VERSION,
        "status": sufficiency["status"],
        "generated_at": _now(),
        "preflight_only": False,
        "custody": _public_custody(custody),
        "private_evidence": stream,
        "chronology": chronology,
        "cohort_manifest": cohorts,
        "exclusions": exclusions,
        "existing_label_coverage": existing_labels,
        "assisted_label_coverage": policy_private,
        "rule_evidence_distribution": {
            "event_counts": policy_private["rule_event_counts"],
            "representative_group_counts": policy_private[
                "rule_group_counts"
            ],
        },
        "anomaly_evidence_distribution": anomaly,
        "review_pack": {
            "generated": review_generated,
            "rows": len(review_rows) if review_generated else 0,
            "assisted_only": True,
            "human_must_confirm": True,
            "human_reviewed": False,
            "import_ready": False,
            "raw_logs_included": False,
            "ip_addresses_included": False,
            "private_path_returned": False,
        },
        "private_development_lock": private_lock,
        "sufficiency": sufficiency,
        "safety": {**safety, "all_invariants_passed": safety_passed},
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "lifecycle_state": "shadow_observation",
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "rules_alert_authoritative": True,
        "supervised_phases_remaining": 5,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        if review_rows:
            _write_review_pack(output_dir / V544_REVIEW_PACK, review_rows)
        _atomic_write_json(output_dir / V544_LATEST, result)
        report = output_dir / f"{V544_REPORT_PREFIX}_{_stamp()}.md"
        report.write_text(_render_report(result), encoding="utf-8")
        result["reports"] = {
            "written": True,
            "file_names_returned": False,
            "private_paths_returned": False,
        }
    else:
        result["reports"] = {
            "written": False,
            "file_names_returned": False,
            "private_paths_returned": False,
        }
    return result
