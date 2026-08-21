from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56


V541_VERSION = "v5.41-governed-blind-evidence-v1"
V541_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_41_blind_evidence"
V541_MANIFEST = "v5_41_collection_manifest.json"
V541_PRIVATE_STATE = "v5_41_private_custody_state.json"
V541_CANDIDATES = "v5_41_private_candidate_store.json"
V541_REVIEW_PACK = "v5_41_prediction_blind_human_review_pack.csv"
V541_PREDICTION_SEAL = "v5_41_private_prediction_seal.json"
V541_LATEST = "v5_41_blind_evidence_acquisition_latest.json"
V541_REPORT_PREFIX = "v5_41_governed_blind_evidence_acquisition"

TARGET_REVIEW_ROWS = 240
MINIMUM_SOURCE_COUNT = 2
MINIMUM_WINDOW_COUNT = 3
MINIMUM_CLASS_SUPPORT = {
    "benign_like": 100,
    "suspicious": 50,
    "malicious": 50,
}
PUBLIC_STATUSES = (
    "Designed",
    "Collecting",
    "Insufficient Sources",
    "Ready For Human Review",
    "Review Complete",
    "Ready For Frozen Evaluation",
)
HUMAN_REVIEW_FIELDS = {
    "human_decision",
    "human_attack_type",
    "human_confidence",
    "human_notes",
    "human_reviewer",
    "human_reviewed_at",
    "human_must_confirm",
    "human_reviewed",
    "import_ready",
}
ALLOWED_HUMAN_DECISIONS = {
    "benign",
    "benign_unusual",
    "needs_context",
    "suspicious",
    "malicious",
}
FORBIDDEN_REVIEW_COLUMN_PARTS = (
    "prediction",
    "predicted",
    "model_score",
    "model_confidence",
    "rule_code",
    "rule_score",
    "suggestion",
    "ground_truth",
    "answer_key",
    "exact_hash",
    "near_hash",
    "feature_hash",
)
_AI_REVIEWER_PATTERN = re.compile(
    r"(?:assistant|automated|bot|chatgpt|claude|codex|gemini|heuristic|llm|model|openai|synthetic)",
    re.IGNORECASE,
)


class V541EvidenceError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as stream:
            temporary_name = stream.name
            json.dump(payload, stream, indent=2, sort_keys=True, default=str)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _read_json(path: Path, *, default: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return dict(default)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V541EvidenceError("Private v5.41 evidence state failed integrity validation.") from exc
    if not isinstance(payload, dict):
        raise V541EvidenceError("Private v5.41 evidence state failed integrity validation.")
    return payload


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise V541EvidenceError("A human-review pack cannot be created without evidence rows.")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        columns = list(reader.fieldnames or [])
        return [dict(row) for row in reader], columns


def _manifest_default() -> dict[str, Any]:
    return {
        "schema_version": V541_VERSION,
        "created_at": _now(),
        "updated_at": _now(),
        "status": "Designed",
        "policy": {
            "minimum_independent_sources": MINIMUM_SOURCE_COUNT,
            "minimum_collection_windows": MINIMUM_WINDOW_COUNT,
            "target_review_rows": TARGET_REVIEW_ROWS,
            "minimum_class_support": dict(MINIMUM_CLASS_SUPPORT),
            "strictly_after_development_cutoff": True,
            "predictions_hidden_from_reviewers": True,
        },
        "collections": [],
        "review_pack": {
            "created": False,
            "rows": 0,
            "human_reviewed_rows": 0,
            "import_ready": False,
            "predictions_exposed": False,
        },
        "prediction_seal": {
            "created": False,
            "rows": 0,
            "stored_separately": True,
            "labels_included": False,
        },
        "safety": {
            "raw_logs_included": False,
            "ip_addresses_included": False,
            "private_paths_included": False,
            "model_artifact_written": False,
            "model_activated": False,
            "response_actions_created": 0,
        },
    }


def _private_state_default() -> dict[str, Any]:
    return {
        "schema_version": V541_VERSION,
        "token_salt": os.urandom(32).hex(),
        "collections": {},
        "manifest_protected_digest": None,
        "candidate_store_digest": None,
        "review_pack_protected_digest": None,
        "prediction_seal_digest": None,
        "private_paths_recorded": False,
    }


def _candidate_store_default() -> dict[str, Any]:
    return {
        "schema_version": V541_VERSION,
        "rows": [],
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "predictions_included": False,
        "human_labels_included": False,
    }


def _manifest_protected_digest(manifest: dict[str, Any]) -> str:
    return _stable_hash(manifest)


def _candidate_store_digest(candidate_store: dict[str, Any]) -> str:
    return _stable_hash(candidate_store)


def _validate_workspace_integrity(
    manifest: dict[str, Any],
    private_state: dict[str, Any],
    *,
    candidate_store: dict[str, Any] | None = None,
) -> None:
    collections = manifest.get("collections") or []
    if collections:
        expected_manifest = str(private_state.get("manifest_protected_digest") or "")
        if not expected_manifest or _manifest_protected_digest(manifest) != expected_manifest:
            raise V541EvidenceError("The v5.41 collection manifest failed custody validation.")
    if candidate_store is not None:
        candidate_rows = candidate_store.get("rows") or []
        if candidate_rows:
            expected_candidates = str(private_state.get("candidate_store_digest") or "")
            if not expected_candidates or _candidate_store_digest(candidate_store) != expected_candidates:
                raise V541EvidenceError("The v5.41 candidate store failed custody validation.")


def _collection_gate_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    qualifying = [
        item
        for item in manifest.get("collections") or []
        if isinstance(item, dict) and item.get("qualifying") is True
    ]
    sources = {str(item.get("source_token") or "") for item in qualifying}
    windows = {
        str(item.get("collection_window_token") or "") for item in qualifying
    }
    candidate_rows = sum(int(item.get("candidate_rows") or 0) for item in qualifying)
    custody_valid = bool(
        qualifying
        and all(
            item.get("custody_state") == "sealed"
            and item.get("duplicate_group_state") == "contained"
            for item in qualifying
        )
    )
    passed = bool(
        len(sources) >= MINIMUM_SOURCE_COUNT
        and len(windows) >= MINIMUM_WINDOW_COUNT
        and candidate_rows >= TARGET_REVIEW_ROWS
        and custody_valid
    )
    return {
        "passed": passed,
        "independent_source_count": len(sources),
        "collection_window_count": len(windows),
        "candidate_rows": candidate_rows,
        "custody_valid": custody_valid,
    }


def _validate_prediction_seal_integrity(
    private_state: dict[str, Any],
    *,
    output_dir: Path,
) -> bool:
    seal_path = output_dir / V541_PREDICTION_SEAL
    if not seal_path.is_file():
        return False
    expected = str(private_state.get("prediction_seal_digest") or "")
    if not expected:
        raise V541EvidenceError("The v5.41 prediction seal failed custody validation.")
    payload = _read_json(seal_path, default={})
    if _stable_hash(payload) != expected:
        raise V541EvidenceError("The v5.41 prediction seal failed custody validation.")
    return True


def _safe_failure(status: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V541_VERSION,
        "status": status,
        "message": message,
        "lifecycle_state": "shadow_observation",
        "qualifying_blind_evidence": False,
        "configured_database_written": False,
        "labels_written": 0,
        "model_artifact_written": False,
        "model_activated": False,
        "response_actions_created": 0,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }


def _public_v539_boundary(boundary: dict[str, Any]) -> dict[str, Any]:
    value = v540._public_boundary(boundary)
    value["revalidated"] = value.get("status") == "consumed_boundary_locked"
    return value


def load_v541_development_boundary(
    db: Session,
    *,
    min_samples: int = 100,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
) -> dict[str, Any]:
    """Rebuild only the frozen evidence boundary; no model is fitted or scored."""

    boundary = v540.load_v539_consumed_boundary(
        state_path=state_path,
        pack_path=pack_path,
    )
    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        raise V541EvidenceError(str(dataset.get("message") or "Development evidence is unavailable."))
    filtered, exclusion = v540.exclude_v539_consumed_evidence(dataset, boundary)
    canonical = frozen.build_frozen_partition(
        filtered["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(filtered["rows"], canonical)
    if not leakage.get("passed"):
        raise V541EvidenceError("The v5.40 development boundary failed duplicate isolation.")
    development = v55.build_development_dataset(filtered, canonical)
    timestamps = sorted(
        timestamp
        for row in development["rows"]
        if (timestamp := _parse_timestamp(row.get("timestamp"))) is not None
    )
    if not timestamps:
        raise V541EvidenceError("The v5.40 development cutoff is unavailable.")

    propagation_hashes: set[str] = set()
    for log in development["logs"]:
        timestamp = frozen._timestamp(log)
        minute = v56._minute_bucket(timestamp)
        normalized = {
            "log_type": getattr(log, "log_type", None),
            "subtype": getattr(log, "subtype", None),
            "app": getattr(log, "app", None),
            "action": getattr(log, "action", None),
            "protocol": getattr(log, "protocol", None),
            "src_port": getattr(log, "src_port", None),
            "dst_port": getattr(log, "dst_port", None),
            "src_zone": getattr(log, "src_zone", None),
            "dst_zone": getattr(log, "dst_zone", None),
            "app_risk": getattr(log, "app_risk", None),
            "bytes": getattr(log, "bytes", None),
            "packets": getattr(log, "packets", None),
        }
        propagation_hashes.add(
            v56._stable_hash(
                {
                    "source": v56._safe_token("source", getattr(log, "src_ip", None)),
                    "pattern": v56._near_fingerprint(normalized, minute=minute),
                }
            )
        )

    return {
        "status": "v5_41_development_boundary_locked",
        "cutoff": timestamps[-1],
        "development_rows": len(development["rows"]),
        "development_exact_hashes": frozenset(
            str(row.get("exact_fingerprint") or "")
            for row in development["rows"]
            if row.get("exact_fingerprint")
        ),
        "development_near_hashes": frozenset(
            str(row.get("near_fingerprint") or "")
            for row in development["rows"]
            if row.get("near_fingerprint")
        ),
        "development_propagation_hashes": frozenset(propagation_hashes),
        "development_source_names": frozenset(
            str(row.get("source_name") or "").strip().casefold()
            for row in development["rows"]
            if str(row.get("source_name") or "").strip()
        ),
        "protected_v539_tokens": boundary["_protected_tokens"],
        "v539_boundary": boundary,
        "v539_exclusion": exclusion,
        "duplicate_isolation_passed": True,
        "labels_used_for_modeling": False,
        "model_fitted": False,
    }


def _validate_attestation(
    path: Path | None,
    *,
    source_name: str,
    collection_window: str,
) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"valid": False, "status": "source_attestation_missing"}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "status": "source_attestation_invalid"}
    if not isinstance(value, dict):
        return {"valid": False, "status": "source_attestation_invalid"}
    reviewer = str(value.get("attested_by") or "").strip()
    timestamp = _parse_timestamp(value.get("attested_at"))
    valid = bool(
        value.get("physical_device_confirmed") is True
        and str(value.get("source_name") or "").strip() == source_name
        and str(value.get("collection_window") or "").strip() == collection_window
        and reviewer
        and not _AI_REVIEWER_PATTERN.search(reviewer)
        and timestamp is not None
    )
    return {
        "valid": valid,
        "status": "operator_attestation_valid" if valid else "source_attestation_invalid",
        "human_attestation_required": True,
        "identity_returned": False,
    }


def _token(salt: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{salt}:{kind}:{value}".encode("utf-8")).hexdigest()[:24]


def _install_prior_hashes(
    connection: sqlite3.Connection,
    *,
    exact_hashes: Iterable[str],
    propagation_hashes: Iterable[str],
) -> dict[str, int]:
    connection.executescript(
        """
        CREATE TEMP TABLE v541_prior_exact(hash TEXT PRIMARY KEY);
        CREATE TEMP TABLE v541_prior_propagation(hash TEXT PRIMARY KEY);
        """
    )
    connection.executemany(
        "INSERT OR IGNORE INTO v541_prior_exact(hash) VALUES (?)",
        ((value,) for value in exact_hashes),
    )
    connection.executemany(
        "INSERT OR IGNORE INTO v541_prior_propagation(hash) VALUES (?)",
        ((value,) for value in propagation_hashes),
    )
    exact_overlap = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE exact_hash IN (SELECT hash FROM v541_prior_exact)"
        ).fetchone()[0]
    )
    near_overlap = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE propagation_hash IN "
            "(SELECT hash FROM v541_prior_propagation)"
        ).fetchone()[0]
    )
    connection.executescript(
        """
        UPDATE events
        SET quarantine_reason=COALESCE(quarantine_reason, 'v540_exact_overlap')
        WHERE exact_hash IN (SELECT hash FROM v541_prior_exact);
        UPDATE events
        SET quarantine_reason=COALESCE(quarantine_reason, 'v540_near_overlap')
        WHERE propagation_hash IN (SELECT hash FROM v541_prior_propagation);
        """
    )
    connection.commit()
    return {"exact_overlap_rows": exact_overlap, "near_overlap_rows": near_overlap}


def _count_v539_token_overlap(
    connection: sqlite3.Connection,
    protected_tokens: frozenset[str],
) -> int:
    matches = 0
    cursor = connection.execute("SELECT DISTINCT propagation_hash FROM events")
    while batch := cursor.fetchmany(5000):
        matches += sum(
            v521._review_token(str(row[0])) in protected_tokens
            for row in batch
        )
    return matches


def _apply_cutoff(
    connection: sqlite3.Connection,
    *,
    cutoff: datetime,
) -> dict[str, int]:
    cutoff_text = cutoff.astimezone(UTC).isoformat()
    connection.execute(
        "UPDATE events SET quarantine_reason=COALESCE(quarantine_reason, "
        "'missing_event_time') WHERE event_time IS NULL"
    )
    connection.execute(
        "UPDATE events SET quarantine_reason=COALESCE(quarantine_reason, "
        "'not_after_development_cutoff') WHERE event_time IS NOT NULL AND event_time <= ?",
        (cutoff_text,),
    )
    connection.execute(
        "UPDATE events SET role_rank=0 WHERE quarantine_reason IS NULL AND event_time > ?",
        (cutoff_text,),
    )
    connection.commit()
    return {
        "missing_time_rows": int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_time IS NULL"
            ).fetchone()[0]
        ),
        "at_or_before_cutoff_rows": int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_time IS NOT NULL AND event_time <= ?",
                (cutoff_text,),
            ).fetchone()[0]
        ),
        "strictly_after_cutoff_rows": int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_time > ?",
                (cutoff_text,),
            ).fetchone()[0]
        ),
        "eligible_after_all_exclusions": int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE role_rank=0 AND quarantine_reason IS NULL"
            ).fetchone()[0]
        ),
    }


def _candidate_projection(
    row: dict[str, Any],
    *,
    exact_hash: str,
    source_token: str,
    window_token: str,
) -> dict[str, Any]:
    pattern = v521._pattern(row)
    near_hash = frozen._stable_hash(
        {
            "log_type": row.get("log_type"),
            "subtype": row.get("subtype"),
            "app": str(row.get("app") or "").lower(),
            "action": str(row.get("action") or "").lower(),
            "protocol": str(row.get("protocol") or "").lower(),
            "src_port": row.get("src_port"),
            "dst_port": row.get("dst_port"),
            "src_zone": str(row.get("src_zone") or "").lower(),
            "dst_zone": str(row.get("dst_zone") or "").lower(),
            "app_risk": row.get("app_risk"),
            "bytes_bucket": frozen._magnitude_bucket(row.get("bytes")),
            "packets_bucket": frozen._magnitude_bucket(row.get("packets")),
        }
    )
    feature_hash = _stable_hash(
        {
            key: row.get(key)
            for key in (
                "log_type",
                "subtype",
                "app",
                "action",
                "protocol",
                "src_port",
                "dst_port",
                "src_zone",
                "dst_zone",
                "app_risk",
                "schema_bucket",
                "source_event_count",
                "source_unique_destinations",
                "source_unique_ports",
                "source_deny_count",
                "source_unknown_app_count",
                "source_high_risk_app_count",
            )
        }
    )
    review_token = _stable_hash(
        {
            "version": V541_VERSION,
            "source": source_token,
            "window": window_token,
            "exact": exact_hash,
            "near": near_hash,
        }
    )[:24]
    return {
        "review_token": review_token,
        "source_token": source_token,
        "window_token": window_token,
        "exact_hash": exact_hash,
        "near_hash": near_hash,
        "feature_hash": feature_hash,
        "pattern": pattern,
        "review_priority": "required_human_ground_truth",
        "event_time_utc": row.get("event_time"),
        "log_type": row.get("log_type"),
        "subtype": row.get("subtype"),
        "application": row.get("app"),
        "action": row.get("action"),
        "protocol": row.get("protocol"),
        "source_port": row.get("src_port"),
        "destination_port": row.get("dst_port"),
        "source_zone": row.get("src_zone"),
        "destination_zone": row.get("dst_zone"),
        "bytes": row.get("bytes"),
        "packets": row.get("packets"),
        "elapsed_time": row.get("elapsed_time"),
        "application_risk": row.get("app_risk"),
        "threat_severity": row.get("threat_severity"),
        "session_end_reason": row.get("session_end_reason"),
        "parser_error": bool(row.get("parser_error")),
        "parser_warning_count": int(row.get("parser_warning_count") or 0),
        "required_missing_count": int(row.get("required_missing_count") or 0),
        "schema_bucket": row.get("schema_bucket"),
        "group_size": int(row.get("group_size") or 1),
        "source_event_count": int(row.get("source_event_count") or 0),
        "source_deny_count": int(row.get("source_deny_count") or 0),
        "source_unique_destinations": int(row.get("source_unique_destinations") or 0),
        "source_unique_ports": int(row.get("source_unique_ports") or 0),
        "source_unknown_app_count": int(row.get("source_unknown_app_count") or 0),
        "source_high_risk_app_count": int(row.get("source_high_risk_app_count") or 0),
        "destination_repeat_count": int(row.get("destination_repeat_count") or 0),
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "prediction_included": False,
    }


def _select_candidates(
    connection: sqlite3.Connection,
    *,
    source_token: str,
    window_token: str,
    development_near_hashes: frozenset[str],
    existing_rows: list[dict[str, Any]],
    limit: int = TARGET_REVIEW_ROWS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    v56.build_disposable_behavior_aggregates(connection)
    existing_exact = {str(row.get("exact_hash") or "") for row in existing_rows}
    existing_near = {str(row.get("near_hash") or "") for row in existing_rows}
    selected_exact = set(existing_exact)
    selected_near = set(existing_near)
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded = Counter()
    for values in connection.execute(v56.REPRESENTATIVE_QUERY):
        row = v56._row_mapping(values)
        exact_row = connection.execute(
            "SELECT exact_hash, quarantine_reason FROM events WHERE id=?",
            (int(row["id"]),),
        ).fetchone()
        if exact_row is None or exact_row[1] is not None:
            excluded["quarantined"] += 1
            continue
        candidate = _candidate_projection(
            row,
            exact_hash=str(exact_row[0]),
            source_token=source_token,
            window_token=window_token,
        )
        if candidate["exact_hash"] in selected_exact:
            excluded["candidate_exact_duplicate"] += 1
            continue
        if candidate["near_hash"] in selected_near:
            excluded["candidate_near_duplicate"] += 1
            continue
        if candidate["near_hash"] in development_near_hashes:
            excluded["v540_near_overlap"] += 1
            continue
        candidate["selection_key"] = _stable_hash(
            {
                "version": V541_VERSION,
                "pattern": candidate["pattern"],
                "token": candidate["review_token"],
            }
        )
        buckets[str(candidate["pattern"])].append(candidate)
        selected_exact.add(str(candidate["exact_hash"]))
        selected_near.add(str(candidate["near_hash"]))

    for values in buckets.values():
        values.sort(key=lambda item: str(item["selection_key"]))
    selected: list[dict[str, Any]] = []
    patterns = sorted(buckets)
    offset = 0
    while len(selected) < max(1, int(limit)):
        added = False
        for pattern in patterns:
            values = buckets[pattern]
            if offset < len(values):
                selected.append(values[offset])
                added = True
                if len(selected) >= limit:
                    break
        if not added:
            break
        offset += 1
    for row in selected:
        row.pop("selection_key", None)
    return selected, {
        "selected_rows": len(selected),
        "represented_strata": len({str(row["pattern"]) for row in selected}),
        "excluded_candidate_rows": sum(excluded.values()),
        "exclusion_reasons": dict(excluded),
        "duplicate_families_contained": len(
            {str(row["exact_hash"]) for row in selected}
        )
        == len(selected)
        and len({str(row["near_hash"]) for row in selected}) == len(selected),
    }


def _review_projection(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_token": row["review_token"],
        "source_reference": row["source_token"],
        "collection_window_reference": row["window_token"],
        "pattern": row["pattern"],
        "review_priority": row["review_priority"],
        "event_time_utc": row.get("event_time_utc"),
        "log_type": row.get("log_type"),
        "subtype": row.get("subtype"),
        "application": row.get("application"),
        "action": row.get("action"),
        "protocol": row.get("protocol"),
        "source_port": row.get("source_port"),
        "destination_port": row.get("destination_port"),
        "source_zone": row.get("source_zone"),
        "destination_zone": row.get("destination_zone"),
        "bytes": row.get("bytes"),
        "packets": row.get("packets"),
        "elapsed_time": row.get("elapsed_time"),
        "application_risk": row.get("application_risk"),
        "threat_severity": row.get("threat_severity"),
        "session_end_reason": row.get("session_end_reason"),
        "parser_error": row.get("parser_error"),
        "parser_warning_count": row.get("parser_warning_count"),
        "required_missing_count": row.get("required_missing_count"),
        "schema_bucket": row.get("schema_bucket"),
        "group_size": row.get("group_size"),
        "source_event_count": row.get("source_event_count"),
        "source_deny_count": row.get("source_deny_count"),
        "source_unique_destinations": row.get("source_unique_destinations"),
        "source_unique_ports": row.get("source_unique_ports"),
        "source_unknown_app_count": row.get("source_unknown_app_count"),
        "source_high_risk_app_count": row.get("source_high_risk_app_count"),
        "destination_repeat_count": row.get("destination_repeat_count"),
        "human_decision": "",
        "human_attack_type": "",
        "human_confidence": "",
        "human_notes": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_must_confirm": True,
        "human_reviewed": False,
        "import_ready": False,
    }


def _protected_review_digest(rows: list[dict[str, Any]], columns: list[str]) -> str:
    def canonical(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        text = str(value)
        if text.casefold() in {"true", "false"}:
            return text.casefold()
        return text

    protected = [column for column in columns if column not in HUMAN_REVIEW_FIELDS]
    return _stable_hash(
        {
            "columns": columns,
            "protected_rows": [
                {column: canonical(row.get(column)) for column in protected}
                for row in rows
            ],
        }
    )


def seal_predictions_separately(
    *,
    predictions: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    output_dir: Path = V541_OUTPUT_DIR,
    candidate_contract: dict[str, Any],
) -> dict[str, Any]:
    """Seal future frozen predictions away from the human review CSV."""

    if candidate_contract.get("status") != "diagnostic_configuration_frozen":
        raise V541EvidenceError("A frozen diagnostic candidate contract is required.")
    manifest = _read_json(output_dir / V541_MANIFEST, default=_manifest_default())
    private_state = _read_json(
        output_dir / V541_PRIVATE_STATE,
        default=_private_state_default(),
    )
    candidate_store = _read_json(
        output_dir / V541_CANDIDATES,
        default=_candidate_store_default(),
    )
    _validate_workspace_integrity(
        manifest,
        private_state,
        candidate_store=candidate_store,
    )
    if not _collection_gate_summary(manifest)["passed"]:
        raise V541EvidenceError("The blind-evidence collection gate is incomplete.")
    stored_tokens = {
        str(row.get("review_token") or "")
        for row in candidate_store.get("rows") or []
    }
    expected = {str(row["review_token"]) for row in candidate_rows}
    received = {str(row.get("review_token") or "") for row in predictions}
    if (
        len(candidate_rows) != TARGET_REVIEW_ROWS
        or not expected
        or expected != received
        or not expected.issubset(stored_tokens)
    ):
        raise V541EvidenceError("Prediction rows do not match the sealed candidate evidence.")
    allowed = {"review_token", "queue_decision", "queue_score", "confidence"}
    sealed_rows = []
    for prediction in predictions:
        if set(prediction) - allowed:
            raise V541EvidenceError("Prediction seal contains an unsupported field.")
        sealed_rows.append({key: prediction.get(key) for key in sorted(allowed)})
    payload = {
        "schema_version": V541_VERSION,
        "created_at": _now(),
        "candidate_contract_digest": _stable_hash(candidate_contract),
        "rows": sealed_rows,
        "predictions_created_before_human_review": True,
        "human_labels_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    seal_path = output_dir / V541_PREDICTION_SEAL
    _atomic_write_json(seal_path, payload)
    seal_digest = _stable_hash(payload)
    private_state["prediction_seal_digest"] = seal_digest
    manifest["prediction_seal"] = {
        "created": True,
        "rows": len(sealed_rows),
        "stored_separately": True,
        "labels_included": False,
    }
    manifest["updated_at"] = _now()
    private_state["manifest_protected_digest"] = _manifest_protected_digest(manifest)
    _atomic_write_json(output_dir / V541_MANIFEST, manifest)
    _atomic_write_json(output_dir / V541_PRIVATE_STATE, private_state)
    return {
        "created": True,
        "rows": len(sealed_rows),
        "stored_separately": True,
        "labels_included": False,
        "path_returned": False,
        "seal_digest": seal_digest,
    }


def generate_prediction_blind_review_pack(
    *,
    candidate_rows: list[dict[str, Any]],
    output_dir: Path = V541_OUTPUT_DIR,
    prediction_seal_digest: str,
    target_rows: int = TARGET_REVIEW_ROWS,
) -> dict[str, Any]:
    if not prediction_seal_digest:
        raise V541EvidenceError("Predictions must be sealed separately before review opens.")
    manifest = _read_json(output_dir / V541_MANIFEST, default=_manifest_default())
    private_state = _read_json(
        output_dir / V541_PRIVATE_STATE,
        default=_private_state_default(),
    )
    candidate_store = _read_json(
        output_dir / V541_CANDIDATES,
        default=_candidate_store_default(),
    )
    _validate_workspace_integrity(
        manifest,
        private_state,
        candidate_store=candidate_store,
    )
    if not _collection_gate_summary(manifest)["passed"]:
        raise V541EvidenceError("The blind-evidence collection gate is incomplete.")
    if not _validate_prediction_seal_integrity(private_state, output_dir=output_dir):
        raise V541EvidenceError("Predictions must be sealed separately before review opens.")
    if prediction_seal_digest != private_state.get("prediction_seal_digest"):
        raise V541EvidenceError("The prediction-seal custody digest does not match.")
    if len(candidate_rows) < target_rows:
        raise V541EvidenceError("Insufficient disjoint rows for the human-review target.")
    stored_tokens = {
        str(row.get("review_token") or "")
        for row in candidate_store.get("rows") or []
    }
    if not {
        str(row.get("review_token") or "") for row in candidate_rows
    }.issubset(stored_tokens):
        raise V541EvidenceError("Review rows do not match the sealed candidate evidence.")
    selected = sorted(
        candidate_rows,
        key=lambda row: (str(row.get("pattern") or ""), str(row["review_token"])),
    )[:target_rows]
    rows = [_review_projection(row) for row in selected]
    columns = list(rows[0])
    lowered = [column.lower() for column in columns]
    if any(part in column for column in lowered for part in FORBIDDEN_REVIEW_COLUMN_PARTS):
        raise V541EvidenceError("The review pack would expose hidden prediction or fingerprint data.")
    if len({str(row["review_token"]) for row in rows}) != len(rows):
        raise V541EvidenceError("The review pack contains duplicate row tokens.")
    output_dir.mkdir(parents=True, exist_ok=True)
    pack_path = output_dir / V541_REVIEW_PACK
    _write_csv(pack_path, rows)
    result = {
        "created": True,
        "rows": len(rows),
        "protected_digest": _protected_review_digest(rows, columns),
        "prediction_seal_digest": prediction_seal_digest,
        "predictions_exposed": False,
        "suggestions_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "human_reviewed_rows": 0,
        "import_ready": False,
        "path_returned": False,
    }
    private_state["review_pack_protected_digest"] = result["protected_digest"]
    manifest["review_pack"] = {
        "created": True,
        "rows": len(rows),
        "human_reviewed_rows": 0,
        "import_ready": False,
        "predictions_exposed": False,
    }
    manifest["updated_at"] = _now()
    private_state["manifest_protected_digest"] = _manifest_protected_digest(manifest)
    _atomic_write_json(output_dir / V541_MANIFEST, manifest)
    _atomic_write_json(output_dir / V541_PRIVATE_STATE, private_state)
    return result


def _review_progress(
    manifest: dict[str, Any],
    private_state: dict[str, Any],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    path = output_dir / V541_REVIEW_PACK
    if not path.is_file():
        if manifest.get("review_pack", {}).get("created"):
            raise V541EvidenceError("The v5.41 review pack failed custody validation.")
        return {
            "available": False,
            "rows": 0,
            "reviewed": 0,
            "invalid": 0,
            "class_support": {key: 0 for key in MINIMUM_CLASS_SUPPORT},
            "complete": False,
            "protected_content_valid": False,
        }
    rows, columns = _read_csv(path)
    if any(
        part in column.lower()
        for column in columns
        for part in FORBIDDEN_REVIEW_COLUMN_PARTS
    ):
        raise V541EvidenceError("The v5.41 review pack violated prediction blindness.")
    expected_digest = str(private_state.get("review_pack_protected_digest") or "")
    protected_valid = bool(
        expected_digest and _protected_review_digest(rows, columns) == expected_digest
    )
    if not protected_valid:
        raise V541EvidenceError("The v5.41 review pack failed custody validation.")
    reviewed = 0
    invalid = 0
    support = Counter()
    for row in rows:
        if not _boolean(row.get("human_reviewed")):
            continue
        reviewed += 1
        decision = str(row.get("human_decision") or "").strip().lower()
        reviewer = str(row.get("human_reviewer") or "").strip()
        confidence = str(row.get("human_confidence") or "").strip()
        valid = bool(
            decision in ALLOWED_HUMAN_DECISIONS
            and reviewer
            and not _AI_REVIEWER_PATTERN.search(reviewer)
            and _parse_timestamp(row.get("human_reviewed_at")) is not None
            and confidence.isdigit()
            and 1 <= int(confidence) <= 100
            and _boolean(row.get("human_must_confirm"))
        )
        if not valid:
            invalid += 1
            continue
        if decision in {"benign", "benign_unusual"}:
            support["benign_like"] += 1
        elif decision == "suspicious":
            support["suspicious"] += 1
        elif decision == "malicious":
            support["malicious"] += 1
    complete = bool(
        rows
        and reviewed == len(rows)
        and invalid == 0
        and protected_valid
    )
    return {
        "available": True,
        "rows": len(rows),
        "reviewed": reviewed,
        "invalid": invalid,
        "class_support": {
            key: int(support.get(key, 0)) for key in MINIMUM_CLASS_SUPPORT
        },
        "complete": complete,
        "class_support_passed": bool(
            complete
            and all(support.get(key, 0) >= target for key, target in MINIMUM_CLASS_SUPPORT.items())
        ),
        "protected_content_valid": protected_valid,
        "metrics_calculated": False,
    }


def _derive_status(
    manifest: dict[str, Any],
    private_state: dict[str, Any],
    *,
    output_dir: Path,
) -> tuple[str, dict[str, Any]]:
    collections = [
        item for item in manifest.get("collections") or [] if isinstance(item, dict)
    ]
    qualifying = [item for item in collections if item.get("qualifying") is True]
    sources = {str(item.get("source_token") or "") for item in qualifying}
    windows = {str(item.get("collection_window_token") or "") for item in qualifying}
    eligible_rows = sum(int(item.get("candidate_rows") or 0) for item in qualifying)
    review = _review_progress(manifest, private_state, output_dir=output_dir)
    prediction_sealed = bool(
        manifest.get("prediction_seal", {}).get("created")
        and _validate_prediction_seal_integrity(
            private_state,
            output_dir=output_dir,
        )
    )
    if review.get("complete") and review.get("class_support_passed") and prediction_sealed:
        status = "Ready For Frozen Evaluation"
    elif review.get("complete"):
        status = "Review Complete"
    elif review.get("available") and prediction_sealed:
        status = "Ready For Human Review"
    elif collections and (len(sources) < MINIMUM_SOURCE_COUNT or len(windows) < MINIMUM_WINDOW_COUNT):
        status = "Insufficient Sources"
    elif qualifying:
        status = "Collecting"
    else:
        status = "Designed"
    return status, {
        "qualifying_collections": len(qualifying),
        "independent_source_count": len(sources),
        "collection_window_count": len(windows),
        "candidate_rows": eligible_rows,
        "review": review,
        "prediction_sealed": prediction_sealed,
    }


def get_public_blind_evidence_status(
    *,
    output_dir: Path = V541_OUTPUT_DIR,
) -> dict[str, Any]:
    manifest_path = output_dir / V541_MANIFEST
    private_path = output_dir / V541_PRIVATE_STATE
    candidate_path = output_dir / V541_CANDIDATES
    if manifest_path.is_file() != private_path.is_file():
        raise V541EvidenceError("Private v5.41 evidence state failed integrity validation.")
    if candidate_path.is_file() and not manifest_path.is_file():
        raise V541EvidenceError("Private v5.41 evidence state failed integrity validation.")
    if not manifest_path.is_file():
        manifest = _manifest_default()
        private_state = _private_state_default()
    else:
        manifest = _read_json(manifest_path, default=_manifest_default())
        private_state = _read_json(private_path, default=_private_state_default())
        if manifest.get("schema_version") != V541_VERSION or private_state.get("schema_version") != V541_VERSION:
            raise V541EvidenceError("Private v5.41 evidence state failed integrity validation.")
        candidate_store = None
        if manifest.get("collections"):
            if not candidate_path.is_file():
                raise V541EvidenceError(
                    "Private v5.41 evidence state failed integrity validation."
                )
            candidate_store = _read_json(
                candidate_path,
                default=_candidate_store_default(),
            )
        _validate_workspace_integrity(
            manifest,
            private_state,
            candidate_store=candidate_store,
        )
    status, summary = _derive_status(manifest, private_state, output_dir=output_dir)
    review = summary["review"]
    return {
        "version": V541_VERSION,
        "status": status,
        "qualifying_collection_count": summary["qualifying_collections"],
        "independent_source_count": summary["independent_source_count"],
        "required_source_count": MINIMUM_SOURCE_COUNT,
        "collection_window_count": summary["collection_window_count"],
        "required_window_count": MINIMUM_WINDOW_COUNT,
        "candidate_rows": summary["candidate_rows"],
        "target_review_rows": TARGET_REVIEW_ROWS,
        "review_pack_available": bool(review.get("available")),
        "human_reviewed_rows": int(review.get("reviewed") or 0),
        "human_review_complete": bool(review.get("complete")),
        "class_support": review.get("class_support") or {},
        "prediction_sealed_separately": summary["prediction_sealed"],
        "metrics_available": False,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "private_paths_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "secrets_exposed": False,
        "message": {
            "Designed": "The governed collection protocol is ready; no qualifying blind evidence is registered.",
            "Collecting": "Qualifying evidence is being collected; review remains closed.",
            "Insufficient Sources": "Additional independently verified sources or collection windows are required.",
            "Ready For Human Review": "Predictions are sealed separately and the prediction-blind review pack is ready.",
            "Review Complete": "Human review is complete; frozen-evaluation prerequisites are still incomplete.",
            "Ready For Frozen Evaluation": "Custody and human-review gates are complete for a separate one-shot evaluator.",
        }[status],
    }


def _render_report(result: dict[str, Any]) -> str:
    rehearsal = result.get("rehearsal") or {}
    readiness = result.get("collection_readiness") or {}
    return "\n".join(
        [
            "# v5.41 Governed Blind Evidence Acquisition",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Rehearsal only: `{result.get('rehearsal_only')}`",
            f"- Rows parsed: `{rehearsal.get('rows_processed', 0)}`",
            f"- Parser failures: `{rehearsal.get('parser_failures', 0)}`",
            f"- Configured-data exact overlap rows: `{rehearsal.get('configured_overlap_rows', 0)}`",
            f"- Strictly-after-cutoff rows: `{rehearsal.get('strictly_after_cutoff_rows', 0)}`",
            f"- Qualifying sources: `{readiness.get('independent_source_count', 0)}`",
            f"- Qualifying windows: `{readiness.get('collection_window_count', 0)}`",
            f"- Review-pack ready: `{readiness.get('review_pack_available', False)}`",
            "- Existing private paths, raw logs, IP addresses, source identities, and fingerprints are not included.",
            "- No label, model, alert, detection-run, or response-action write occurred.",
            "- Supervised lifecycle remains `shadow_observation`; deterministic rules remain alert-authoritative.",
            "",
        ]
    )


def run_v541_blind_evidence_acquisition(
    db: Session,
    *,
    sample_path: Path | None = None,
    source_name: str = "",
    collection_window: str = "",
    parser_profile: str = "palo_alto",
    use_temp_db: bool = False,
    rehearsal_only: bool = False,
    preflight_only: bool = False,
    source_attestation: Path | None = None,
    min_samples: int = 100,
    candidate_limit: int = TARGET_REVIEW_ROWS,
    output_dir: Path = V541_OUTPUT_DIR,
    write_output: bool = True,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
) -> dict[str, Any]:
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    try:
        boundary = load_v541_development_boundary(
            db,
            min_samples=min_samples,
            state_path=state_path,
            pack_path=pack_path,
        )
    except (V541EvidenceError, v540.V540EvidenceBoundaryError) as exc:
        return _safe_failure("failed_closed_boundary", str(exc))

    base = {
        "ok": True,
        "version": V541_VERSION,
        "generated_at": _now(),
        "status": "preflight_complete",
        "preflight_only": bool(preflight_only),
        "rehearsal_only": bool(rehearsal_only),
        "qualifying_blind_evidence": False,
        "v539_boundary": _public_v539_boundary(boundary["v539_boundary"]),
        "v540_boundary": {
            "status": boundary["status"],
            "development_rows": boundary["development_rows"],
            "cutoff_locked": True,
            "cutoff_returned": False,
            "duplicate_isolation_passed": boundary["duplicate_isolation_passed"],
            "model_fitted": False,
        },
    }
    if sample_path is None:
        status = get_public_blind_evidence_status(output_dir=output_dir)
        return {
            **base,
            "collection_readiness": status,
            "safety": {
                "configured_database_written": False,
                "labels_written": 0,
                "model_artifact_written": False,
                "model_activated": False,
                "response_actions_created": 0,
            },
        }
    if not use_temp_db:
        return _safe_failure(
            "failed_closed_temp_db_acknowledgement_required",
            "Private evidence may be inspected only with --use-temp-db.",
        )
    if not sample_path.is_file():
        return _safe_failure("private_evidence_unavailable", "The private evidence file is unavailable.")
    if parser_profile != "palo_alto":
        return _safe_failure(
            "unsupported_parser_profile",
            "v5.41 currently accepts only the governed palo_alto evidence profile.",
        )
    if not rehearsal_only and (not source_name.strip() or not collection_window.strip()):
        return _safe_failure(
            "source_metadata_required",
            "Qualifying collection requires a source name and collection window.",
        )

    manifest = _read_json(output_dir / V541_MANIFEST, default=_manifest_default())
    private_state = _read_json(output_dir / V541_PRIVATE_STATE, default=_private_state_default())
    candidate_store = _read_json(output_dir / V541_CANDIDATES, default=_candidate_store_default())
    if manifest.get("schema_version") != V541_VERSION or private_state.get("schema_version") != V541_VERSION:
        return _safe_failure("failed_closed_private_state", "Private v5.41 state failed integrity validation.")
    try:
        _validate_workspace_integrity(
            manifest,
            private_state,
            candidate_store=candidate_store,
        )
    except V541EvidenceError as exc:
        return _safe_failure("failed_closed_private_state", str(exc))
    salt = str(private_state.get("token_salt") or "")
    if len(salt) < 32:
        return _safe_failure("failed_closed_private_state", "Private v5.41 state failed integrity validation.")
    safe_source_name = source_name.strip() or "rehearsal-source"
    safe_window = collection_window.strip() or "rehearsal-window"
    source_token = _token(salt, "source", safe_source_name)
    window_token = _token(salt, "window", f"{safe_source_name}:{safe_window}")
    attestation = _validate_attestation(
        source_attestation,
        source_name=safe_source_name,
        collection_window=safe_window,
    )
    source_overlaps_development = (
        safe_source_name.casefold() in boundary["development_source_names"]
    )

    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v541-") as temporary:
            connection = sqlite3.connect(Path(temporary) / "blind-evidence.sqlite3")
            try:
                streamed = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                    chunk_size=2000,
                )
                if not streamed.get("ok"):
                    return _safe_failure(
                        "private_evidence_stream_failed",
                        "Private evidence could not be parsed in disposable storage.",
                    )
                prior_overlap = _install_prior_hashes(
                    connection,
                    exact_hashes=boundary["development_exact_hashes"],
                    propagation_hashes=boundary["development_propagation_hashes"],
                )
                v539_overlap = _count_v539_token_overlap(
                    connection,
                    boundary["protected_v539_tokens"],
                )
                cutoff = _apply_cutoff(connection, cutoff=boundary["cutoff"])
                selected, selection = _select_candidates(
                    connection,
                    source_token=source_token,
                    window_token=window_token,
                    development_near_hashes=boundary["development_near_hashes"],
                    existing_rows=list(candidate_store.get("rows") or []),
                    limit=candidate_limit,
                )
            finally:
                connection.close()
    except (OSError, sqlite3.Error, ValueError, V541EvidenceError) as exc:
        result = _safe_failure(
            "private_evidence_rehearsal_failed",
            "The disposable private-evidence rehearsal failed closed.",
        )
        result["error_type"] = exc.__class__.__name__
        return result

    configured_overlap = int(streamed.get("configured_database_overlap_rows") or 0)
    qualification_reasons = []
    if rehearsal_only:
        qualification_reasons.append("rehearsal_only")
    if not attestation.get("valid"):
        qualification_reasons.append(str(attestation.get("status") or "source_attestation_missing"))
    if source_overlaps_development:
        qualification_reasons.append("development_source_overlap")
    if int(cutoff["eligible_after_all_exclusions"]) <= 0:
        qualification_reasons.append("no_rows_after_cutoff_and_overlap_exclusions")
    if configured_overlap:
        qualification_reasons.append("configured_database_overlap_detected")
    if v539_overlap:
        qualification_reasons.append("v539_consumed_overlap_detected")
    if not selection["duplicate_families_contained"]:
        qualification_reasons.append("duplicate_family_isolation_failed")
    qualifying = not qualification_reasons

    if qualifying and not preflight_only:
        collection_key = _stable_hash(
            {
                "source": source_token,
                "window": window_token,
                "file": _file_sha256(sample_path),
            }
        )
        if collection_key not in private_state["collections"]:
            private_state["collections"][collection_key] = {
                "source_token": source_token,
                "window_token": window_token,
                "file_digest": _file_sha256(sample_path),
                "attestation_valid": True,
                "created_at": _now(),
            }
            candidate_store["rows"] = [
                *list(candidate_store.get("rows") or []),
                *selected,
            ]
            manifest["collections"].append(
                {
                    "source_token": source_token,
                    "collection_window_token": window_token,
                    "parser_profile": parser_profile,
                    "schema_profiles": streamed.get("schema_profiles") or [],
                    "aggregate_counts": {
                        "rows_processed": int(streamed.get("rows_processed") or 0),
                        "parser_successes": int(streamed.get("parser_successes") or 0),
                        "parser_failures": int(streamed.get("parser_failures") or 0),
                        "eligible_rows": int(cutoff["eligible_after_all_exclusions"]),
                    },
                    "custody_state": "sealed",
                    "duplicate_group_state": (
                        "contained" if selection["duplicate_families_contained"] else "failed"
                    ),
                    "candidate_rows": len(selected),
                    "qualifying": True,
                    "rehearsal_only": False,
                }
            )
            manifest["updated_at"] = _now()
            private_state["candidate_store_digest"] = _candidate_store_digest(
                candidate_store
            )
            private_state["manifest_protected_digest"] = (
                _manifest_protected_digest(manifest)
            )
            _atomic_write_json(output_dir / V541_CANDIDATES, candidate_store)
            _atomic_write_json(output_dir / V541_MANIFEST, manifest)
            _atomic_write_json(output_dir / V541_PRIVATE_STATE, private_state)

    public_status = get_public_blind_evidence_status(output_dir=output_dir)
    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    safety = {
        "configured_database_counts_unchanged": counts_before == counts_after,
        "configured_database_written": False,
        "labels_written": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_written": counts_after["ml_model_runs"] - counts_before["ml_model_runs"],
        "detection_runs_written": counts_after["detection_runs"] - counts_before["detection_runs"],
        "alerts_written": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"] - counts_before["response_actions"],
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
        "disposable_index_removed": True,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    result = {
        **base,
        "status": "rehearsal_complete" if rehearsal_only else (
            "qualifying_collection_registered" if qualifying else "collection_rejected"
        ),
        "qualifying_blind_evidence": bool(qualifying and not rehearsal_only),
        "rehearsal": {
            "rows_processed": int(streamed.get("rows_processed") or 0),
            "parser_successes": int(streamed.get("parser_successes") or 0),
            "parser_failures": int(streamed.get("parser_failures") or 0),
            "parser_success_rate": streamed.get("parser_success_rate"),
            "schema_profiles": streamed.get("schema_profiles") or [],
            "configured_overlap_rows": configured_overlap,
            "v540_exact_overlap_rows": prior_overlap["exact_overlap_rows"],
            "v540_near_overlap_rows": prior_overlap["near_overlap_rows"],
            "v539_consumed_overlap_families": v539_overlap,
            "missing_time_rows": cutoff["missing_time_rows"],
            "at_or_before_cutoff_rows": cutoff["at_or_before_cutoff_rows"],
            "strictly_after_cutoff_rows": cutoff["strictly_after_cutoff_rows"],
            "eligible_after_all_exclusions": cutoff["eligible_after_all_exclusions"],
            "candidate_rows_examined": selection["selected_rows"],
            "represented_strata": selection["represented_strata"],
            "duplicate_families_contained": selection["duplicate_families_contained"],
            "raw_logs_returned": False,
            "private_identifiers_returned": False,
        },
        "qualification": {
            "operator_attestation_valid": bool(attestation.get("valid")),
            "source_overlaps_development": source_overlaps_development,
            "reasons": qualification_reasons,
            "source_name_returned": False,
            "collection_window_returned": False,
        },
        "collection_readiness": public_status,
        "review_pack": {
            "generator_available": True,
            "available": public_status["review_pack_available"],
            "human_reviewed_rows": public_status["human_reviewed_rows"],
            "import_ready": False,
            "predictions_exposed": False,
        },
        "prediction_seal": {
            "workflow_available": True,
            "created": public_status["prediction_sealed_separately"],
            "stored_separately": True,
            "labels_included": False,
        },
        "safety": safety,
        "lifecycle_state": "shadow_observation",
        "metrics_calculated": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    result["ok"] = bool(
        safety["configured_database_counts_unchanged"]
        and safety["model_artifacts_unchanged"]
        and safety["labels_written"] == 0
        and safety["model_runs_written"] == 0
        and safety["detection_runs_written"] == 0
        and safety["alerts_written"] == 0
        and safety["response_actions_created"] == 0
    )
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(output_dir / V541_LATEST, result)
        (output_dir / f"{V541_REPORT_PREFIX}_{_stamp()}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
        result["reports"] = {
            "ignored_output": True,
            "latest_file_name": V541_LATEST,
            "private_paths_returned": False,
        }
    return result
