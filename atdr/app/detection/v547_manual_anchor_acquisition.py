from __future__ import annotations

import csv
import hashlib
import json
import os
import re
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
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v543_temporal_stability_repair as v543
from atdr.app.detection import v544_chronological_evidence as v544
from atdr.app.detection import v545_development_model_repair as v545
from atdr.app.detection import v546_manual_anchor_transfer_repair as v546
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56


V547_VERSION = "v5.47-prediction-blind-manual-anchor-acquisition-v1"
V547_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_47_manual_anchors"
V547_LATEST = "v5_47_manual_anchor_acquisition_latest.json"
V547_MANIFEST = "v5_47_private_manual_anchor_manifest.json"
V547_SEALED_PACK = "v5_47_prediction_blind_manual_anchor_pack.csv"
V547_WORKING_COPY = "v5_47_manual_anchor_review_working.csv"
V547_REPORT_PREFIX = "v5_47_manual_anchor_acquisition"

TARGET_REVIEW_ROWS = 120
MINIMUM_REVIEW_ROWS = 80
MINIMUM_CLASS_SUPPORT = {
    "benign_like": 20,
    "suspicious": 15,
    "malicious": 10,
}
CORE_STRATA = (
    "unknown_transport",
    "incomplete_allow_80",
    "scan_like_behavior",
    "low_signal_suspicious_boundary",
    "routine_benign_control",
)
COVERAGE_TARGETS = {
    "unknown_transport": 20,
    "incomplete_allow_80": 20,
    "scan_like_behavior": 20,
    "low_signal_suspicious_boundary": 15,
    "quic_443_control": 15,
    "high_risk_or_threat_context": 15,
    "routine_benign_control": 10,
    "parser_limited_context": 5,
}
DEVELOPMENT_ROLES = {
    0: "development_fit",
    1: "calibration",
    2: "threshold",
}
HUMAN_FIELDS = {
    "human_decision",
    "human_attack_type",
    "human_confidence",
    "human_rationale",
    "human_reviewer",
    "human_reviewed_at",
    "human_must_confirm",
    "human_reviewed",
    "import_ready",
}
ALLOWED_DECISIONS = {
    "benign",
    "benign_unusual",
    "needs_context",
    "suspicious",
    "malicious",
}
FORBIDDEN_COLUMN_PARTS = (
    "prediction",
    "model_score",
    "suggestion",
    "assisted_label",
    "exact_hash",
    "near_hash",
    "fingerprint",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "raw_log",
    "source_token",
    "destination_token",
    "device_token",
)
SAFE_GUARD_COLUMNS = {
    "predictions_exposed",
    "model_scores_exposed",
    "assisted_labels_exposed",
    "raw_logs_exposed",
    "ip_addresses_exposed",
    "source_identities_exposed",
    "fingerprints_exposed",
}
AI_REVIEWER_PATTERN = re.compile(
    r"\b(ai|assistant|automated|automation|chatgpt|claude|codex|gemini|llm|model)\b",
    re.IGNORECASE,
)


class V547AcquisitionError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V547AcquisitionError(
            "A protected manual-anchor record is unreadable."
        ) from exc
    if not isinstance(value, dict):
        raise V547AcquisitionError(
            "A protected manual-anchor record is malformed."
        )
    return value


def _atomic_write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise V547AcquisitionError("The manual-anchor pack cannot be empty.")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            return list(reader), list(reader.fieldnames or [])
    except (OSError, csv.Error) as exc:
        raise V547AcquisitionError(
            "The protected manual-anchor pack is unreadable."
        ) from exc


def _canonical(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return text.casefold() if text.casefold() in {"true", "false"} else text


def _protected_digest(rows: list[dict[str, Any]], columns: list[str]) -> str:
    protected = [column for column in columns if column not in HUMAN_FIELDS]
    return _stable_hash(
        {
            "columns": columns,
            "rows": [
                {column: _canonical(row.get(column)) for column in protected}
                for row in rows
            ],
        }
    )


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _v546_status_lock(output_dir: Path) -> dict[str, Any]:
    path = output_dir / v546.V546_LATEST
    if not path.is_file():
        raise V547AcquisitionError(
            "The completed v5.46 transfer record is required."
        )
    latest = _read_json(path)
    checks = {
        "version_valid": latest.get("version") == v546.V546_VERSION,
        "measured_run_valid": bool(latest.get("ok")),
        "transfer_remains_incomplete": latest.get("status")
        == "manual_anchor_transfer_incomplete",
        "safety_valid": bool(
            (latest.get("safety") or {}).get("all_invariants_passed")
        ),
        "candidate_not_frozen": not bool(
            (latest.get("candidate_freeze") or {}).get("candidate_frozen")
        ),
        "future_labels_sealed": not bool(latest.get("future_labels_opened")),
        "model_not_activated": not bool(latest.get("model_activated")),
        "model_not_promoted": not bool(latest.get("model_promoted")),
        "rules_authoritative": bool(latest.get("rules_alert_authoritative")),
    }
    if not all(checks.values()):
        raise V547AcquisitionError(
            "The v5.46 transfer record failed custody validation."
        )
    return {
        "checks": checks,
        "all_checks_passed": True,
        "file_state": v55._file_state(path),
    }


def revalidate_v547_custody(
    db: Session,
    *,
    min_samples: int = 100,
    v544_output_dir: Path = v544.V544_OUTPUT_DIR,
    v545_output_dir: Path = v545.V545_OUTPUT_DIR,
    v546_output_dir: Path = v546.V546_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    prior = v546.revalidate_v546_custody(
        db,
        min_samples=min_samples,
        v544_output_dir=v544_output_dir,
        v545_output_dir=v545_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    v546_lock = _v546_status_lock(v546_output_dir)
    checks = {
        "v539_through_v546_custody_valid": bool(
            prior.get("all_checks_passed")
        ),
        "v546_measured_record_valid": bool(v546_lock["all_checks_passed"]),
        "eligible_roles_development_only": True,
        "future_labels_sealed": True,
        "candidate_not_frozen": True,
    }
    if not all(checks.values()):
        raise V547AcquisitionError(
            "The governed evidence boundary is not eligible for anchor acquisition."
        )
    return {
        "prior": prior,
        "v546_lock": v546_lock,
        "checks": checks,
        "all_checks_passed": True,
    }


def _public_custody(custody: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "v5_39_through_v5_46_custody_revalidated",
        "checks": dict(custody["checks"]),
        "eligible_roles": list(DEVELOPMENT_ROLES.values()),
        "future_labels_opened": False,
        "private_paths_returned": False,
        "private_digests_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "all_checks_passed": True,
    }


def _protected_state(
    *,
    v544_output_dir: Path,
    v545_output_dir: Path,
    v546_output_dir: Path,
    state_path: Path,
    pack_path: Path,
    blind_output_dir: Path,
    v542_output_dir: Path,
    v543_output_dir: Path,
) -> dict[str, Any]:
    return {
        "through_v545": v546._protected_state(
            v544_output_dir=v544_output_dir,
            v545_output_dir=v545_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        ),
        "v546_latest": v55._file_state(v546_output_dir / v546.V546_LATEST),
        "v546_recipe": v55._file_state(
            v546_output_dir / v546.V546_FREEZE_MANIFEST
        ),
    }


def _manual_anchor_families(custody: dict[str, Any]) -> set[str]:
    try:
        state = custody["prior"]["prior"]["custody"]["state"]
        bundles = v545._human_role_bundles(
            state["development"],
            state["canonical"],
        )
    except (KeyError, TypeError, v545.V545RepairError) as exc:
        raise V547AcquisitionError(
            "The governed manual-anchor boundary is unavailable."
        ) from exc
    return {
        str(row.get("_duplicate_family") or "")
        for bundle in bundles.values()
        for row in bundle.get("rows") or []
        if row.get("human_reviewed") and row.get("_duplicate_family")
    }


def classify_coverage_stratum(row: dict[str, Any]) -> str:
    app = str(row.get("app") or "unknown").casefold()
    action = str(row.get("action") or "unknown").casefold()
    protocol = str(row.get("protocol") or "unknown").casefold()
    destination_port = _integer(row.get("dst_port"), -1)
    unique_destinations = _integer(row.get("source_unique_destinations"))
    unique_ports = _integer(row.get("source_unique_ports"))
    deny_count = _integer(row.get("source_deny_count"))
    high_risk_count = _integer(row.get("source_high_risk_app_count"))
    app_risk = _integer(row.get("app_risk"))
    log_type = str(row.get("log_type") or "").upper()
    parser_limited = bool(
        _integer(row.get("parser_error"))
        or _integer(row.get("parser_warning_count"))
        or _integer(row.get("required_missing_count"))
    )
    rule_codes, _ = v56._rule_evidence(row)
    scan_like = bool(
        "possible_port_scan" in rule_codes
        or unique_ports >= 8
        or unique_destinations >= 8
    )
    if scan_like:
        return "scan_like_behavior"
    if app == "incomplete" and action == "allow" and destination_port == 80:
        return "incomplete_allow_80"
    if app in {"unknown", "unknown-tcp", "unknown-udp"} or (
        app == "incomplete" and protocol in {"tcp", "udp"}
    ):
        return "unknown_transport"
    if log_type == "THREAT" or high_risk_count > 0 or app_risk >= 4:
        return "high_risk_or_threat_context"
    low_signal_probe = bool(
        app in {"ping", "icmp", "quic", "quic-base"}
        and not rule_codes
        and (unique_destinations > 1 or unique_ports > 1 or deny_count > 0)
    )
    if low_signal_probe:
        return "low_signal_suspicious_boundary"
    if (
        app in {"quic", "quic-base"}
        and action == "allow"
        and destination_port == 443
        and not rule_codes
    ):
        return "quic_443_control"
    if parser_limited:
        return "parser_limited_context"
    if (
        action == "allow"
        and destination_port in {22, 53, 80, 123, 443}
        and not rule_codes
        and unique_destinations <= 2
        and unique_ports <= 2
    ):
        return "routine_benign_control"
    return "low_signal_suspicious_boundary"


def _candidate_projection(
    row: dict[str, Any],
    *,
    family: str,
) -> dict[str, Any]:
    role_rank = _integer(row.get("role_rank"), 4)
    stratum = classify_coverage_stratum(row)
    review_token = _stable_hash(
        {
            "version": V547_VERSION,
            "family": family,
            "stratum": stratum,
            "role": role_rank,
        }
    )[:24]
    return {
        "review_token": review_token,
        "evidence_role": DEVELOPMENT_ROLES[role_rank],
        "selection_stratum": stratum,
        "review_priority": "manual_anchor_gap",
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
        "parser_warning_count": _integer(row.get("parser_warning_count")),
        "required_missing_count": _integer(row.get("required_missing_count")),
        "schema_bucket": row.get("schema_bucket"),
        "group_size": _integer(row.get("group_size"), 1),
        "source_event_count": _integer(row.get("source_event_count")),
        "source_deny_count": _integer(row.get("source_deny_count")),
        "source_unique_destinations": _integer(
            row.get("source_unique_destinations")
        ),
        "source_unique_ports": _integer(row.get("source_unique_ports")),
        "source_unknown_app_count": _integer(
            row.get("source_unknown_app_count")
        ),
        "source_high_risk_app_count": _integer(
            row.get("source_high_risk_app_count")
        ),
        "destination_repeat_count": _integer(
            row.get("destination_repeat_count")
        ),
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "human_decision": "",
        "human_attack_type": "",
        "human_confidence": "",
        "human_rationale": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_must_confirm": True,
        "human_reviewed": False,
        "import_ready": False,
        "_family": family,
    }


def select_manual_anchor_candidates(
    rows: Iterable[dict[str, Any]],
    *,
    manual_families: set[str],
    limit: int = TARGET_REVIEW_ROWS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded: Counter[str] = Counter()
    seen_families: set[str] = set()
    for row in rows:
        role_rank = _integer(row.get("role_rank"), 4)
        family = str(row.get("_candidate_family") or "")
        if role_rank not in DEVELOPMENT_ROLES:
            excluded["future_or_reserved_role"] += 1
            continue
        if row.get("_quarantine_reason"):
            excluded["quarantined"] += 1
            continue
        if not family:
            excluded["missing_duplicate_family"] += 1
            continue
        if family in manual_families:
            excluded["existing_manual_anchor_family"] += 1
            continue
        if family in seen_families:
            excluded["duplicate_family"] += 1
            continue
        candidate = _candidate_projection(row, family=family)
        candidate["_selection_key"] = _stable_hash(
            {
                "version": V547_VERSION,
                "stratum": candidate["selection_stratum"],
                "token": candidate["review_token"],
            }
        )
        buckets[str(candidate["selection_stratum"])].append(candidate)
        seen_families.add(family)

    for values in buckets.values():
        values.sort(key=lambda item: str(item["_selection_key"]))
    selected: list[dict[str, Any]] = []
    selected_tokens: set[str] = set()
    for stratum, target in COVERAGE_TARGETS.items():
        for candidate in buckets.get(stratum, [])[:target]:
            selected.append(candidate)
            selected_tokens.add(str(candidate["review_token"]))
            if len(selected) >= limit:
                break
        if len(selected) >= limit:
            break

    remaining = sorted(
        (
            candidate
            for values in buckets.values()
            for candidate in values
            if str(candidate["review_token"]) not in selected_tokens
        ),
        key=lambda item: (
            str(item["selection_stratum"]),
            str(item["_selection_key"]),
        ),
    )
    selected.extend(remaining[: max(0, limit - len(selected))])
    selected = sorted(
        selected,
        key=lambda item: (
            str(item["selection_stratum"]),
            str(item["_selection_key"]),
        ),
    )
    for candidate in selected:
        candidate.pop("_selection_key", None)
        candidate.pop("_family", None)

    counts = Counter(str(row["selection_stratum"]) for row in selected)
    core_coverage = {
        stratum: int(counts.get(stratum, 0)) for stratum in CORE_STRATA
    }
    coverage_gate = bool(
        len(selected) >= min(MINIMUM_REVIEW_ROWS, max(1, int(limit)))
        and all(value >= 5 for value in core_coverage.values())
    )
    return selected, {
        "eligible_unique_families": sum(len(values) for values in buckets.values()),
        "selected_rows": len(selected),
        "target_rows": int(limit),
        "coverage_counts": dict(sorted(counts.items())),
        "represented_strata": len(counts),
        "core_coverage": core_coverage,
        "coverage_gate_passed": coverage_gate,
        "exclusion_reasons": dict(sorted(excluded.items())),
        "duplicate_families_contained": len(selected)
        == len({str(row["review_token"]) for row in selected}),
        "future_roles_selected": 0,
        "predictions_used_for_selection": False,
        "assisted_labels_used_for_selection": False,
    }


def _load_representatives(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for values in connection.execute(v56.REPRESENTATIVE_QUERY):
        row = v56._row_mapping(values)
        family_row = connection.execute(
            "SELECT candidate_near_hash, quarantine_reason FROM events WHERE id=?",
            (_integer(row.get("id")),),
        ).fetchone()
        if family_row is None:
            continue
        row["_candidate_family"] = str(family_row[0] or "")
        row["_quarantine_reason"] = family_row[1]
        rows.append(row)
    return rows


def _assert_pack_contract(
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    sealed: bool,
) -> None:
    required = {
        "review_token",
        "evidence_role",
        "selection_stratum",
        "human_decision",
        "human_confidence",
        "human_reviewer",
        "human_reviewed_at",
        "human_must_confirm",
        "human_reviewed",
        "import_ready",
    }
    if not rows or required - set(columns):
        raise V547AcquisitionError(
            "The manual-anchor pack is missing required fields."
        )
    lowered = [column.casefold() for column in columns]
    if any(
        part in column
        for column in lowered
        if column not in SAFE_GUARD_COLUMNS
        for part in FORBIDDEN_COLUMN_PARTS
    ):
        raise V547AcquisitionError(
            "The manual-anchor pack exposes forbidden evidence."
        )
    tokens = [str(row.get("review_token") or "") for row in rows]
    if not all(tokens) or len(tokens) != len(set(tokens)):
        raise V547AcquisitionError(
            "The manual-anchor pack contains invalid review tokens."
        )
    for row in rows:
        if str(row.get("evidence_role") or "") not in DEVELOPMENT_ROLES.values():
            raise V547AcquisitionError(
                "The manual-anchor pack includes a reserved evidence role."
            )
        if any(
            _boolean(row.get(field))
            for field in (
                "predictions_exposed",
                "model_scores_exposed",
                "assisted_labels_exposed",
                "raw_logs_exposed",
                "ip_addresses_exposed",
                "source_identities_exposed",
                "fingerprints_exposed",
                "import_ready",
            )
        ):
            raise V547AcquisitionError(
                "The manual-anchor pack violates its privacy or import contract."
            )
        if sealed and (
            _boolean(row.get("human_reviewed"))
            or any(
                str(row.get(field) or "").strip()
                for field in HUMAN_FIELDS
                if field
                not in {"human_must_confirm", "human_reviewed", "import_ready"}
            )
        ):
            raise V547AcquisitionError(
                "The sealed manual-anchor pack contains review decisions."
            )


def _review_progress(output_dir: Path) -> dict[str, Any]:
    manifest_path = output_dir / V547_MANIFEST
    sealed_path = output_dir / V547_SEALED_PACK
    working_path = output_dir / V547_WORKING_COPY
    present = [path.is_file() for path in (manifest_path, sealed_path, working_path)]
    if not any(present):
        return {
            "status": "not_prepared",
            "total": 0,
            "reviewed": 0,
            "remaining": 0,
            "invalid": 0,
            "class_support": dict.fromkeys(MINIMUM_CLASS_SUPPORT, 0),
            "complete": False,
            "ready_for_fixed_revalidation": False,
        }
    if not all(present):
        raise V547AcquisitionError(
            "The manual-anchor workspace is incomplete."
        )
    manifest = _read_json(manifest_path)
    sealed_rows, sealed_columns = _read_csv(sealed_path)
    working_rows, working_columns = _read_csv(working_path)
    _assert_pack_contract(sealed_rows, sealed_columns, sealed=True)
    _assert_pack_contract(working_rows, working_columns, sealed=False)
    protected = str(manifest.get("protected_digest") or "")
    if (
        manifest.get("schema_version") != V547_VERSION
        or sealed_columns != working_columns
        or len(sealed_rows) != len(working_rows)
        or not protected
        or _protected_digest(sealed_rows, sealed_columns) != protected
        or _protected_digest(working_rows, working_columns) != protected
        or _file_sha256(sealed_path) != manifest.get("sealed_pack_digest")
    ):
        raise V547AcquisitionError(
            "The manual-anchor workspace failed custody validation."
        )

    reviewed = 0
    invalid = 0
    support: Counter[str] = Counter()
    for row in working_rows:
        review_fields_present = any(
            str(row.get(field) or "").strip()
            for field in (
                "human_decision",
                "human_attack_type",
                "human_confidence",
                "human_rationale",
                "human_reviewer",
                "human_reviewed_at",
            )
        )
        if not _boolean(row.get("human_reviewed")) and not review_fields_present:
            continue
        decision = str(row.get("human_decision") or "").strip().casefold()
        reviewer = str(row.get("human_reviewer") or "").strip()
        confidence = str(row.get("human_confidence") or "").strip()
        rationale = str(row.get("human_rationale") or "").strip()
        valid = bool(
            _boolean(row.get("human_reviewed"))
            and _boolean(row.get("human_must_confirm"))
            and decision in ALLOWED_DECISIONS
            and reviewer
            and not AI_REVIEWER_PATTERN.search(reviewer)
            and confidence.isdigit()
            and 1 <= int(confidence) <= 100
            and len(rationale) >= 8
            and _parse_timestamp(row.get("human_reviewed_at")) is not None
            and not _boolean(row.get("import_ready"))
        )
        if not valid:
            invalid += 1
            continue
        reviewed += 1
        if decision in {"benign", "benign_unusual"}:
            support["benign_like"] += 1
        elif decision == "suspicious":
            support["suspicious"] += 1
        elif decision == "malicious":
            support["malicious"] += 1

    total = len(working_rows)
    class_support = {
        key: int(support.get(key, 0)) for key in MINIMUM_CLASS_SUPPORT
    }
    complete = bool(total and reviewed == total and invalid == 0)
    class_support_passed = bool(
        complete
        and all(
            class_support[key] >= target
            for key, target in MINIMUM_CLASS_SUPPORT.items()
        )
    )
    return {
        "status": (
            "review_complete"
            if complete
            else "review_in_progress"
            if reviewed or invalid
            else "ready_for_human_review"
        ),
        "total": total,
        "reviewed": reviewed,
        "remaining": max(0, total - reviewed),
        "invalid": invalid,
        "class_support": class_support,
        "minimum_class_support": dict(MINIMUM_CLASS_SUPPORT),
        "class_support_passed": class_support_passed,
        "complete": complete,
        "ready_for_fixed_revalidation": class_support_passed,
        "predictions_exposed": False,
        "assisted_labels_exposed": False,
        "import_ready": False,
        "automatic_import_performed": False,
        "reviewer_identities_returned": False,
        "review_tokens_returned": False,
    }


def _prepare_workspace(
    rows: list[dict[str, Any]],
    selection: dict[str, Any],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    if not rows:
        raise V547AcquisitionError(
            "No eligible development rows were available for manual review."
        )
    columns = list(rows[0])
    _assert_pack_contract(rows, columns, sealed=True)
    protected = _protected_digest(rows, columns)
    manifest_path = output_dir / V547_MANIFEST
    sealed_path = output_dir / V547_SEALED_PACK
    working_path = output_dir / V547_WORKING_COPY
    present = [path.is_file() for path in (manifest_path, sealed_path, working_path)]
    if any(present) and not all(present):
        raise V547AcquisitionError(
            "An incomplete manual-anchor workspace already exists."
        )
    created = not all(present)
    if created:
        output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_csv(sealed_path, rows)
        _atomic_write_csv(working_path, rows)
        manifest = {
            "schema_version": V547_VERSION,
            "created_at": _now(),
            "status": "prediction_blind_manual_anchor_pack_sealed",
            "selected_rows": len(rows),
            "coverage": selection,
            "protected_digest": protected,
            "sealed_pack_digest": _file_sha256(sealed_path),
            "development_roles_only": True,
            "future_labels_opened": False,
            "predictions_included": False,
            "assisted_labels_included": False,
            "raw_logs_included": False,
            "ip_addresses_included": False,
            "source_identities_included": False,
            "import_ready": False,
        }
        _atomic_write_json(manifest_path, manifest)
    else:
        manifest = _read_json(manifest_path)
        existing_rows, existing_columns = _read_csv(sealed_path)
        _assert_pack_contract(existing_rows, existing_columns, sealed=True)
        if (
            existing_columns != columns
            or _protected_digest(existing_rows, existing_columns) != protected
            or manifest.get("protected_digest") != protected
        ):
            raise V547AcquisitionError(
                "A different sealed manual-anchor pack already exists."
            )
    progress = _review_progress(output_dir)
    return {
        "status": "workspace_created" if created else "workspace_reused",
        "created": created,
        "sealed_rows": len(rows),
        "coverage_gate_passed": bool(selection.get("coverage_gate_passed")),
        "review": progress,
        "predictions_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "import_ready": False,
        "path_returned": False,
        "file_names_returned": False,
    }


def _private_source_count(connection: sqlite3.Connection) -> int:
    return int(
        connection.execute(
            "SELECT COUNT(DISTINCT device_token) FROM events "
            "WHERE device_identity_present=1 AND device_token<>''"
        ).fetchone()[0]
    )


def _safe_failure(
    status: str,
    *,
    error_type: str | None = None,
    failure_stage: str | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V547_VERSION,
        "status": status,
        "error_type": error_type,
        "failure_stage": failure_stage,
        "message": (
            "Manual-anchor acquisition failed closed without changing governed state."
        ),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "future_labels_opened": False,
        "human_reviewed_labels_created": 0,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }


def _render_report(result: dict[str, Any]) -> str:
    selection = result.get("selection") or {}
    review = (result.get("workspace") or {}).get("review") or {}
    return "\n".join(
        [
            "# v5.47 Prediction-Blind Manual-Anchor Acquisition",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Selected rows: `{selection.get('selected_rows', 0)}`",
            f"- Represented strata: `{selection.get('represented_strata', 0)}`",
            f"- Coverage gate: `{selection.get('coverage_gate_passed', False)}`",
            f"- Review progress: `{review.get('reviewed', 0)}/{review.get('total', 0)}`",
            f"- Independent real sources observed: `{result.get('independent_source_count', 0)}`",
            "- Predictions exposed: `False`",
            "- Assisted labels exposed: `False`",
            "- Import performed: `False`",
            "- Model activated: `False`",
            "- Rules remain authoritative: `True`",
            "",
            "This is development-only evidence acquisition. It is not an independent activation result.",
            "",
        ]
    )


def run_v547_manual_anchor_acquisition(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = False,
    review_limit: int = TARGET_REVIEW_ROWS,
    min_samples: int = 100,
    output_dir: Path = V547_OUTPUT_DIR,
    write_report: bool = True,
    v544_output_dir: Path = v544.V544_OUTPUT_DIR,
    v545_output_dir: Path = v545.V545_OUTPUT_DIR,
    v546_output_dir: Path = v546.V546_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    protected_before = _protected_state(
        v544_output_dir=v544_output_dir,
        v545_output_dir=v545_output_dir,
        v546_output_dir=v546_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    stage = "custody_revalidation"
    try:
        custody = revalidate_v547_custody(
            db,
            min_samples=min_samples,
            v544_output_dir=v544_output_dir,
            v545_output_dir=v545_output_dir,
            v546_output_dir=v546_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
    except (
        V547AcquisitionError,
        v546.V546TransferRepairError,
        v545.V545RepairError,
        v544.V544EvidenceError,
        v543.V543RepairError,
        v542.V542FreezeError,
        v541.V541EvidenceError,
    ) as exc:
        return _safe_failure(
            "failed_closed_custody",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
        )

    available = bool(sample_path and sample_path.is_file())
    if preflight_only:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        protected_after = _protected_state(
            v544_output_dir=v544_output_dir,
            v545_output_dir=v545_output_dir,
            v546_output_dir=v546_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
        safe = bool(
            available
            and counts_before == counts_after
            and artifacts_before == artifacts_after
            and protected_before == protected_after
        )
        return {
            "ok": safe,
            "version": V547_VERSION,
            "status": "preflight_complete" if safe else "private_file_unavailable",
            "generated_at": _now(),
            "preflight_only": True,
            "custody": _public_custody(custody),
            "private_file": {
                "supplied": sample_path is not None,
                "available": available,
                "path_returned": False,
                "file_name_returned": False,
                "digest_returned": False,
            },
            "safety": {
                "configured_database_counts_unchanged": counts_before == counts_after,
                "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
                "protected_workspaces_unchanged": protected_before == protected_after,
                "all_invariants_passed": safe,
            },
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    if not available:
        return _safe_failure("private_file_unavailable")
    if not use_temp_db:
        return _safe_failure("temporary_storage_acknowledgement_required")
    review_limit = max(1, min(500, int(review_limit)))

    stage = "disposable_candidate_preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v547-") as directory:
            connection = sqlite3.connect(Path(directory) / "anchors.sqlite3")
            try:
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile.get("ok"):
                    raise V547AcquisitionError("Private evidence parsing failed.")
                stage = "protected_boundary_install"
                v544._install_protected_boundaries(
                    connection,
                    custody=custody["prior"]["prior"]["custody"],
                    blind_output_dir=blind_output_dir,
                )
                stage = "chronological_role_reconstruction"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V547AcquisitionError(
                        "Chronological role reconstruction failed."
                    )
                stage = "behavior_aggregate_build"
                v56.build_disposable_behavior_aggregates(connection)
                stage = "candidate_near_containment"
                containment = v545._contain_candidate_near_families(connection)
                if not containment.get("passed"):
                    raise V547AcquisitionError(
                        "Candidate families cross protected evidence roles."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "existing_manual_anchor_exclusion"
                manual_families = _manual_anchor_families(custody)
                stage = "prediction_blind_selection"
                representatives = _load_representatives(connection)
                candidates, selection = select_manual_anchor_candidates(
                    representatives,
                    manual_families=manual_families,
                    limit=review_limit,
                )
                source_count = _private_source_count(connection)
                stage = "sealed_workspace_creation"
                workspace = _prepare_workspace(
                    candidates,
                    selection,
                    output_dir=output_dir,
                )
            finally:
                connection.close()
    except (
        V547AcquisitionError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _safe_failure(
            "failed_closed_manual_anchor_acquisition",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    protected_after = _protected_state(
        v544_output_dir=v544_output_dir,
        v545_output_dir=v545_output_dir,
        v546_output_dir=v546_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    deltas = {
        key: int(counts_after[key]) - int(counts_before[key]) for key in counts_before
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
        "human_reviewed_labels_created": 0,
        "automatic_import_performed": False,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "future_labels_opened": False,
    }
    safety_passed = bool(
        safety["configured_database_counts_unchanged"]
        and safety["active_model_artifacts_unchanged"]
        and safety["protected_workspaces_unchanged"]
        and all(value == 0 for value in deltas.values())
    )
    review = workspace["review"]
    coverage_passed = bool(selection.get("coverage_gate_passed"))
    status = (
        "ready_for_fixed_revalidation"
        if review.get("ready_for_fixed_revalidation")
        else "human_review_in_progress"
        if review.get("reviewed") or review.get("invalid")
        else "ready_for_human_review"
        if coverage_passed
        else "manual_anchor_coverage_incomplete"
    )
    result = {
        "ok": safety_passed,
        "version": V547_VERSION,
        "status": status,
        "generated_at": _now(),
        "preflight_only": False,
        "custody": _public_custody(custody),
        "private_reconstruction": {
            "parsed_rows": _integer(profile.get("rows_processed")),
            "parser_success_rows": _integer(profile.get("parser_successes")),
            "parser_failure_rows": _integer(profile.get("parser_failures")),
            "future_labels_opened": False,
            "private_paths_returned": False,
            "private_identifiers_returned": False,
            "fingerprints_returned": False,
        },
        "selection": selection,
        "workspace": workspace,
        "existing_manual_anchor_families_excluded": len(manual_families),
        "independent_source_count": source_count,
        "second_real_source_present": source_count >= 2,
        "development_evidence_only": True,
        "independent_activation_evidence": False,
        "fixed_revalidation_allowed": bool(
            review.get("ready_for_fixed_revalidation")
        ),
        "candidate_frozen": False,
        "candidate_recipe_written": False,
        "safety": {**safety, "all_invariants_passed": safety_passed},
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }
    if write_report:
        _atomic_write_json(output_dir / V547_LATEST, result)
        (output_dir / f"{V547_REPORT_PREFIX}_{_stamp()}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
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


def get_public_v547_status(
    output_dir: Path = V547_OUTPUT_DIR,
) -> dict[str, Any]:
    path = output_dir / V547_LATEST
    if not path.is_file():
        return {
            "version": V547_VERSION,
            "status": "not_run",
            "generated_at": None,
            "selected_rows": 0,
            "target_rows": TARGET_REVIEW_ROWS,
            "represented_strata": 0,
            "coverage_counts": {},
            "coverage_gate_passed": False,
            "review_status": "not_prepared",
            "reviewed_rows": 0,
            "total_review_rows": 0,
            "invalid_review_rows": 0,
            "class_support": dict.fromkeys(MINIMUM_CLASS_SUPPORT, 0),
            "ready_for_fixed_revalidation": False,
            "independent_source_count": 0,
            "second_real_source_present": False,
            "development_evidence_only": True,
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "predictions_exposed": False,
            "assisted_labels_exposed": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    latest = _read_json(path)
    if latest.get("version") != V547_VERSION:
        raise V547AcquisitionError(
            "The manual-anchor status record has an unsupported version."
        )
    progress = _review_progress(output_dir)
    selection = latest.get("selection") or {}
    workspace = latest.get("workspace") or {}
    return {
        "version": V547_VERSION,
        "status": latest.get("status") or "unknown",
        "generated_at": latest.get("generated_at"),
        "selected_rows": _integer(selection.get("selected_rows")),
        "target_rows": _integer(selection.get("target_rows"), TARGET_REVIEW_ROWS),
        "represented_strata": _integer(selection.get("represented_strata")),
        "coverage_counts": {
            str(key): _integer(value)
            for key, value in (selection.get("coverage_counts") or {}).items()
        },
        "coverage_gate_passed": bool(selection.get("coverage_gate_passed")),
        "review_status": progress.get("status") or "not_prepared",
        "reviewed_rows": _integer(progress.get("reviewed")),
        "total_review_rows": _integer(progress.get("total")),
        "invalid_review_rows": _integer(progress.get("invalid")),
        "class_support": {
            str(key): _integer(value)
            for key, value in (progress.get("class_support") or {}).items()
        },
        "ready_for_fixed_revalidation": bool(
            progress.get("ready_for_fixed_revalidation")
        ),
        "independent_source_count": _integer(
            latest.get("independent_source_count")
        ),
        "second_real_source_present": bool(
            latest.get("second_real_source_present")
        ),
        "development_evidence_only": True,
        "workspace_created": bool(
            workspace.get("status") in {"workspace_created", "workspace_reused"}
            and _integer(workspace.get("sealed_rows")) > 0
        ),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "future_labels_opened": False,
        "predictions_exposed": False,
        "assisted_labels_exposed": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
