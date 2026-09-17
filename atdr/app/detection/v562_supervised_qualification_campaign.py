from __future__ import annotations

import csv
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
from atdr.app.detection import v530_supervised_evidence_closure as v530
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548
from atdr.app.detection import (
    v549a_supplemental_threat_anchor_acquisition as v549a,
)
from atdr.app.detection import v549b_combined_fixed_revalidation as v549b
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v545_development_model_repair as v545


V562_VERSION = "v5.62-supervised-qualification-campaign-v1"
V562_PROTOCOL_VERSION = "v5.62-fresh-evidence-protocol-v1"
V562_OUTPUT_DIR = (
    PROJECT_ROOT / "ml_baseline_reviews" / "v5_62_supervised_qualification"
)
V562_LATEST = "v5_62_supervised_qualification_campaign_latest.json"
V562_EXCLUSION_MANIFEST = "v5_62_consumed_evidence_exclusion.json"
V562_PROTOCOL_LOCK = "v5_62_fresh_evidence_protocol.json"
V562_SEALED_PACK = "v5_62_prediction_blind_review_pack.csv"
V562_WORKING_COPY = "v5_62_protected_review_working.csv"
V562_REVIEW_STATE = "v5_62_protected_review_state.json"
V562_REPORT_PREFIX = "v5_62_supervised_qualification_campaign"
PREPARE_CONFIRMATION = "PREPARE_V562_SUPERVISED_QUALIFICATION_CAMPAIGN"

TARGET_REVIEW_ROWS = 300
MINIMUM_REVIEW_ROWS = 200
EXPECTED_CONSUMED_ROWS = 180
ROLE_NAMES = {
    0: "development_fit",
    1: "calibration",
    2: "threshold_selection",
    3: "untouched_future_evaluation",
}
DEVELOPMENT_ROLE_NAMES = frozenset(
    {"development_fit", "calibration", "threshold_selection"}
)
EVALUATION_ROLE_NAME = "untouched_future_evaluation"
SECOND_SOURCE_ROLE_NAME = "second_source_validation"
ROLE_TARGET_WEIGHTS = {
    "development_fit": 0.50,
    "calibration": 0.20,
    "threshold_selection": 0.15,
    "untouched_future_evaluation": 0.15,
}
FIXED_QUALIFICATION_GATES = dict(v530.FIXED_PROMOTION_GATES)
LOCKED_CANDIDATE_STRATEGIES = tuple(v548.FIXED_CANDIDATE_STRATEGIES)
LOCKED_FEATURE_SCHEMA = tuple(v548.FIXED_FEATURE_SCHEMA)
ALLOWED_DECISIONS = frozenset(v547.ALLOWED_DECISIONS)
HUMAN_FIELDS = frozenset(v547.HUMAN_FIELDS)

APPROVED_EVIDENCE_FIELDS = (
    "evidence_role",
    "event_time_utc",
    "log_type",
    "subtype",
    "application",
    "action",
    "protocol",
    "source_port",
    "destination_port",
    "source_zone",
    "destination_zone",
    "bytes",
    "packets",
    "elapsed_time",
    "application_risk",
    "threat_severity",
    "session_end_reason",
    "parser_error",
    "parser_warning_count",
    "required_missing_count",
    "schema_bucket",
    "group_size",
    "source_event_count",
    "source_deny_count",
    "source_unique_destinations",
    "source_unique_ports",
    "source_unknown_app_count",
    "source_high_risk_app_count",
    "destination_repeat_count",
)


class V562CampaignError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V562CampaignError(
            "A protected v5.62 campaign record failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V562CampaignError(
            "A protected v5.62 campaign record failed integrity validation."
        )
    return payload


def _atomic_write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise V562CampaignError("The protected qualification pack cannot be empty.")
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
        raise V562CampaignError(
            "The protected v5.62 review pack is unreadable."
        ) from exc


def _protected_digest(rows: list[dict[str, Any]], columns: list[str]) -> str:
    protected_columns = [column for column in columns if column not in HUMAN_FIELDS]
    return v547._stable_hash(
        {
            "columns": columns,
            "rows": [
                {
                    column: v547._canonical(row.get(column))
                    for column in protected_columns
                }
                for row in rows
            ],
        }
    )


def _workspace_paths(output_dir: Path = V562_OUTPUT_DIR) -> dict[str, Path]:
    output_dir = Path(output_dir)
    return {
        "output_dir": output_dir,
        "latest": output_dir / V562_LATEST,
        "exclusion": output_dir / V562_EXCLUSION_MANIFEST,
        "protocol": output_dir / V562_PROTOCOL_LOCK,
        "sealed": output_dir / V562_SEALED_PACK,
        "working": output_dir / V562_WORKING_COPY,
        "review_state": output_dir / V562_REVIEW_STATE,
    }


def validate_consumed_v549b_boundary() -> dict[str, Any]:
    try:
        status = v549b.get_public_v549b_status()
    except (OSError, ValueError, v549b.V549BRevalidationError) as exc:
        raise V562CampaignError(
            "The consumed v5.49b boundary is unavailable."
        ) from exc
    if not (
        status.get("status") == "combined_fixed_revalidation_completed"
        and int(status.get("evaluation_execution_count") or 0) == 1
        and status.get("evaluation_attempted") is True
        and status.get("diagnostic_candidate_qualified") is False
        and status.get("diagnostic_candidate") is None
        and status.get("model_activated") is False
        and status.get("active_artifact_written") is False
        and status.get("rules_alert_authoritative") is True
        and status.get("response_automation_allowed") is False
    ):
        raise V562CampaignError(
            "The consumed v5.49b decision no longer matches its immutable boundary."
        )
    custody = status.get("custody") or {}
    if int(custody.get("combined_reviewed") or 0) != EXPECTED_CONSUMED_ROWS:
        raise V562CampaignError(
            "The consumed v5.49b review count failed integrity validation."
        )
    return {
        "status": "immutable_consumed_negative_decision",
        "execution_count": 1,
        "combined_reviewed": EXPECTED_CONSUMED_ROWS,
        "candidate_selected": False,
        "model_activated": False,
        "rules_alert_authoritative": True,
        "response_mode": "simulation_only",
    }


def _consumed_review_tokens() -> tuple[set[str], set[str]]:
    original_rows, original_columns = v547._read_csv(
        v548.V548_OUTPUT_DIR / v547.V547_SEALED_PACK
    )
    supplemental_rows, supplemental_columns = v547._read_csv(
        v549a.V549A_OUTPUT_DIR / v549a.V549A_SEALED_PACK
    )
    v547._assert_pack_contract(original_rows, original_columns, sealed=True)
    v547._assert_pack_contract(supplemental_rows, supplemental_columns, sealed=True)
    original = {str(row.get("review_token") or "") for row in original_rows}
    supplemental = {
        str(row.get("review_token") or "") for row in supplemental_rows
    }
    if (
        len(original) != v549b.EXPECTED_ORIGINAL_ROWS
        or len(supplemental) != v549b.EXPECTED_SUPPLEMENTAL_ROWS
        or "" in original
        or "" in supplemental
    ):
        raise V562CampaignError(
            "Consumed review-token custody failed integrity validation."
        )
    return original, supplemental


def _supplemental_token_for(
    row: dict[str, Any],
    *,
    family: str,
) -> str | None:
    rule_codes, rule_score = v56._rule_evidence(row)
    stratum, _ = v549a.classify_supplemental_stratum(
        row,
        rule_codes=rule_codes,
        rule_score=rule_score,
    )
    if not stratum:
        return None
    return v547._stable_hash(
        {
            "version": v549a.V549A_VERSION,
            "family": family,
            "stratum": stratum,
            "role": v547._integer(row.get("role_rank"), 4),
        }
    )[:24]


def _install_consumed_exclusion(
    connection: sqlite3.Connection,
    *,
    sample_digest: str,
    output_dir: Path,
) -> dict[str, Any]:
    original_tokens, supplemental_tokens = _consumed_review_tokens()
    representatives = v547._load_representatives(connection)
    matched_original: set[str] = set()
    matched_supplemental: set[str] = set()
    consumed_families: set[str] = set()
    for row in representatives:
        family = str(row.get("_candidate_family") or "")
        if not family:
            continue
        original_token = v549a._original_token_for(row, family=family)
        if original_token in original_tokens:
            matched_original.add(original_token)
            consumed_families.add(family)
        supplemental_token = _supplemental_token_for(row, family=family)
        if supplemental_token and supplemental_token in supplemental_tokens:
            matched_supplemental.add(supplemental_token)
            consumed_families.add(family)
    if matched_original != original_tokens or matched_supplemental != supplemental_tokens:
        raise V562CampaignError(
            "The private source cannot reconstruct every consumed v5.49b family."
        )

    connection.execute(
        "CREATE TEMP TABLE v562_consumed_families (family TEXT PRIMARY KEY)"
    )
    connection.executemany(
        "INSERT INTO v562_consumed_families(family) VALUES (?)",
        [(family,) for family in sorted(consumed_families)],
    )
    private_rows = [
        {
            "exact_hash": str(row[0]),
            "propagation_hash": str(row[1]),
            "candidate_near_hash": str(row[2]),
            "minute_bucket": str(row[3] or ""),
            "role_rank": int(row[4]),
        }
        for row in connection.execute(
            "SELECT exact_hash, propagation_hash, candidate_near_hash, "
            "minute_bucket, role_rank FROM events WHERE candidate_near_hash "
            "IN (SELECT family FROM v562_consumed_families)"
        )
    ]
    connection.execute(
        "UPDATE events SET role_rank=4, "
        "quarantine_reason='consumed_v549b_evidence' "
        "WHERE candidate_near_hash IN "
        "(SELECT family FROM v562_consumed_families)"
    )
    connection.commit()
    manifest = {
        "schema_version": V562_VERSION,
        "created_at": _now(),
        "source_digest": sample_digest,
        "v549b_protocol_version": v549b.V549B_PROTOCOL_VERSION,
        "v549b_execution_count": 1,
        "original_review_tokens": sorted(original_tokens),
        "supplemental_review_tokens": sorted(supplemental_tokens),
        "candidate_families": sorted(consumed_families),
        "bound_rows": private_rows,
        "counts": {
            "original_review_tokens": len(original_tokens),
            "supplemental_review_tokens": len(supplemental_tokens),
            "candidate_families": len(consumed_families),
            "bound_rows": len(private_rows),
            "exact_families": len({row["exact_hash"] for row in private_rows}),
            "propagation_families": len(
                {row["propagation_hash"] for row in private_rows}
            ),
            "time_windows": len(
                {row["minute_bucket"] for row in private_rows if row["minute_bucket"]}
            ),
        },
        "private": True,
        "tracked": False,
        "raw_logs_included": False,
        "labels_included": False,
    }
    exclusion_path = _workspace_paths(output_dir)["exclusion"]
    if exclusion_path.is_file():
        existing = _read_json(exclusion_path)
        comparable_keys = (
            "schema_version",
            "source_digest",
            "v549b_protocol_version",
            "original_review_tokens",
            "supplemental_review_tokens",
            "candidate_families",
            "bound_rows",
            "counts",
        )
        if any(existing.get(key) != manifest.get(key) for key in comparable_keys):
            raise V562CampaignError(
                "A different consumed-evidence exclusion manifest already exists."
            )
    else:
        _atomic_write_json(exclusion_path, manifest)
    return {
        "locked": True,
        "consumed_review_rows": EXPECTED_CONSUMED_ROWS,
        "excluded_event_rows": len(private_rows),
        "excluded_candidate_families": len(consumed_families),
        "excluded_exact_families": manifest["counts"]["exact_families"],
        "excluded_propagation_families": manifest["counts"][
            "propagation_families"
        ],
        "excluded_time_windows": manifest["counts"]["time_windows"],
        "manifest_private": True,
        "fingerprints_exposed": False,
        "tokens_exposed": False,
        "digest_exposed": False,
    }


def _coverage_group(row: dict[str, Any]) -> str:
    stratum = v547.classify_coverage_stratum(row)
    mapping = {
        "routine_benign_control": "routine_service_context",
        "quic_443_control": "web_transport_context",
        "incomplete_allow_80": "incomplete_transport_context",
        "unknown_transport": "unknown_transport_context",
        "scan_like_behavior": "high_activity_context",
        "high_risk_or_threat_context": "vendor_security_context",
        "parser_limited_context": "parser_limited_context",
        "low_signal_suspicious_boundary": "boundary_context",
    }
    return mapping.get(stratum, "other_network_context")


def _candidate_projection(row: dict[str, Any], *, family: str) -> dict[str, Any]:
    role_rank = v547._integer(row.get("role_rank"), 4)
    if role_rank not in ROLE_NAMES:
        raise V562CampaignError("A candidate has no eligible predeclared role.")
    coverage_group = _coverage_group(row)
    review_token = v547._stable_hash(
        {
            "version": V562_VERSION,
            "family": family,
            "coverage_group": coverage_group,
            "role": role_rank,
        }
    )[:24]
    return {
        "review_token": review_token,
        "evidence_role": ROLE_NAMES[role_rank],
        "coverage_group": coverage_group,
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
        "parser_warning_count": v547._integer(row.get("parser_warning_count")),
        "required_missing_count": v547._integer(row.get("required_missing_count")),
        "schema_bucket": row.get("schema_bucket"),
        "group_size": v547._integer(row.get("group_size"), 1),
        "source_event_count": v547._integer(row.get("source_event_count")),
        "source_deny_count": v547._integer(row.get("source_deny_count")),
        "source_unique_destinations": v547._integer(
            row.get("source_unique_destinations")
        ),
        "source_unique_ports": v547._integer(row.get("source_unique_ports")),
        "source_unknown_app_count": v547._integer(
            row.get("source_unknown_app_count")
        ),
        "source_high_risk_app_count": v547._integer(
            row.get("source_high_risk_app_count")
        ),
        "destination_repeat_count": v547._integer(
            row.get("destination_repeat_count")
        ),
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "rule_recommendations_exposed": False,
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


def select_fresh_review_candidates(
    rows: Iterable[dict[str, Any]],
    *,
    limit: int = TARGET_REVIEW_ROWS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    limit = max(1, min(1000, int(limit)))
    buckets: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    excluded: Counter[str] = Counter()
    seen_families: set[str] = set()
    for row in rows:
        role_rank = v547._integer(row.get("role_rank"), 4)
        family = str(row.get("_candidate_family") or "")
        quarantine = str(row.get("_quarantine_reason") or "")
        if role_rank not in ROLE_NAMES:
            excluded[quarantine or "quarantined_or_ineligible_role"] += 1
            continue
        if quarantine:
            excluded[quarantine] += 1
            continue
        if not family:
            excluded["missing_duplicate_family"] += 1
            continue
        if family in seen_families:
            excluded["duplicate_family"] += 1
            continue
        candidate = _candidate_projection(row, family=family)
        candidate["_selection_key"] = v547._stable_hash(
            {
                "version": V562_VERSION,
                "role": candidate["evidence_role"],
                "coverage": candidate["coverage_group"],
                "token": candidate["review_token"],
            }
        )
        buckets[candidate["evidence_role"]][candidate["coverage_group"]].append(
            candidate
        )
        seen_families.add(family)

    for role_buckets in buckets.values():
        for values in role_buckets.values():
            values.sort(key=lambda item: str(item["_selection_key"]))

    role_targets = {
        role: int(limit * weight) for role, weight in ROLE_TARGET_WEIGHTS.items()
    }
    role_targets["development_fit"] += limit - sum(role_targets.values())
    selected: list[dict[str, Any]] = []
    selected_tokens: set[str] = set()
    for role in ROLE_TARGET_WEIGHTS:
        role_selected: list[dict[str, Any]] = []
        role_buckets = buckets.get(role, {})
        groups = sorted(role_buckets)
        while len(role_selected) < role_targets[role] and groups:
            next_groups: list[str] = []
            for group in groups:
                values = role_buckets[group]
                if values and len(role_selected) < role_targets[role]:
                    candidate = values.pop(0)
                    role_selected.append(candidate)
                    selected_tokens.add(str(candidate["review_token"]))
                if values:
                    next_groups.append(group)
            groups = next_groups
        selected.extend(role_selected)

    remaining = sorted(
        (
            candidate
            for role_buckets in buckets.values()
            for values in role_buckets.values()
            for candidate in values
            if str(candidate["review_token"]) not in selected_tokens
        ),
        key=lambda item: (
            str(item["evidence_role"]),
            str(item["coverage_group"]),
            str(item["_selection_key"]),
        ),
    )
    selected.extend(remaining[: max(0, limit - len(selected))])
    selected.sort(
        key=lambda item: (
            list(ROLE_NAMES.values()).index(str(item["evidence_role"])),
            str(item["coverage_group"]),
            str(item["_selection_key"]),
        )
    )
    for candidate in selected:
        candidate.pop("_selection_key", None)
        candidate.pop("_family", None)

    role_counts = Counter(str(row["evidence_role"]) for row in selected)
    coverage_counts = Counter(str(row["coverage_group"]) for row in selected)
    roles_present = all(role_counts.get(role, 0) > 0 for role in ROLE_NAMES.values())
    unique_tokens = len({str(row["review_token"]) for row in selected})
    return selected, {
        "eligible_unique_families": sum(
            len(values)
            for role_buckets in buckets.values()
            for values in role_buckets.values()
        )
        + len(selected),
        "selected_rows": len(selected),
        "target_rows": limit,
        "minimum_review_rows": MINIMUM_REVIEW_ROWS,
        "role_counts": dict(sorted(role_counts.items())),
        "role_targets": role_targets,
        "coverage_counts": dict(sorted(coverage_counts.items())),
        "represented_coverage_groups": len(coverage_counts),
        "all_primary_roles_present": roles_present,
        "selection_gate_passed": bool(
            len(selected) >= min(MINIMUM_REVIEW_ROWS, limit)
            and roles_present
            and unique_tokens == len(selected)
        ),
        "duplicate_families_contained": unique_tokens == len(selected),
        "exclusion_reasons": dict(sorted(excluded.items())),
        "predictions_used_for_selection": False,
        "model_scores_used_for_selection": False,
        "rules_used_as_labels": False,
        "assisted_labels_used_for_selection": False,
    }


def _assert_pack_contract(
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    sealed: bool,
) -> None:
    required = {
        "review_token",
        "evidence_role",
        "coverage_group",
        "human_decision",
        "human_confidence",
        "human_reviewer",
        "human_reviewed_at",
        "human_must_confirm",
        "human_reviewed",
        "import_ready",
    }
    if not rows or required - set(columns):
        raise V562CampaignError(
            "The protected qualification pack is missing required fields."
        )
    forbidden = (
        "prediction",
        "model_score",
        "suggested",
        "assisted_label",
        "raw_log",
        "source_ip",
        "destination_ip",
        "src_ip",
        "dst_ip",
        "fingerprint",
        "exact_hash",
        "near_hash",
        "device_token",
        "source_token",
        "destination_token",
    )
    safe_guards = {
        "predictions_exposed",
        "model_scores_exposed",
        "assisted_labels_exposed",
        "raw_logs_exposed",
        "ip_addresses_exposed",
        "source_identities_exposed",
        "fingerprints_exposed",
    }
    for column in columns:
        lowered = column.casefold()
        if column not in safe_guards and any(part in lowered for part in forbidden):
            raise V562CampaignError(
                "The protected qualification pack exposes forbidden evidence."
            )
    tokens = [str(row.get("review_token") or "") for row in rows]
    if not all(tokens) or len(tokens) != len(set(tokens)):
        raise V562CampaignError(
            "The protected qualification pack contains invalid review tokens."
        )
    for row in rows:
        if str(row.get("evidence_role") or "") not in set(ROLE_NAMES.values()):
            raise V562CampaignError(
                "The protected qualification pack contains an invalid role."
            )
        if any(
            v547._boolean(row.get(field))
            for field in (
                "predictions_exposed",
                "model_scores_exposed",
                "rule_recommendations_exposed",
                "assisted_labels_exposed",
                "raw_logs_exposed",
                "ip_addresses_exposed",
                "source_identities_exposed",
                "fingerprints_exposed",
                "import_ready",
            )
        ):
            raise V562CampaignError(
                "The protected qualification pack violates its safety contract."
            )
        if sealed and (
            v547._boolean(row.get("human_reviewed"))
            or any(
                str(row.get(field) or "").strip()
                for field in HUMAN_FIELDS
                if field
                not in {"human_must_confirm", "human_reviewed", "import_ready"}
            )
        ):
            raise V562CampaignError(
                "The sealed qualification pack contains review decisions."
            )


def _review_progress(output_dir: Path = V562_OUTPUT_DIR) -> dict[str, Any]:
    paths = _workspace_paths(output_dir)
    if not paths["working"].is_file():
        return {
            "total": 0,
            "reviewed": 0,
            "remaining": 0,
            "invalid": 0,
            "complete": False,
            "development_class_support": dict.fromkeys(
                ("benign_like", "needs_context", "suspicious", "malicious"), 0
            ),
            "evaluation_class_support_sealed": True,
            "human_reviewed_labels_created": 0,
        }
    rows, columns = _read_csv(paths["working"])
    _assert_pack_contract(rows, columns, sealed=False)
    reviewed = 0
    invalid = 0
    class_support: Counter[str] = Counter()
    role_progress: dict[str, Counter[str]] = {
        role: Counter(total=0, reviewed=0) for role in ROLE_NAMES.values()
    }
    for row in rows:
        role = str(row.get("evidence_role") or "")
        role_progress[role]["total"] += 1
        is_reviewed = v547._boolean(row.get("human_reviewed"))
        if not is_reviewed:
            continue
        reviewed += 1
        role_progress[role]["reviewed"] += 1
        decision = str(row.get("human_decision") or "").strip().casefold()
        rationale = str(row.get("human_rationale") or "").strip()
        reviewer = str(row.get("human_reviewer") or "").strip()
        attack_type = str(row.get("human_attack_type") or "").strip()
        confidence = v547._integer(row.get("human_confidence"), 0)
        valid = bool(
            decision in ALLOWED_DECISIONS
            and 1 <= confidence <= 100
            and len(rationale) >= 8
            and reviewer
            and not v547.AI_REVIEWER_PATTERN.search(reviewer)
            and v547._boolean(row.get("human_must_confirm"))
            and not v547._boolean(row.get("import_ready"))
            and (decision not in {"suspicious", "malicious"} or attack_type)
        )
        if not valid:
            invalid += 1
            continue
        if role in DEVELOPMENT_ROLE_NAMES:
            if decision in {"benign", "benign_unusual"}:
                class_support["benign_like"] += 1
            elif decision == "needs_context":
                class_support["needs_context"] += 1
            elif decision == "suspicious":
                class_support["suspicious"] += 1
            elif decision == "malicious":
                class_support["malicious"] += 1
    return {
        "total": len(rows),
        "reviewed": reviewed,
        "remaining": len(rows) - reviewed,
        "invalid": invalid,
        "complete": bool(rows and reviewed == len(rows) and invalid == 0),
        "development_class_support": dict(
            sorted(
                {
                    "benign_like": class_support.get("benign_like", 0),
                    "needs_context": class_support.get("needs_context", 0),
                    "suspicious": class_support.get("suspicious", 0),
                    "malicious": class_support.get("malicious", 0),
                }.items()
            )
        ),
        "role_progress": {
            role: dict(values) for role, values in role_progress.items()
        },
        "evaluation_class_support_sealed": True,
        "human_reviewed_labels_created": 0,
        "import_ready": False,
    }


def _qualification_gates(
    *,
    protocol: dict[str, Any] | None,
    review: dict[str, Any],
) -> dict[str, Any]:
    evidence = (protocol or {}).get("evidence") or {}
    source_count = int(evidence.get("real_source_identities") or 0)
    time_windows = int(evidence.get("independent_time_windows") or 0)
    reviewed = int(review.get("reviewed") or 0)
    support = review.get("development_class_support") or {}
    benign_like = int(support.get("benign_like") or 0)
    threat_positive = int(support.get("suspicious") or 0) + int(
        support.get("malicious") or 0
    )

    def evidence_gate(observed: int, threshold: int) -> dict[str, Any]:
        return {
            "observed": observed,
            "threshold": threshold,
            "status": "pass" if observed >= threshold else "fail",
        }

    return {
        "independent_human_blind_labels": evidence_gate(
            reviewed,
            int(FIXED_QUALIFICATION_GATES["minimum_independent_human_blind_labels"]),
        ),
        "independent_comparable_rows": evidence_gate(
            reviewed,
            int(FIXED_QUALIFICATION_GATES["minimum_independent_comparable_rows"]),
        ),
        "benign_like_rows": evidence_gate(
            benign_like,
            int(FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"]),
        ),
        "threat_positive_rows": evidence_gate(
            threat_positive,
            int(FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"]),
        ),
        "real_source_identities": evidence_gate(
            source_count,
            int(FIXED_QUALIFICATION_GATES["minimum_real_source_identities"]),
        ),
        "independent_time_windows": evidence_gate(
            time_windows,
            int(FIXED_QUALIFICATION_GATES["minimum_independent_time_windows"]),
        ),
        "untouched_evaluation_class_support": {
            "observed": None,
            "threshold": "all required classes measurable",
            "status": "blocked",
            "reason": "evaluation_labels_sealed",
        },
        "quality_metrics": {
            metric: {
                "observed": None,
                "threshold": threshold,
                "status": "blocked",
                "reason": "no_candidate_evaluated",
            }
            for metric, threshold in FIXED_QUALIFICATION_GATES.items()
            if metric
            in {
                "queue_f1_min",
                "threat_recall_min",
                "benign_like_false_positive_rate_max",
                "suspicious_recall_min",
                "malicious_recall_min",
                "expected_calibration_error_max",
                "max_confidence_accuracy_gap_max",
            }
        },
    }


def _prepare_workspace(
    rows: list[dict[str, Any]],
    *,
    selection: dict[str, Any],
    exclusion: dict[str, Any],
    profile: dict[str, Any],
    roles: dict[str, Any],
    sample_digest: str,
    output_dir: Path,
) -> dict[str, Any]:
    if not rows:
        raise V562CampaignError("No fresh rows were eligible for protected review.")
    paths = _workspace_paths(output_dir)
    columns = list(rows[0])
    _assert_pack_contract(rows, columns, sealed=True)
    protected_digest = _protected_digest(rows, columns)
    present = [
        paths["protocol"].is_file(),
        paths["sealed"].is_file(),
        paths["working"].is_file(),
    ]
    if any(present) and not all(present):
        raise V562CampaignError(
            "An incomplete v5.62 protected workspace already exists."
        )
    protocol = {
        "schema_version": V562_PROTOCOL_VERSION,
        "campaign_version": V562_VERSION,
        "created_at": _now(),
        "source_digest": sample_digest,
        "consumed_exclusion_locked": True,
        "consumed_review_rows": EXPECTED_CONSUMED_ROWS,
        "selected_rows": len(rows),
        "protected_digest": protected_digest,
        "sealed_pack_digest": None,
        "evidence_roles": [
            *ROLE_NAMES.values(),
            SECOND_SOURCE_ROLE_NAME,
        ],
        "role_counts": selection["role_counts"],
        "second_source_placeholder": {
            "role": SECOND_SOURCE_ROLE_NAME,
            "rows": 0,
            "fabricated": False,
        },
        "fixed_qualification_gates": FIXED_QUALIFICATION_GATES,
        "locked_candidate_strategies": list(LOCKED_CANDIDATE_STRATEGIES),
        "locked_feature_schema": list(LOCKED_FEATURE_SCHEMA),
        "partition": {
            "chronological": True,
            "duplicate_group_isolation": True,
            "roles_assigned_before_labels": True,
            "rows_movable_after_label_opening": False,
            "future_evaluation_labels_sealed": True,
        },
        "evidence": {
            "source_rows": int(profile.get("rows_processed") or 0),
            "fresh_rows_available": int(selection.get("fresh_rows_available") or 0),
            "real_source_identities": int(
                ((profile.get("device_sources") or {}).get("identified_source_count"))
                or 0
            ),
            "independent_time_windows": int(
                roles.get("distinct_time_windows") or 0
            ),
        },
        "exclusion_counts": {
            key: value
            for key, value in exclusion.items()
            if key.startswith("excluded_")
        },
        "predictions_included": False,
        "model_scores_included": False,
        "rule_recommendations_included": False,
        "assisted_labels_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "source_identities_included": False,
        "import_ready": False,
        "activation_allowed": False,
    }
    created = not all(present)
    if created:
        output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_csv(paths["sealed"], rows)
        _atomic_write_csv(paths["working"], rows)
        protocol["sealed_pack_digest"] = v547._file_sha256(paths["sealed"])
        _atomic_write_json(paths["protocol"], protocol)
    else:
        existing = _read_json(paths["protocol"])
        existing_rows, existing_columns = _read_csv(paths["sealed"])
        _assert_pack_contract(existing_rows, existing_columns, sealed=True)
        if (
            existing_columns != columns
            or _protected_digest(existing_rows, existing_columns) != protected_digest
            or existing.get("protected_digest") != protected_digest
            or existing.get("source_digest") != sample_digest
            or existing.get("fixed_qualification_gates")
            != FIXED_QUALIFICATION_GATES
        ):
            raise V562CampaignError(
                "A different immutable v5.62 campaign already exists."
            )
        protocol = existing
    return {
        "created": created,
        "protocol_locked": True,
        "protocol_valid": True,
        "selected_rows": len(rows),
        "review": _review_progress(output_dir),
    }


def validate_campaign_protocol(
    output_dir: Path = V562_OUTPUT_DIR,
) -> dict[str, Any]:
    paths = _workspace_paths(output_dir)
    if not all(
        path.is_file() for path in (paths["protocol"], paths["sealed"], paths["working"])
    ):
        raise V562CampaignError("The v5.62 campaign is not prepared.")
    protocol = _read_json(paths["protocol"])
    sealed_rows, sealed_columns = _read_csv(paths["sealed"])
    working_rows, working_columns = _read_csv(paths["working"])
    _assert_pack_contract(sealed_rows, sealed_columns, sealed=True)
    _assert_pack_contract(working_rows, working_columns, sealed=False)
    if not (
        protocol.get("schema_version") == V562_PROTOCOL_VERSION
        and protocol.get("campaign_version") == V562_VERSION
        and protocol.get("fixed_qualification_gates") == FIXED_QUALIFICATION_GATES
        and tuple(protocol.get("locked_candidate_strategies") or ())
        == LOCKED_CANDIDATE_STRATEGIES
        and tuple(protocol.get("locked_feature_schema") or ())
        == LOCKED_FEATURE_SCHEMA
        and protocol.get("protected_digest")
        == _protected_digest(sealed_rows, sealed_columns)
        and sealed_columns == working_columns
        and len(sealed_rows) == len(working_rows)
        and _protected_digest(working_rows, working_columns)
        == protocol.get("protected_digest")
        and protocol.get("consumed_exclusion_locked") is True
        and protocol.get("activation_allowed") is False
    ):
        raise V562CampaignError(
            "The immutable v5.62 protocol failed integrity validation."
        )
    return protocol


def load_reviewed_development_rows(
    output_dir: Path = V562_OUTPUT_DIR,
) -> list[dict[str, str]]:
    """Load only reviewed development roles; future evaluation is inaccessible."""

    validate_campaign_protocol(output_dir)
    state_path = _workspace_paths(output_dir)["review_state"]
    state = _read_json(state_path) if state_path.is_file() else {}
    if not state.get("closed_at"):
        raise V562CampaignError(
            "Development labels remain sealed until the human review is closed."
        )
    rows, _ = _read_csv(_workspace_paths(output_dir)["working"])
    selected: list[dict[str, str]] = []
    for row in rows:
        role = str(row.get("evidence_role") or "")
        if role == EVALUATION_ROLE_NAME:
            continue
        if role not in DEVELOPMENT_ROLE_NAMES:
            raise V562CampaignError("An unknown evidence role failed closed.")
        if v547._boolean(row.get("human_reviewed")):
            selected.append(row)
    return selected


def get_development_repair_preflight(
    output_dir: Path = V562_OUTPUT_DIR,
) -> dict[str, Any]:
    """Describe development-only repair readiness without fitting any model."""

    paths = _workspace_paths(output_dir)
    if not paths["protocol"].is_file():
        return {
            "status": "blocked_campaign_not_prepared",
            "strategy_count": len(LOCKED_CANDIDATE_STRATEGIES),
            "strategies": [
                {
                    key: spec.get(key)
                    for key in (
                        "name",
                        "model_type",
                        "target_mode",
                        "calibration_method",
                    )
                }
                for spec in LOCKED_CANDIDATE_STRATEGIES
            ],
            "feature_schema_valid": True,
            "training_allowed": False,
            "training_executed": False,
            "evaluation_labels_accessed": False,
            "evaluation_rows_loaded": 0,
            "candidate_frozen": False,
        }
    protocol = validate_campaign_protocol(output_dir)
    review = _review_progress(output_dir)
    state = _read_json(paths["review_state"]) if paths["review_state"].is_file() else {}
    closed = bool(state.get("closed_at"))
    development_rows: list[dict[str, str]] = []
    if closed:
        development_rows = load_reviewed_development_rows(output_dir)
    role_support = Counter(
        str(row.get("evidence_role") or "unknown") for row in development_rows
    )
    decision_support = Counter(
        str(row.get("human_decision") or "unknown") for row in development_rows
    )
    benign_like = decision_support.get("benign", 0) + decision_support.get(
        "benign_unusual", 0
    )
    threat_positive = decision_support.get("suspicious", 0) + decision_support.get(
        "malicious", 0
    )
    evidence = protocol.get("evidence") or {}
    minimum_binary = int(
        FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"]
    )
    minimum_comparable = int(
        FIXED_QUALIFICATION_GATES["minimum_independent_comparable_rows"]
    )
    minimum_sources = int(
        FIXED_QUALIFICATION_GATES["minimum_real_source_identities"]
    )
    checks = {
        "review_closed": closed,
        "review_complete": bool(review.get("complete")),
        "feature_schema_locked": tuple(protocol.get("locked_feature_schema") or ())
        == LOCKED_FEATURE_SCHEMA,
        "strategy_contract_locked": tuple(
            protocol.get("locked_candidate_strategies") or ()
        )
        == LOCKED_CANDIDATE_STRATEGIES,
        "chronological_roles_locked": bool(
            (protocol.get("partition") or {}).get("chronological")
        ),
        "duplicate_groups_isolated": bool(
            (protocol.get("partition") or {}).get("duplicate_group_isolation")
        ),
        "roles_assigned_before_labels": bool(
            (protocol.get("partition") or {}).get("roles_assigned_before_labels")
        ),
        "development_rows_sufficient": len(development_rows) >= minimum_comparable,
        "benign_like_support_sufficient": benign_like >= minimum_binary,
        "threat_positive_support_sufficient": threat_positive >= minimum_binary,
        "calibration_partition_reviewed": role_support.get("calibration", 0) > 0,
        "threshold_partition_reviewed": role_support.get("threshold_selection", 0)
        > 0,
        "provenance_support_sufficient": int(
            evidence.get("real_source_identities") or 0
        )
        >= minimum_sources,
        "time_window_support_sufficient": int(
            evidence.get("independent_time_windows") or 0
        )
        >= int(FIXED_QUALIFICATION_GATES["minimum_independent_time_windows"]),
        "evaluation_partition_sealed": True,
    }
    training_allowed = all(checks.values())
    return {
        "status": (
            "ready_for_explicit_development_experiment"
            if training_allowed
            else "blocked_insufficient_fresh_development_support"
        ),
        "strategy_count": len(LOCKED_CANDIDATE_STRATEGIES),
        "strategies": [
            {
                key: spec.get(key)
                for key in (
                    "name",
                    "model_type",
                    "target_mode",
                    "calibration_method",
                )
            }
            for spec in LOCKED_CANDIDATE_STRATEGIES
        ],
        "feature_count": len(LOCKED_FEATURE_SCHEMA),
        "feature_schema_valid": checks["feature_schema_locked"],
        "checks": checks,
        "development_rows": len(development_rows),
        "development_role_counts": dict(sorted(role_support.items())),
        "development_binary_support": {
            "benign_like": benign_like,
            "threat_positive": threat_positive,
        },
        "calibration_method_contracts": sorted(
            {
                str(spec.get("calibration_method") or "none")
                for spec in LOCKED_CANDIDATE_STRATEGIES
            }
        ),
        "training_allowed": training_allowed,
        "training_executed": False,
        "calibration_outcomes_accessed": False,
        "threshold_outcomes_accessed": False,
        "evaluation_labels_accessed": False,
        "evaluation_rows_loaded": 0,
        "candidate_frozen": False,
        "active_artifact_written": False,
        "private_identifiers_exposed": False,
    }


def _public_protocol(protocol: dict[str, Any] | None) -> dict[str, Any]:
    if not protocol:
        return {
            "version": V562_PROTOCOL_VERSION,
            "locked": False,
            "valid": False,
            "selected_rows": 0,
            "roles": [*ROLE_NAMES.values(), SECOND_SOURCE_ROLE_NAME],
            "role_counts": {},
            "strategy_count": len(LOCKED_CANDIDATE_STRATEGIES),
            "feature_count": len(LOCKED_FEATURE_SCHEMA),
            "gates_unchanged": True,
            "evaluation_labels_sealed": True,
            "digest_exposed": False,
        }
    return {
        "version": protocol.get("schema_version"),
        "locked": True,
        "valid": True,
        "selected_rows": int(protocol.get("selected_rows") or 0),
        "roles": list(protocol.get("evidence_roles") or []),
        "role_counts": dict(protocol.get("role_counts") or {}),
        "strategy_count": len(protocol.get("locked_candidate_strategies") or []),
        "feature_count": len(protocol.get("locked_feature_schema") or []),
        "gates_unchanged": protocol.get("fixed_qualification_gates")
        == FIXED_QUALIFICATION_GATES,
        "chronological": bool((protocol.get("partition") or {}).get("chronological")),
        "duplicate_group_isolation": bool(
            (protocol.get("partition") or {}).get("duplicate_group_isolation")
        ),
        "evaluation_labels_sealed": True,
        "digest_exposed": False,
    }


def get_public_v562_status(
    output_dir: Path = V562_OUTPUT_DIR,
) -> dict[str, Any]:
    paths = _workspace_paths(output_dir)
    boundary = validate_consumed_v549b_boundary()
    if not paths["protocol"].is_file():
        review = _review_progress(output_dir)
        return {
            "version": V562_VERSION,
            "status": "not_prepared",
            "consumed_boundary": boundary,
            "protocol": _public_protocol(None),
            "evidence": {
                "fresh_rows_available": 0,
                "selected_rows": 0,
                "excluded_rows": 0,
                "overlap_rejected": 0,
                "role_counts": {},
                "real_source_identities": 0,
                "independent_time_windows": 0,
                "second_source_present": False,
            },
            "review": review,
            "qualification_gates": _qualification_gates(
                protocol=None,
                review=review,
            ),
            "development_repair": get_development_repair_preflight(output_dir),
            **_safety_projection(),
        }
    protocol = validate_campaign_protocol(output_dir)
    review = _review_progress(output_dir)
    evidence = protocol.get("evidence") or {}
    exclusion_counts = protocol.get("exclusion_counts") or {}
    state = _read_json(paths["review_state"]) if paths["review_state"].is_file() else {}
    closed = bool(state.get("closed_at"))
    status = (
        "protected_review_closed"
        if closed
        else "protected_review_complete"
        if review.get("complete")
        else "protected_review_in_progress"
        if review.get("reviewed")
        else "ready_for_protected_review"
    )
    return {
        "version": V562_VERSION,
        "status": status,
        "consumed_boundary": boundary,
        "protocol": _public_protocol(protocol),
        "evidence": {
            "fresh_rows_available": int(evidence.get("fresh_rows_available") or 0),
            "selected_rows": int(protocol.get("selected_rows") or 0),
            "excluded_rows": int(exclusion_counts.get("excluded_event_rows") or 0),
            "overlap_rejected": int(
                exclusion_counts.get("excluded_event_rows") or 0
            ),
            "role_counts": dict(protocol.get("role_counts") or {}),
            "real_source_identities": int(
                evidence.get("real_source_identities") or 0
            ),
            "independent_time_windows": int(
                evidence.get("independent_time_windows") or 0
            ),
            "second_source_present": int(
                evidence.get("real_source_identities") or 0
            )
            >= int(FIXED_QUALIFICATION_GATES["minimum_real_source_identities"]),
        },
        "review": {**review, "closed": closed},
        "qualification_gates": _qualification_gates(
            protocol=protocol,
            review=review,
        ),
        "development_repair": get_development_repair_preflight(output_dir),
        "external_evidence_required": [
            "second_physical_source",
            "new_untouched_future_window",
            "independent_human_review",
        ],
        **_safety_projection(),
    }


def _safety_projection() -> dict[str, Any]:
    return {
        "lifecycle_state": "shadow_observation",
        "supervised_state": "unqualified",
        "activation_allowed": False,
        "candidate_frozen": False,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "rules_alert_authoritative": True,
        "anomaly_advisory_only": True,
        "hybrid_advisory_only": True,
        "response_mode": "simulation_only",
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "automatic_import_performed": False,
        "human_reviewed_labels_created": 0,
        "evaluation_executed": False,
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "rule_recommendations_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "private_paths_exposed": False,
        "secrets_exposed": False,
    }


def _safe_failure(status: str, *, stage: str, error_type: str) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V562_VERSION,
        "status": status,
        "failure_stage": stage,
        "error_type": error_type,
        "message": "The v5.62 campaign failed closed without changing governed state.",
        **_safety_projection(),
    }


def _render_report(result: dict[str, Any]) -> str:
    evidence = result.get("evidence") or {}
    selection = result.get("selection") or {}
    return "\n".join(
        [
            "# v5.62 Supervised Qualification Campaign",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Fresh rows available: `{evidence.get('fresh_rows_available', 0)}`",
            f"- Selected review rows: `{selection.get('selected_rows', 0)}`",
            f"- Consumed rows excluded: `{evidence.get('overlap_rejected', 0)}`",
            f"- Real source identities: `{evidence.get('real_source_identities', 0)}`",
            f"- Independent time windows: `{evidence.get('independent_time_windows', 0)}`",
            "- Predictions exposed: `False`",
            "- Evaluation executed: `False`",
            "- Model activated: `False`",
            "- Rules remain authoritative: `True`",
            "- Response mode: `simulation_only`",
            "",
            "This phase prepares fresh protected evidence; it does not qualify a model.",
            "",
        ]
    )


def run_v562_supervised_qualification_campaign(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = True,
    prepare_protected_review: bool = False,
    confirmation: str | None = None,
    review_limit: int = TARGET_REVIEW_ROWS,
    output_dir: Path = V562_OUTPUT_DIR,
    write_report: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    stage = "consumed_boundary_validation"
    try:
        boundary = validate_consumed_v549b_boundary()
    except (V562CampaignError, v549b.V549BRevalidationError) as exc:
        return _safe_failure(
            "failed_closed_consumed_boundary",
            stage=stage,
            error_type=exc.__class__.__name__,
        )
    available = bool(sample_path and Path(sample_path).is_file())
    if preflight_only and not prepare_protected_review:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        safe = bool(
            available
            and counts_before == counts_after
            and artifacts_before == artifacts_after
        )
        return {
            "ok": safe,
            "version": V562_VERSION,
            "status": "ready_for_explicit_preparation"
            if safe
            else "private_file_unavailable",
            "preflight_only": True,
            "consumed_boundary": boundary,
            "private_file": {
                "supplied": sample_path is not None,
                "available": available,
                "path_returned": False,
                "file_name_returned": False,
                "digest_returned": False,
            },
            "required_confirmation": PREPARE_CONFIRMATION,
            "configured_database_counts_unchanged": counts_before == counts_after,
            "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
            **_safety_projection(),
        }
    if not prepare_protected_review:
        return _safe_failure(
            "explicit_preparation_required",
            stage="preparation_gate",
            error_type="ConfirmationRequired",
        )
    if confirmation != PREPARE_CONFIRMATION:
        return _safe_failure(
            "confirmation_phrase_required",
            stage="preparation_gate",
            error_type="ConfirmationRequired",
        )
    if not available:
        return _safe_failure(
            "private_file_unavailable",
            stage="private_file_validation",
            error_type="FileNotFoundError",
        )
    if not use_temp_db:
        return _safe_failure(
            "temporary_storage_acknowledgement_required",
            stage="disposable_storage_gate",
            error_type="AcknowledgementRequired",
        )

    try:
        sample_path = Path(sample_path)
        sample_digest = v547._file_sha256(sample_path)
        with tempfile.TemporaryDirectory(prefix="atdr-v562-") as directory:
            connection = sqlite3.connect(Path(directory) / "campaign.sqlite3")
            try:
                stage = "private_source_stream"
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile.get("ok"):
                    raise V562CampaignError("Private evidence parsing failed.")
                stage = "chronological_role_lock"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V562CampaignError(
                        "Chronological evidence roles could not be locked."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                containment = v545._contain_candidate_near_families(connection)
                if not containment.get("passed"):
                    raise V562CampaignError(
                        "Duplicate families cross predeclared evidence roles."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "consumed_evidence_exclusion"
                exclusion = _install_consumed_exclusion(
                    connection,
                    sample_digest=sample_digest,
                    output_dir=output_dir,
                )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "prediction_blind_selection"
                representatives = v547._load_representatives(connection)
                candidates, selection = select_fresh_review_candidates(
                    representatives,
                    limit=review_limit,
                )
                fresh_rows = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM events WHERE role_rank < 4 "
                        "AND quarantine_reason IS NULL"
                    ).fetchone()[0]
                )
                selection["fresh_rows_available"] = fresh_rows
                stage = "protected_protocol_lock"
                workspace = _prepare_workspace(
                    candidates,
                    selection=selection,
                    exclusion=exclusion,
                    profile=profile,
                    roles=roles,
                    sample_digest=sample_digest,
                    output_dir=output_dir,
                )
            finally:
                connection.close()
    except (
        V562CampaignError,
        v547.V547AcquisitionError,
        v549b.V549BRevalidationError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _safe_failure(
            "failed_closed_campaign_preparation",
            stage=stage,
            error_type=exc.__class__.__name__,
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    deltas = {
        key: int(counts_after[key]) - int(counts_before[key]) for key in counts_before
    }
    safety_passed = bool(
        counts_before == counts_after
        and artifacts_before == artifacts_after
        and all(value == 0 for value in deltas.values())
    )
    protocol = validate_campaign_protocol(output_dir)
    review = _review_progress(output_dir)
    qualification_gates = _qualification_gates(protocol=protocol, review=review)
    evidence = {
        "source_rows": int(profile.get("rows_processed") or 0),
        "parser_success_rows": int(profile.get("parser_successes") or 0),
        "parser_failure_rows": int(profile.get("parser_failures") or 0),
        "fresh_rows_available": int(selection.get("fresh_rows_available") or 0),
        "selected_rows": int(selection.get("selected_rows") or 0),
        "overlap_rejected": int(exclusion.get("excluded_event_rows") or 0),
        "duplicate_rows": int(profile.get("exact_duplicate_rows") or 0),
        "near_duplicate_rows": int(profile.get("near_duplicate_rows") or 0),
        "real_source_identities": int(
            ((profile.get("device_sources") or {}).get("identified_source_count"))
            or 0
        ),
        "independent_time_windows": int(
            (protocol.get("evidence") or {}).get("independent_time_windows") or 0
        ),
        "second_source_present": int(
            ((profile.get("device_sources") or {}).get("identified_source_count"))
            or 0
        )
        >= int(FIXED_QUALIFICATION_GATES["minimum_real_source_identities"]),
    }
    result = {
        "ok": safety_passed and bool(selection.get("selection_gate_passed")),
        "version": V562_VERSION,
        "status": "ready_for_protected_human_review"
        if safety_passed and selection.get("selection_gate_passed")
        else "campaign_evidence_incomplete",
        "generated_at": _now(),
        "preflight_only": False,
        "consumed_boundary": boundary,
        "protocol": _public_protocol(protocol),
        "exclusion": exclusion,
        "evidence": evidence,
        "selection": selection,
        "workspace": workspace,
        "review": review,
        "qualification_gates": qualification_gates,
        "model_repair": get_development_repair_preflight(output_dir),
        "authoritative_mutations": deltas,
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        **_safety_projection(),
    }
    if write_report:
        _atomic_write_json(_workspace_paths(output_dir)["latest"], result)
        (output_dir / f"{V562_REPORT_PREFIX}_{_stamp()}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
        result["reports_written"] = True
    else:
        result["reports_written"] = False
    encoded = json.dumps(result, default=str)
    if str(sample_path) in encoded or sample_path.name in encoded:
        return _safe_failure(
            "public_output_redaction_failed",
            stage="public_output_redaction",
            error_type="PrivatePathExposure",
        )
    return result
