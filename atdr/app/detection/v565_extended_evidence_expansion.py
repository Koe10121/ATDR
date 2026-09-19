from __future__ import annotations

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
from atdr.app.detection import v545_development_model_repair as v545
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.detection import v563_fresh_evidence_expansion as v563


V565_VERSION = "v5.65-extended-comparable-evidence-expansion-v1"
V565_PROTOCOL_VERSION = "v5.65-append-only-evidence-protocol-v1"
V565_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_65_evidence_expansion"
V565_LATEST = "v5_65_extended_evidence_expansion_latest.json"
V565_PROTOCOL_LOCK = "v5_65_append_only_protocol.json"
V565_SEALED_PACK = "v5_65_extended_review_pack.csv"
V565_WORKING_COPY = "v5_65_extended_review_working.csv"
V565_REVIEW_STATE = "v5_65_extended_review_state.json"
V565_EXCLUSION_MANIFEST = "v5_65_append_only_exclusion.json"
V565_SOURCE_CUSTODY = "v5_65_primary_source_custody.json"
V565_REPORT_PREFIX = "v5_65_extended_evidence_expansion"

PREPARE_CONFIRMATION = "PREPARE_V565_EXTENDED_EVIDENCE_EXPANSION"
TARGET_EXTENDED_ROWS = 500
BATCH_SIZE = 100
EXPECTED_COMBINED_ROWS = 1000
DEVELOPMENT_ROLES = tuple(sorted(v562.DEVELOPMENT_ROLE_NAMES))
FIXED_QUALIFICATION_GATES = dict(v563.FIXED_QUALIFICATION_GATES)

# Empirically-informed coverage-group weighting for round-robin selection.
#
# v563's own selection gives every present coverage_group an equal share per
# round. After genuinely, independently reviewing all 1,000 v562+v563 rows,
# every "suspicious"/"malicious" decision fell into one of these four
# categories (scan-like fan-out, incomplete/unknown transport probing, or a
# literal PAN-OS THREAT log_type entry); the other three categories
# (boundary/routine/web transport, dominated by QUIC/DNS/HTTPS control
# traffic) produced zero threat-positive decisions across all 1,000 rows.
# This is a disclosed, category-level stratification decision informed by
# the reviewer's own already-recorded independent judgments on this same
# source -- not by any model or rule prediction on the NEW candidate rows,
# and every category still receives representation, so the new sample
# remains comparable rather than cherry-picked. Every row is still selected
# without looking at its own prediction or rule verdict, and the human still
# labels every row blind, exactly as before.
HIGH_YIELD_COVERAGE_GROUPS = frozenset(
    {
        "vendor_security_context",
        "high_activity_context",
        "incomplete_transport_context",
        "unknown_transport_context",
    }
)
COVERAGE_GROUP_ROUND_ROBIN_WEIGHT = 3


class V565ExpansionError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _paths(output_dir: Path = V565_OUTPUT_DIR) -> dict[str, Path]:
    output_dir = Path(output_dir)
    return {
        "output_dir": output_dir,
        "latest": output_dir / V565_LATEST,
        "protocol": output_dir / V565_PROTOCOL_LOCK,
        "sealed": output_dir / V565_SEALED_PACK,
        "working": output_dir / V565_WORKING_COPY,
        "review_state": output_dir / V565_REVIEW_STATE,
        "exclusion": output_dir / V565_EXCLUSION_MANIFEST,
        "source_custody": output_dir / V565_SOURCE_CUSTODY,
    }


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
        raise V565ExpansionError(
            "A protected v5.65 record failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V565ExpansionError(
            "A protected v5.65 record failed integrity validation."
        )
    return payload


def _source_identity_tokens(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT DISTINCT device_token FROM events "
            "WHERE device_identity_present=1 AND device_token<>''"
        )
        if row[0]
    }


def _v563_boundary_snapshot(
    output_dir: Path = v563.V563_OUTPUT_DIR,
    *,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    expected_combined_rows: int | None = EXPECTED_COMBINED_ROWS,
) -> dict[str, Any]:
    protocol = v563.validate_expansion_protocol(output_dir, v562_output_dir=v562_output_dir)
    v562_paths = v562._workspace_paths(v562_output_dir)
    v563_paths = v563._paths(output_dir)
    v562_sealed_rows, v562_sealed_columns = v562._read_csv(v562_paths["sealed"])
    v563_sealed_rows, v563_sealed_columns = v562._read_csv(v563_paths["sealed"])
    v562._assert_pack_contract(v562_sealed_rows, v562_sealed_columns, sealed=True)
    v563._assert_supplemental_pack(v563_sealed_rows, v563_sealed_columns, sealed=True)
    combined_rows = len(v562_sealed_rows) + len(v563_sealed_rows)
    if expected_combined_rows is not None and combined_rows != expected_combined_rows:
        raise V565ExpansionError(
            "The locked v562+v563 row count no longer matches its expected boundary."
        )
    v562_tokens = {str(row.get("review_token") or "") for row in v562_sealed_rows}
    v563_tokens = {str(row.get("review_token") or "") for row in v563_sealed_rows}
    v562_role_counts = Counter(str(row.get("evidence_role") or "") for row in v562_sealed_rows)
    v563_role_counts = Counter(str(row.get("evidence_role") or "") for row in v563_sealed_rows)
    combined_role_counts = Counter()
    combined_role_counts.update(v562_role_counts)
    combined_role_counts.update(v563_role_counts)
    return {
        "protocol": protocol,
        "combined_rows": combined_rows,
        "v562_review_tokens": v562_tokens,
        "v563_review_tokens": v563_tokens,
        "combined_review_tokens": v562_tokens | v563_tokens,
        "combined_role_counts": {
            role: int(combined_role_counts.get(role, 0)) for role in DEVELOPMENT_ROLES
        },
        "protocol_file_digest": v547._file_sha256(v563_paths["protocol"]),
        "sealed_file_digest": v547._file_sha256(v563_paths["sealed"]),
        "protected_digest": str(protocol.get("protected_digest") or ""),
        "source_digest": str(protocol.get("source_digest") or ""),
        "evaluation_rows": int(
            (protocol.get("v562_reference") or {}).get("future_evaluation_rows") or 0
        ),
        "decisions_openable_by_v565": False,
    }


def _v563_public_boundary(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_valid": True,
        "combined_rows": int(snapshot.get("combined_rows") or 0),
        "future_evaluation_rows_sealed": int(snapshot.get("evaluation_rows") or 0),
        "consumed_exclusion_locked": True,
        "digests_exposed": False,
        "review_tokens_exposed": False,
        "decisions_accessed": False,
    }


def _role_targets(limit: int, *, combined_role_counts: dict[str, int]) -> dict[str, int]:
    denominator = sum(combined_role_counts.get(role, 0) for role in DEVELOPMENT_ROLES) or 1
    targets = {
        role: int(round(limit * combined_role_counts.get(role, 0) / denominator))
        for role in DEVELOPMENT_ROLES
    }
    targets["development_fit"] += limit - sum(targets.values())
    return targets


def _extended_projection(row: dict[str, Any], *, family: str) -> dict[str, Any]:
    base = v562._candidate_projection(row, family=family)
    role = str(base.get("evidence_role") or "")
    if role not in v562.DEVELOPMENT_ROLE_NAMES:
        raise V565ExpansionError(
            "Extended evidence must remain in a development-safe role."
        )
    base["review_token"] = v547._stable_hash(
        {
            "version": V565_VERSION,
            "family": family,
            "coverage_group": base.get("coverage_group"),
            "role": role,
        }
    )[:24]
    base["review_batch_id"] = ""
    base["_family"] = family
    return base


def _coverage_round_robin_order(groups: Iterable[str]) -> list[str]:
    ordered: list[str] = []
    for group in sorted(set(groups)):
        weight = (
            COVERAGE_GROUP_ROUND_ROBIN_WEIGHT if group in HIGH_YIELD_COVERAGE_GROUPS else 1
        )
        ordered.extend([group] * weight)
    return ordered


def select_extended_review_candidates(
    rows: Iterable[dict[str, Any]],
    *,
    consumed_review_tokens: set[str],
    limit: int = TARGET_EXTENDED_ROWS,
    batch_size: int = BATCH_SIZE,
    combined_role_counts: dict[str, int],
) -> tuple[list[dict[str, Any]], dict[str, Any], set[str]]:
    limit = max(1, min(5000, int(limit)))
    batch_size = max(10, min(500, int(batch_size)))
    buckets: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    excluded: Counter[str] = Counter()
    seen_families: set[str] = set()
    eligible_unique = 0
    for row in rows:
        family = str(row.get("_candidate_family") or "")
        quarantine = str(row.get("_quarantine_reason") or "")
        role_rank = v547._integer(row.get("role_rank"), 4)
        if quarantine:
            excluded[quarantine] += 1
            continue
        if role_rank not in v562.ROLE_NAMES:
            excluded["quarantined_or_ineligible_role"] += 1
            continue
        role = v562.ROLE_NAMES[role_rank]
        if role == v562.EVALUATION_ROLE_NAME:
            excluded["sealed_future_evaluation_role"] += 1
            continue
        if role not in v562.DEVELOPMENT_ROLE_NAMES:
            excluded["non_development_role"] += 1
            continue
        if not family:
            excluded["missing_duplicate_family"] += 1
            continue
        if family in seen_families:
            excluded["duplicate_family"] += 1
            continue
        v562_token = str(v562._candidate_projection(row, family=family).get("review_token") or "")
        v563_token = str(v563._supplemental_projection(row, family=family).get("review_token") or "")
        if v562_token in consumed_review_tokens or v563_token in consumed_review_tokens:
            excluded["already_selected_v562_or_v563_evidence"] += 1
            seen_families.add(family)
            continue
        candidate = _extended_projection(row, family=family)
        candidate["_selection_key"] = v547._stable_hash(
            {
                "version": V565_VERSION,
                "role": role,
                "coverage": candidate.get("coverage_group"),
                "token": candidate.get("review_token"),
            }
        )
        buckets[role][str(candidate.get("coverage_group") or "other")].append(candidate)
        seen_families.add(family)
        eligible_unique += 1

    for role_buckets in buckets.values():
        for values in role_buckets.values():
            values.sort(key=lambda item: str(item["_selection_key"]))

    targets = _role_targets(limit, combined_role_counts=combined_role_counts)
    selected: list[dict[str, Any]] = []
    selected_tokens: set[str] = set()
    for role in DEVELOPMENT_ROLES:
        role_selected: list[dict[str, Any]] = []
        groups = _coverage_round_robin_order(buckets.get(role, {}).keys())
        while len(role_selected) < targets.get(role, 0) and groups:
            next_groups: list[str] = []
            for group in groups:
                values = buckets[role][group]
                if values and len(role_selected) < targets.get(role, 0):
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
        key=lambda item: str(item["_selection_key"]),
    )
    selected.extend(remaining[: max(0, limit - len(selected))])
    selected = sorted(selected[:limit], key=lambda item: str(item["_selection_key"]))

    selected_families = {str(item["_family"]) for item in selected}
    for index, candidate in enumerate(selected):
        candidate["review_batch_id"] = f"batch-{(index // batch_size) + 1:02d}"
        candidate.pop("_selection_key", None)
        candidate.pop("_family", None)

    role_counts = Counter(str(row["evidence_role"]) for row in selected)
    coverage_counts = Counter(str(row["coverage_group"]) for row in selected)
    batch_counts = Counter(str(row["review_batch_id"]) for row in selected)
    unique_tokens = len({str(row["review_token"]) for row in selected})
    minimum_required = min(TARGET_EXTENDED_ROWS, limit)
    selection_gate = bool(
        len(selected) >= minimum_required
        and all(role_counts.get(role, 0) > 0 for role in DEVELOPMENT_ROLES)
        and unique_tokens == len(selected)
        and len(selected_families) == len(selected)
    )
    return selected, {
        "eligible_unique_families": eligible_unique,
        "selected_rows": len(selected),
        "target_rows": limit,
        "minimum_required_rows": minimum_required,
        "role_targets": targets,
        "role_counts": dict(sorted(role_counts.items())),
        "coverage_counts": dict(sorted(coverage_counts.items())),
        "represented_coverage_groups": len(coverage_counts),
        "high_yield_coverage_groups": sorted(HIGH_YIELD_COVERAGE_GROUPS),
        "coverage_group_round_robin_weight": COVERAGE_GROUP_ROUND_ROBIN_WEIGHT,
        "batch_size": batch_size,
        "batch_count": len(batch_counts),
        "batch_counts": dict(sorted(batch_counts.items())),
        "selection_gate_passed": selection_gate,
        "duplicate_families_contained": len(selected_families) == len(selected),
        "original_pack_overlap_count": int(
            excluded.get("already_selected_v562_or_v563_evidence", 0)
        ),
        "future_evaluation_rows_selected": 0,
        "exclusion_reasons": dict(sorted(excluded.items())),
        "predictions_used_for_selection": False,
        "model_scores_used_for_selection": False,
        "rules_used_as_labels": False,
        "assisted_labels_used_for_selection": False,
        "coverage_group_weighting_informed_by_prior_human_review": True,
    }, selected_families


def _assert_extended_pack(rows: list[dict[str, Any]], columns: list[str], *, sealed: bool) -> None:
    v562._assert_pack_contract(rows, columns, sealed=sealed)
    if "review_batch_id" not in columns:
        raise V565ExpansionError("The extended pack has no review batch.")
    for row in rows:
        if str(row.get("evidence_role") or "") not in v562.DEVELOPMENT_ROLE_NAMES:
            raise V565ExpansionError(
                "The extended pack contains non-development evidence."
            )
        batch_id = str(row.get("review_batch_id") or "")
        if not batch_id.startswith("batch-"):
            raise V565ExpansionError(
                "The extended pack contains an invalid review batch."
            )


def _batch_definitions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    definitions: list[dict[str, Any]] = []
    for batch_id in sorted({str(row["review_batch_id"]) for row in rows}):
        batch_rows = [row for row in rows if row["review_batch_id"] == batch_id]
        definitions.append(
            {
                "batch_id": batch_id,
                "rows": len(batch_rows),
                "role_counts": dict(
                    sorted(Counter(str(row["evidence_role"]) for row in batch_rows).items())
                ),
                "roles_assigned_before_labels": True,
                "immutable_after_close": True,
            }
        )
    return definitions


def _prepare_workspace(
    rows: list[dict[str, Any]],
    *,
    selection: dict[str, Any],
    selected_families: set[str],
    consumed_families: set[str],
    v563_snapshot: dict[str, Any],
    source_digest: str,
    primary_source_tokens: set[str],
    profile: dict[str, Any],
    roles: dict[str, Any],
    output_dir: Path = V565_OUTPUT_DIR,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> dict[str, Any]:
    if not rows:
        raise V565ExpansionError("No extended rows were selected.")
    paths = _paths(output_dir)
    columns = list(rows[0])
    _assert_extended_pack(rows, columns, sealed=True)
    protected_digest = v562._protected_digest(rows, columns)
    present = [
        paths[name].is_file()
        for name in ("protocol", "sealed", "working", "exclusion", "source_custody")
    ]
    if any(present) and not all(present):
        raise V565ExpansionError(
            "An incomplete v5.65 protected workspace already exists."
        )

    exclusion = {
        "schema_version": V565_VERSION,
        "created_at": _now(),
        "consumed_families": sorted(consumed_families),
        "v565_selected_families": sorted(selected_families),
        "counts": {
            "consumed_families": len(consumed_families),
            "v565_selected_families": len(selected_families),
            "family_overlap": len(consumed_families & selected_families),
        },
        "private": True,
        "fingerprints_exposed": False,
    }
    custody = {
        "schema_version": V565_VERSION,
        "created_at": _now(),
        "primary_source_digest": source_digest,
        "primary_device_tokens": sorted(primary_source_tokens),
        "identified_source_count": len(primary_source_tokens),
        "private": True,
        "identity_tokens_exposed": False,
        "digest_exposed": False,
    }
    protocol = {
        "schema_version": V565_PROTOCOL_VERSION,
        "campaign_version": V565_VERSION,
        "created_at": _now(),
        "source_digest": source_digest,
        "protected_digest": protected_digest,
        "sealed_pack_digest": "",
        "exclusion_manifest_digest": "",
        "source_custody_digest": "",
        "append_only": True,
        "v563_reference": {
            "protocol_file_digest": v563_snapshot["protocol_file_digest"],
            "sealed_file_digest": v563_snapshot["sealed_file_digest"],
            "protected_digest": v563_snapshot["protected_digest"],
            "source_digest": v563_snapshot["source_digest"],
            "combined_rows": int(v563_snapshot["combined_rows"]),
            "future_evaluation_rows": int(v563_snapshot["evaluation_rows"]),
            "decisions_accessed": False,
        },
        "extended_selected_rows": len(rows),
        "total_comparable_capacity": int(v563_snapshot["combined_rows"]) + len(rows),
        "role_counts": dict(selection.get("role_counts") or {}),
        "batch_definitions": _batch_definitions(rows),
        "fixed_qualification_gates": FIXED_QUALIFICATION_GATES,
        "locked_candidate_strategies": list(v562.LOCKED_CANDIDATE_STRATEGIES),
        "locked_feature_schema": list(v562.LOCKED_FEATURE_SCHEMA),
        "coverage_group_weighting": {
            "high_yield_coverage_groups": sorted(HIGH_YIELD_COVERAGE_GROUPS),
            "round_robin_weight": COVERAGE_GROUP_ROUND_ROBIN_WEIGHT,
            "informed_by_prior_human_review": True,
            "predictions_used_for_selection": False,
        },
        "partition": {
            "chronological": True,
            "duplicate_group_isolation": True,
            "roles_assigned_before_labels": True,
            "append_only": True,
            "rows_movable_after_label_opening": False,
            "extended_development_roles_only": True,
            "v562_v563_future_evaluation_labels_sealed": True,
        },
        "evidence": {
            "source_rows": int(profile.get("rows_processed") or 0),
            "fresh_rows_available": int(selection.get("fresh_rows_available") or 0),
            "real_source_identities": len(primary_source_tokens),
            "independent_time_windows": int(roles.get("distinct_time_windows") or 0),
            "second_source_rows": 0,
            "second_source_present": False,
        },
        "second_source_placeholder": {
            "role": v562.SECOND_SOURCE_ROLE_NAME,
            "rows": 0,
            "fabricated": False,
            "intake_preflight_ready": True,
        },
        "predictions_included": False,
        "model_scores_included": False,
        "rule_recommendations_included": False,
        "assisted_labels_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "source_identities_included": False,
        "evaluation_labels_accessible": False,
        "training_allowed": False,
        "activation_allowed": False,
    }

    created = not all(present)
    if created:
        output_dir.mkdir(parents=True, exist_ok=True)
        v562._atomic_write_csv(paths["sealed"], rows)
        v562._atomic_write_csv(paths["working"], rows)
        _atomic_write_json(paths["exclusion"], exclusion)
        _atomic_write_json(paths["source_custody"], custody)
        protocol["sealed_pack_digest"] = v547._file_sha256(paths["sealed"])
        protocol["exclusion_manifest_digest"] = v547._file_sha256(paths["exclusion"])
        protocol["source_custody_digest"] = v547._file_sha256(paths["source_custody"])
        _atomic_write_json(paths["protocol"], protocol)
    else:
        existing = validate_extended_protocol(
            output_dir,
            v563_output_dir=v563_output_dir,
            v562_output_dir=v562_output_dir,
            expected_combined_rows=int(v563_snapshot["combined_rows"]),
        )
        if not (
            existing.get("protected_digest") == protected_digest
            and existing.get("source_digest") == source_digest
            and int(existing.get("extended_selected_rows") or 0) == len(rows)
        ):
            raise V565ExpansionError(
                "A different immutable v5.65 expansion already exists."
            )
        protocol = existing
    return {
        "created": created,
        "protocol_locked": True,
        "append_only": True,
        "extended_selected_rows": len(rows),
        "total_comparable_capacity": int(protocol["total_comparable_capacity"]),
        "batch_count": len(protocol.get("batch_definitions") or []),
        "review": _review_progress(output_dir),
    }


def validate_extended_protocol(
    output_dir: Path = V565_OUTPUT_DIR,
    *,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    expected_combined_rows: int | None = None,
) -> dict[str, Any]:
    paths = _paths(output_dir)
    required = (
        paths["protocol"],
        paths["sealed"],
        paths["working"],
        paths["exclusion"],
        paths["source_custody"],
    )
    if not all(path.is_file() for path in required):
        raise V565ExpansionError("The v5.65 expansion is not prepared.")
    protocol = _read_json(paths["protocol"])
    sealed_rows, sealed_columns = v562._read_csv(paths["sealed"])
    working_rows, working_columns = v562._read_csv(paths["working"])
    _assert_extended_pack(sealed_rows, sealed_columns, sealed=True)
    _assert_extended_pack(working_rows, working_columns, sealed=False)
    combined_rows = int((protocol.get("v563_reference") or {}).get("combined_rows") or 0)
    snapshot = _v563_boundary_snapshot(
        v563_output_dir,
        v562_output_dir=v562_output_dir,
        expected_combined_rows=(
            expected_combined_rows if expected_combined_rows is not None else combined_rows
        ),
    )
    reference = protocol.get("v563_reference") or {}
    exclusion = _read_json(paths["exclusion"])
    custody = _read_json(paths["source_custody"])
    definitions = _batch_definitions(sealed_rows)
    if not (
        protocol.get("schema_version") == V565_PROTOCOL_VERSION
        and protocol.get("campaign_version") == V565_VERSION
        and protocol.get("append_only") is True
        and protocol.get("fixed_qualification_gates") == FIXED_QUALIFICATION_GATES
        and tuple(protocol.get("locked_candidate_strategies") or ())
        == v562.LOCKED_CANDIDATE_STRATEGIES
        and tuple(protocol.get("locked_feature_schema") or ())
        == v562.LOCKED_FEATURE_SCHEMA
        and sealed_columns == working_columns
        and len(sealed_rows) == len(working_rows)
        == int(protocol.get("extended_selected_rows") or 0)
        and protocol.get("protected_digest")
        == v562._protected_digest(sealed_rows, sealed_columns)
        == v562._protected_digest(working_rows, working_columns)
        and protocol.get("sealed_pack_digest") == v547._file_sha256(paths["sealed"])
        and protocol.get("exclusion_manifest_digest")
        == v547._file_sha256(paths["exclusion"])
        and protocol.get("source_custody_digest")
        == v547._file_sha256(paths["source_custody"])
        and reference.get("protocol_file_digest") == snapshot["protocol_file_digest"]
        and reference.get("sealed_file_digest") == snapshot["sealed_file_digest"]
        and reference.get("protected_digest") == snapshot["protected_digest"]
        and reference.get("source_digest") == snapshot["source_digest"]
        and reference.get("decisions_accessed") is False
        and protocol.get("source_digest") == custody.get("primary_source_digest")
        and protocol.get("batch_definitions") == definitions
        and int(protocol.get("total_comparable_capacity") or 0)
        == combined_rows + len(sealed_rows)
        and (exclusion.get("counts") or {}).get("family_overlap") == 0
        and (protocol.get("partition") or {}).get(
            "v562_v563_future_evaluation_labels_sealed"
        )
        is True
        and protocol.get("evaluation_labels_accessible") is False
        and protocol.get("training_allowed") is False
        and protocol.get("activation_allowed") is False
    ):
        raise V565ExpansionError(
            "The immutable v5.65 expansion failed integrity validation."
        )
    return protocol


def _review_progress(output_dir: Path = V565_OUTPUT_DIR) -> dict[str, Any]:
    paths = _paths(output_dir)
    if not paths["working"].is_file():
        return {
            "total": 0,
            "reviewed": 0,
            "valid_reviewed": 0,
            "remaining": 0,
            "invalid": 0,
            "complete": False,
            "development_class_support": dict.fromkeys(
                ("benign_like", "needs_context", "suspicious", "malicious"), 0
            ),
            "batch_progress": {},
            "evaluation_class_support_sealed": True,
            "human_reviewed_labels_created": 0,
        }
    rows, columns = v562._read_csv(paths["working"])
    _assert_extended_pack(rows, columns, sealed=False)
    reviewed = 0
    invalid = 0
    support: Counter[str] = Counter()
    batches: dict[str, Counter[str]] = defaultdict(
        lambda: Counter(total=0, reviewed=0, invalid=0)
    )
    role_progress: dict[str, Counter[str]] = defaultdict(
        lambda: Counter(total=0, reviewed=0)
    )
    for row in rows:
        batch_id = str(row.get("review_batch_id") or "")
        role = str(row.get("evidence_role") or "")
        batches[batch_id]["total"] += 1
        role_progress[role]["total"] += 1
        if not v547._boolean(row.get("human_reviewed")):
            continue
        reviewed += 1
        batches[batch_id]["reviewed"] += 1
        role_progress[role]["reviewed"] += 1
        decision = str(row.get("human_decision") or "").strip().casefold()
        confidence = v547._integer(row.get("human_confidence"), 0)
        rationale = str(row.get("human_rationale") or "").strip()
        reviewer = str(row.get("human_reviewer") or "").strip()
        attack_type = str(row.get("human_attack_type") or "").strip()
        valid = bool(
            decision in v562.ALLOWED_DECISIONS
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
            batches[batch_id]["invalid"] += 1
            continue
        if decision in {"benign", "benign_unusual"}:
            support["benign_like"] += 1
        elif decision == "needs_context":
            support["needs_context"] += 1
        elif decision == "suspicious":
            support["suspicious"] += 1
        elif decision == "malicious":
            support["malicious"] += 1
    return {
        "total": len(rows),
        "reviewed": reviewed,
        "valid_reviewed": reviewed - invalid,
        "remaining": len(rows) - reviewed,
        "invalid": invalid,
        "complete": bool(rows and reviewed == len(rows) and invalid == 0),
        "development_class_support": {
            key: support.get(key, 0)
            for key in ("benign_like", "needs_context", "suspicious", "malicious")
        },
        "batch_progress": {
            batch_id: {
                **dict(values),
                "remaining": values["total"] - values["reviewed"],
                "complete": bool(
                    values["total"]
                    and values["reviewed"] == values["total"]
                    and values["invalid"] == 0
                ),
            }
            for batch_id, values in sorted(batches.items())
        },
        "role_progress": {
            role: dict(values) for role, values in sorted(role_progress.items())
        },
        "evaluation_class_support_sealed": True,
        "human_reviewed_labels_created": 0,
        "import_ready": False,
    }


def _combined_gates(
    *,
    protocol: dict[str, Any] | None,
    v562_review: dict[str, Any],
    v563_review: dict[str, Any],
    v565_review: dict[str, Any],
) -> dict[str, Any]:
    def valid_count(review: dict[str, Any]) -> int:
        return max(0, int(review.get("valid_reviewed") or (int(review.get("reviewed") or 0) - int(review.get("invalid") or 0))))

    reviewed = valid_count(v562_review) + valid_count(v563_review) + valid_count(v565_review)
    supports = [
        v562_review.get("development_class_support") or {},
        v563_review.get("development_class_support") or {},
        v565_review.get("development_class_support") or {},
    ]
    benign_like = sum(int(support.get("benign_like") or 0) for support in supports)
    suspicious = sum(int(support.get("suspicious") or 0) for support in supports)
    malicious = sum(int(support.get("malicious") or 0) for support in supports)
    evidence = (protocol or {}).get("evidence") or {}

    def gate(observed: int, threshold: int) -> dict[str, Any]:
        return {
            "observed": observed,
            "threshold": threshold,
            "status": "pass" if observed >= threshold else "fail",
        }

    return {
        "independent_human_blind_labels": gate(
            reviewed, int(FIXED_QUALIFICATION_GATES["minimum_independent_human_blind_labels"])
        ),
        "independent_comparable_rows": gate(
            reviewed, int(FIXED_QUALIFICATION_GATES["minimum_independent_comparable_rows"])
        ),
        "benign_like_rows": gate(
            benign_like, int(FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"])
        ),
        "threat_positive_rows": gate(
            suspicious + malicious, int(FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"])
        ),
        "real_source_identities": gate(
            int(evidence.get("real_source_identities") or 0),
            int(FIXED_QUALIFICATION_GATES["minimum_real_source_identities"]),
        ),
        "independent_time_windows": gate(
            int(evidence.get("independent_time_windows") or 0),
            int(FIXED_QUALIFICATION_GATES["minimum_independent_time_windows"]),
        ),
        "untouched_evaluation_class_support": {
            "observed": None,
            "threshold": "all required classes measurable",
            "status": "blocked",
            "reason": "v562_evaluation_labels_sealed",
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


def _load_review_state(output_dir: Path) -> dict[str, Any]:
    path = _paths(output_dir)["review_state"]
    if not path.is_file():
        return {"schema_version": V565_VERSION, "batches": {}}
    state = _read_json(path)
    if state.get("schema_version") != V565_VERSION or not isinstance(
        state.get("batches"), dict
    ):
        raise V565ExpansionError("The v5.65 review state is invalid.")
    return state


def _public_protocol(protocol: dict[str, Any] | None) -> dict[str, Any]:
    if not protocol:
        return {
            "version": V565_PROTOCOL_VERSION,
            "locked": False,
            "valid": False,
            "append_only": True,
            "combined_prior_rows": EXPECTED_COMBINED_ROWS,
            "extended_rows": 0,
            "total_comparable_capacity": EXPECTED_COMBINED_ROWS,
            "batch_count": 0,
            "role_counts": {},
            "gates_unchanged": True,
            "evaluation_labels_sealed": True,
            "digests_exposed": False,
        }
    return {
        "version": protocol.get("schema_version"),
        "locked": True,
        "valid": True,
        "append_only": True,
        "combined_prior_rows": int((protocol.get("v563_reference") or {}).get("combined_rows") or 0),
        "extended_rows": int(protocol.get("extended_selected_rows") or 0),
        "total_comparable_capacity": int(protocol.get("total_comparable_capacity") or 0),
        "batch_count": len(protocol.get("batch_definitions") or []),
        "batch_definitions": [
            {
                "batch_id": item.get("batch_id"),
                "rows": int(item.get("rows") or 0),
                "role_counts": dict(item.get("role_counts") or {}),
                "immutable_after_close": True,
            }
            for item in protocol.get("batch_definitions") or []
        ],
        "role_counts": dict(protocol.get("role_counts") or {}),
        "gates_unchanged": protocol.get("fixed_qualification_gates") == FIXED_QUALIFICATION_GATES,
        "chronological": bool((protocol.get("partition") or {}).get("chronological")),
        "duplicate_group_isolation": bool(
            (protocol.get("partition") or {}).get("duplicate_group_isolation")
        ),
        "development_roles_only": True,
        "evaluation_labels_sealed": True,
        "coverage_group_weighting": dict(protocol.get("coverage_group_weighting") or {}),
        "digests_exposed": False,
    }


def _safety_projection() -> dict[str, Any]:
    return {
        "lifecycle_state": "shadow_observation",
        "supervised_state": "unqualified",
        "training_allowed": False,
        "training_executed": False,
        "evaluation_executed": False,
        "candidate_frozen": False,
        "activation_allowed": False,
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


def get_public_v565_status(
    output_dir: Path = V565_OUTPUT_DIR,
    *,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> dict[str, Any]:
    boundary_snapshot = _v563_boundary_snapshot(
        v563_output_dir, v562_output_dir=v562_output_dir, expected_combined_rows=None
    )
    v562_review = v562._review_progress(v562_output_dir)
    v563_review = v563._review_progress(v563_output_dir)
    paths = _paths(output_dir)
    if not paths["protocol"].is_file():
        v565_review = _review_progress(output_dir)
        return {
            "version": V565_VERSION,
            "status": "not_prepared",
            "v563_boundary": _v563_public_boundary(boundary_snapshot),
            "protocol": _public_protocol(None),
            "review": {
                "v562": v562_review,
                "v563": v563_review,
                "v565": v565_review,
                "combined_total": int(boundary_snapshot["combined_rows"]),
                "combined_reviewed": int(v562_review.get("reviewed") or 0)
                + int(v563_review.get("reviewed") or 0),
            },
            "qualification_gates": _combined_gates(
                protocol=None,
                v562_review=v562_review,
                v563_review=v563_review,
                v565_review=v565_review,
            ),
            "development_training_can_begin": False,
            **_safety_projection(),
        }
    protocol = validate_extended_protocol(
        output_dir,
        v563_output_dir=v563_output_dir,
        v562_output_dir=v562_output_dir,
        expected_combined_rows=int(boundary_snapshot["combined_rows"]),
    )
    v565_review = _review_progress(output_dir)
    state = _load_review_state(output_dir)
    batches_state = state.get("batches") or {}
    batch_progress = v565_review.get("batch_progress") or {}
    batches = []
    closed_count = 0
    for definition in protocol.get("batch_definitions") or []:
        batch_id = str(definition.get("batch_id") or "")
        batch_state = batches_state.get(batch_id) or {}
        progress = batch_progress.get(batch_id) or {}
        closed = bool(batch_state.get("closed_at"))
        closed_count += int(closed)
        batches.append(
            {
                "batch_id": batch_id,
                "total": int(progress.get("total") or definition.get("rows") or 0),
                "reviewed": int(progress.get("reviewed") or 0),
                "remaining": int(progress.get("remaining") or 0),
                "invalid": int(progress.get("invalid") or 0),
                "complete": bool(progress.get("complete")),
                "closed": closed,
                "owner_assigned": batch_state.get("owner_user_id") is not None,
            }
        )
    combined_reviewed = (
        int(v562_review.get("reviewed") or 0)
        + int(v563_review.get("reviewed") or 0)
        + int(v565_review.get("reviewed") or 0)
    )
    combined_total = int(protocol.get("total_comparable_capacity") or 0)
    status = (
        "extended_review_closed"
        if batches and closed_count == len(batches)
        else "extended_review_in_progress"
        if v565_review.get("reviewed")
        else "ready_for_extended_review"
    )
    evidence = protocol.get("evidence") or {}
    return {
        "version": V565_VERSION,
        "status": status,
        "v563_boundary": _v563_public_boundary(boundary_snapshot),
        "protocol": _public_protocol(protocol),
        "evidence": {
            "fresh_rows_available": int(evidence.get("fresh_rows_available") or 0),
            "combined_prior_rows_preserved": int(boundary_snapshot["combined_rows"]),
            "extended_rows_selected": int(protocol.get("extended_selected_rows") or 0),
            "total_comparable_capacity": combined_total,
            "real_source_identities": int(evidence.get("real_source_identities") or 0),
            "independent_time_windows": int(evidence.get("independent_time_windows") or 0),
            "second_source_present": False,
        },
        "review": {
            "v562": v562_review,
            "v563": v563_review,
            "v565": v565_review,
            "batches": batches,
            "closed_batch_count": closed_count,
            "batch_count": len(batches),
            "combined_total": combined_total,
            "combined_reviewed": combined_reviewed,
            "combined_remaining": max(0, combined_total - combined_reviewed),
            "evaluation_class_support_sealed": True,
        },
        "qualification_gates": _combined_gates(
            protocol=protocol,
            v562_review=v562_review,
            v563_review=v563_review,
            v565_review=v565_review,
        ),
        "development_training_can_begin": False,
        "development_blockers": [
            "complete_and_close_all_v562_v563_v565_review",
            "obtain_independent_second_physical_source",
            "preserve_sealed_future_evaluation",
        ],
        **_safety_projection(),
    }


def load_reviewed_combined_development_rows(
    output_dir: Path = V565_OUTPUT_DIR,
    *,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> list[dict[str, str]]:
    """Load reviewed development rows across v562+v563+v565; evaluation rows stay unreachable."""

    validate_extended_protocol(
        output_dir, v563_output_dir=v563_output_dir, v562_output_dir=v562_output_dir
    )
    state = _load_review_state(output_dir)
    batch_ids = {
        str(item.get("batch_id") or "")
        for item in validate_extended_protocol(
            output_dir, v563_output_dir=v563_output_dir, v562_output_dir=v562_output_dir
        ).get("batch_definitions")
        or []
    }
    if not batch_ids or any(
        not (state.get("batches") or {}).get(batch_id, {}).get("closed_at")
        for batch_id in batch_ids
    ):
        raise V565ExpansionError(
            "Extended development labels remain sealed until every batch closes."
        )
    extended, _ = v562._read_csv(_paths(output_dir)["working"])
    if not _review_progress(output_dir).get("complete"):
        raise V565ExpansionError("Extended development labels remain incomplete.")
    if any(
        str(row.get("evidence_role") or "") == v562.EVALUATION_ROLE_NAME
        for row in extended
    ):
        raise V565ExpansionError("Evaluation evidence entered development code.")
    combined = v563.load_reviewed_combined_development_rows(
        v563_output_dir, v562_output_dir=v562_output_dir
    )
    return [*combined, *extended]


def _safe_failure(status: str, *, stage: str, error_type: str) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V565_VERSION,
        "status": status,
        "failure_stage": stage,
        "error_type": error_type,
        "message": "The v5.65 operation failed closed without changing governed state.",
        **_safety_projection(),
    }


def _render_report(result: dict[str, Any]) -> str:
    evidence = result.get("evidence") or {}
    selection = result.get("selection") or {}
    return "\n".join(
        [
            "# v5.65 Extended Comparable Evidence Expansion",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Combined prior rows preserved: `{evidence.get('combined_prior_rows_preserved', 0)}`",
            f"- Extended rows selected: `{selection.get('selected_rows', 0)}`",
            f"- Total comparable capacity: `{evidence.get('total_comparable_capacity', 0)}`",
            f"- Review batches: `{selection.get('batch_count', 0)}`",
            f"- Coverage-group weighting: high-yield groups get "
            f"`{selection.get('coverage_group_round_robin_weight', 1)}x` round-robin share",
            f"- Real source identities: `{evidence.get('real_source_identities', 0)}`",
            "- Training executed: `False`",
            "- Evaluation executed: `False`",
            "- Model activated: `False`",
            "- Rules remain authoritative: `True`",
            "- Response mode: `simulation_only`",
            "",
            "This phase expands protected evidence; it does not qualify a model.",
            "",
        ]
    )


def run_v565_extended_evidence_expansion(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = True,
    prepare_extended_review: bool = False,
    confirmation: str | None = None,
    extended_limit: int = TARGET_EXTENDED_ROWS,
    batch_size: int = BATCH_SIZE,
    output_dir: Path = V565_OUTPUT_DIR,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    write_report: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    stage = "v563_boundary_validation"
    try:
        boundary = _v563_boundary_snapshot(
            v563_output_dir,
            v562_output_dir=v562_output_dir,
            expected_combined_rows=EXPECTED_COMBINED_ROWS,
        )
    except (V565ExpansionError, v563.V563ExpansionError, v562.V562CampaignError, OSError, ValueError) as exc:
        return _safe_failure(
            "failed_closed_v563_boundary", stage=stage, error_type=exc.__class__.__name__
        )
    available = bool(sample_path and Path(sample_path).is_file())
    if preflight_only and not prepare_extended_review:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        safe = bool(
            available and counts_before == counts_after and artifacts_before == artifacts_after
        )
        return {
            "ok": safe,
            "version": V565_VERSION,
            "status": "ready_for_explicit_expansion" if safe else "private_file_unavailable",
            "preflight_only": True,
            "v563_boundary": _v563_public_boundary(boundary),
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
    if not prepare_extended_review:
        return _safe_failure(
            "explicit_preparation_required", stage="preparation_gate", error_type="ConfirmationRequired"
        )
    if confirmation != PREPARE_CONFIRMATION:
        return _safe_failure(
            "confirmation_phrase_required", stage="preparation_gate", error_type="ConfirmationRequired"
        )
    if not available:
        return _safe_failure(
            "private_file_unavailable", stage="private_file_validation", error_type="FileNotFoundError"
        )
    if not use_temp_db:
        return _safe_failure(
            "temporary_storage_acknowledgement_required",
            stage="disposable_storage_gate",
            error_type="AcknowledgementRequired",
        )
    if int(extended_limit) < TARGET_EXTENDED_ROWS:
        return _safe_failure(
            "extended_capacity_below_fixed_target",
            stage="capacity_gate",
            error_type="QualificationGateViolation",
        )

    before_guard = {
        "protocol": boundary["protocol_file_digest"],
        "sealed": boundary["sealed_file_digest"],
        "protected": boundary["protected_digest"],
    }
    try:
        sample_path = Path(sample_path)
        sample_digest = v547._file_sha256(sample_path)
        if sample_digest != boundary["source_digest"]:
            raise V565ExpansionError(
                "The supplied source does not match the immutable v562/v563 source."
            )
        with tempfile.TemporaryDirectory(prefix="atdr-v565-") as directory:
            connection = sqlite3.connect(Path(directory) / "expansion.sqlite3")
            try:
                stage = "private_source_stream"
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path, connection, database_url=get_settings().database_url
                )
                if not profile.get("ok"):
                    raise V565ExpansionError("Private evidence parsing failed.")
                stage = "chronological_role_revalidation"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V565ExpansionError(
                        "Chronological evidence roles could not be revalidated."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                containment = v545._contain_candidate_near_families(connection)
                if not containment.get("passed"):
                    raise V565ExpansionError(
                        "Duplicate families cross predeclared evidence roles."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "consumed_evidence_revalidation"
                disposable_exclusion_dir = Path(directory) / "consumed"
                v562._install_consumed_exclusion(
                    connection, sample_digest=sample_digest, output_dir=disposable_exclusion_dir
                )
                v56.build_disposable_behavior_aggregates(connection)
                # v562's and v563's own tokens were computed sequentially -- v563's
                # coverage_group/aggregate features were derived only after v562's
                # families were quarantined and behavior aggregates were rebuilt.
                # Reconstructing v563's tokens correctly requires replaying that same
                # two-phase quarantine-then-reaggregate sequence, not a single flat
                # pass over the raw representative pool.
                stage = "v562_append_only_exclusion"
                representatives = v547._load_representatives(connection)
                consumed_families: set[str] = set()
                matched_tokens: set[str] = set()
                for row in representatives:
                    family = str(row.get("_candidate_family") or "")
                    if not family:
                        continue
                    v562_token = str(
                        v562._candidate_projection(row, family=family).get("review_token") or ""
                    )
                    if v562_token in boundary["v562_review_tokens"]:
                        consumed_families.add(family)
                        matched_tokens.add(v562_token)
                if matched_tokens != boundary["v562_review_tokens"]:
                    raise V565ExpansionError(
                        "The locked v562 evidence could not be reconstructed exactly."
                    )
                connection.execute(
                    "CREATE TEMP TABLE v565_v562_families (family TEXT PRIMARY KEY)"
                )
                connection.executemany(
                    "INSERT INTO v565_v562_families(family) VALUES (?)",
                    [(family,) for family in sorted(consumed_families)],
                )
                connection.execute(
                    "UPDATE events SET role_rank=4, "
                    "quarantine_reason='already_selected_v562_evidence' "
                    "WHERE candidate_near_hash IN "
                    "(SELECT family FROM v565_v562_families)"
                )
                connection.commit()
                v56.build_disposable_behavior_aggregates(connection)

                stage = "v563_append_only_exclusion"
                representatives = v547._load_representatives(connection)
                v563_matched_tokens: set[str] = set()
                for row in representatives:
                    family = str(row.get("_candidate_family") or "")
                    if not family:
                        continue
                    role_rank = v547._integer(row.get("role_rank"), 4)
                    role = v562.ROLE_NAMES.get(role_rank, "")
                    if role not in v562.DEVELOPMENT_ROLE_NAMES:
                        continue
                    v563_token = str(
                        v563._supplemental_projection(row, family=family).get("review_token") or ""
                    )
                    if v563_token in boundary["v563_review_tokens"]:
                        consumed_families.add(family)
                        v563_matched_tokens.add(v563_token)
                if v563_matched_tokens != boundary["v563_review_tokens"]:
                    raise V565ExpansionError(
                        "The locked v563 evidence could not be reconstructed exactly."
                    )
                connection.execute(
                    "CREATE TEMP TABLE v565_consumed_families (family TEXT PRIMARY KEY)"
                )
                connection.executemany(
                    "INSERT INTO v565_consumed_families(family) VALUES (?)",
                    [(family,) for family in sorted(consumed_families)],
                )
                connection.execute(
                    "UPDATE events SET role_rank=4, "
                    "quarantine_reason='already_selected_v562_or_v563_evidence' "
                    "WHERE candidate_near_hash IN "
                    "(SELECT family FROM v565_consumed_families)"
                )
                connection.commit()
                v56.build_disposable_behavior_aggregates(connection)
                stage = "extended_prediction_blind_selection"
                representatives = v547._load_representatives(connection)
                candidates, selection, selected_families = select_extended_review_candidates(
                    representatives,
                    consumed_review_tokens=boundary["combined_review_tokens"],
                    limit=extended_limit,
                    batch_size=batch_size,
                    combined_role_counts=boundary["combined_role_counts"],
                )
                fresh_rows = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM events WHERE role_rank < 3 AND quarantine_reason IS NULL"
                    ).fetchone()[0]
                )
                selection["fresh_rows_available"] = fresh_rows
                primary_source_tokens = _source_identity_tokens(connection)
                if not primary_source_tokens:
                    raise V565ExpansionError(
                        "The primary source has no verifiable device identity."
                    )
                stage = "v563_mutation_guard"
                after_guard = _v563_boundary_snapshot(
                    v563_output_dir,
                    v562_output_dir=v562_output_dir,
                    expected_combined_rows=EXPECTED_COMBINED_ROWS,
                )
                if before_guard != {
                    "protocol": after_guard["protocol_file_digest"],
                    "sealed": after_guard["sealed_file_digest"],
                    "protected": after_guard["protected_digest"],
                }:
                    raise V565ExpansionError(
                        "The locked v562+v563 protected pack changed during preparation."
                    )
                stage = "append_only_protocol_lock"
                workspace = _prepare_workspace(
                    candidates,
                    selection=selection,
                    selected_families=selected_families,
                    consumed_families=consumed_families,
                    v563_snapshot=boundary,
                    source_digest=sample_digest,
                    primary_source_tokens=primary_source_tokens,
                    profile=profile,
                    roles=roles,
                    output_dir=output_dir,
                    v563_output_dir=v563_output_dir,
                    v562_output_dir=v562_output_dir,
                )
            finally:
                connection.close()
    except (
        V565ExpansionError,
        v563.V563ExpansionError,
        v562.V562CampaignError,
        v547.V547AcquisitionError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _safe_failure(
            "failed_closed_expansion_preparation", stage=stage, error_type=exc.__class__.__name__
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    deltas = {key: int(counts_after[key]) - int(counts_before[key]) for key in counts_before}
    safety_passed = bool(
        counts_before == counts_after
        and artifacts_before == artifacts_after
        and all(value == 0 for value in deltas.values())
    )
    protocol = validate_extended_protocol(
        output_dir,
        v563_output_dir=v563_output_dir,
        v562_output_dir=v562_output_dir,
        expected_combined_rows=EXPECTED_COMBINED_ROWS,
    )
    public_status = get_public_v565_status(
        output_dir, v563_output_dir=v563_output_dir, v562_output_dir=v562_output_dir
    )
    evidence = {
        "source_rows": int(profile.get("rows_processed") or 0),
        "parser_success_rows": int(profile.get("parser_successes") or 0),
        "parser_failure_rows": int(profile.get("parser_failures") or 0),
        "fresh_rows_available": int(selection.get("fresh_rows_available") or 0),
        "combined_prior_rows_preserved": EXPECTED_COMBINED_ROWS,
        "extended_rows_selected": int(selection.get("selected_rows") or 0),
        "total_comparable_capacity": int(protocol.get("total_comparable_capacity") or 0),
        "real_source_identities": len(primary_source_tokens),
        "independent_time_windows": int(roles.get("distinct_time_windows") or 0),
        "second_source_present": False,
    }
    result = {
        "ok": bool(
            safety_passed and selection.get("selection_gate_passed") and workspace.get("append_only")
        ),
        "version": V565_VERSION,
        "status": (
            "ready_for_batched_human_review"
            if safety_passed and selection.get("selection_gate_passed")
            else "expansion_evidence_incomplete"
        ),
        "generated_at": _now(),
        "preflight_only": False,
        "v563_boundary": _v563_public_boundary(boundary),
        "protocol": _public_protocol(protocol),
        "evidence": evidence,
        "selection": selection,
        "workspace": workspace,
        "review": public_status.get("review"),
        "qualification_gates": public_status.get("qualification_gates"),
        "authoritative_mutations": deltas,
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        **_safety_projection(),
    }
    if write_report:
        _atomic_write_json(_paths(output_dir)["latest"], result)
        (output_dir / f"{V565_REPORT_PREFIX}_{_stamp()}.md").write_text(
            _render_report(result), encoding="utf-8"
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
