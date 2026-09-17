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


V563_VERSION = "v5.63-fresh-comparable-evidence-expansion-v1"
V563_PROTOCOL_VERSION = "v5.63-append-only-evidence-protocol-v1"
V563_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_63_evidence_expansion"
V563_LATEST = "v5_63_fresh_evidence_expansion_latest.json"
V563_PROTOCOL_LOCK = "v5_63_append_only_protocol.json"
V563_SEALED_PACK = "v5_63_supplemental_review_pack.csv"
V563_WORKING_COPY = "v5_63_supplemental_review_working.csv"
V563_REVIEW_STATE = "v5_63_supplemental_review_state.json"
V563_EXCLUSION_MANIFEST = "v5_63_append_only_exclusion.json"
V563_SOURCE_CUSTODY = "v5_63_primary_source_custody.json"
V563_REPORT_PREFIX = "v5_63_fresh_evidence_expansion"

PREPARE_CONFIRMATION = "PREPARE_V563_FRESH_EVIDENCE_EXPANSION"
TARGET_SUPPLEMENTAL_ROWS = 700
BATCH_SIZE = 100
EXPECTED_V562_ROWS = 300
DEVELOPMENT_ROLES = tuple(sorted(v562.DEVELOPMENT_ROLE_NAMES))
FIXED_QUALIFICATION_GATES = dict(v562.FIXED_QUALIFICATION_GATES)


class V563ExpansionError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _paths(output_dir: Path = V563_OUTPUT_DIR) -> dict[str, Path]:
    output_dir = Path(output_dir)
    return {
        "output_dir": output_dir,
        "latest": output_dir / V563_LATEST,
        "protocol": output_dir / V563_PROTOCOL_LOCK,
        "sealed": output_dir / V563_SEALED_PACK,
        "working": output_dir / V563_WORKING_COPY,
        "review_state": output_dir / V563_REVIEW_STATE,
        "exclusion": output_dir / V563_EXCLUSION_MANIFEST,
        "source_custody": output_dir / V563_SOURCE_CUSTODY,
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
        raise V563ExpansionError(
            "A protected v5.63 record failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V563ExpansionError(
            "A protected v5.63 record failed integrity validation."
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


def _v562_snapshot(
    output_dir: Path = v562.V562_OUTPUT_DIR,
    *,
    expected_rows: int | None = EXPECTED_V562_ROWS,
) -> dict[str, Any]:
    protocol = v562.validate_campaign_protocol(output_dir)
    paths = v562._workspace_paths(output_dir)
    sealed_rows, sealed_columns = v562._read_csv(paths["sealed"])
    working_rows, working_columns = v562._read_csv(paths["working"])
    v562._assert_pack_contract(sealed_rows, sealed_columns, sealed=True)
    v562._assert_pack_contract(working_rows, working_columns, sealed=False)
    selected_rows = int(protocol.get("selected_rows") or 0)
    if expected_rows is not None and selected_rows != expected_rows:
        raise V563ExpansionError(
            "The original v5.62 row count no longer matches its locked boundary."
        )
    sealed_tokens = [str(row.get("review_token") or "") for row in sealed_rows]
    working_tokens = [str(row.get("review_token") or "") for row in working_rows]
    sealed_roles = {
        str(row.get("review_token") or ""): str(row.get("evidence_role") or "")
        for row in sealed_rows
    }
    working_roles = {
        str(row.get("review_token") or ""): str(row.get("evidence_role") or "")
        for row in working_rows
    }
    protected_digest = str(protocol.get("protected_digest") or "")
    if not (
        selected_rows == len(sealed_rows) == len(working_rows)
        and sealed_columns == working_columns
        and sealed_tokens == working_tokens
        and sealed_roles == working_roles
        and protected_digest
        == v562._protected_digest(sealed_rows, sealed_columns)
        == v562._protected_digest(working_rows, working_columns)
        and protocol.get("fixed_qualification_gates")
        == FIXED_QUALIFICATION_GATES
        and (protocol.get("partition") or {}).get("future_evaluation_labels_sealed")
        is True
    ):
        raise V563ExpansionError(
            "The original v5.62 protected evidence changed unexpectedly."
        )
    return {
        "protocol": protocol,
        "selected_rows": selected_rows,
        "review_tokens": set(sealed_tokens),
        "token_roles": sealed_roles,
        "protected_digest": protected_digest,
        "protocol_file_digest": v547._file_sha256(paths["protocol"]),
        "sealed_file_digest": v547._file_sha256(paths["sealed"]),
        "source_digest": str(protocol.get("source_digest") or ""),
        "evaluation_rows": sum(
            role == v562.EVALUATION_ROLE_NAME for role in sealed_roles.values()
        ),
        "roles_unchanged": sealed_roles == working_roles,
        "decisions_openable_by_v563": False,
    }


def _v562_public_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_valid": True,
        "selected_rows": int(snapshot.get("selected_rows") or 0),
        "roles_unchanged": bool(snapshot.get("roles_unchanged")),
        "future_evaluation_rows_sealed": int(snapshot.get("evaluation_rows") or 0),
        "consumed_exclusion_locked": True,
        "digests_exposed": False,
        "review_tokens_exposed": False,
        "decisions_accessed": False,
    }


def _role_targets(limit: int) -> dict[str, int]:
    original_development_counts = {
        "development_fit": 150,
        "calibration": 60,
        "threshold_selection": 45,
    }
    denominator = sum(original_development_counts.values())
    targets = {
        role: int(round(limit * count / denominator))
        for role, count in original_development_counts.items()
    }
    targets["development_fit"] += limit - sum(targets.values())
    return targets


def _supplemental_projection(
    row: dict[str, Any],
    *,
    family: str,
) -> dict[str, Any]:
    base = v562._candidate_projection(row, family=family)
    role = str(base.get("evidence_role") or "")
    if role not in v562.DEVELOPMENT_ROLE_NAMES:
        raise V563ExpansionError(
            "Supplemental evidence must remain in a development-safe role."
        )
    base["review_token"] = v547._stable_hash(
        {
            "version": V563_VERSION,
            "family": family,
            "coverage_group": base.get("coverage_group"),
            "role": role,
        }
    )[:24]
    base["review_batch_id"] = ""
    base["_family"] = family
    return base


def select_supplemental_review_candidates(
    rows: Iterable[dict[str, Any]],
    *,
    original_review_tokens: set[str],
    limit: int = TARGET_SUPPLEMENTAL_ROWS,
    batch_size: int = BATCH_SIZE,
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
        v562_token = str(
            v562._candidate_projection(row, family=family).get("review_token") or ""
        )
        if v562_token in original_review_tokens:
            excluded["selected_v562_evidence"] += 1
            seen_families.add(family)
            continue
        candidate = _supplemental_projection(row, family=family)
        candidate["_selection_key"] = v547._stable_hash(
            {
                "version": V563_VERSION,
                "role": role,
                "coverage": candidate.get("coverage_group"),
                "token": candidate.get("review_token"),
            }
        )
        buckets[role][str(candidate.get("coverage_group") or "other")].append(
            candidate
        )
        seen_families.add(family)
        eligible_unique += 1

    for role_buckets in buckets.values():
        for values in role_buckets.values():
            values.sort(key=lambda item: str(item["_selection_key"]))

    targets = _role_targets(limit)
    selected: list[dict[str, Any]] = []
    selected_tokens: set[str] = set()
    for role in DEVELOPMENT_ROLES:
        role_selected: list[dict[str, Any]] = []
        groups = sorted(buckets.get(role, {}))
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
    minimum_required = min(TARGET_SUPPLEMENTAL_ROWS, limit)
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
        "batch_size": batch_size,
        "batch_count": len(batch_counts),
        "batch_counts": dict(sorted(batch_counts.items())),
        "selection_gate_passed": selection_gate,
        "duplicate_families_contained": len(selected_families) == len(selected),
        "original_pack_overlap_count": int(
            excluded.get("selected_v562_evidence", 0)
        ),
        "future_evaluation_rows_selected": 0,
        "exclusion_reasons": dict(sorted(excluded.items())),
        "predictions_used_for_selection": False,
        "model_scores_used_for_selection": False,
        "rules_used_as_labels": False,
        "assisted_labels_used_for_selection": False,
    }, selected_families


def _assert_supplemental_pack(
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    sealed: bool,
) -> None:
    v562._assert_pack_contract(rows, columns, sealed=sealed)
    if "review_batch_id" not in columns:
        raise V563ExpansionError("The supplemental pack has no review batch.")
    for row in rows:
        if str(row.get("evidence_role") or "") not in v562.DEVELOPMENT_ROLE_NAMES:
            raise V563ExpansionError(
                "The supplemental pack contains non-development evidence."
            )
        batch_id = str(row.get("review_batch_id") or "")
        if not batch_id.startswith("batch-"):
            raise V563ExpansionError(
                "The supplemental pack contains an invalid review batch."
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
    original_families: set[str],
    v562_snapshot: dict[str, Any],
    source_digest: str,
    primary_source_tokens: set[str],
    profile: dict[str, Any],
    roles: dict[str, Any],
    output_dir: Path = V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> dict[str, Any]:
    if not rows:
        raise V563ExpansionError("No supplemental rows were selected.")
    paths = _paths(output_dir)
    columns = list(rows[0])
    _assert_supplemental_pack(rows, columns, sealed=True)
    protected_digest = v562._protected_digest(rows, columns)
    present = [
        paths[name].is_file()
        for name in ("protocol", "sealed", "working", "exclusion", "source_custody")
    ]
    if any(present) and not all(present):
        raise V563ExpansionError(
            "An incomplete v5.63 protected workspace already exists."
        )

    exclusion = {
        "schema_version": V563_VERSION,
        "created_at": _now(),
        "v562_selected_families": sorted(original_families),
        "v563_selected_families": sorted(selected_families),
        "counts": {
            "v562_selected_families": len(original_families),
            "v563_selected_families": len(selected_families),
            "family_overlap": len(original_families & selected_families),
        },
        "private": True,
        "fingerprints_exposed": False,
    }
    custody = {
        "schema_version": V563_VERSION,
        "created_at": _now(),
        "primary_source_digest": source_digest,
        "primary_device_tokens": sorted(primary_source_tokens),
        "identified_source_count": len(primary_source_tokens),
        "private": True,
        "identity_tokens_exposed": False,
        "digest_exposed": False,
    }
    protocol = {
        "schema_version": V563_PROTOCOL_VERSION,
        "campaign_version": V563_VERSION,
        "created_at": _now(),
        "source_digest": source_digest,
        "protected_digest": protected_digest,
        "sealed_pack_digest": "",
        "exclusion_manifest_digest": "",
        "source_custody_digest": "",
        "append_only": True,
        "v562_reference": {
            "protocol_file_digest": v562_snapshot["protocol_file_digest"],
            "sealed_file_digest": v562_snapshot["sealed_file_digest"],
            "protected_digest": v562_snapshot["protected_digest"],
            "source_digest": v562_snapshot["source_digest"],
            "selected_rows": int(v562_snapshot["selected_rows"]),
            "future_evaluation_rows": int(v562_snapshot["evaluation_rows"]),
            "roles_unchanged": True,
            "decisions_accessed": False,
        },
        "supplemental_selected_rows": len(rows),
        "total_comparable_capacity": int(v562_snapshot["selected_rows"])
        + len(rows),
        "role_counts": dict(selection.get("role_counts") or {}),
        "batch_definitions": _batch_definitions(rows),
        "fixed_qualification_gates": FIXED_QUALIFICATION_GATES,
        "locked_candidate_strategies": list(v562.LOCKED_CANDIDATE_STRATEGIES),
        "locked_feature_schema": list(v562.LOCKED_FEATURE_SCHEMA),
        "partition": {
            "chronological": True,
            "duplicate_group_isolation": True,
            "roles_assigned_before_labels": True,
            "append_only": True,
            "rows_movable_after_label_opening": False,
            "supplemental_development_roles_only": True,
            "v562_future_evaluation_labels_sealed": True,
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
        protocol["exclusion_manifest_digest"] = v547._file_sha256(
            paths["exclusion"]
        )
        protocol["source_custody_digest"] = v547._file_sha256(
            paths["source_custody"]
        )
        _atomic_write_json(paths["protocol"], protocol)
    else:
        existing = validate_expansion_protocol(
            output_dir,
            v562_output_dir=v562_output_dir,
            expected_original_rows=int(v562_snapshot["selected_rows"]),
        )
        if not (
            existing.get("protected_digest") == protected_digest
            and existing.get("source_digest") == source_digest
            and int(existing.get("supplemental_selected_rows") or 0) == len(rows)
        ):
            raise V563ExpansionError(
                "A different immutable v5.63 expansion already exists."
            )
        protocol = existing
    return {
        "created": created,
        "protocol_locked": True,
        "append_only": True,
        "supplemental_selected_rows": len(rows),
        "total_comparable_capacity": int(protocol["total_comparable_capacity"]),
        "batch_count": len(protocol.get("batch_definitions") or []),
        "review": _review_progress(output_dir),
    }


def validate_expansion_protocol(
    output_dir: Path = V563_OUTPUT_DIR,
    *,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    expected_original_rows: int | None = None,
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
        raise V563ExpansionError("The v5.63 expansion is not prepared.")
    protocol = _read_json(paths["protocol"])
    sealed_rows, sealed_columns = v562._read_csv(paths["sealed"])
    working_rows, working_columns = v562._read_csv(paths["working"])
    _assert_supplemental_pack(sealed_rows, sealed_columns, sealed=True)
    _assert_supplemental_pack(working_rows, working_columns, sealed=False)
    original_rows = int(
        ((protocol.get("v562_reference") or {}).get("selected_rows")) or 0
    )
    snapshot = _v562_snapshot(
        v562_output_dir,
        expected_rows=(
            expected_original_rows
            if expected_original_rows is not None
            else original_rows
        ),
    )
    reference = protocol.get("v562_reference") or {}
    exclusion = _read_json(paths["exclusion"])
    custody = _read_json(paths["source_custody"])
    definitions = _batch_definitions(sealed_rows)
    if not (
        protocol.get("schema_version") == V563_PROTOCOL_VERSION
        and protocol.get("campaign_version") == V563_VERSION
        and protocol.get("append_only") is True
        and protocol.get("fixed_qualification_gates")
        == FIXED_QUALIFICATION_GATES
        and tuple(protocol.get("locked_candidate_strategies") or ())
        == v562.LOCKED_CANDIDATE_STRATEGIES
        and tuple(protocol.get("locked_feature_schema") or ())
        == v562.LOCKED_FEATURE_SCHEMA
        and sealed_columns == working_columns
        and len(sealed_rows) == len(working_rows)
        == int(protocol.get("supplemental_selected_rows") or 0)
        and protocol.get("protected_digest")
        == v562._protected_digest(sealed_rows, sealed_columns)
        == v562._protected_digest(working_rows, working_columns)
        and protocol.get("sealed_pack_digest")
        == v547._file_sha256(paths["sealed"])
        and protocol.get("exclusion_manifest_digest")
        == v547._file_sha256(paths["exclusion"])
        and protocol.get("source_custody_digest")
        == v547._file_sha256(paths["source_custody"])
        and reference.get("protocol_file_digest")
        == snapshot["protocol_file_digest"]
        and reference.get("sealed_file_digest") == snapshot["sealed_file_digest"]
        and reference.get("protected_digest") == snapshot["protected_digest"]
        and reference.get("source_digest") == snapshot["source_digest"]
        and reference.get("roles_unchanged") is True
        and reference.get("decisions_accessed") is False
        and protocol.get("source_digest") == custody.get("primary_source_digest")
        and protocol.get("batch_definitions") == definitions
        and int(protocol.get("total_comparable_capacity") or 0)
        == original_rows + len(sealed_rows)
        and (exclusion.get("counts") or {}).get("family_overlap") == 0
        and (protocol.get("partition") or {}).get(
            "v562_future_evaluation_labels_sealed"
        )
        is True
        and protocol.get("evaluation_labels_accessible") is False
        and protocol.get("training_allowed") is False
        and protocol.get("activation_allowed") is False
    ):
        raise V563ExpansionError(
            "The immutable v5.63 expansion failed integrity validation."
        )
    return protocol


def _review_progress(output_dir: Path = V563_OUTPUT_DIR) -> dict[str, Any]:
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
    _assert_supplemental_pack(rows, columns, sealed=False)
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
    original_review: dict[str, Any],
    supplemental_review: dict[str, Any],
) -> dict[str, Any]:
    original_valid = int(original_review.get("reviewed") or 0) - int(
        original_review.get("invalid") or 0
    )
    supplemental_valid = int(supplemental_review.get("valid_reviewed") or 0)
    reviewed = max(0, original_valid) + max(0, supplemental_valid)
    original_support = original_review.get("development_class_support") or {}
    supplemental_support = supplemental_review.get("development_class_support") or {}
    benign_like = int(original_support.get("benign_like") or 0) + int(
        supplemental_support.get("benign_like") or 0
    )
    suspicious = int(original_support.get("suspicious") or 0) + int(
        supplemental_support.get("suspicious") or 0
    )
    malicious = int(original_support.get("malicious") or 0) + int(
        supplemental_support.get("malicious") or 0
    )
    evidence = (protocol or {}).get("evidence") or {}

    def gate(observed: int, threshold: int) -> dict[str, Any]:
        return {
            "observed": observed,
            "threshold": threshold,
            "status": "pass" if observed >= threshold else "fail",
        }

    return {
        "independent_human_blind_labels": gate(
            reviewed,
            int(FIXED_QUALIFICATION_GATES["minimum_independent_human_blind_labels"]),
        ),
        "independent_comparable_rows": gate(
            reviewed,
            int(FIXED_QUALIFICATION_GATES["minimum_independent_comparable_rows"]),
        ),
        "benign_like_rows": gate(
            benign_like,
            int(FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"]),
        ),
        "threat_positive_rows": gate(
            suspicious + malicious,
            int(FIXED_QUALIFICATION_GATES["minimum_rows_per_binary_class"]),
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
        return {"schema_version": V563_VERSION, "batches": {}}
    state = _read_json(path)
    if state.get("schema_version") != V563_VERSION or not isinstance(
        state.get("batches"), dict
    ):
        raise V563ExpansionError("The v5.63 review state is invalid.")
    return state


def _public_protocol(protocol: dict[str, Any] | None) -> dict[str, Any]:
    if not protocol:
        return {
            "version": V563_PROTOCOL_VERSION,
            "locked": False,
            "valid": False,
            "append_only": True,
            "original_rows": EXPECTED_V562_ROWS,
            "supplemental_rows": 0,
            "total_comparable_capacity": EXPECTED_V562_ROWS,
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
        "original_rows": int(
            ((protocol.get("v562_reference") or {}).get("selected_rows")) or 0
        ),
        "supplemental_rows": int(protocol.get("supplemental_selected_rows") or 0),
        "total_comparable_capacity": int(
            protocol.get("total_comparable_capacity") or 0
        ),
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
        "gates_unchanged": protocol.get("fixed_qualification_gates")
        == FIXED_QUALIFICATION_GATES,
        "chronological": bool((protocol.get("partition") or {}).get("chronological")),
        "duplicate_group_isolation": bool(
            (protocol.get("partition") or {}).get("duplicate_group_isolation")
        ),
        "development_roles_only": True,
        "evaluation_labels_sealed": True,
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


def get_public_v563_status(
    output_dir: Path = V563_OUTPUT_DIR,
    *,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> dict[str, Any]:
    original_snapshot = _v562_snapshot(v562_output_dir, expected_rows=None)
    original_review = v562._review_progress(v562_output_dir)
    paths = _paths(output_dir)
    if not paths["protocol"].is_file():
        supplemental_review = _review_progress(output_dir)
        return {
            "version": V563_VERSION,
            "status": "not_prepared",
            "v562_boundary": _v562_public_snapshot(original_snapshot),
            "protocol": _public_protocol(None),
            "review": {
                "original": original_review,
                "supplemental": supplemental_review,
                "combined_total": int(original_snapshot["selected_rows"]),
                "combined_reviewed": int(original_review.get("reviewed") or 0),
                "combined_remaining": int(original_review.get("remaining") or 0),
            },
            "qualification_gates": _combined_gates(
                protocol=None,
                original_review=original_review,
                supplemental_review=supplemental_review,
            ),
            "second_source_intake": {
                "preflight_ready": False,
                "independent_source_added": False,
                "source_gate_updated": False,
            },
            "development_training_can_begin": False,
            **_safety_projection(),
        }
    protocol = validate_expansion_protocol(
        output_dir,
        v562_output_dir=v562_output_dir,
        expected_original_rows=int(original_snapshot["selected_rows"]),
    )
    supplemental_review = _review_progress(output_dir)
    state = _load_review_state(output_dir)
    batches_state = state.get("batches") or {}
    batch_progress = supplemental_review.get("batch_progress") or {}
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
    combined_reviewed = int(original_review.get("reviewed") or 0) + int(
        supplemental_review.get("reviewed") or 0
    )
    combined_total = int(protocol.get("total_comparable_capacity") or 0)
    status = (
        "supplemental_review_closed"
        if batches and closed_count == len(batches)
        else "supplemental_review_in_progress"
        if supplemental_review.get("reviewed")
        else "ready_for_supplemental_review"
    )
    evidence = protocol.get("evidence") or {}
    return {
        "version": V563_VERSION,
        "status": status,
        "v562_boundary": _v562_public_snapshot(original_snapshot),
        "protocol": _public_protocol(protocol),
        "evidence": {
            "fresh_rows_available": int(evidence.get("fresh_rows_available") or 0),
            "original_rows_preserved": int(original_snapshot["selected_rows"]),
            "supplemental_rows_selected": int(
                protocol.get("supplemental_selected_rows") or 0
            ),
            "total_comparable_capacity": combined_total,
            "real_source_identities": int(
                evidence.get("real_source_identities") or 0
            ),
            "independent_time_windows": int(
                evidence.get("independent_time_windows") or 0
            ),
            "second_source_present": False,
            "future_evaluation_rows_added": 0,
        },
        "review": {
            "original": original_review,
            "supplemental": supplemental_review,
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
            original_review=original_review,
            supplemental_review=supplemental_review,
        ),
        "second_source_intake": {
            "preflight_ready": paths["source_custody"].is_file(),
            "independent_source_added": False,
            "source_gate_updated": False,
            "future_path_cli_only": True,
        },
        "development_training_can_begin": False,
        "development_blockers": [
            "complete_and_close_original_review",
            "complete_and_close_all_supplemental_batches",
            "obtain_independent_second_physical_source",
            "preserve_sealed_future_evaluation",
        ],
        **_safety_projection(),
    }


def load_reviewed_combined_development_rows(
    output_dir: Path = V563_OUTPUT_DIR,
    *,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> list[dict[str, str]]:
    """Load reviewed development rows only; evaluation rows remain unreachable."""

    validate_expansion_protocol(
        output_dir,
        v562_output_dir=v562_output_dir,
    )
    state = _load_review_state(output_dir)
    batch_ids = {
        str(item.get("batch_id") or "")
        for item in validate_expansion_protocol(
            output_dir,
            v562_output_dir=v562_output_dir,
        ).get("batch_definitions")
        or []
    }
    if not batch_ids or any(
        not (state.get("batches") or {}).get(batch_id, {}).get("closed_at")
        for batch_id in batch_ids
    ):
        raise V563ExpansionError(
            "Supplemental development labels remain sealed until every batch closes."
        )
    supplemental, _ = v562._read_csv(_paths(output_dir)["working"])
    if not _review_progress(output_dir).get("complete"):
        raise V563ExpansionError(
            "Supplemental development labels remain incomplete."
        )
    if any(
        str(row.get("evidence_role") or "") == v562.EVALUATION_ROLE_NAME
        for row in supplemental
    ):
        raise V563ExpansionError("Evaluation evidence entered development code.")
    original = v562.load_reviewed_development_rows(v562_output_dir)
    return [*original, *supplemental]


def run_second_source_intake_preflight(
    db: Session,
    *,
    second_source_path: Path | None,
    use_temp_db: bool,
    output_dir: Path = V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
) -> dict[str, Any]:
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    try:
        validate_expansion_protocol(
            output_dir,
            v562_output_dir=v562_output_dir,
        )
        paths = _paths(output_dir)
        custody = _read_json(paths["source_custody"])
        primary_tokens = set(custody.get("primary_device_tokens") or [])
        available = bool(second_source_path and Path(second_source_path).is_file())
        if not use_temp_db:
            raise V563ExpansionError(
                "Disposable storage acknowledgement is required."
            )
        if not available:
            raise V563ExpansionError("The candidate second source is unavailable.")
        with tempfile.TemporaryDirectory(prefix="atdr-v563-source-") as directory:
            connection = sqlite3.connect(Path(directory) / "source.sqlite3")
            try:
                profile = v56.stream_private_file_to_disposable_index(
                    Path(second_source_path),
                    connection,
                    database_url=None,
                )
                candidate_tokens = _source_identity_tokens(connection)
            finally:
                connection.close()
        candidate_digest = v547._file_sha256(Path(second_source_path))
        new_tokens = candidate_tokens - primary_tokens
        overlap_tokens = candidate_tokens & primary_tokens
        independent = bool(
            profile.get("ok")
            and candidate_tokens
            and new_tokens
            and candidate_digest != custody.get("primary_source_digest")
        )
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        result = {
            "ok": bool(
                independent
                and counts_before == counts_after
                and artifacts_before == artifacts_after
            ),
            "version": V563_VERSION,
            "status": (
                "independent_second_source_candidate"
                if independent
                else "failed_closed_not_independent"
            ),
            "preflight_only": True,
            "candidate": {
                "available": True,
                "rows_processed": int(profile.get("rows_processed") or 0),
                "parser_success_rows": int(profile.get("parser_successes") or 0),
                "parser_failure_rows": int(profile.get("parser_failures") or 0),
                "identified_source_count": len(candidate_tokens),
                "new_source_identity_count": len(new_tokens),
                "overlapping_source_identity_count": len(overlap_tokens),
                "independent_from_primary": independent,
                "path_returned": False,
                "file_name_returned": False,
                "identity_tokens_returned": False,
                "digest_returned": False,
            },
            "candidate_added_to_campaign": False,
            "source_gate_updated": False,
            "configured_database_counts_unchanged": counts_before == counts_after,
            "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
            **_safety_projection(),
        }
    except (V563ExpansionError, v562.V562CampaignError, OSError, sqlite3.Error) as exc:
        result = _safe_failure(
            "failed_closed_second_source_preflight",
            stage="second_source_independence",
            error_type=exc.__class__.__name__,
        )
        result.update(
            {
                "preflight_only": True,
                "candidate_added_to_campaign": False,
                "source_gate_updated": False,
            }
        )
    encoded = json.dumps(result, default=str)
    if second_source_path and (
        str(second_source_path) in encoded or Path(second_source_path).name in encoded
    ):
        return _safe_failure(
            "public_output_redaction_failed",
            stage="second_source_redaction",
            error_type="PrivatePathExposure",
        )
    return result


def _safe_failure(status: str, *, stage: str, error_type: str) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V563_VERSION,
        "status": status,
        "failure_stage": stage,
        "error_type": error_type,
        "message": "The v5.63 operation failed closed without changing governed state.",
        **_safety_projection(),
    }


def _render_report(result: dict[str, Any]) -> str:
    evidence = result.get("evidence") or {}
    selection = result.get("selection") or {}
    return "\n".join(
        [
            "# v5.63 Fresh Comparable Evidence Expansion",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Original rows preserved: `{evidence.get('original_rows_preserved', 0)}`",
            f"- Supplemental rows selected: `{selection.get('selected_rows', 0)}`",
            f"- Total comparable capacity: `{evidence.get('total_comparable_capacity', 0)}`",
            f"- Review batches: `{selection.get('batch_count', 0)}`",
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


def run_v563_fresh_evidence_expansion(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = True,
    prepare_supplemental_review: bool = False,
    confirmation: str | None = None,
    supplemental_limit: int = TARGET_SUPPLEMENTAL_ROWS,
    batch_size: int = BATCH_SIZE,
    output_dir: Path = V563_OUTPUT_DIR,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    write_report: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    stage = "v562_boundary_validation"
    try:
        original = _v562_snapshot(
            v562_output_dir,
            expected_rows=EXPECTED_V562_ROWS,
        )
    except (V563ExpansionError, v562.V562CampaignError, OSError, ValueError) as exc:
        return _safe_failure(
            "failed_closed_v562_boundary",
            stage=stage,
            error_type=exc.__class__.__name__,
        )
    available = bool(sample_path and Path(sample_path).is_file())
    if preflight_only and not prepare_supplemental_review:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        safe = bool(
            available
            and counts_before == counts_after
            and artifacts_before == artifacts_after
        )
        return {
            "ok": safe,
            "version": V563_VERSION,
            "status": (
                "ready_for_explicit_expansion"
                if safe
                else "private_file_unavailable"
            ),
            "preflight_only": True,
            "v562_boundary": _v562_public_snapshot(original),
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
    if not prepare_supplemental_review:
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
    if int(supplemental_limit) < TARGET_SUPPLEMENTAL_ROWS:
        return _safe_failure(
            "supplemental_capacity_below_fixed_target",
            stage="capacity_gate",
            error_type="QualificationGateViolation",
        )

    before_guard = {
        "protocol": original["protocol_file_digest"],
        "sealed": original["sealed_file_digest"],
        "protected": original["protected_digest"],
    }
    try:
        sample_path = Path(sample_path)
        sample_digest = v547._file_sha256(sample_path)
        if sample_digest != original["source_digest"]:
            raise V563ExpansionError(
                "The supplied source does not match the immutable v5.62 source."
            )
        with tempfile.TemporaryDirectory(prefix="atdr-v563-") as directory:
            connection = sqlite3.connect(Path(directory) / "expansion.sqlite3")
            try:
                stage = "private_source_stream"
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile.get("ok"):
                    raise V563ExpansionError("Private evidence parsing failed.")
                stage = "chronological_role_revalidation"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V563ExpansionError(
                        "Chronological evidence roles could not be revalidated."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                containment = v545._contain_candidate_near_families(connection)
                if not containment.get("passed"):
                    raise V563ExpansionError(
                        "Duplicate families cross predeclared evidence roles."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "consumed_evidence_revalidation"
                disposable_exclusion_dir = Path(directory) / "consumed"
                v562._install_consumed_exclusion(
                    connection,
                    sample_digest=sample_digest,
                    output_dir=disposable_exclusion_dir,
                )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "v562_append_only_exclusion"
                representatives = v547._load_representatives(connection)
                original_families: set[str] = set()
                matched_tokens: set[str] = set()
                for row in representatives:
                    family = str(row.get("_candidate_family") or "")
                    if not family:
                        continue
                    token = str(
                        v562._candidate_projection(row, family=family).get(
                            "review_token"
                        )
                        or ""
                    )
                    if token in original["review_tokens"]:
                        original_families.add(family)
                        matched_tokens.add(token)
                if matched_tokens != original["review_tokens"]:
                    raise V563ExpansionError(
                        "The original v5.62 evidence could not be reconstructed exactly."
                    )
                connection.execute(
                    "CREATE TEMP TABLE v563_original_families "
                    "(family TEXT PRIMARY KEY)"
                )
                connection.executemany(
                    "INSERT INTO v563_original_families(family) VALUES (?)",
                    [(family,) for family in sorted(original_families)],
                )
                connection.execute(
                    "UPDATE events SET role_rank=4, "
                    "quarantine_reason='selected_v562_evidence' "
                    "WHERE candidate_near_hash IN "
                    "(SELECT family FROM v563_original_families)"
                )
                connection.commit()
                v56.build_disposable_behavior_aggregates(connection)
                stage = "supplemental_prediction_blind_selection"
                representatives = v547._load_representatives(connection)
                candidates, selection, selected_families = (
                    select_supplemental_review_candidates(
                        representatives,
                        original_review_tokens=original["review_tokens"],
                        limit=supplemental_limit,
                        batch_size=batch_size,
                    )
                )
                fresh_rows = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM events WHERE role_rank < 3 "
                        "AND quarantine_reason IS NULL"
                    ).fetchone()[0]
                )
                selection["fresh_rows_available"] = fresh_rows
                primary_source_tokens = _source_identity_tokens(connection)
                if not primary_source_tokens:
                    raise V563ExpansionError(
                        "The primary source has no verifiable device identity."
                    )
                stage = "v562_mutation_guard"
                after_guard = _v562_snapshot(
                    v562_output_dir,
                    expected_rows=EXPECTED_V562_ROWS,
                )
                if before_guard != {
                    "protocol": after_guard["protocol_file_digest"],
                    "sealed": after_guard["sealed_file_digest"],
                    "protected": after_guard["protected_digest"],
                }:
                    raise V563ExpansionError(
                        "The original v5.62 protected pack changed during preparation."
                    )
                stage = "append_only_protocol_lock"
                workspace = _prepare_workspace(
                    candidates,
                    selection=selection,
                    selected_families=selected_families,
                    original_families=original_families,
                    v562_snapshot=original,
                    source_digest=sample_digest,
                    primary_source_tokens=primary_source_tokens,
                    profile=profile,
                    roles=roles,
                    output_dir=output_dir,
                    v562_output_dir=v562_output_dir,
                )
            finally:
                connection.close()
    except (
        V563ExpansionError,
        v562.V562CampaignError,
        v547.V547AcquisitionError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _safe_failure(
            "failed_closed_expansion_preparation",
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
    protocol = validate_expansion_protocol(
        output_dir,
        v562_output_dir=v562_output_dir,
        expected_original_rows=EXPECTED_V562_ROWS,
    )
    public_status = get_public_v563_status(
        output_dir,
        v562_output_dir=v562_output_dir,
    )
    evidence = {
        "source_rows": int(profile.get("rows_processed") or 0),
        "parser_success_rows": int(profile.get("parser_successes") or 0),
        "parser_failure_rows": int(profile.get("parser_failures") or 0),
        "fresh_rows_available": int(selection.get("fresh_rows_available") or 0),
        "original_rows_preserved": EXPECTED_V562_ROWS,
        "supplemental_rows_selected": int(selection.get("selected_rows") or 0),
        "total_comparable_capacity": int(
            protocol.get("total_comparable_capacity") or 0
        ),
        "real_source_identities": len(primary_source_tokens),
        "independent_time_windows": int(roles.get("distinct_time_windows") or 0),
        "second_source_present": False,
    }
    result = {
        "ok": bool(
            safety_passed
            and selection.get("selection_gate_passed")
            and workspace.get("append_only")
        ),
        "version": V563_VERSION,
        "status": (
            "ready_for_batched_human_review"
            if safety_passed and selection.get("selection_gate_passed")
            else "expansion_evidence_incomplete"
        ),
        "generated_at": _now(),
        "preflight_only": False,
        "v562_boundary": _v562_public_snapshot(original),
        "protocol": _public_protocol(protocol),
        "evidence": evidence,
        "selection": selection,
        "workspace": workspace,
        "review": public_status.get("review"),
        "qualification_gates": public_status.get("qualification_gates"),
        "second_source_intake": public_status.get("second_source_intake"),
        "authoritative_mutations": deltas,
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        **_safety_projection(),
    }
    if write_report:
        _atomic_write_json(_paths(output_dir)["latest"], result)
        (output_dir / f"{V563_REPORT_PREFIX}_{_stamp()}.md").write_text(
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
