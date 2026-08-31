from __future__ import annotations

import json
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
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56


V549A_VERSION = "v5.49a-supplemental-threat-anchor-recovery-v1"
V549B_PROPOSED_VERSION = "v5.49b-relocked-fixed-revalidation-proposal-v1"
V549A_OUTPUT_DIR = (
    PROJECT_ROOT / "ml_baseline_reviews" / "v5_49a_supplemental_threat_anchors"
)
V549A_LATEST = "v5_49a_supplemental_threat_anchor_latest.json"
V549A_MANIFEST = "v5_49a_private_supplemental_manifest.json"
V549A_SEALED_PACK = "v5_49a_prediction_blind_supplemental_pack.csv"
V549A_WORKING_COPY = "v5_49a_supplemental_review_working.csv"
V549A_REVIEW_STATE = "v5_49a_supplemental_review_state.json"
V549B_PROPOSED_PROTOCOL = "v5_49b_proposed_fixed_protocol.json"
V549A_REPORT_PREFIX = "v5_49a_supplemental_threat_anchor_recovery"

TARGET_REVIEW_ROWS = 60
MINIMUM_REVIEW_ROWS = 40
MAX_HARD_NEGATIVES = 5
COMBINED_MINIMUM_CLASS_SUPPORT = dict(v547.MINIMUM_CLASS_SUPPORT)

COVERAGE_TARGETS = {
    "vendor_threat_high": 10,
    "vendor_threat_other": 8,
    "c2_or_exfiltration_evidence": 5,
    "brute_force_or_access_attempt": 7,
    "scan_like_behavior": 10,
    "denied_high_risk_service": 7,
    "unknown_correlated_transport": 6,
    "high_risk_rule_context": 4,
    "hard_negative_control": 3,
}
THREAT_ENRICHED_STRATA = frozenset(COVERAGE_TARGETS) - {"hard_negative_control"}
HIGH_RISK_SERVICE_PORTS = frozenset(
    {21, 22, 23, 25, 110, 135, 139, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900}
)
C2_OR_EXFILTRATION_RULES = frozenset(
    {"beaconing_like_outbound", "high_outbound_bytes", "high_bytes_outlier"}
)


class V549ASupplementalAcquisitionError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _original_private_state(output_dir: Path) -> dict[str, Any]:
    return {
        "manifest": v55._file_state(output_dir / v547.V547_MANIFEST),
        "sealed_pack": v55._file_state(output_dir / v547.V547_SEALED_PACK),
        "working_copy": v55._file_state(output_dir / v547.V547_WORKING_COPY),
        "protocol": v55._file_state(output_dir / v548.V548_PROTOCOL_LOCK),
        "review_state": v55._file_state(output_dir / v548.V548_REVIEW_STATE),
        "execution_claim": v55._file_state(output_dir / v548.V548_EXECUTION_CLAIM),
        "evaluation_result": v55._file_state(output_dir / v548.V548_RESULT),
    }


def validate_original_review_custody(
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    original_output_dir = Path(original_output_dir)
    try:
        status = v548.get_public_v548_status(original_output_dir)
        review = status.get("review") or {}
        sealed_rows, sealed_columns = v547._read_csv(
            original_output_dir / v547.V547_SEALED_PACK
        )
        v547._assert_pack_contract(sealed_rows, sealed_columns, sealed=True)
    except (OSError, ValueError, v547.V547AcquisitionError, v548.V548RevalidationError) as exc:
        raise V549ASupplementalAcquisitionError(
            "The closed v5.48 review failed custody validation."
        ) from exc
    if (
        int(review.get("total") or 0) != 120
        or int(review.get("reviewed") or 0) != 120
        or int(review.get("remaining") or 0) != 0
        or int(review.get("invalid") or 0) != 0
        or review.get("closed") is not True
        or int(status.get("evaluation_execution_count") or 0) != 0
        or status.get("evaluation_attempted") is not False
        or status.get("metrics_available") is not False
    ):
        raise V549ASupplementalAcquisitionError(
            "The original review is not in the required closed, unconsumed state."
        )
    return status


def _original_review_tokens(original_output_dir: Path) -> set[str]:
    rows, columns = v547._read_csv(
        Path(original_output_dir) / v547.V547_SEALED_PACK
    )
    v547._assert_pack_contract(rows, columns, sealed=True)
    return {str(row.get("review_token") or "") for row in rows}


def _original_token_for(row: dict[str, Any], *, family: str) -> str:
    role_rank = v547._integer(row.get("role_rank"), 4)
    return v547._stable_hash(
        {
            "version": v547.V547_VERSION,
            "family": family,
            "stratum": v547.classify_coverage_stratum(row),
            "role": role_rank,
        }
    )[:24]


def _hard_negative(row: dict[str, Any], rule_codes: list[str], rule_score: int) -> bool:
    app = str(row.get("app") or "unknown").casefold()
    action = str(row.get("action") or "unknown").casefold()
    dst_port = v547._integer(row.get("dst_port"), -1)
    app_risk = v547._integer(row.get("app_risk"))
    return bool(
        action == "allow"
        and app not in v56.UNKNOWN_APPS
        and dst_port in {53, 80, 123, 443}
        and app_risk <= 2
        and not rule_codes
        and rule_score == 0
        and v547._integer(row.get("source_unique_destinations")) <= 2
        and v547._integer(row.get("source_unique_ports")) <= 2
        and v547._integer(row.get("source_deny_count")) == 0
        and not v547._integer(row.get("parser_error"))
    )


def classify_supplemental_stratum(
    row: dict[str, Any],
    *,
    rule_codes: list[str],
    rule_score: int,
) -> tuple[str | None, int]:
    log_type = str(row.get("log_type") or "").upper()
    severity = str(row.get("threat_severity") or "").casefold()
    app = str(row.get("app") or "unknown").casefold()
    dst_port = v547._integer(row.get("dst_port"), -1)
    app_risk = v547._integer(row.get("app_risk"))
    source_events = v547._integer(row.get("source_event_count"))
    deny_count = v547._integer(row.get("source_deny_count"))
    auth_denies = v547._integer(row.get("source_auth_deny_count"))
    unique_destinations = v547._integer(row.get("source_unique_destinations"))
    unique_ports = v547._integer(row.get("source_unique_ports"))
    external_to_internal = bool(row.get("external_to_internal_flag"))
    codes = set(rule_codes)

    if log_type == "THREAT" and severity in {"critical", "high"}:
        return "vendor_threat_high", 1_000 + rule_score
    if log_type == "THREAT":
        return "vendor_threat_other", 900 + rule_score
    if codes & C2_OR_EXFILTRATION_RULES:
        return "c2_or_exfiltration_evidence", 850 + rule_score
    if "brute_force_like_attempts" in codes or auth_denies >= 8:
        return "brute_force_or_access_attempt", 825 + rule_score
    if (
        "possible_port_scan" in codes
        or "possible_horizontal_scan" in codes
        or unique_ports >= 8
        or (source_events >= 20 and unique_destinations >= 8)
    ):
        return "scan_like_behavior", 800 + rule_score
    if (
        deny_count >= 5
        and (dst_port in HIGH_RISK_SERVICE_PORTS or app_risk >= 4)
        and (external_to_internal or rule_score >= 30)
    ):
        return "denied_high_risk_service", 760 + rule_score
    if (
        app in v56.UNKNOWN_APPS
        and (
            unique_ports >= 5
            or unique_destinations >= 5
            or deny_count >= 5
            or rule_score >= 40
        )
    ):
        return "unknown_correlated_transport", 720 + rule_score
    if (
        app_risk >= 4
        or v547._integer(row.get("source_high_risk_app_count")) > 0
        or rule_score >= 50
    ):
        return "high_risk_rule_context", 680 + rule_score
    if _hard_negative(row, rule_codes, rule_score):
        return "hard_negative_control", 0
    return None, -1


def _candidate_projection(
    row: dict[str, Any],
    *,
    family: str,
    stratum: str,
    rule_codes: list[str],
    rule_score: int,
) -> dict[str, Any]:
    role_rank = v547._integer(row.get("role_rank"), 4)
    candidate = v547._candidate_projection(row, family=family)
    candidate.update(
        {
            "review_token": v547._stable_hash(
                {
                    "version": V549A_VERSION,
                    "family": family,
                    "stratum": stratum,
                    "role": role_rank,
                }
            )[:24],
            "selection_stratum": stratum,
            "review_priority": "supplemental_threat_anchor",
            "rule_evidence": "; ".join(rule_codes),
            "rule_evidence_score": rule_score,
            "source_auth_deny_count": v547._integer(
                row.get("source_auth_deny_count")
            ),
            "bytes_sent": v547._integer(row.get("bytes_sent")),
            "external_to_internal": bool(row.get("external_to_internal_flag")),
        }
    )
    return candidate


def select_supplemental_candidates(
    rows: Iterable[dict[str, Any]],
    *,
    original_review_tokens: set[str],
    prior_manual_families: set[str],
    limit: int = TARGET_REVIEW_ROWS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded: Counter[str] = Counter()
    seen_families: set[str] = set()
    for row in rows:
        role_rank = v547._integer(row.get("role_rank"), 4)
        family = str(row.get("_candidate_family") or "")
        if role_rank not in v547.DEVELOPMENT_ROLES:
            excluded["locked_or_reserved_role"] += 1
            continue
        if row.get("_quarantine_reason"):
            excluded["quarantined"] += 1
            continue
        if not family:
            excluded["missing_duplicate_family"] += 1
            continue
        if family in prior_manual_families:
            excluded["prior_manual_anchor_family"] += 1
            continue
        if _original_token_for(row, family=family) in original_review_tokens:
            excluded["closed_v548_anchor_family"] += 1
            continue
        if family in seen_families:
            excluded["duplicate_family"] += 1
            continue
        rule_codes, rule_score = v56._rule_evidence(row)
        stratum, deterministic_priority = classify_supplemental_stratum(
            row,
            rule_codes=rule_codes,
            rule_score=rule_score,
        )
        if stratum is None:
            excluded["outside_supplemental_evidence_policy"] += 1
            continue
        candidate = _candidate_projection(
            row,
            family=family,
            stratum=stratum,
            rule_codes=rule_codes,
            rule_score=rule_score,
        )
        candidate["_family"] = family
        candidate["_deterministic_priority"] = deterministic_priority
        candidate["_selection_key"] = v547._stable_hash(
            {
                "version": V549A_VERSION,
                "stratum": stratum,
                "token": candidate["review_token"],
            }
        )
        buckets[stratum].append(candidate)
        seen_families.add(family)

    for stratum, values in buckets.items():
        values.sort(
            key=lambda item: (
                int(item["_deterministic_priority"])
                if stratum == "hard_negative_control"
                else -int(item["_deterministic_priority"]),
                str(item["_selection_key"]),
            )
        )

    selected: list[dict[str, Any]] = []
    selected_tokens: set[str] = set()
    for stratum, target in COVERAGE_TARGETS.items():
        for candidate in buckets.get(stratum, [])[:target]:
            selected.append(candidate)
            selected_tokens.add(str(candidate["review_token"]))

    remaining = sorted(
        (
            candidate
            for stratum, values in buckets.items()
            if stratum != "hard_negative_control"
            for candidate in values
            if str(candidate["review_token"]) not in selected_tokens
        ),
        key=lambda item: (
            -int(item["_deterministic_priority"]),
            str(item["selection_stratum"]),
            str(item["_selection_key"]),
        ),
    )
    selected.extend(remaining[: max(0, limit - len(selected))])
    selected = selected[:limit]
    selected.sort(
        key=lambda item: (
            str(item["selection_stratum"]),
            str(item["_selection_key"]),
        )
    )
    selected_families = {str(item["_family"]) for item in selected}
    for candidate in selected:
        candidate.pop("_family", None)
        candidate.pop("_deterministic_priority", None)
        candidate.pop("_selection_key", None)

    counts = Counter(str(row["selection_stratum"]) for row in selected)
    threat_enriched_rows = sum(counts.get(name, 0) for name in THREAT_ENRICHED_STRATA)
    hard_negatives = int(counts.get("hard_negative_control", 0))
    represented_threat_strata = sum(
        1 for name in THREAT_ENRICHED_STRATA if counts.get(name, 0) > 0
    )
    coverage_gate = bool(
        len(selected) >= min(MINIMUM_REVIEW_ROWS, max(1, int(limit)))
        and threat_enriched_rows >= min(35, max(1, int(limit) - MAX_HARD_NEGATIVES))
        and hard_negatives <= MAX_HARD_NEGATIVES
        and represented_threat_strata >= 3
        and len(selected_families) == len(selected)
    )
    return selected, {
        "eligible_unique_families": sum(len(values) for values in buckets.values()),
        "selected_rows": len(selected),
        "target_rows": int(limit),
        "coverage_counts": dict(sorted(counts.items())),
        "represented_strata": len(counts),
        "represented_threat_strata": represented_threat_strata,
        "threat_enriched_rows": threat_enriched_rows,
        "hard_negative_rows": hard_negatives,
        "coverage_gate_passed": coverage_gate,
        "exclusion_reasons": dict(sorted(excluded.items())),
        "duplicate_families_contained": len(selected_families) == len(selected),
        "original_anchor_families_selected": 0,
        "future_roles_selected": 0,
        "predictions_used_for_selection": False,
        "assisted_labels_used_for_selection": False,
    }


def _assert_pack_contract(
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    sealed: bool,
) -> None:
    v547._assert_pack_contract(rows, columns, sealed=sealed)
    required = {"rule_evidence", "rule_evidence_score", "review_priority"}
    if required - set(columns):
        raise V549ASupplementalAcquisitionError(
            "The supplemental pack is missing deterministic evidence fields."
        )
    if any(str(row.get("review_priority")) != "supplemental_threat_anchor" for row in rows):
        raise V549ASupplementalAcquisitionError(
            "The supplemental pack contains an unsupported review priority."
        )


def review_progress(output_dir: Path = V549A_OUTPUT_DIR) -> dict[str, Any]:
    output_dir = Path(output_dir)
    manifest_path = output_dir / V549A_MANIFEST
    sealed_path = output_dir / V549A_SEALED_PACK
    working_path = output_dir / V549A_WORKING_COPY
    present = [path.is_file() for path in (manifest_path, sealed_path, working_path)]
    if not any(present):
        return {
            "status": "not_prepared",
            "total": 0,
            "reviewed": 0,
            "remaining": 0,
            "invalid": 0,
            "class_support": dict.fromkeys(COMBINED_MINIMUM_CLASS_SUPPORT, 0),
            "complete": False,
        }
    if not all(present):
        raise V549ASupplementalAcquisitionError(
            "The supplemental review workspace is incomplete."
        )
    manifest = v547._read_json(manifest_path)
    sealed_rows, sealed_columns = v547._read_csv(sealed_path)
    working_rows, working_columns = v547._read_csv(working_path)
    _assert_pack_contract(sealed_rows, sealed_columns, sealed=True)
    _assert_pack_contract(working_rows, working_columns, sealed=False)
    protected = str(manifest.get("protected_digest") or "")
    if (
        manifest.get("schema_version") != V549A_VERSION
        or sealed_columns != working_columns
        or len(sealed_rows) != len(working_rows)
        or not protected
        or v547._protected_digest(sealed_rows, sealed_columns) != protected
        or v547._protected_digest(working_rows, working_columns) != protected
        or v547._file_sha256(sealed_path) != manifest.get("sealed_pack_digest")
    ):
        raise V549ASupplementalAcquisitionError(
            "The supplemental review workspace failed custody validation."
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
        if not v547._boolean(row.get("human_reviewed")) and not review_fields_present:
            continue
        decision = str(row.get("human_decision") or "").strip().casefold()
        attack_type = str(row.get("human_attack_type") or "").strip()
        reviewer = str(row.get("human_reviewer") or "").strip()
        confidence = str(row.get("human_confidence") or "").strip()
        rationale = str(row.get("human_rationale") or "").strip()
        valid = bool(
            v547._boolean(row.get("human_reviewed"))
            and v547._boolean(row.get("human_must_confirm"))
            and decision in v547.ALLOWED_DECISIONS
            and (decision not in {"suspicious", "malicious"} or attack_type)
            and reviewer
            and not v547.AI_REVIEWER_PATTERN.search(reviewer)
            and confidence.isdigit()
            and 1 <= int(confidence) <= 100
            and len(rationale) >= 8
            and v547._parse_timestamp(row.get("human_reviewed_at")) is not None
            and not v547._boolean(row.get("import_ready"))
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
    complete = bool(total and reviewed == total and invalid == 0)
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
        "class_support": {
            key: int(support.get(key, 0)) for key in COMBINED_MINIMUM_CLASS_SUPPORT
        },
        "complete": complete,
        "predictions_exposed": False,
        "assisted_labels_exposed": False,
        "import_ready": False,
        "reviewer_identities_returned": False,
        "review_tokens_returned": False,
    }


def _prepare_workspace(
    rows: list[dict[str, Any]],
    selection: dict[str, Any],
    *,
    output_dir: Path,
    original_output_dir: Path,
) -> dict[str, Any]:
    if not rows or not selection.get("coverage_gate_passed"):
        raise V549ASupplementalAcquisitionError(
            "The supplemental evidence coverage gate did not pass."
        )
    columns = list(rows[0])
    _assert_pack_contract(rows, columns, sealed=True)
    protected = v547._protected_digest(rows, columns)
    manifest_path = output_dir / V549A_MANIFEST
    sealed_path = output_dir / V549A_SEALED_PACK
    working_path = output_dir / V549A_WORKING_COPY
    present = [path.is_file() for path in (manifest_path, sealed_path, working_path)]
    if any(present) and not all(present):
        raise V549ASupplementalAcquisitionError(
            "An incomplete supplemental workspace already exists."
        )
    created = not all(present)
    if created:
        output_dir.mkdir(parents=True, exist_ok=True)
        v547._atomic_write_csv(sealed_path, rows)
        v547._atomic_write_csv(working_path, rows)
        original_manifest = v547._read_json(
            Path(original_output_dir) / v547.V547_MANIFEST
        )
        manifest = {
            "schema_version": V549A_VERSION,
            "created_at": _now(),
            "status": "prediction_blind_supplemental_pack_sealed",
            "selected_rows": len(rows),
            "coverage": selection,
            "protected_digest": protected,
            "sealed_pack_digest": v547._file_sha256(sealed_path),
            "original_pack_digest": original_manifest.get("sealed_pack_digest"),
            "original_review_immutable": True,
            "original_evaluation_execution_count": 0,
            "development_roles_only": True,
            "future_labels_opened": False,
            "predictions_included": False,
            "assisted_labels_included": False,
            "raw_logs_included": False,
            "ip_addresses_included": False,
            "source_identities_included": False,
            "import_ready": False,
        }
        v547._atomic_write_json(manifest_path, manifest)
    else:
        manifest = v547._read_json(manifest_path)
        existing_rows, existing_columns = v547._read_csv(sealed_path)
        _assert_pack_contract(existing_rows, existing_columns, sealed=True)
        if (
            existing_columns != columns
            or v547._protected_digest(existing_rows, existing_columns) != protected
            or manifest.get("protected_digest") != protected
        ):
            raise V549ASupplementalAcquisitionError(
                "A different sealed supplemental pack already exists."
            )
    return {
        "status": "workspace_created" if created else "workspace_reused",
        "created": created,
        "sealed_rows": len(rows),
        "coverage_gate_passed": True,
        "review": review_progress(output_dir),
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


def _review_closed(output_dir: Path) -> bool:
    path = Path(output_dir) / V549A_REVIEW_STATE
    if not path.is_file():
        return False
    try:
        payload = v547._read_json(path)
    except (OSError, ValueError) as exc:
        raise V549ASupplementalAcquisitionError(
            "The supplemental review state failed integrity validation."
        ) from exc
    if payload.get("schema_version") != V549A_VERSION:
        raise V549ASupplementalAcquisitionError(
            "The supplemental review state has an unsupported version."
        )
    return bool(payload.get("closed_at"))


def combined_support_status(
    *,
    output_dir: Path = V549A_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    original = validate_original_review_custody(original_output_dir)
    supplemental = review_progress(output_dir)
    original_support = (original.get("review") or {}).get("class_support") or {}
    combined = {
        key: int(original_support.get(key) or 0)
        + int((supplemental.get("class_support") or {}).get(key) or 0)
        for key in COMBINED_MINIMUM_CLASS_SUPPORT
    }
    closed = _review_closed(output_dir)
    passed = bool(
        closed
        and supplemental.get("complete")
        and all(
            combined[key] >= target
            for key, target in COMBINED_MINIMUM_CLASS_SUPPORT.items()
        )
    )
    return {
        "visible": closed,
        "class_support": combined if closed else {},
        "minimum_class_support": (
            dict(COMBINED_MINIMUM_CLASS_SUPPORT) if closed else {}
        ),
        "passed": passed,
        "ready_for_relocked_protocol": passed,
    }


def write_proposed_v549b_protocol(
    *,
    output_dir: Path = V549A_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any] | None:
    combined = combined_support_status(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    if not combined["passed"]:
        return None
    supplemental_manifest = v547._read_json(Path(output_dir) / V549A_MANIFEST)
    original_protocol = v548.validate_fixed_protocol(Path(original_output_dir))
    proposal = {
        "schema_version": V549B_PROPOSED_VERSION,
        "created_at": _now(),
        "status": "proposal_only_not_locked_or_executed",
        "original_protocol_version": original_protocol.get("schema_version"),
        "original_protocol_digest": original_protocol.get("protocol_digest"),
        "original_pack_digest": supplemental_manifest.get("original_pack_digest"),
        "supplemental_pack_digest": supplemental_manifest.get("sealed_pack_digest"),
        "combined_class_support": combined["class_support"],
        "minimum_class_support": dict(COMBINED_MINIMUM_CLASS_SUPPORT),
        "original_review_immutable": True,
        "supplemental_review_immutable": True,
        "evaluation_execution_count": 0,
        "evaluation_claim_created": False,
        "evaluation_labels_accessed": False,
        "partitions_changed": False,
        "features_changed": False,
        "strategies_changed": False,
        "thresholds_changed": False,
        "calibration_changed": False,
        "quality_gates_changed": False,
        "model_activated": False,
        "response_automation_allowed": False,
    }
    v547._atomic_write_json(Path(output_dir) / V549B_PROPOSED_PROTOCOL, proposal)
    return proposal


def _safe_failure(
    status: str,
    *,
    error_type: str | None = None,
    failure_stage: str | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V549A_VERSION,
        "status": status,
        "error_type": error_type,
        "failure_stage": failure_stage,
        "message": "Supplemental acquisition failed closed without changing governed state.",
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "evaluation_execution_count": 0,
        "evaluation_claim_created": False,
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
            "# v5.49a Supplemental Threat Anchor Recovery",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Selected rows: `{selection.get('selected_rows', 0)}`",
            f"- Threat-enriched rows: `{selection.get('threat_enriched_rows', 0)}`",
            f"- Represented threat strata: `{selection.get('represented_threat_strata', 0)}`",
            f"- Review progress: `{review.get('reviewed', 0)}/{review.get('total', 0)}`",
            "- Original review immutable: `True`",
            "- Original evaluation executions: `0`",
            "- Predictions used or exposed: `False`",
            "- Automatic import performed: `False`",
            "- Model activated: `False`",
            "- Rules remain authoritative: `True`",
            "",
            "This is a prediction-blind supplemental human-review workspace, not an activation result.",
            "",
        ]
    )


def run_v549a_supplemental_threat_anchor_acquisition(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = False,
    prepare_review: bool = False,
    review_limit: int = TARGET_REVIEW_ROWS,
    min_samples: int = 100,
    output_dir: Path = V549A_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
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
    output_dir = Path(output_dir)
    original_output_dir = Path(original_output_dir)
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    original_before = _original_private_state(original_output_dir)
    stage = "original_review_custody"
    try:
        original_status = validate_original_review_custody(original_output_dir)
        stage = "governed_development_custody"
        custody = v547.revalidate_v547_custody(
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
        V549ASupplementalAcquisitionError,
        v547.V547AcquisitionError,
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
        original_after = _original_private_state(original_output_dir)
        safe = bool(
            available
            and counts_before == counts_after
            and artifacts_before == artifacts_after
            and original_before == original_after
        )
        return {
            "ok": safe,
            "version": V549A_VERSION,
            "status": "preflight_complete" if safe else "private_file_unavailable",
            "generated_at": _now(),
            "preflight_only": True,
            "original_review": {
                "reviewed": int((original_status.get("review") or {}).get("reviewed") or 0),
                "remaining": int((original_status.get("review") or {}).get("remaining") or 0),
                "invalid": int((original_status.get("review") or {}).get("invalid") or 0),
                "closed": bool((original_status.get("review") or {}).get("closed")),
                "evaluation_execution_count": 0,
                "immutable": True,
            },
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
                "original_review_unchanged": original_before == original_after,
                "all_invariants_passed": safe,
            },
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "response_automation_allowed": False,
            "evaluation_execution_count": 0,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    if not prepare_review:
        return _safe_failure("prepare_review_confirmation_required")
    if not available:
        return _safe_failure("private_file_unavailable")
    if not use_temp_db:
        return _safe_failure("temporary_storage_acknowledgement_required")
    review_limit = max(MINIMUM_REVIEW_ROWS, min(100, int(review_limit)))

    stage = "disposable_candidate_preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v549a-") as directory:
            connection = sqlite3.connect(Path(directory) / "supplemental.sqlite3")
            try:
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile.get("ok"):
                    raise V549ASupplementalAcquisitionError(
                        "Private evidence parsing failed."
                    )
                stage = "protected_boundary_install"
                v544._install_protected_boundaries(
                    connection,
                    custody=custody["prior"]["prior"]["custody"],
                    blind_output_dir=blind_output_dir,
                )
                stage = "chronological_role_reconstruction"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V549ASupplementalAcquisitionError(
                        "Chronological role reconstruction failed."
                    )
                stage = "behavior_aggregate_build"
                v56.build_disposable_behavior_aggregates(connection)
                stage = "candidate_near_containment"
                containment = v545._contain_candidate_near_families(connection)
                if not containment.get("passed"):
                    raise V549ASupplementalAcquisitionError(
                        "Candidate families cross protected evidence roles."
                    )
                v56.build_disposable_behavior_aggregates(connection)
                stage = "original_and_prior_anchor_exclusion"
                original_tokens = _original_review_tokens(original_output_dir)
                prior_manual_families = v547._manual_anchor_families(custody)
                stage = "prediction_blind_threat_enriched_selection"
                representatives = v547._load_representatives(connection)
                candidates, selection = select_supplemental_candidates(
                    representatives,
                    original_review_tokens=original_tokens,
                    prior_manual_families=prior_manual_families,
                    limit=review_limit,
                )
                if not selection.get("coverage_gate_passed"):
                    raise V549ASupplementalAcquisitionError(
                        "Insufficient unique development evidence passed the supplemental policy."
                    )
                source_count = v547._private_source_count(connection)
                stage = "sealed_supplemental_workspace_creation"
                workspace = _prepare_workspace(
                    candidates,
                    selection,
                    output_dir=output_dir,
                    original_output_dir=original_output_dir,
                )
            finally:
                connection.close()
    except (
        V549ASupplementalAcquisitionError,
        v547.V547AcquisitionError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        return _safe_failure(
            "failed_closed_supplemental_acquisition",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    original_after = _original_private_state(original_output_dir)
    deltas = {
        key: int(counts_after[key]) - int(counts_before[key]) for key in counts_before
    }
    safety = {
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "original_review_unchanged": original_before == original_after,
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
        "evaluation_execution_count": 0,
        "evaluation_claim_created": False,
    }
    safety_passed = bool(
        safety["configured_database_counts_unchanged"]
        and safety["active_model_artifacts_unchanged"]
        and safety["original_review_unchanged"]
        and all(value == 0 for value in deltas.values())
    )
    result = {
        "ok": safety_passed,
        "version": V549A_VERSION,
        "status": "ready_for_supplemental_human_review",
        "generated_at": _now(),
        "preflight_only": False,
        "original_review": {
            "reviewed": 120,
            "remaining": 0,
            "invalid": 0,
            "closed": True,
            "evaluation_execution_count": 0,
            "immutable": True,
        },
        "private_reconstruction": {
            "parsed_rows": v547._integer(profile.get("rows_processed")),
            "parser_success_rows": v547._integer(profile.get("parser_successes")),
            "parser_failure_rows": v547._integer(profile.get("parser_failures")),
            "future_labels_opened": False,
            "private_paths_returned": False,
            "private_identifiers_returned": False,
            "fingerprints_returned": False,
        },
        "selection": selection,
        "workspace": workspace,
        "original_anchor_families_selected": 0,
        "prior_manual_anchor_families_excluded": len(prior_manual_families),
        "independent_source_count": source_count,
        "development_evidence_only": True,
        "evaluation_allowed_in_this_phase": False,
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
        v547._atomic_write_json(output_dir / V549A_LATEST, result)
        (output_dir / f"{V549A_REPORT_PREFIX}_{_stamp()}.md").write_text(
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


def get_public_v549a_status(
    *,
    output_dir: Path = V549A_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    original = validate_original_review_custody(original_output_dir)
    latest_path = Path(output_dir) / V549A_LATEST
    progress = review_progress(output_dir)
    closed = _review_closed(output_dir) if progress.get("total") else False
    combined = (
        combined_support_status(
            output_dir=output_dir,
            original_output_dir=original_output_dir,
        )
        if closed
        else {
            "visible": False,
            "class_support": {},
            "minimum_class_support": {},
            "passed": False,
            "ready_for_relocked_protocol": False,
        }
    )
    if latest_path.is_file():
        latest = v547._read_json(latest_path)
        if latest.get("version") != V549A_VERSION:
            raise V549ASupplementalAcquisitionError(
                "The supplemental status record has an unsupported version."
            )
        selection = latest.get("selection") or {}
    else:
        latest = {}
        selection = {}
    proposal_exists = (Path(output_dir) / V549B_PROPOSED_PROTOCOL).is_file()
    if proposal_exists and not combined.get("passed"):
        raise V549ASupplementalAcquisitionError(
            "A proposed relocked protocol exists without sufficient closed evidence."
        )
    original_review = original.get("review") or {}
    status = (
        "ready_for_v549b_protocol_lock"
        if combined.get("passed") and proposal_exists
        else "supplemental_review_closed_insufficient_support"
        if closed
        else "supplemental_human_review_in_progress"
        if progress.get("reviewed") or progress.get("invalid")
        else "ready_for_supplemental_human_review"
        if progress.get("total")
        else "not_prepared"
    )
    return {
        "version": V549A_VERSION,
        "status": status,
        "generated_at": latest.get("generated_at"),
        "original_review": {
            "total": int(original_review.get("total") or 0),
            "reviewed": int(original_review.get("reviewed") or 0),
            "remaining": int(original_review.get("remaining") or 0),
            "invalid": int(original_review.get("invalid") or 0),
            "closed": bool(original_review.get("closed")),
            "immutable": True,
            "evaluation_execution_count": 0,
        },
        "selected_rows": int(selection.get("selected_rows") or 0),
        "target_rows": int(selection.get("target_rows") or TARGET_REVIEW_ROWS),
        "coverage_counts": {
            str(key): int(value)
            for key, value in (selection.get("coverage_counts") or {}).items()
        },
        "represented_threat_strata": int(
            selection.get("represented_threat_strata") or 0
        ),
        "threat_enriched_rows": int(selection.get("threat_enriched_rows") or 0),
        "coverage_gate_passed": bool(selection.get("coverage_gate_passed")),
        "exclusion_counts": {
            str(key): int(value)
            for key, value in (selection.get("exclusion_reasons") or {}).items()
        },
        "review": {
            "status": progress.get("status"),
            "total": int(progress.get("total") or 0),
            "reviewed": int(progress.get("reviewed") or 0),
            "remaining": int(progress.get("remaining") or 0),
            "invalid": int(progress.get("invalid") or 0),
            "complete": bool(progress.get("complete")),
            "closed": closed,
        },
        "combined_support_visible": bool(combined.get("visible")),
        "combined_class_support": dict(combined.get("class_support") or {}),
        "minimum_class_support": dict(
            combined.get("minimum_class_support") or {}
        ),
        "combined_support_passed": bool(combined.get("passed")),
        "ready_for_relocked_protocol": bool(
            combined.get("ready_for_relocked_protocol") and proposal_exists
        ),
        "proposed_protocol_created": proposal_exists,
        "evaluation_execution_count": 0,
        "evaluation_claim_created": False,
        "evaluation_result_created": False,
        "predictions_used_for_selection": False,
        "predictions_exposed": False,
        "assisted_labels_exposed": False,
        "development_evidence_only": True,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "automatic_import_performed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
