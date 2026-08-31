from __future__ import annotations

import json
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atdr.app.db.models import User
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548
from atdr.app.detection import (
    v549a_supplemental_threat_anchor_acquisition as v549a,
)
from atdr.app.services.evidence_review_service import (
    EvidenceReviewError,
    EvidenceReviewIntegrityError,
)


V549A_WORKSPACE_NAME = "supplemental_threat_anchors"
_WORKSPACE_LOCK = threading.RLock()

APPROVED_EVIDENCE_FIELDS = (
    "evidence_role",
    "selection_stratum",
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
    "bytes_sent",
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
    "source_auth_deny_count",
    "source_unique_destinations",
    "source_unique_ports",
    "source_unknown_app_count",
    "source_high_risk_app_count",
    "destination_repeat_count",
    "external_to_internal",
    "rule_evidence",
    "rule_evidence_score",
)


@dataclass(frozen=True)
class SupplementalThreatAnchorReviewPaths:
    output_dir: Path
    sealed_pack: Path
    working_copy: Path
    manifest: Path
    state: Path
    proposed_protocol: Path
    original_output_dir: Path


def _workspace_paths() -> SupplementalThreatAnchorReviewPaths:
    output_dir = v549a.V549A_OUTPUT_DIR
    return SupplementalThreatAnchorReviewPaths(
        output_dir=output_dir,
        sealed_pack=output_dir / v549a.V549A_SEALED_PACK,
        working_copy=output_dir / v549a.V549A_WORKING_COPY,
        manifest=output_dir / v549a.V549A_MANIFEST,
        state=output_dir / v549a.V549A_REVIEW_STATE,
        proposed_protocol=output_dir / v549a.V549B_PROPOSED_PROTOCOL,
        original_output_dir=v548.V548_OUTPUT_DIR,
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _default_state() -> dict[str, Any]:
    return {
        "schema_version": v549a.V549A_VERSION,
        "revision": 0,
    }


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return _default_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise EvidenceReviewIntegrityError(
            "supplemental_anchor_state_invalid",
            "The protected supplemental review state failed integrity validation.",
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != v549a.V549A_VERSION
    ):
        raise EvidenceReviewIntegrityError(
            "supplemental_anchor_state_invalid",
            "The protected supplemental review state failed integrity validation.",
        )
    return payload


def _write_state(path: Path, state: dict[str, Any]) -> None:
    v547._atomic_write_json(path, state)


def _assert_human_reviewer(current_user: User) -> None:
    identity = " ".join(
        value
        for value in (current_user.username, current_user.full_name or "")
        if value
    )
    if v547.AI_REVIEWER_PATTERN.search(identity):
        raise EvidenceReviewError(
            "automated_reviewer_not_allowed",
            "Only a genuine authenticated human analyst may record decisions.",
            status_code=422,
        )


def _authorize_owner(state: dict[str, Any], current_user: User) -> None:
    owner_id = state.get("owner_user_id")
    if owner_id is None:
        raise EvidenceReviewError(
            "supplemental_anchor_review_not_started",
            "Start the supplemental review before opening protected evidence.",
        )
    if int(owner_id) != current_user.id:
        raise EvidenceReviewError(
            "supplemental_anchor_review_owned_by_another_reviewer",
            "Only the assigned reviewer can open or change this evidence.",
            status_code=403,
        )


def _assert_revision(state: dict[str, Any], expected_revision: int) -> None:
    if int(state.get("revision") or 0) != expected_revision:
        raise EvidenceReviewError(
            "supplemental_anchor_revision_conflict",
            "This review changed in another request. Reload before saving.",
        )


def _assert_open(state: dict[str, Any]) -> None:
    if state.get("closed_at"):
        raise EvidenceReviewError(
            "supplemental_anchor_review_closed",
            "The formally closed supplemental review is immutable.",
        )


def _manifest_digest(paths: SupplementalThreatAnchorReviewPaths) -> str:
    try:
        manifest = v547._read_json(paths.manifest)
    except (OSError, ValueError) as exc:
        raise EvidenceReviewIntegrityError(
            "supplemental_anchor_manifest_invalid",
            "The protected supplemental workspace failed integrity validation.",
        ) from exc
    digest = str(manifest.get("protected_digest") or "")
    if manifest.get("schema_version") != v549a.V549A_VERSION or not digest:
        raise EvidenceReviewIntegrityError(
            "supplemental_anchor_manifest_invalid",
            "The protected supplemental workspace failed integrity validation.",
        )
    return digest


def _validated_rows(
    paths: SupplementalThreatAnchorReviewPaths,
    state: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    try:
        v549a.validate_original_review_custody(paths.original_output_dir)
        digest = _manifest_digest(paths)
        if state is not None and state.get("owner_user_id") is not None:
            if state.get("workspace_digest") != digest:
                raise v549a.V549ASupplementalAcquisitionError(
                    "The review state is not bound to the sealed supplemental pack."
                )
        v549a.review_progress(paths.output_dir)
        rows, _ = v547._read_csv(paths.working_copy)
    except (
        OSError,
        ValueError,
        v547.V547AcquisitionError,
        v548.V548RevalidationError,
        v549a.V549ASupplementalAcquisitionError,
    ) as exc:
        raise EvidenceReviewIntegrityError(
            "supplemental_anchor_integrity_failed",
            "The protected supplemental workspace failed integrity validation.",
        ) from exc
    return rows


def _owner_projection(state: dict[str, Any], current_user: User) -> dict[str, bool]:
    owner_id = state.get("owner_user_id")
    assigned = owner_id is not None
    owned = bool(assigned and int(owner_id) == current_user.id)
    return {
        "owner_assigned": assigned,
        "owned_by_current_user": owned,
        "can_review": bool(not assigned or owned),
    }


def _next_unreviewed(rows: list[dict[str, Any]]) -> int | None:
    return next(
        (
            index
            for index, row in enumerate(rows)
            if not v547._boolean(row.get("human_reviewed"))
        ),
        None,
    )


def _progress_percent(reviewed: int, total: int) -> float:
    return round((reviewed / total) * 100, 1) if total else 0.0


def _safety_projection() -> dict[str, bool]:
    return {
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "private_paths_exposed": False,
        "reviewer_identity_exposed": False,
        "import_ready": False,
        "automatic_import_performed": False,
        "model_activation_performed": False,
        "response_action_performed": False,
        "secrets_exposed": False,
    }


def _status(
    paths: SupplementalThreatAnchorReviewPaths,
    state: dict[str, Any],
    current_user: User,
) -> dict[str, Any]:
    required = (paths.sealed_pack, paths.working_copy, paths.manifest)
    if not all(path.is_file() for path in required):
        return {
            "workspace": V549A_WORKSPACE_NAME,
            "available": False,
            "prepared": False,
            "integrity_status": "unavailable",
            "total": 0,
            "reviewed": 0,
            "remaining": 0,
            "invalid": 0,
            "progress_percent": 0.0,
            "revision": int(state.get("revision") or 0),
            "completed": False,
            "closed": False,
            "combined_support_visible": False,
            "combined_class_support": {},
            "minimum_class_support": {},
            "combined_support_passed": False,
            "ready_for_relocked_protocol": False,
            "proposed_protocol_created": False,
            "coverage_counts": {},
            "coverage_strata": [],
            "next_pending_index": None,
            "evaluation_execution_count": 0,
            "message": "The private supplemental anchor pack is unavailable.",
            **_owner_projection(state, current_user),
            **_safety_projection(),
        }
    try:
        progress = v549a.review_progress(paths.output_dir)
        rows = _validated_rows(paths, state)
    except (
        OSError,
        ValueError,
        v549a.V549ASupplementalAcquisitionError,
    ) as exc:
        raise EvidenceReviewIntegrityError(
            "supplemental_anchor_integrity_failed",
            "The protected supplemental workspace failed integrity validation.",
        ) from exc
    coverage = Counter(str(row.get("selection_stratum") or "unknown") for row in rows)
    reviewed = int(progress.get("reviewed") or 0)
    total = int(progress.get("total") or 0)
    closed = bool(state.get("closed_at"))
    combined = (
        v549a.combined_support_status(
            output_dir=paths.output_dir,
            original_output_dir=paths.original_output_dir,
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
    proposal_created = paths.proposed_protocol.is_file()
    return {
        "workspace": V549A_WORKSPACE_NAME,
        "available": True,
        "prepared": bool(state.get("owner_user_id") is not None),
        "integrity_status": "valid",
        "total": total,
        "reviewed": reviewed,
        "remaining": int(progress.get("remaining") or 0),
        "invalid": int(progress.get("invalid") or 0),
        "progress_percent": _progress_percent(reviewed, total),
        "revision": int(state.get("revision") or 0),
        "completed": bool(progress.get("complete")),
        "closed": closed,
        "combined_support_visible": bool(combined.get("visible")),
        "combined_class_support": dict(combined.get("class_support") or {}),
        "minimum_class_support": dict(
            combined.get("minimum_class_support") or {}
        ),
        "combined_support_passed": bool(combined.get("passed")),
        "ready_for_relocked_protocol": bool(
            combined.get("ready_for_relocked_protocol") and proposal_created
        ),
        "proposed_protocol_created": proposal_created,
        "coverage_counts": dict(sorted(coverage.items())),
        "coverage_strata": sorted(coverage),
        "next_pending_index": _next_unreviewed(rows),
        "evaluation_execution_count": 0,
        "message": (
            "Review is formally closed and aggregate support passed."
            if closed and combined.get("passed")
            else "Review is formally closed; aggregate support remains insufficient."
            if closed
            else "All rows are valid; close the review when ready."
            if progress.get("complete")
            else "Record independent human decisions using approved evidence only."
        ),
        **_owner_projection(state, current_user),
        **_safety_projection(),
    }


def get_supplemental_review_status(current_user: User) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        return _status(paths, state, current_user)


def start_supplemental_review(current_user: User) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        if not all(
            path.is_file()
            for path in (paths.sealed_pack, paths.working_copy, paths.manifest)
        ):
            raise EvidenceReviewError(
                "supplemental_anchor_pack_unavailable",
                "The private supplemental anchor pack is unavailable.",
                status_code=404,
            )
        rows = _validated_rows(paths)
        state = _load_state(paths.state)
        owner_id = state.get("owner_user_id")
        if owner_id is not None and int(owner_id) != current_user.id:
            raise EvidenceReviewError(
                "supplemental_anchor_review_owned_by_another_reviewer",
                "This supplemental review is already assigned to another reviewer.",
                status_code=403,
            )
        existing_reviewers = {
            str(row.get("human_reviewer") or "").strip()
            for row in rows
            if v547._boolean(row.get("human_reviewed"))
        }
        if owner_id is None and existing_reviewers and existing_reviewers != {
            current_user.username
        }:
            raise EvidenceReviewError(
                "supplemental_anchor_existing_owner_unverified",
                "Existing decisions cannot be assigned to this reviewer automatically.",
            )
        state.update(
            {
                "schema_version": v549a.V549A_VERSION,
                "owner_user_id": current_user.id,
                "owner_username": current_user.username,
                "workspace_digest": _manifest_digest(paths),
                "started_at": state.get("started_at") or _now(),
                "revision": max(
                    int(state.get("revision") or 0),
                    sum(v547._boolean(row.get("human_reviewed")) for row in rows),
                ),
            }
        )
        _write_state(paths.state, state)
        status = _status(paths, state, current_user)
        next_index = status.get("next_pending_index")
        return _operation(
            "supplemental_anchor_review_started",
            status,
            next_item=(
                _item(paths, state, current_user, int(next_index))
                if next_index is not None
                else None
            ),
        )


def _review_input(row: dict[str, Any]) -> dict[str, Any] | None:
    if not v547._boolean(row.get("human_reviewed")):
        return None
    return {
        "decision": str(row.get("human_decision") or ""),
        "attack_type": str(row.get("human_attack_type") or ""),
        "confidence": int(str(row.get("human_confidence") or "0")),
        "rationale": str(row.get("human_rationale") or ""),
    }


def _evidence(row: dict[str, Any]) -> dict[str, str]:
    return {
        field: str(row.get(field) or "").strip()
        for field in APPROVED_EVIDENCE_FIELDS
        if str(row.get(field) or "").strip()
    }


def _item(
    paths: SupplementalThreatAnchorReviewPaths,
    state: dict[str, Any],
    current_user: User,
    row_index: int,
) -> dict[str, Any]:
    _authorize_owner(state, current_user)
    rows = _validated_rows(paths, state)
    if row_index < 0 or row_index >= len(rows):
        raise EvidenceReviewError(
            "supplemental_anchor_row_out_of_range",
            "The requested supplemental item does not exist.",
            status_code=404,
        )
    row = rows[row_index]
    return {
        "workspace": V549A_WORKSPACE_NAME,
        "row_index": row_index,
        "display_position": row_index + 1,
        "total": len(rows),
        "revision": int(state.get("revision") or 0),
        "reviewed": v547._boolean(row.get("human_reviewed")),
        "closed": bool(state.get("closed_at")),
        "coverage_stratum": str(row.get("selection_stratum") or "unknown"),
        "evidence": _evidence(row),
        "existing_review": _review_input(row),
        "next_pending_index": _next_unreviewed(rows),
        **_safety_projection(),
    }


def get_supplemental_review_item(
    current_user: User,
    *,
    row_index: int,
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        return _item(paths, state, current_user, row_index)


def list_supplemental_review_items(
    current_user: User,
    *,
    offset: int = 0,
    limit: int = 20,
    coverage_stratum: str | None = None,
    review_state: str = "all",
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        _authorize_owner(state, current_user)
        rows = _validated_rows(paths, state)
        indexed = list(enumerate(rows))
        if coverage_stratum:
            indexed = [
                (index, row)
                for index, row in indexed
                if row.get("selection_stratum") == coverage_stratum
            ]
        if review_state == "reviewed":
            indexed = [
                (index, row)
                for index, row in indexed
                if v547._boolean(row.get("human_reviewed"))
            ]
        elif review_state == "pending":
            indexed = [
                (index, row)
                for index, row in indexed
                if not v547._boolean(row.get("human_reviewed"))
            ]
        page = indexed[offset : offset + limit]
        return {
            "workspace": V549A_WORKSPACE_NAME,
            "offset": offset,
            "limit": limit,
            "filtered_total": len(indexed),
            "items": [
                {
                    "row_index": index,
                    "display_position": index + 1,
                    "reviewed": v547._boolean(row.get("human_reviewed")),
                    "coverage_stratum": str(
                        row.get("selection_stratum") or "unknown"
                    ),
                    "evidence": _evidence(row),
                }
                for index, row in page
            ],
            "predictions_exposed": False,
            "raw_logs_exposed": False,
            "private_paths_exposed": False,
            "reviewer_identities_exposed": False,
            "secrets_exposed": False,
        }


def save_supplemental_review_item(
    current_user: User,
    *,
    row_index: int,
    expected_revision: int,
    decision: str,
    attack_type: str,
    confidence: int,
    rationale: str,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    normalized_decision = decision.strip().casefold()
    normalized_attack_type = attack_type.strip()
    normalized_rationale = rationale.strip()
    if normalized_decision not in v547.ALLOWED_DECISIONS:
        raise EvidenceReviewError(
            "supplemental_anchor_decision_invalid",
            "Select an approved human review decision.",
            status_code=422,
        )
    if (
        confidence < 1
        or confidence > 100
        or len(normalized_rationale) < 8
        or (
            normalized_decision in {"suspicious", "malicious"}
            and not normalized_attack_type
        )
    ):
        raise EvidenceReviewError(
            "supplemental_anchor_review_invalid",
            "Confidence, rationale, and required attack type must satisfy the review contract.",
            status_code=422,
        )
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        _authorize_owner(state, current_user)
        _assert_open(state)
        _assert_revision(state, expected_revision)
        rows = _validated_rows(paths, state)
        if row_index < 0 or row_index >= len(rows):
            raise EvidenceReviewError(
                "supplemental_anchor_row_out_of_range",
                "The requested supplemental item does not exist.",
                status_code=404,
            )
        original_rows = [dict(row) for row in rows]
        rows[row_index].update(
            {
                "human_decision": normalized_decision,
                "human_attack_type": normalized_attack_type,
                "human_confidence": str(confidence),
                "human_rationale": normalized_rationale,
                "human_reviewer": current_user.username,
                "human_reviewed_at": _now(),
                "human_must_confirm": True,
                "human_reviewed": True,
                "import_ready": False,
            }
        )
        v547._atomic_write_csv(paths.working_copy, rows)
        try:
            progress = v549a.review_progress(paths.output_dir)
        except v549a.V549ASupplementalAcquisitionError as exc:
            v547._atomic_write_csv(paths.working_copy, original_rows)
            raise EvidenceReviewIntegrityError(
                "supplemental_anchor_save_integrity_failed",
                "The saved decision failed protected workspace validation.",
            ) from exc
        if progress.get("invalid"):
            v547._atomic_write_csv(paths.working_copy, original_rows)
            raise EvidenceReviewIntegrityError(
                "supplemental_anchor_save_integrity_failed",
                "The saved decision failed protected workspace validation.",
            )
        state["revision"] = int(state.get("revision") or 0) + 1
        state["updated_at"] = _now()
        _write_state(paths.state, state)
        status = _status(paths, state, current_user)
        next_index = status.get("next_pending_index")
        return _operation(
            "supplemental_anchor_review_saved",
            status,
            next_item=(
                _item(paths, state, current_user, int(next_index))
                if next_index is not None
                else _item(paths, state, current_user, row_index)
            ),
        )


def close_supplemental_review(
    current_user: User,
    *,
    expected_revision: int,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        _authorize_owner(state, current_user)
        _assert_open(state)
        _assert_revision(state, expected_revision)
        _validated_rows(paths, state)
        progress = v549a.review_progress(paths.output_dir)
        if not progress.get("complete") or progress.get("invalid"):
            raise EvidenceReviewError(
                "supplemental_anchor_review_incomplete",
                "Complete every valid supplemental decision before closure.",
            )
        state["closed_at"] = _now()
        state["revision"] = int(state.get("revision") or 0) + 1
        _write_state(paths.state, state)
        try:
            v549a.write_proposed_v549b_protocol(
                output_dir=paths.output_dir,
                original_output_dir=paths.original_output_dir,
            )
        except (
            OSError,
            ValueError,
            v547.V547AcquisitionError,
            v548.V548RevalidationError,
            v549a.V549ASupplementalAcquisitionError,
        ) as exc:
            raise EvidenceReviewIntegrityError(
                "supplemental_anchor_protocol_proposal_failed",
                "The review closed safely, but the proposed protocol failed closed.",
            ) from exc
        status = _status(paths, state, current_user)
        return _operation("supplemental_anchor_review_closed", status)


def _operation(
    operation_status: str,
    progress: dict[str, Any],
    *,
    next_item: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": True,
        "workspace": V549A_WORKSPACE_NAME,
        "status": operation_status,
        "revision": int(progress.get("revision") or 0),
        "progress": progress,
        "next_item": next_item,
        "authoritative_mutations": {
            "labels": 0,
            "model_runs": 0,
            "detection_runs": 0,
            "alerts": 0,
            "response_actions": 0,
        },
        "evaluation_execution_count": 0,
        "evaluation_claim_created": False,
        "import_performed": False,
        "model_activation_performed": False,
        "response_action_performed": False,
    }
