from __future__ import annotations

import json
import threading
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atdr.app.db.models import User
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.services.evidence_review_service import (
    EvidenceReviewError,
    EvidenceReviewIntegrityError,
)


V562_WORKSPACE_NAME = "supervised_qualification"
_WORKSPACE_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _paths() -> dict[str, Path]:
    return v562._workspace_paths()


def _default_state() -> dict[str, Any]:
    return {
        "schema_version": v562.V562_VERSION,
        "revision": 0,
    }


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return _default_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise EvidenceReviewIntegrityError(
            "qualification_review_state_invalid",
            "The supervised qualification review state failed integrity validation.",
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != v562.V562_VERSION
    ):
        raise EvidenceReviewIntegrityError(
            "qualification_review_state_invalid",
            "The supervised qualification review state failed integrity validation.",
        )
    return payload


def _write_state(path: Path, state: dict[str, Any]) -> None:
    v562._atomic_write_json(path, state)


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
            "qualification_review_not_started",
            "Start the supervised qualification review before opening evidence.",
        )
    if int(owner_id) != current_user.id:
        raise EvidenceReviewError(
            "qualification_review_owned_by_another_reviewer",
            "Only the assigned reviewer can open or change this evidence.",
            status_code=403,
        )


def _assert_revision(state: dict[str, Any], expected_revision: int) -> None:
    if int(state.get("revision") or 0) != expected_revision:
        raise EvidenceReviewError(
            "qualification_review_revision_conflict",
            "This review changed in another request. Reload before saving.",
        )


def _assert_open(state: dict[str, Any]) -> None:
    if state.get("closed_at"):
        raise EvidenceReviewError(
            "qualification_review_closed",
            "The formally closed qualification review is immutable.",
        )


def _validated_rows(
    paths: dict[str, Path],
    state: dict[str, Any] | None = None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    try:
        protocol = v562.validate_campaign_protocol(paths["output_dir"])
        if state is not None and state.get("owner_user_id") is not None:
            if state.get("protocol_digest") != protocol.get("protected_digest"):
                raise v562.V562CampaignError(
                    "The review state is not bound to the locked campaign."
                )
        rows, _ = v562._read_csv(paths["working"])
        v562._review_progress(paths["output_dir"])
    except (OSError, ValueError, v562.V562CampaignError) as exc:
        raise EvidenceReviewIntegrityError(
            "qualification_review_integrity_failed",
            "The protected supervised qualification workspace failed integrity validation.",
        ) from exc
    return rows, protocol


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


def _safety_projection() -> dict[str, Any]:
    return {
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "rule_recommendations_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "private_paths_exposed": False,
        "reviewer_identity_exposed": False,
        "evaluation_class_support_sealed": True,
        "import_ready": False,
        "automatic_import_performed": False,
        "model_activation_performed": False,
        "response_action_performed": False,
        "activation_allowed": False,
        "rules_alert_authoritative": True,
        "response_mode": "simulation_only",
        "secrets_exposed": False,
    }


def _status(
    paths: dict[str, Path],
    state: dict[str, Any],
    current_user: User,
) -> dict[str, Any]:
    required = (paths["protocol"], paths["sealed"], paths["working"])
    if not all(path.is_file() for path in required):
        return {
            "workspace": V562_WORKSPACE_NAME,
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
            "development_ready": False,
            "role_counts": {},
            "role_progress": {},
            "coverage_counts": {},
            "coverage_groups": [],
            "development_class_support": {},
            "qualification_gates": {},
            "next_pending_index": None,
            "message": "Prepare the private v5.62 campaign with the guarded CLI.",
            **_owner_projection(state, current_user),
            **_safety_projection(),
        }
    rows, protocol = _validated_rows(paths, state)
    progress = v562._review_progress(paths["output_dir"])
    coverage = Counter(str(row.get("coverage_group") or "other") for row in rows)
    role_counts = Counter(str(row.get("evidence_role") or "unknown") for row in rows)
    reviewed = int(progress.get("reviewed") or 0)
    total = int(progress.get("total") or 0)
    closed = bool(state.get("closed_at"))
    gates = v562._qualification_gates(protocol=protocol, review=progress)
    return {
        "workspace": V562_WORKSPACE_NAME,
        "available": True,
        "prepared": state.get("owner_user_id") is not None,
        "integrity_status": "valid",
        "total": total,
        "reviewed": reviewed,
        "remaining": int(progress.get("remaining") or 0),
        "invalid": int(progress.get("invalid") or 0),
        "progress_percent": round((reviewed / total) * 100, 1) if total else 0.0,
        "revision": int(state.get("revision") or 0),
        "completed": bool(progress.get("complete")),
        "closed": closed,
        "development_ready": bool(closed and progress.get("complete")),
        "role_counts": dict(sorted(role_counts.items())),
        "role_progress": dict(progress.get("role_progress") or {}),
        "coverage_counts": dict(sorted(coverage.items())),
        "coverage_groups": sorted(coverage),
        "development_class_support": dict(
            progress.get("development_class_support") or {}
        ),
        "qualification_gates": gates,
        "next_pending_index": _next_unreviewed(rows),
        "message": (
            "Review is formally closed; evaluation labels remain sealed."
            if closed
            else "All decisions are valid; close the review to make them immutable."
            if progress.get("complete")
            else "Record independent human decisions using displayed evidence only."
        ),
        **_owner_projection(state, current_user),
        **_safety_projection(),
    }


def get_qualification_review_status(current_user: User) -> dict[str, Any]:
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        return _status(paths, state, current_user)


def start_qualification_review(current_user: User) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _paths()
    with _WORKSPACE_LOCK:
        if not all(
            path.is_file()
            for path in (paths["protocol"], paths["sealed"], paths["working"])
        ):
            raise EvidenceReviewError(
                "qualification_campaign_unavailable",
                "Prepare the private v5.62 campaign before starting review.",
                status_code=404,
            )
        rows, protocol = _validated_rows(paths)
        state = _load_state(paths["review_state"])
        owner_id = state.get("owner_user_id")
        if owner_id is not None and int(owner_id) != current_user.id:
            raise EvidenceReviewError(
                "qualification_review_owned_by_another_reviewer",
                "This qualification review is already assigned to another reviewer.",
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
                "qualification_existing_owner_unverified",
                "Existing decisions cannot be assigned to this reviewer automatically.",
            )
        state.update(
            {
                "schema_version": v562.V562_VERSION,
                "owner_user_id": current_user.id,
                "owner_username": current_user.username,
                "protocol_digest": protocol["protected_digest"],
                "started_at": state.get("started_at") or _now(),
                "revision": max(
                    int(state.get("revision") or 0),
                    sum(v547._boolean(row.get("human_reviewed")) for row in rows),
                ),
            }
        )
        _write_state(paths["review_state"], state)
        status = _status(paths, state, current_user)
        next_index = status.get("next_pending_index")
        return _operation(
            "qualification_review_started",
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
        for field in v562.APPROVED_EVIDENCE_FIELDS
        if str(row.get(field) or "").strip()
    }


def _item(
    paths: dict[str, Path],
    state: dict[str, Any],
    current_user: User,
    row_index: int,
) -> dict[str, Any]:
    _authorize_owner(state, current_user)
    rows, _ = _validated_rows(paths, state)
    if row_index < 0 or row_index >= len(rows):
        raise EvidenceReviewError(
            "qualification_review_row_out_of_range",
            "The requested qualification item does not exist.",
            status_code=404,
        )
    row = rows[row_index]
    return {
        "workspace": V562_WORKSPACE_NAME,
        "row_index": row_index,
        "display_position": row_index + 1,
        "total": len(rows),
        "revision": int(state.get("revision") or 0),
        "reviewed": v547._boolean(row.get("human_reviewed")),
        "closed": bool(state.get("closed_at")),
        "evidence_role": str(row.get("evidence_role") or "unknown"),
        "coverage_group": str(row.get("coverage_group") or "other"),
        "evidence": _evidence(row),
        "existing_review": _review_input(row),
        "next_pending_index": _next_unreviewed(rows),
        **_safety_projection(),
    }


def get_qualification_review_item(
    current_user: User,
    *,
    row_index: int,
) -> dict[str, Any]:
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        return _item(paths, state, current_user, row_index)


def list_qualification_review_items(
    current_user: User,
    *,
    offset: int = 0,
    limit: int = 20,
    evidence_role: str | None = None,
    coverage_group: str | None = None,
    review_state: str = "all",
) -> dict[str, Any]:
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        _authorize_owner(state, current_user)
        rows, _ = _validated_rows(paths, state)
        indexed = list(enumerate(rows))
        if evidence_role:
            indexed = [
                (index, row)
                for index, row in indexed
                if row.get("evidence_role") == evidence_role
            ]
        if coverage_group:
            indexed = [
                (index, row)
                for index, row in indexed
                if row.get("coverage_group") == coverage_group
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
            "workspace": V562_WORKSPACE_NAME,
            "offset": offset,
            "limit": limit,
            "filtered_total": len(indexed),
            "items": [
                {
                    "row_index": index,
                    "display_position": index + 1,
                    "reviewed": v547._boolean(row.get("human_reviewed")),
                    "evidence_role": str(row.get("evidence_role") or "unknown"),
                    "coverage_group": str(row.get("coverage_group") or "other"),
                    "evidence": _evidence(row),
                }
                for index, row in page
            ],
            "predictions_exposed": False,
            "raw_logs_exposed": False,
            "private_paths_exposed": False,
            "reviewer_identities_exposed": False,
            "evaluation_class_support_sealed": True,
            "secrets_exposed": False,
        }


def save_qualification_review_item(
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
    if normalized_decision not in v562.ALLOWED_DECISIONS:
        raise EvidenceReviewError(
            "qualification_review_decision_invalid",
            "Select an approved human review decision.",
            status_code=422,
        )
    if confidence < 1 or confidence > 100 or len(normalized_rationale) < 8:
        raise EvidenceReviewError(
            "qualification_review_input_invalid",
            "Confidence and rationale must satisfy the review contract.",
            status_code=422,
        )
    if (
        normalized_decision in {"suspicious", "malicious"}
        and not normalized_attack_type
    ):
        raise EvidenceReviewError(
            "qualification_attack_type_required",
            "Suspicious and malicious decisions require an attack type.",
            status_code=422,
        )
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        _authorize_owner(state, current_user)
        _assert_open(state)
        _assert_revision(state, expected_revision)
        rows, _ = _validated_rows(paths, state)
        if row_index < 0 or row_index >= len(rows):
            raise EvidenceReviewError(
                "qualification_review_row_out_of_range",
                "The requested qualification item does not exist.",
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
        v562._atomic_write_csv(paths["working"], rows)
        try:
            progress = v562._review_progress(paths["output_dir"])
        except v562.V562CampaignError as exc:
            v562._atomic_write_csv(paths["working"], original_rows)
            raise EvidenceReviewIntegrityError(
                "qualification_review_save_integrity_failed",
                "The saved decision failed protected workspace validation.",
            ) from exc
        if progress.get("invalid"):
            v562._atomic_write_csv(paths["working"], original_rows)
            raise EvidenceReviewIntegrityError(
                "qualification_review_save_integrity_failed",
                "The saved decision failed protected workspace validation.",
            )
        state["revision"] = int(state.get("revision") or 0) + 1
        state["updated_at"] = _now()
        _write_state(paths["review_state"], state)
        status = _status(paths, state, current_user)
        next_index = status.get("next_pending_index")
        return _operation(
            "qualification_review_saved",
            status,
            next_item=(
                _item(paths, state, current_user, int(next_index))
                if next_index is not None
                else _item(paths, state, current_user, row_index)
            ),
        )


def close_qualification_review(
    current_user: User,
    *,
    expected_revision: int,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        _authorize_owner(state, current_user)
        _assert_open(state)
        _assert_revision(state, expected_revision)
        _validated_rows(paths, state)
        progress = v562._review_progress(paths["output_dir"])
        if not progress.get("complete") or progress.get("invalid"):
            raise EvidenceReviewError(
                "qualification_review_incomplete",
                "Complete every valid qualification decision before closure.",
            )
        state["closed_at"] = _now()
        state["revision"] = int(state.get("revision") or 0) + 1
        _write_state(paths["review_state"], state)
        status = _status(paths, state, current_user)
        return _operation("qualification_review_closed", status)


def _operation(
    operation_status: str,
    progress: dict[str, Any],
    *,
    next_item: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": True,
        "workspace": V562_WORKSPACE_NAME,
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
        "evaluation_executed": False,
        "import_performed": False,
        "model_activation_performed": False,
        "response_action_performed": False,
    }
