from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atdr.app.db.models import User
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.detection import v567_signal_concentrated_evidence_expansion as v567
from atdr.app.services.evidence_review_service import (
    EvidenceReviewError,
    EvidenceReviewIntegrityError,
)


V567_WORKSPACE_NAME = "supervised_qualification_signal_concentrated_expansion"
_WORKSPACE_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _paths() -> dict[str, Path]:
    return v567._paths(v567.V567_OUTPUT_DIR)


def _validate_protocol(output_dir: Path) -> dict[str, Any]:
    return v567.validate_signal_protocol(output_dir)


def _campaign_status(output_dir: Path) -> dict[str, Any]:
    return v567.get_public_v567_status(output_dir)


def _load_state(path: Path) -> dict[str, Any]:
    try:
        return v567._load_review_state(path.parent)
    except (OSError, ValueError, v567.V567ExpansionError) as exc:
        raise EvidenceReviewIntegrityError(
            "signal_concentrated_expansion_review_state_invalid",
            "The signal-concentrated qualification review state failed integrity validation.",
        ) from exc


def _write_state(path: Path, state: dict[str, Any]) -> None:
    v567._atomic_write_json(path, state)


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


def _batch_state(state: dict[str, Any], batch_id: str) -> dict[str, Any]:
    batches = state.setdefault("batches", {})
    if not isinstance(batches, dict):
        raise EvidenceReviewIntegrityError(
            "signal_concentrated_expansion_review_state_invalid",
            "The signal-concentrated qualification review state failed integrity validation.",
        )
    return batches.setdefault(batch_id, {"revision": 0})


def _authorize_owner(batch: dict[str, Any], current_user: User) -> None:
    owner_id = batch.get("owner_user_id")
    if owner_id is None:
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_batch_not_started",
            "Start this signal-concentrated review batch before opening evidence.",
        )
    if int(owner_id) != current_user.id:
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_batch_owned_by_another_reviewer",
            "Only the assigned reviewer can open or change this batch.",
            status_code=403,
        )


def _assert_revision(batch: dict[str, Any], expected_revision: int) -> None:
    if int(batch.get("revision") or 0) != expected_revision:
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_revision_conflict",
            "This review batch changed in another request. Reload before saving.",
        )


def _assert_open(batch: dict[str, Any]) -> None:
    if batch.get("closed_at"):
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_batch_closed",
            "This formally closed signal-concentrated review batch is immutable.",
        )


def _validated_rows(
    paths: dict[str, Path],
    state: dict[str, Any] | None = None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    try:
        protocol = _validate_protocol(paths["output_dir"])
        rows, _ = v562._read_csv(paths["working"])
        v567._review_progress(paths["output_dir"])
        if state is not None:
            for batch in (state.get("batches") or {}).values():
                if batch.get("owner_user_id") is not None and batch.get(
                    "protocol_digest"
                ) != protocol.get("protected_digest"):
                    raise v567.V567ExpansionError(
                        "A review batch is not bound to the locked expansion."
                    )
    except (OSError, ValueError, v562.V562CampaignError, v567.V567ExpansionError) as exc:
        raise EvidenceReviewIntegrityError(
            "signal_concentrated_expansion_review_integrity_failed",
            "The protected signal-concentrated qualification workspace failed integrity validation.",
        ) from exc
    return rows, protocol


def _defined_batch_ids(protocol: dict[str, Any]) -> set[str]:
    return {
        str(item.get("batch_id") or "")
        for item in protocol.get("batch_definitions") or []
        if item.get("batch_id")
    }


def _assert_batch(protocol: dict[str, Any], batch_id: str) -> None:
    if batch_id not in _defined_batch_ids(protocol):
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_batch_not_found",
            "The requested signal-concentrated review batch does not exist.",
            status_code=404,
        )


def _batch_indexes(rows: list[dict[str, Any]], batch_id: str) -> list[int]:
    return [
        index
        for index, row in enumerate(rows)
        if str(row.get("review_batch_id") or "") == batch_id
    ]


def _next_unreviewed(rows: list[dict[str, Any]], batch_id: str) -> int | None:
    return next(
        (
            index
            for index in _batch_indexes(rows, batch_id)
            if not v547._boolean(rows[index].get("human_reviewed"))
        ),
        None,
    )


def _owner_projection(batch: dict[str, Any], current_user: User) -> dict[str, bool]:
    owner_id = batch.get("owner_user_id")
    assigned = owner_id is not None
    owned = bool(assigned and int(owner_id) == current_user.id)
    return {
        "owner_assigned": assigned,
        "owned_by_current_user": owned,
        "can_review": bool(not assigned or owned),
    }


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
        "training_executed": False,
        "evaluation_executed": False,
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
            "workspace": V567_WORKSPACE_NAME,
            "available": False,
            "integrity_status": "unavailable",
            "total": 0,
            "reviewed": 0,
            "remaining": 0,
            "invalid": 0,
            "progress_percent": 0.0,
            "completed": False,
            "closed": False,
            "closed_batch_count": 0,
            "batch_count": 0,
            "batches": [],
            "development_class_support": {},
            "combined_total": 1500,
            "combined_reviewed": 0,
            "development_training_can_begin": False,
            "message": "Prepare the private v5.67 expansion with the guarded CLI.",
            **_safety_projection(),
        }
    rows, protocol = _validated_rows(paths, state)
    progress = v567._review_progress(paths["output_dir"])
    batch_progress = progress.get("batch_progress") or {}
    batches = []
    closed_count = 0
    for definition in protocol.get("batch_definitions") or []:
        batch_id = str(definition.get("batch_id") or "")
        batch = (state.get("batches") or {}).get(batch_id) or {"revision": 0}
        values = batch_progress.get(batch_id) or {}
        closed = bool(batch.get("closed_at"))
        closed_count += int(closed)
        batches.append(
            {
                "batch_id": batch_id,
                "total": int(values.get("total") or definition.get("rows") or 0),
                "reviewed": int(values.get("reviewed") or 0),
                "remaining": int(values.get("remaining") or 0),
                "invalid": int(values.get("invalid") or 0),
                "completed": bool(values.get("complete")),
                "closed": closed,
                "revision": int(batch.get("revision") or 0),
                "next_pending_index": _next_unreviewed(rows, batch_id),
                **_owner_projection(batch, current_user),
            }
        )
    campaign = _campaign_status(paths["output_dir"])
    reviewed = int(progress.get("reviewed") or 0)
    total = int(progress.get("total") or 0)
    all_closed = bool(batches and closed_count == len(batches))
    return {
        "workspace": V567_WORKSPACE_NAME,
        "available": True,
        "integrity_status": "valid",
        "total": total,
        "reviewed": reviewed,
        "remaining": int(progress.get("remaining") or 0),
        "invalid": int(progress.get("invalid") or 0),
        "progress_percent": round((reviewed / total) * 100, 1) if total else 0.0,
        "completed": bool(progress.get("complete")),
        "closed": all_closed,
        "closed_batch_count": closed_count,
        "batch_count": len(batches),
        "batches": batches,
        "role_progress": dict(progress.get("role_progress") or {}),
        "development_class_support": dict(
            progress.get("development_class_support") or {}
        ),
        "combined_total": int(
            (campaign.get("review") or {}).get("combined_total") or 0
        ),
        "combined_reviewed": int(
            (campaign.get("review") or {}).get("combined_reviewed") or 0
        ),
        "qualification_gates": dict(campaign.get("qualification_gates") or {}),
        "development_training_can_begin": False,
        "message": (
            "All signal-concentrated batches are closed; external source evidence remains required."
            if all_closed
            else "Review each prediction-blind batch independently, then close it."
        ),
        **_safety_projection(),
    }


def get_signal_concentrated_expansion_review_status(current_user: User) -> dict[str, Any]:
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        return _status(paths, state, current_user)


def start_signal_concentrated_expansion_review_batch(
    current_user: User,
    *,
    batch_id: str,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _paths()
    with _WORKSPACE_LOCK:
        rows, protocol = _validated_rows(paths)
        _assert_batch(protocol, batch_id)
        state = _load_state(paths["review_state"])
        batch = _batch_state(state, batch_id)
        owner_id = batch.get("owner_user_id")
        if owner_id is not None and int(owner_id) != current_user.id:
            raise EvidenceReviewError(
                "signal_concentrated_expansion_review_batch_owned_by_another_reviewer",
                "This signal-concentrated review batch is assigned to another reviewer.",
                status_code=403,
            )
        existing_reviewers = {
            str(rows[index].get("human_reviewer") or "").strip()
            for index in _batch_indexes(rows, batch_id)
            if v547._boolean(rows[index].get("human_reviewed"))
        }
        if owner_id is None and existing_reviewers and existing_reviewers != {
            current_user.username
        }:
            raise EvidenceReviewError(
                "signal_concentrated_expansion_existing_owner_unverified",
                "Existing decisions cannot be assigned to this reviewer automatically.",
            )
        batch.update(
            {
                "owner_user_id": current_user.id,
                "owner_username": current_user.username,
                "protocol_digest": protocol["protected_digest"],
                "started_at": batch.get("started_at") or _now(),
                "revision": max(
                    int(batch.get("revision") or 0),
                    sum(
                        v547._boolean(rows[index].get("human_reviewed"))
                        for index in _batch_indexes(rows, batch_id)
                    ),
                ),
            }
        )
        _write_state(paths["review_state"], state)
        status = _status(paths, state, current_user)
        next_index = _next_unreviewed(rows, batch_id)
        return _operation(
            "signal_concentrated_expansion_review_batch_started",
            batch_id,
            batch,
            status,
            next_item=(
                _item(paths, state, current_user, batch_id, int(next_index))
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
    batch_id: str,
    row_index: int,
) -> dict[str, Any]:
    rows, protocol = _validated_rows(paths, state)
    _assert_batch(protocol, batch_id)
    batch = _batch_state(state, batch_id)
    _authorize_owner(batch, current_user)
    if (
        row_index < 0
        or row_index >= len(rows)
        or str(rows[row_index].get("review_batch_id") or "") != batch_id
    ):
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_row_out_of_range",
            "The requested signal-concentrated review item does not exist in this batch.",
            status_code=404,
        )
    row = rows[row_index]
    indexes = _batch_indexes(rows, batch_id)
    return {
        "workspace": V567_WORKSPACE_NAME,
        "batch_id": batch_id,
        "row_index": row_index,
        "display_position": indexes.index(row_index) + 1,
        "total": len(indexes),
        "revision": int(batch.get("revision") or 0),
        "reviewed": v547._boolean(row.get("human_reviewed")),
        "closed": bool(batch.get("closed_at")),
        "evidence_role": str(row.get("evidence_role") or "unknown"),
        "coverage_group": str(row.get("coverage_group") or "other"),
        "evidence": _evidence(row),
        "existing_review": _review_input(row),
        "next_pending_index": _next_unreviewed(rows, batch_id),
        **_safety_projection(),
    }


def get_signal_concentrated_expansion_review_item(
    current_user: User,
    *,
    batch_id: str,
    row_index: int,
) -> dict[str, Any]:
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        return _item(paths, state, current_user, batch_id, row_index)


def list_signal_concentrated_expansion_review_items(
    current_user: User,
    *,
    batch_id: str,
    offset: int = 0,
    limit: int = 20,
    evidence_role: str | None = None,
    coverage_group: str | None = None,
    review_state: str = "all",
) -> dict[str, Any]:
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        rows, protocol = _validated_rows(paths, state)
        _assert_batch(protocol, batch_id)
        _authorize_owner(_batch_state(state, batch_id), current_user)
        indexed = [
            (index, rows[index]) for index in _batch_indexes(rows, batch_id)
        ]
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
            "workspace": V567_WORKSPACE_NAME,
            "batch_id": batch_id,
            "offset": offset,
            "limit": limit,
            "filtered_total": len(indexed),
            "items": [
                {
                    "row_index": index,
                    "display_position": _batch_indexes(rows, batch_id).index(index)
                    + 1,
                    "reviewed": v547._boolean(row.get("human_reviewed")),
                    "evidence_role": str(row.get("evidence_role") or "unknown"),
                    "coverage_group": str(row.get("coverage_group") or "other"),
                    "evidence": _evidence(row),
                }
                for index, row in page
            ],
            **{
                key: value
                for key, value in _safety_projection().items()
                if key
                in {
                    "predictions_exposed",
                    "raw_logs_exposed",
                    "private_paths_exposed",
                    "reviewer_identity_exposed",
                    "evaluation_class_support_sealed",
                    "secrets_exposed",
                }
            },
        }


def save_signal_concentrated_expansion_review_item(
    current_user: User,
    *,
    batch_id: str,
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
            "signal_concentrated_expansion_review_decision_invalid",
            "Select an approved human review decision.",
            status_code=422,
        )
    if confidence < 1 or confidence > 100 or len(normalized_rationale) < 8:
        raise EvidenceReviewError(
            "signal_concentrated_expansion_review_input_invalid",
            "Confidence and rationale must satisfy the review contract.",
            status_code=422,
        )
    if normalized_decision in {"suspicious", "malicious"} and not normalized_attack_type:
        raise EvidenceReviewError(
            "signal_concentrated_expansion_attack_type_required",
            "Suspicious and malicious decisions require an attack type.",
            status_code=422,
        )
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        rows, protocol = _validated_rows(paths, state)
        _assert_batch(protocol, batch_id)
        batch = _batch_state(state, batch_id)
        _authorize_owner(batch, current_user)
        _assert_open(batch)
        _assert_revision(batch, expected_revision)
        if (
            row_index < 0
            or row_index >= len(rows)
            or str(rows[row_index].get("review_batch_id") or "") != batch_id
        ):
            raise EvidenceReviewError(
                "signal_concentrated_expansion_review_row_out_of_range",
                "The requested signal-concentrated review item does not exist in this batch.",
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
            progress = v567._review_progress(paths["output_dir"])
        except (v562.V562CampaignError, v567.V567ExpansionError) as exc:
            v562._atomic_write_csv(paths["working"], original_rows)
            raise EvidenceReviewIntegrityError(
                "signal_concentrated_expansion_review_save_integrity_failed",
                "The saved decision failed protected workspace validation.",
            ) from exc
        if progress.get("invalid"):
            v562._atomic_write_csv(paths["working"], original_rows)
            raise EvidenceReviewIntegrityError(
                "signal_concentrated_expansion_review_save_integrity_failed",
                "The saved decision failed protected workspace validation.",
            )
        batch["revision"] = int(batch.get("revision") or 0) + 1
        batch["updated_at"] = _now()
        _write_state(paths["review_state"], state)
        status = _status(paths, state, current_user)
        next_index = _next_unreviewed(rows, batch_id)
        return _operation(
            "signal_concentrated_expansion_review_saved",
            batch_id,
            batch,
            status,
            next_item=(
                _item(paths, state, current_user, batch_id, int(next_index))
                if next_index is not None
                else _item(paths, state, current_user, batch_id, row_index)
            ),
        )


def close_signal_concentrated_expansion_review_batch(
    current_user: User,
    *,
    batch_id: str,
    expected_revision: int,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths["review_state"])
        rows, protocol = _validated_rows(paths, state)
        _assert_batch(protocol, batch_id)
        batch = _batch_state(state, batch_id)
        _authorize_owner(batch, current_user)
        _assert_open(batch)
        _assert_revision(batch, expected_revision)
        indexes = _batch_indexes(rows, batch_id)
        if not indexes or any(
            not v547._boolean(rows[index].get("human_reviewed"))
            for index in indexes
        ):
            raise EvidenceReviewError(
                "signal_concentrated_expansion_review_batch_incomplete",
                "Complete every valid decision in this batch before closure.",
            )
        progress = v567._review_progress(paths["output_dir"])
        batch_progress = (progress.get("batch_progress") or {}).get(batch_id) or {}
        if not batch_progress.get("complete") or batch_progress.get("invalid"):
            raise EvidenceReviewError(
                "signal_concentrated_expansion_review_batch_invalid",
                "Resolve invalid decisions before closing this batch.",
            )
        batch["closed_at"] = _now()
        batch["revision"] = int(batch.get("revision") or 0) + 1
        _write_state(paths["review_state"], state)
        return _operation(
            "signal_concentrated_expansion_review_batch_closed",
            batch_id,
            batch,
            _status(paths, state, current_user),
        )


def _operation(
    operation_status: str,
    batch_id: str,
    batch: dict[str, Any],
    progress: dict[str, Any],
    *,
    next_item: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": True,
        "workspace": V567_WORKSPACE_NAME,
        "batch_id": batch_id,
        "status": operation_status,
        "revision": int(batch.get("revision") or 0),
        "progress": progress,
        "next_item": next_item,
        "authoritative_mutations": {
            "labels": 0,
            "model_runs": 0,
            "detection_runs": 0,
            "alerts": 0,
            "response_actions": 0,
        },
        "training_executed": False,
        "evaluation_executed": False,
        "import_performed": False,
        "model_activation_performed": False,
        "response_action_performed": False,
    }
