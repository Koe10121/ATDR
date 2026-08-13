from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.models import User
from atdr.app.detection import v527_blind_review_evaluation as v527
from atdr.app.detection import v528_blind_review_helper as v528
from atdr.app.services import v533_independent_acceptance_service as v533


V537_VERSION = "v5.37.0"
WORKSPACE_STATE_FILE = "v5_37_evidence_review_workspace_state.json"
_WORKSPACE_LOCK = threading.RLock()
_AI_REVIEWER_PATTERN = re.compile(
    r"(?:assistant|automated|bot|chatgpt|claude|codex|gemini|heuristic|language model|llm|model|openai|synthetic)",
    re.IGNORECASE,
)

DETECTION_DECISION_GROUPS = {
    "benign_like": {"benign", "benign_unusual"},
    "needs_context": {"needs_context"},
    "threat_positive": {"suspicious", "malicious"},
}
ASSISTANT_SCORE_TO_FIELD = {
    "factual_correctness": "human_factual_correctness",
    "evidence_grounding": "human_evidence_grounding",
    "citation_correctness": "human_citation_correctness",
    "relevance": "human_relevance",
    "concision": "human_concision",
    "actionable_usefulness": "human_actionable_usefulness",
    "privacy": "human_privacy",
    "unsafe_action_refusal": "human_unsafe_action_refusal",
}


@dataclass(frozen=True)
class EvidenceWorkspacePaths:
    evidence_dir: Path
    detection_pack: Path
    detection_working: Path
    assistant_review: Path
    assistant_manifest: Path
    state: Path


class EvidenceReviewError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.status_code = status_code


class EvidenceReviewIntegrityError(EvidenceReviewError):
    pass


def _workspace_paths() -> EvidenceWorkspacePaths:
    evidence_dir = v528.DEFAULT_EVIDENCE_DIR
    return EvidenceWorkspacePaths(
        evidence_dir=evidence_dir,
        detection_pack=v528.DEFAULT_PACK_PATH,
        detection_working=v528.DEFAULT_WORKING_PATH,
        assistant_review=v533.DEFAULT_ASSISTANT_REVIEW_PATH,
        assistant_manifest=v533.DEFAULT_ASSISTANT_MANIFEST_PATH,
        state=evidence_dir / WORKSPACE_STATE_FILE,
    )


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _default_state() -> dict[str, Any]:
    return {
        "schema_version": V537_VERSION,
        "detection": {},
        "assistant": {},
    }


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return _default_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceReviewIntegrityError(
            "workspace_state_invalid",
            "The private review workspace state failed integrity validation.",
        ) from exc
    if not isinstance(payload, dict) or not all(
        isinstance(payload.get(name), dict) for name in ("detection", "assistant")
    ):
        raise EvidenceReviewIntegrityError(
            "workspace_state_invalid",
            "The private review workspace state failed integrity validation.",
        )
    payload.setdefault("schema_version", V537_VERSION)
    return payload


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
            json.dump(payload, stream, indent=2, sort_keys=True)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _detection_pack_digest(path: Path) -> str:
    try:
        rows, columns = v528._read_rows(path)
        v528._assert_safe_blind_source(rows, columns)
        if v527._prediction_exposure_detected(rows, columns):
            raise ValueError("prediction exposure detected")
    except (OSError, ValueError) as exc:
        raise EvidenceReviewIntegrityError(
            "detection_blindness_compromised",
            "The detection review pack failed its prediction-blind contract.",
        ) from exc
    protected = [column for column in columns if column not in v527.HUMAN_REVIEW_FIELDS]
    return _sha256(
        {
            "columns": columns,
            "protected_rows": [
                {column: str(row.get(column) or "") for column in protected}
                for row in rows
            ],
        }
    )


def _assistant_pack_digest(paths: EvidenceWorkspacePaths, *, secret: str) -> str:
    try:
        validation = v533.validate_assistant_human_review_pack(
            review_path=paths.assistant_review,
            manifest_path=paths.assistant_manifest,
            secret=secret,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceReviewIntegrityError(
            "assistant_pack_integrity_failed",
            "The Assistant acceptance pack failed protected-content validation.",
        ) from exc
    if not validation.get("ok") or not validation.get(
        "protected_content_integrity_passed"
    ):
        raise EvidenceReviewIntegrityError(
            "assistant_pack_integrity_failed",
            "The Assistant acceptance pack failed protected-content validation.",
        )
    try:
        manifest = json.loads(paths.assistant_manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceReviewIntegrityError(
            "assistant_manifest_invalid",
            "The Assistant acceptance manifest failed integrity validation.",
        ) from exc
    digest = str(manifest.get("protected_digest") or "")
    if not digest:
        raise EvidenceReviewIntegrityError(
            "assistant_manifest_invalid",
            "The Assistant acceptance manifest failed integrity validation.",
        )
    return digest


def _assert_digest(workspace: dict[str, Any], digest: str, *, code: str) -> None:
    existing = str(workspace.get("pack_digest") or "")
    if existing and existing != digest:
        raise EvidenceReviewIntegrityError(
            code,
            "The private review pack changed after this review session started.",
        )


def _claim_workspace(
    workspace: dict[str, Any],
    *,
    current_user: User,
    pack_digest: str,
    reviewed_rows: list[dict[str, str]],
) -> None:
    owner_id = workspace.get("owner_user_id")
    if owner_id is not None and int(owner_id) != current_user.id:
        raise EvidenceReviewError(
            "workspace_owned_by_another_reviewer",
            "This review workspace is already assigned to another reviewer.",
            status_code=403,
        )
    existing_reviewers = {
        str(row.get("human_reviewer") or "").strip()
        for row in reviewed_rows
        if _boolean(row.get("human_reviewed"))
    }
    if owner_id is None and existing_reviewers and existing_reviewers != {
        current_user.username
    }:
        raise EvidenceReviewError(
            "existing_review_owner_unverified",
            "Existing human input cannot be assigned to the current reviewer automatically.",
            status_code=409,
        )
    workspace.update(
        {
            "owner_user_id": current_user.id,
            "owner_username": current_user.username,
            "pack_digest": pack_digest,
            "started_at": workspace.get("started_at") or _now(),
            "revision": max(
                int(workspace.get("revision") or 0),
                sum(_boolean(row.get("human_reviewed")) for row in reviewed_rows),
            ),
        }
    )


def _authorize_owner(workspace: dict[str, Any], current_user: User) -> None:
    owner_id = workspace.get("owner_user_id")
    if owner_id is None:
        raise EvidenceReviewError(
            "workspace_not_started",
            "Start this review workspace before opening evidence.",
        )
    if int(owner_id) != current_user.id:
        raise EvidenceReviewError(
            "workspace_owned_by_another_reviewer",
            "Only the assigned reviewer can open or change review evidence.",
            status_code=403,
        )


def _assert_revision(workspace: dict[str, Any], expected_revision: int) -> None:
    if int(workspace.get("revision") or 0) != expected_revision:
        raise EvidenceReviewError(
            "workspace_revision_conflict",
            "This review changed in another request. Reload before saving.",
        )


def _assert_human_reviewer(current_user: User) -> None:
    if _AI_REVIEWER_PATTERN.search(current_user.username):
        raise EvidenceReviewError(
            "automated_reviewer_not_allowed",
            "This workflow accepts decisions only from a genuine authenticated human reviewer.",
            status_code=422,
        )


def _owner_projection(workspace: dict[str, Any], current_user: User) -> dict[str, bool]:
    owner_id = workspace.get("owner_user_id")
    assigned = owner_id is not None
    owned = assigned and int(owner_id) == current_user.id
    return {
        "owner_assigned": assigned,
        "owned_by_current_user": owned,
        "can_review": bool(not assigned or owned),
    }


def _progress_percent(reviewed: int, total: int) -> float:
    return round((reviewed / total) * 100, 1) if total else 0.0


def _next_pending_index(rows: list[dict[str, str]]) -> int | None:
    return next(
        (
            index
            for index, row in enumerate(rows)
            if not _boolean(row.get("human_reviewed"))
        ),
        None,
    )


def _detection_progress(
    paths: EvidenceWorkspacePaths,
    state: dict[str, Any],
    current_user: User,
) -> dict[str, Any]:
    workspace = state["detection"]
    if not paths.detection_pack.is_file():
        return {
            "workspace": "detection",
            "available": False,
            "prepared": False,
            "integrity_status": "unavailable",
            "message": "The private sealed detection pack is not available on this machine.",
            **_owner_projection(workspace, current_user),
        }
    digest = _detection_pack_digest(paths.detection_pack)
    _assert_digest(workspace, digest, code="detection_pack_changed")
    try:
        progress = v528.review_progress(
            pack_path=paths.detection_pack,
            working_path=paths.detection_working,
        )
        rows = (
            v528._read_rows(paths.detection_working)[0]
            if paths.detection_working.is_file()
            else []
        )
    except (OSError, ValueError) as exc:
        raise EvidenceReviewIntegrityError(
            "detection_working_copy_invalid",
            "The detection review working copy failed integrity validation.",
        ) from exc
    total = int(progress.get("total") or 0)
    reviewed = int(progress.get("reviewed") or 0)
    remaining = int(progress.get("remaining") or 0)
    invalid = int(progress.get("invalid") or 0)
    return {
        "workspace": "detection",
        "available": True,
        "prepared": paths.detection_working.is_file(),
        "integrity_status": "valid",
        "total": total,
        "reviewed": reviewed,
        "remaining": remaining,
        "invalid": invalid,
        "progress_percent": _progress_percent(reviewed, total),
        "completed": bool(total and reviewed == total and invalid == 0),
        "next_pending_index": _next_pending_index(rows),
        "evaluation_ready": bool(progress.get("enough_for_locked_evaluation")),
        "message": (
            "Human review is complete and ready for the separate locked evaluator."
            if total and reviewed == total and invalid == 0
            else "Predictions remain withheld while the assigned reviewer records independent decisions."
        ),
        **_owner_projection(workspace, current_user),
    }


def _assistant_progress(
    paths: EvidenceWorkspacePaths,
    state: dict[str, Any],
    current_user: User,
    *,
    secret: str,
) -> dict[str, Any]:
    workspace = state["assistant"]
    review_exists = paths.assistant_review.is_file()
    manifest_exists = paths.assistant_manifest.is_file()
    if not review_exists and not manifest_exists:
        return {
            "workspace": "assistant",
            "available": False,
            "prepared": False,
            "integrity_status": "not_prepared",
            "message": "The protected Assistant acceptance pack has not been prepared yet.",
            **_owner_projection(workspace, current_user),
        }
    if review_exists != manifest_exists:
        raise EvidenceReviewIntegrityError(
            "assistant_pack_partial",
            "The Assistant acceptance pack is incomplete and cannot be opened.",
        )
    digest = _assistant_pack_digest(paths, secret=secret)
    _assert_digest(workspace, digest, code="assistant_pack_changed")
    try:
        validation = v533.validate_assistant_human_review_pack(
            review_path=paths.assistant_review,
            manifest_path=paths.assistant_manifest,
            secret=secret,
        )
        rows, _ = v533._read_csv(paths.assistant_review)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceReviewIntegrityError(
            "assistant_pack_integrity_failed",
            "The Assistant acceptance pack failed protected-content validation.",
        ) from exc
    total = int(validation.get("total_rows") or 0)
    reviewed = int(validation.get("valid_human_reviews") or 0)
    remaining = int(validation.get("incomplete_rows") or 0)
    invalid = int(validation.get("invalid_rows") or 0)
    return {
        "workspace": "assistant",
        "available": True,
        "prepared": True,
        "integrity_status": "valid",
        "total": total,
        "reviewed": reviewed,
        "remaining": remaining,
        "invalid": invalid,
        "progress_percent": _progress_percent(reviewed, total),
        "completed": bool(total and reviewed == total and invalid == 0),
        "next_pending_index": _next_pending_index(rows),
        "evaluation_ready": bool(validation.get("human_acceptance_permitted")),
        "human_acceptance_passed": (
            bool(validation.get("human_acceptance_passed"))
            if validation.get("human_metrics_calculated")
            else None
        ),
        "message": (
            "Human acceptance review is complete. No tuning or provider call was triggered."
            if total and reviewed == total and invalid == 0
            else "Review the protected answers and citations without sending content back to the provider."
        ),
        **_owner_projection(workspace, current_user),
    }


def get_evidence_review_status(
    current_user: User,
    *,
    settings: Settings,
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        return {
            "version": V537_VERSION,
            "detection": _detection_progress(paths, state, current_user),
            "assistant": _assistant_progress(
                paths,
                state,
                current_user,
                secret=settings.assistant_llm_api_key,
            ),
            "safeguards": [
                "Human Decisions Only",
                "Predictions Withheld",
                "No Auto Import",
                "No Model Activation",
                "No Response Actions",
            ],
            "aggregate_only_for_non_owner": True,
            "secrets_exposed": False,
        }


def start_detection_review(
    current_user: User,
    *,
    settings: Settings,
) -> dict[str, Any]:
    del settings
    _assert_human_reviewer(current_user)
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        if not paths.detection_pack.is_file():
            raise EvidenceReviewError(
                "detection_pack_unavailable",
                "The private sealed detection pack is not available on this machine.",
                status_code=404,
            )
        try:
            v528.prepare_review_working_copy(
                pack_path=paths.detection_pack,
                working_path=paths.detection_working,
            )
            rows, _ = v528._read_rows(paths.detection_working)
        except (OSError, ValueError) as exc:
            raise EvidenceReviewIntegrityError(
                "detection_working_copy_invalid",
                "The detection review working copy failed integrity validation.",
            ) from exc
        digest = _detection_pack_digest(paths.detection_pack)
        state = _load_state(paths.state)
        workspace = state["detection"]
        _assert_digest(workspace, digest, code="detection_pack_changed")
        _claim_workspace(
            workspace,
            current_user=current_user,
            pack_digest=digest,
            reviewed_rows=rows,
        )
        _atomic_write_json(paths.state, state)
        progress = _detection_progress(paths, state, current_user)
        return _operation_response(
            workspace="detection",
            status="detection_review_started",
            revision=int(workspace.get("revision") or 0),
            progress=progress,
            next_item=(
                _detection_item(paths, state, current_user, progress["next_pending_index"])
                if progress.get("next_pending_index") is not None
                else None
            ),
        )


def start_assistant_review(
    db: Session,
    current_user: User,
    *,
    settings: Settings,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        try:
            prepared = v533.prepare_assistant_human_review_pack(
                db,
                settings=settings,
                review_path=paths.assistant_review,
                manifest_path=paths.assistant_manifest,
                execute_provider=False,
                refresh=False,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise EvidenceReviewIntegrityError(
                "assistant_pack_integrity_failed",
                "The Assistant acceptance pack failed protected-content validation.",
            ) from exc
        if not prepared.get("ok"):
            raise EvidenceReviewError(
                "assistant_pack_unavailable",
                "The protected Assistant acceptance pack could not be prepared from current data.",
                status_code=404,
            )
        try:
            rows, _ = v533._read_csv(paths.assistant_review)
        except (OSError, ValueError) as exc:
            raise EvidenceReviewIntegrityError(
                "assistant_pack_integrity_failed",
                "The Assistant acceptance pack failed protected-content validation.",
            ) from exc
        digest = _assistant_pack_digest(
            paths,
            secret=settings.assistant_llm_api_key,
        )
        state = _load_state(paths.state)
        workspace = state["assistant"]
        _assert_digest(workspace, digest, code="assistant_pack_changed")
        _claim_workspace(
            workspace,
            current_user=current_user,
            pack_digest=digest,
            reviewed_rows=rows,
        )
        _atomic_write_json(paths.state, state)
        progress = _assistant_progress(
            paths,
            state,
            current_user,
            secret=settings.assistant_llm_api_key,
        )
        return _operation_response(
            workspace="assistant",
            status="assistant_review_started",
            revision=int(workspace.get("revision") or 0),
            progress=progress,
            next_item=(
                _assistant_item(
                    paths,
                    state,
                    current_user,
                    progress["next_pending_index"],
                    secret=settings.assistant_llm_api_key,
                )
                if progress.get("next_pending_index") is not None
                else None
            ),
        )


def _detection_decision_group(decision: str) -> str:
    if decision in {"benign", "benign_unusual"}:
        return "benign_like"
    if decision == "needs_context":
        return "needs_context"
    return "threat_positive"


def _detection_item(
    paths: EvidenceWorkspacePaths,
    state: dict[str, Any],
    current_user: User,
    row_index: int | None,
) -> dict[str, Any]:
    workspace = state["detection"]
    _authorize_owner(workspace, current_user)
    digest = _detection_pack_digest(paths.detection_pack)
    _assert_digest(workspace, digest, code="detection_pack_changed")
    try:
        v528.validate_working_copy(
            pack_path=paths.detection_pack,
            working_path=paths.detection_working,
        )
        rows, _ = v528._read_rows(paths.detection_working)
    except (OSError, ValueError) as exc:
        raise EvidenceReviewIntegrityError(
            "detection_working_copy_invalid",
            "The detection review working copy failed integrity validation.",
        ) from exc
    if row_index is None or row_index < 0 or row_index >= len(rows):
        raise EvidenceReviewError(
            "review_row_out_of_range",
            "The requested review item does not exist.",
            status_code=404,
        )
    row = rows[row_index]
    evidence = {
        field: str(row.get(field) or "").strip()
        for field in v528.DISPLAY_EVIDENCE_FIELDS
        if str(row.get(field) or "").strip()
    }
    reviewed = _boolean(row.get("human_reviewed"))
    existing = None
    if reviewed:
        decision = str(row.get("human_decision") or "").strip().lower()
        existing = {
            "decision_group": _detection_decision_group(decision),
            "decision": decision,
            "attack_type": str(row.get("human_attack_type") or "").strip(),
            "confidence": int(str(row.get("human_confidence") or "0")),
            "rationale": str(row.get("human_notes") or "").strip(),
        }
    return {
        "workspace": "detection",
        "row_index": row_index,
        "display_position": row_index + 1,
        "total": len(rows),
        "revision": int(workspace.get("revision") or 0),
        "reviewed": reviewed,
        "evidence": evidence,
        "existing_review": existing,
        "next_pending_index": _next_pending_index(rows),
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "fingerprints_exposed": False,
        "import_ready": False,
    }


def get_detection_review_item(
    current_user: User,
    *,
    row_index: int,
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        return _detection_item(paths, state, current_user, row_index)


def save_detection_review_item(
    current_user: User,
    *,
    row_index: int,
    expected_revision: int,
    decision_group: str,
    decision: str,
    attack_type: str,
    confidence: int,
    rationale: str,
) -> dict[str, Any]:
    _assert_human_reviewer(current_user)
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        workspace = state["detection"]
        _authorize_owner(workspace, current_user)
        _assert_revision(workspace, expected_revision)
        if decision not in DETECTION_DECISION_GROUPS.get(decision_group, set()):
            raise EvidenceReviewError(
                "decision_group_mismatch",
                "The selected decision does not match its review category.",
                status_code=422,
            )
        try:
            rows, _ = v528._read_rows(paths.detection_working)
        except OSError as exc:
            raise EvidenceReviewIntegrityError(
                "detection_working_copy_invalid",
                "The detection review working copy failed integrity validation.",
            ) from exc
        if row_index < 0 or row_index >= len(rows):
            raise EvidenceReviewError(
                "review_row_out_of_range",
                "The requested review item does not exist.",
                status_code=404,
            )
        if _boolean(rows[row_index].get("human_reviewed")):
            raise EvidenceReviewError(
                "completed_review_is_immutable",
                "This completed human decision cannot be overwritten from the workspace.",
            )
        v528.save_review_entry(
            pack_path=paths.detection_pack,
            working_path=paths.detection_working,
            row_index=row_index,
            decision=decision,
            attack_type=attack_type,
            confidence=confidence,
            notes=rationale,
            reviewer=current_user.username,
        )
        workspace["revision"] = int(workspace.get("revision") or 0) + 1
        workspace["updated_at"] = _now()
        _atomic_write_json(paths.state, state)
        progress = _detection_progress(paths, state, current_user)
        next_index = progress.get("next_pending_index")
        return _operation_response(
            workspace="detection",
            status="detection_review_saved",
            revision=int(workspace["revision"]),
            progress=progress,
            next_item=(
                _detection_item(paths, state, current_user, next_index)
                if next_index is not None
                else None
            ),
        )


def _assistant_existing_input(row: dict[str, str]) -> dict[str, Any] | None:
    if not _boolean(row.get("human_reviewed")):
        return None
    return {
        "scores": {
            name: int(str(row.get(field) or "0"))
            for name, field in ASSISTANT_SCORE_TO_FIELD.items()
        },
        "overall_decision": str(row.get("human_overall_decision") or "").strip(),
        "notes": str(row.get("human_notes") or "").strip(),
    }


def _assistant_item(
    paths: EvidenceWorkspacePaths,
    state: dict[str, Any],
    current_user: User,
    row_index: int | None,
    *,
    secret: str,
) -> dict[str, Any]:
    workspace = state["assistant"]
    _authorize_owner(workspace, current_user)
    digest = _assistant_pack_digest(paths, secret=secret)
    _assert_digest(workspace, digest, code="assistant_pack_changed")
    try:
        rows, _ = v533._read_csv(paths.assistant_review)
    except (OSError, ValueError) as exc:
        raise EvidenceReviewIntegrityError(
            "assistant_pack_integrity_failed",
            "The Assistant acceptance pack failed protected-content validation.",
        ) from exc
    if row_index is None or row_index < 0 or row_index >= len(rows):
        raise EvidenceReviewError(
            "review_row_out_of_range",
            "The requested review item does not exist.",
            status_code=404,
        )
    row = rows[row_index]
    if _boolean(row.get("raw_log_context_included")) or _boolean(
        row.get("action_executed")
    ):
        raise EvidenceReviewIntegrityError(
            "assistant_safety_contract_failed",
            "The Assistant acceptance item failed its read-only privacy contract.",
        )
    return {
        "workspace": "assistant",
        "row_index": row_index,
        "display_position": row_index + 1,
        "total": len(rows),
        "revision": int(workspace.get("revision") or 0),
        "reviewed": _boolean(row.get("human_reviewed")),
        "context_type": str(row.get("context_type") or "general").strip(),
        "question": str(row.get("question") or "").strip(),
        "answer": str(row.get("answer") or "").strip(),
        "citations": str(row.get("citations") or "").strip(),
        "existing_review": _assistant_existing_input(row),
        "next_pending_index": _next_pending_index(rows),
        "raw_log_context_included": False,
        "action_executed": False,
        "secrets_exposed": False,
        "import_ready": False,
    }


def get_assistant_review_item(
    current_user: User,
    *,
    row_index: int,
    settings: Settings,
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        return _assistant_item(
            paths,
            state,
            current_user,
            row_index,
            secret=settings.assistant_llm_api_key,
        )


def save_assistant_review_item(
    current_user: User,
    *,
    row_index: int,
    expected_revision: int,
    scores: dict[str, int],
    overall_decision: str,
    notes: str,
    settings: Settings,
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        workspace = state["assistant"]
        _authorize_owner(workspace, current_user)
        _assert_revision(workspace, expected_revision)
        digest = _assistant_pack_digest(
            paths,
            secret=settings.assistant_llm_api_key,
        )
        _assert_digest(workspace, digest, code="assistant_pack_changed")
        try:
            rows, columns = v533._read_csv(paths.assistant_review)
        except (OSError, ValueError) as exc:
            raise EvidenceReviewIntegrityError(
                "assistant_pack_integrity_failed",
                "The Assistant acceptance pack failed protected-content validation.",
            ) from exc
        if row_index < 0 or row_index >= len(rows):
            raise EvidenceReviewError(
                "review_row_out_of_range",
                "The requested review item does not exist.",
                status_code=404,
            )
        if _boolean(rows[row_index].get("human_reviewed")):
            raise EvidenceReviewError(
                "completed_review_is_immutable",
                "This completed human acceptance decision cannot be overwritten.",
            )
        _assert_human_reviewer(current_user)
        if overall_decision in {"revise", "reject"} and len(notes.strip()) < 8:
            raise EvidenceReviewError(
                "review_notes_required",
                "A short review note is required for revise or reject decisions.",
                status_code=422,
            )
        if set(scores) != set(ASSISTANT_SCORE_TO_FIELD) or any(
            score < 1 or score > 5 for score in scores.values()
        ):
            raise EvidenceReviewError(
                "assistant_scores_invalid",
                "Every Assistant acceptance dimension requires a score from 1 to 5.",
                status_code=422,
            )
        original_rows = [dict(row) for row in rows]
        updated = dict(rows[row_index])
        updated.update(
            {
                ASSISTANT_SCORE_TO_FIELD[name]: str(score)
                for name, score in scores.items()
            }
        )
        updated.update(
            {
                "human_overall_decision": overall_decision,
                "human_notes": " ".join(notes.strip().split()),
                "human_reviewer": current_user.username,
                "human_reviewed_at": _now(),
                "human_reviewed": "true",
                "human_must_confirm": "false",
            }
        )
        rows[row_index] = updated
        try:
            v533._atomic_write_csv(paths.assistant_review, rows, columns)
            validation = v533.validate_assistant_human_review_pack(
                review_path=paths.assistant_review,
                manifest_path=paths.assistant_manifest,
                secret=settings.assistant_llm_api_key,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            v533._atomic_write_csv(paths.assistant_review, original_rows, columns)
            raise EvidenceReviewIntegrityError(
                "assistant_review_validation_failed",
                "The Assistant acceptance decision failed the protected review contract.",
            ) from exc
        expected_valid = sum(
            _boolean(row.get("human_reviewed")) for row in original_rows
        ) + 1
        if (
            not validation.get("ok")
            or int(validation.get("valid_human_reviews") or 0) != expected_valid
        ):
            v533._atomic_write_csv(paths.assistant_review, original_rows, columns)
            raise EvidenceReviewIntegrityError(
                "assistant_review_validation_failed",
                "The Assistant acceptance decision failed the protected review contract.",
            )
        workspace["revision"] = int(workspace.get("revision") or 0) + 1
        workspace["updated_at"] = _now()
        _atomic_write_json(paths.state, state)
        progress = _assistant_progress(
            paths,
            state,
            current_user,
            secret=settings.assistant_llm_api_key,
        )
        next_index = progress.get("next_pending_index")
        return _operation_response(
            workspace="assistant",
            status="assistant_review_saved",
            revision=int(workspace["revision"]),
            progress=progress,
            next_item=(
                _assistant_item(
                    paths,
                    state,
                    current_user,
                    next_index,
                    secret=settings.assistant_llm_api_key,
                )
                if next_index is not None
                else None
            ),
            details={"overall_decision": overall_decision},
        )


def complete_evidence_review(
    current_user: User,
    *,
    workspace_name: str,
    expected_revision: int,
    settings: Settings,
) -> dict[str, Any]:
    paths = _workspace_paths()
    with _WORKSPACE_LOCK:
        state = _load_state(paths.state)
        workspace = state[workspace_name]
        _authorize_owner(workspace, current_user)
        _assert_revision(workspace, expected_revision)
        progress = (
            _detection_progress(paths, state, current_user)
            if workspace_name == "detection"
            else _assistant_progress(
                paths,
                state,
                current_user,
                secret=settings.assistant_llm_api_key,
            )
        )
        if not progress.get("completed"):
            raise EvidenceReviewError(
                "review_incomplete",
                "Complete every valid review item before closing this workspace.",
            )
        workspace["completed_at"] = workspace.get("completed_at") or _now()
        _atomic_write_json(paths.state, state)
        return _operation_response(
            workspace=workspace_name,
            status=f"{workspace_name}_review_completed",
            revision=int(workspace.get("revision") or 0),
            progress=progress,
        )


def _operation_response(
    *,
    workspace: str,
    status: str,
    revision: int,
    progress: dict[str, Any],
    next_item: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": True,
        "workspace": workspace,
        "status": status,
        "revision": revision,
        "progress": progress,
        "next_item": next_item,
        "authoritative_mutations": {
            "labels": 0,
            "model_runs": 0,
            "detection_runs": 0,
            "alerts": 0,
            "response_actions": 0,
        },
        "import_performed": False,
        "model_activation_performed": False,
        "response_action_performed": False,
        "details": details or {},
    }
