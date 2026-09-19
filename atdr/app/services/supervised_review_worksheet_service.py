from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.db.models import User
from atdr.app.detection import v562_supervised_qualification_campaign as v562_campaign
from atdr.app.services import v562_supervised_qualification_review_service as v562_review
from atdr.app.services import v563_supervised_expansion_review_service as v563_review
from atdr.app.services import v565_extended_expansion_review_service as v565_review
from atdr.app.services import v567_signal_concentrated_expansion_review_service as v567_review
from atdr.app.services.evidence_review_service import (
    EvidenceReviewError,
    EvidenceReviewIntegrityError,
)

CONFIRM_TOKEN = "yes"
_PAGE_LIMIT = 1_000_000

WORKSHEET_COLUMNS: tuple[str, ...] = (
    "workspace",
    "batch_id",
    "row_index",
    "coverage_group",
    *v562_campaign.APPROVED_EVIDENCE_FIELDS,
    "decision",
    "attack_type",
    "confidence",
    "rationale",
    "confirm",
)


def resolve_reviewer(
    db: Session,
    *,
    user_id: int | None = None,
    username: str | None = None,
) -> User:
    if user_id is not None:
        user = db.get(User, user_id)
        if user is None:
            raise ValueError(f"No user with id {user_id}.")
        return user
    if username:
        user = db.query(User).filter(User.username == username).one_or_none()
        if user is None:
            raise ValueError(f"No user with username {username!r}.")
        return user
    paths = v562_campaign._workspace_paths()
    state = v562_review._load_state(paths["review_state"])
    owner_id = state.get("owner_user_id")
    if owner_id is None:
        raise ValueError(
            "No reviewer specified and the v5.62 workspace has no assigned owner "
            "yet. Pass user_id/username explicitly, or start review once through "
            "the UI first."
        )
    user = db.get(User, int(owner_id))
    if user is None:
        raise ValueError(
            "The v5.62 workspace owner_user_id does not match any existing user."
        )
    return user


def _row_for_item(workspace: str, batch_id: str, item: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "workspace": workspace,
        "batch_id": batch_id,
        "row_index": item["row_index"],
        "coverage_group": item.get("coverage_group", ""),
    }
    evidence = item.get("evidence", {})
    for field in v562_campaign.APPROVED_EVIDENCE_FIELDS:
        row[field] = evidence.get(field, "")
    row["decision"] = ""
    row["attack_type"] = ""
    row["confidence"] = ""
    row["rationale"] = ""
    row["confirm"] = ""
    return row


def _export_v562(user: User, include_reviewed: bool) -> list[dict[str, Any]]:
    review_state = "all" if include_reviewed else "pending"
    result = v562_review.list_qualification_review_items(
        user, offset=0, limit=_PAGE_LIMIT, review_state=review_state
    )
    return [_row_for_item("v562", "", item) for item in result["items"]]


def _export_v563(
    user: User, include_reviewed: bool, auto_start_batches: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    status = v563_review.get_expansion_review_status(user)
    review_state = "all" if include_reviewed else "pending"
    rows: list[dict[str, Any]] = []
    skipped_batches: list[str] = []
    for batch in status.get("batches", []):
        batch_id = str(batch["batch_id"])
        if not batch.get("owner_assigned"):
            if not auto_start_batches:
                skipped_batches.append(batch_id)
                continue
            v563_review.start_expansion_review_batch(user, batch_id=batch_id)
        elif not batch.get("owned_by_current_user"):
            skipped_batches.append(batch_id)
            continue
        result = v563_review.list_expansion_review_items(
            user,
            batch_id=batch_id,
            offset=0,
            limit=_PAGE_LIMIT,
            review_state=review_state,
        )
        rows.extend(_row_for_item("v563", batch_id, item) for item in result["items"])
    return rows, skipped_batches


def _export_v565(
    user: User, include_reviewed: bool, auto_start_batches: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    status = v565_review.get_extended_expansion_review_status(user)
    review_state = "all" if include_reviewed else "pending"
    rows: list[dict[str, Any]] = []
    skipped_batches: list[str] = []
    for batch in status.get("batches", []):
        batch_id = str(batch["batch_id"])
        if not batch.get("owner_assigned"):
            if not auto_start_batches:
                skipped_batches.append(batch_id)
                continue
            v565_review.start_extended_expansion_review_batch(user, batch_id=batch_id)
        elif not batch.get("owned_by_current_user"):
            skipped_batches.append(batch_id)
            continue
        result = v565_review.list_extended_expansion_review_items(
            user,
            batch_id=batch_id,
            offset=0,
            limit=_PAGE_LIMIT,
            review_state=review_state,
        )
        rows.extend(_row_for_item("v565", batch_id, item) for item in result["items"])
    return rows, skipped_batches


def _export_v567(
    user: User, include_reviewed: bool, auto_start_batches: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    status = v567_review.get_signal_concentrated_expansion_review_status(user)
    review_state = "all" if include_reviewed else "pending"
    rows: list[dict[str, Any]] = []
    skipped_batches: list[str] = []
    for batch in status.get("batches", []):
        batch_id = str(batch["batch_id"])
        if not batch.get("owner_assigned"):
            if not auto_start_batches:
                skipped_batches.append(batch_id)
                continue
            v567_review.start_signal_concentrated_expansion_review_batch(user, batch_id=batch_id)
        elif not batch.get("owned_by_current_user"):
            skipped_batches.append(batch_id)
            continue
        result = v567_review.list_signal_concentrated_expansion_review_items(
            user,
            batch_id=batch_id,
            offset=0,
            limit=_PAGE_LIMIT,
            review_state=review_state,
        )
        rows.extend(_row_for_item("v567", batch_id, item) for item in result["items"])
    return rows, skipped_batches


def export_worksheet(
    *,
    user: User,
    workspace: str = "all",
    include_reviewed: bool = False,
    auto_start_batches: bool = False,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if workspace in ("v562", "both", "all"):
        try:
            rows.extend(_export_v562(user, include_reviewed))
        except (EvidenceReviewError, EvidenceReviewIntegrityError) as exc:
            warnings.append(f"v562: {exc}")
    if workspace in ("v563", "both", "all"):
        try:
            v563_rows, skipped = _export_v563(user, include_reviewed, auto_start_batches)
            rows.extend(v563_rows)
            if skipped:
                warnings.append(
                    "v563: skipped batches with no owner or owned by another "
                    "reviewer: " + ", ".join(sorted(skipped))
                )
        except (EvidenceReviewError, EvidenceReviewIntegrityError) as exc:
            warnings.append(f"v563: {exc}")
    if workspace in ("v565", "all"):
        try:
            v565_rows, skipped = _export_v565(user, include_reviewed, auto_start_batches)
            rows.extend(v565_rows)
            if skipped:
                warnings.append(
                    "v565: skipped batches with no owner or owned by another "
                    "reviewer: " + ", ".join(sorted(skipped))
                )
        except (EvidenceReviewError, EvidenceReviewIntegrityError) as exc:
            warnings.append(f"v565: {exc}")
    if workspace in ("v567", "all"):
        try:
            v567_rows, skipped = _export_v567(user, include_reviewed, auto_start_batches)
            rows.extend(v567_rows)
            if skipped:
                warnings.append(
                    "v567: skipped batches with no owner or owned by another "
                    "reviewer: " + ", ".join(sorted(skipped))
                )
        except (EvidenceReviewError, EvidenceReviewIntegrityError) as exc:
            warnings.append(f"v567: {exc}")
    return {"rows": rows, "warnings": warnings, "row_count": len(rows)}


def write_worksheet_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=WORKSHEET_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def read_worksheet_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _v562_reviewed_map(user: User) -> dict[int, bool]:
    result = v562_review.list_qualification_review_items(
        user, offset=0, limit=_PAGE_LIMIT, review_state="all"
    )
    return {int(item["row_index"]): bool(item["reviewed"]) for item in result["items"]}


def _v563_reviewed_map(user: User, batch_id: str) -> dict[int, bool]:
    result = v563_review.list_expansion_review_items(
        user, batch_id=batch_id, offset=0, limit=_PAGE_LIMIT, review_state="all"
    )
    return {int(item["row_index"]): bool(item["reviewed"]) for item in result["items"]}


def _v565_reviewed_map(user: User, batch_id: str) -> dict[int, bool]:
    result = v565_review.list_extended_expansion_review_items(
        user, batch_id=batch_id, offset=0, limit=_PAGE_LIMIT, review_state="all"
    )
    return {int(item["row_index"]): bool(item["reviewed"]) for item in result["items"]}


def _v567_reviewed_map(user: User, batch_id: str) -> dict[int, bool]:
    result = v567_review.list_signal_concentrated_expansion_review_items(
        user, batch_id=batch_id, offset=0, limit=_PAGE_LIMIT, review_state="all"
    )
    return {int(item["row_index"]): bool(item["reviewed"]) for item in result["items"]}


def import_worksheet(
    *,
    user: User,
    rows: list[dict[str, str]],
    overwrite_existing: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    submitted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    awaiting_confirmation: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    v562_revision: int | None = None
    v562_reviewed: dict[int, bool] | None = None
    v563_revisions: dict[str, int] = {}
    v563_reviewed: dict[str, dict[int, bool]] = {}
    v565_revisions: dict[str, int] = {}
    v565_reviewed: dict[str, dict[int, bool]] = {}
    v567_revisions: dict[str, int] = {}
    v567_reviewed: dict[str, dict[int, bool]] = {}

    for raw in rows:
        workspace = (raw.get("workspace") or "").strip()
        decision = (raw.get("decision") or "").strip()
        if not decision:
            continue

        batch_id = (raw.get("batch_id") or "").strip()
        attack_type = (raw.get("attack_type") or "").strip()
        rationale = (raw.get("rationale") or "").strip()
        confirm = (raw.get("confirm") or "").strip().casefold()
        location: dict[str, Any] = {
            "workspace": workspace,
            "batch_id": batch_id or None,
            "row_index": raw.get("row_index"),
        }

        try:
            row_index = int(str(raw.get("row_index") or "").strip())
        except ValueError:
            failed.append({**location, "reason": "row_index must be an integer"})
            continue
        location["row_index"] = row_index

        if confirm != CONFIRM_TOKEN:
            awaiting_confirmation.append(
                {**location, "reason": f"type '{CONFIRM_TOKEN}' in the confirm column to submit this decision"}
            )
            continue

        try:
            confidence = int(str(raw.get("confidence") or "").strip())
        except ValueError:
            failed.append({**location, "reason": "confidence must be an integer 1-100"})
            continue

        try:
            if workspace == "v562":
                if v562_revision is None:
                    v562_revision = int(v562_review.get_qualification_review_status(user)["revision"])
                if v562_reviewed is None:
                    v562_reviewed = _v562_reviewed_map(user)
                if v562_reviewed.get(row_index) and not overwrite_existing:
                    skipped.append({**location, "reason": "already reviewed"})
                    continue
                if dry_run:
                    submitted.append({**location, "dry_run": True})
                    continue
                result = v562_review.save_qualification_review_item(
                    user,
                    row_index=row_index,
                    expected_revision=v562_revision,
                    decision=decision,
                    attack_type=attack_type,
                    confidence=confidence,
                    rationale=rationale,
                )
                v562_revision = int(result["revision"])
                submitted.append(location)

            elif workspace == "v563":
                if not batch_id:
                    failed.append({**location, "reason": "missing batch_id"})
                    continue
                if batch_id not in v563_revisions:
                    status = v563_review.get_expansion_review_status(user)
                    batch_status = next(
                        (b for b in status["batches"] if b["batch_id"] == batch_id),
                        None,
                    )
                    if batch_status is None:
                        failed.append({**location, "reason": "unknown batch_id"})
                        continue
                    v563_revisions[batch_id] = int(batch_status["revision"])
                if batch_id not in v563_reviewed:
                    v563_reviewed[batch_id] = _v563_reviewed_map(user, batch_id)
                if v563_reviewed[batch_id].get(row_index) and not overwrite_existing:
                    skipped.append({**location, "reason": "already reviewed"})
                    continue
                if dry_run:
                    submitted.append({**location, "dry_run": True})
                    continue
                result = v563_review.save_expansion_review_item(
                    user,
                    batch_id=batch_id,
                    row_index=row_index,
                    expected_revision=v563_revisions[batch_id],
                    decision=decision,
                    attack_type=attack_type,
                    confidence=confidence,
                    rationale=rationale,
                )
                v563_revisions[batch_id] = int(result["revision"])
                submitted.append(location)

            elif workspace == "v565":
                if not batch_id:
                    failed.append({**location, "reason": "missing batch_id"})
                    continue
                if batch_id not in v565_revisions:
                    status = v565_review.get_extended_expansion_review_status(user)
                    batch_status = next(
                        (b for b in status["batches"] if b["batch_id"] == batch_id),
                        None,
                    )
                    if batch_status is None:
                        failed.append({**location, "reason": "unknown batch_id"})
                        continue
                    v565_revisions[batch_id] = int(batch_status["revision"])
                if batch_id not in v565_reviewed:
                    v565_reviewed[batch_id] = _v565_reviewed_map(user, batch_id)
                if v565_reviewed[batch_id].get(row_index) and not overwrite_existing:
                    skipped.append({**location, "reason": "already reviewed"})
                    continue
                if dry_run:
                    submitted.append({**location, "dry_run": True})
                    continue
                result = v565_review.save_extended_expansion_review_item(
                    user,
                    batch_id=batch_id,
                    row_index=row_index,
                    expected_revision=v565_revisions[batch_id],
                    decision=decision,
                    attack_type=attack_type,
                    confidence=confidence,
                    rationale=rationale,
                )
                v565_revisions[batch_id] = int(result["revision"])
                submitted.append(location)

            elif workspace == "v567":
                if not batch_id:
                    failed.append({**location, "reason": "missing batch_id"})
                    continue
                if batch_id not in v567_revisions:
                    status = v567_review.get_signal_concentrated_expansion_review_status(user)
                    batch_status = next(
                        (b for b in status["batches"] if b["batch_id"] == batch_id),
                        None,
                    )
                    if batch_status is None:
                        failed.append({**location, "reason": "unknown batch_id"})
                        continue
                    v567_revisions[batch_id] = int(batch_status["revision"])
                if batch_id not in v567_reviewed:
                    v567_reviewed[batch_id] = _v567_reviewed_map(user, batch_id)
                if v567_reviewed[batch_id].get(row_index) and not overwrite_existing:
                    skipped.append({**location, "reason": "already reviewed"})
                    continue
                if dry_run:
                    submitted.append({**location, "dry_run": True})
                    continue
                result = v567_review.save_signal_concentrated_expansion_review_item(
                    user,
                    batch_id=batch_id,
                    row_index=row_index,
                    expected_revision=v567_revisions[batch_id],
                    decision=decision,
                    attack_type=attack_type,
                    confidence=confidence,
                    rationale=rationale,
                )
                v567_revisions[batch_id] = int(result["revision"])
                submitted.append(location)

            else:
                failed.append({**location, "reason": f"unknown workspace {workspace!r}"})
        except (EvidenceReviewError, EvidenceReviewIntegrityError) as exc:
            failed.append({**location, "reason": str(exc)})

    return {
        "ok": not failed,
        "dry_run": dry_run,
        "submitted": len(submitted),
        "skipped_already_reviewed": len(skipped),
        "awaiting_confirmation": len(awaiting_confirmation),
        "failed": len(failed),
        "submitted_rows": submitted,
        "skipped_rows": skipped,
        "awaiting_confirmation_rows": awaiting_confirmation,
        "failed_rows": failed,
    }
