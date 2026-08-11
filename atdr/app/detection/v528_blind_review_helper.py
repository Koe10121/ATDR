from __future__ import annotations

import csv
import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v527_blind_review_evaluation as v527


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_DIR = PROJECT_ROOT / "ml_baseline_reviews"
DEFAULT_PACK_PATH = DEFAULT_EVIDENCE_DIR / v521.V521_BLIND_PACK
DEFAULT_WORKING_PATH = (
    DEFAULT_EVIDENCE_DIR / "v5_28_blind_human_review_working.csv"
)
DEFAULT_PROGRESS_PATH = (
    DEFAULT_EVIDENCE_DIR / "v5_28_blind_review_progress_latest.json"
)
V528_VERSION = "v5.28.0"

DISPLAY_EVIDENCE_FIELDS = (
    "evidence_role",
    "pattern",
    "review_priority",
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


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _read_rows(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        return list(reader), list(reader.fieldnames or [])


def _atomic_write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    columns: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as stream:
            temporary_name = stream.name
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _protected_columns(columns: list[str]) -> list[str]:
    return [
        column for column in columns if column not in v527.HUMAN_REVIEW_FIELDS
    ]


def _assert_safe_blind_source(
    rows: list[dict[str, str]],
    columns: list[str],
) -> None:
    missing = {
        "review_token",
        "human_decision",
        "human_reviewer",
        "human_reviewed_at",
        "human_reviewed",
        "human_must_confirm",
        "import_ready",
    } - set(columns)
    if missing:
        raise ValueError("Blind review source is missing required review fields.")
    if not rows:
        raise ValueError("Blind review source is empty.")
    if v527._prediction_exposure_detected(rows, columns):
        raise ValueError("Blind review source contains prediction or assisted evidence.")
    tokens = [str(row.get("review_token") or "").strip() for row in rows]
    if not all(tokens) or len(tokens) != len(set(tokens)):
        raise ValueError("Blind review source tokens are missing or duplicated.")
    if any(
        str(row.get("evidence_role") or "") != "untouched_future_validation"
        or not _boolean(row.get("evidence_role_is_blind"))
        or not _boolean(row.get("blind_suggestion_suppressed"))
        or _boolean(row.get("raw_log_included"))
        or _boolean(row.get("source_ip_included"))
        or _boolean(row.get("destination_ip_included"))
        or _boolean(row.get("import_ready"))
        for row in rows
    ):
        raise ValueError("Blind review source failed its privacy or evidence-role contract.")


def validate_working_copy(
    *,
    pack_path: Path,
    working_path: Path,
) -> dict[str, Any]:
    if pack_path.resolve() == working_path.resolve():
        raise ValueError("The review working copy must not overwrite the sealed pack.")
    pack_rows, pack_columns = _read_rows(pack_path)
    review_rows, review_columns = _read_rows(working_path)
    _assert_safe_blind_source(pack_rows, pack_columns)
    checks = v527._review_copy_contract(
        pack_rows,
        pack_columns,
        review_rows,
        review_columns,
    )
    if v527._prediction_exposure_detected(review_rows, review_columns):
        raise ValueError("Review working copy contains prediction or assisted evidence.")
    if not all(checks.values()):
        raise ValueError("Review working copy does not match the sealed evidence contract.")
    return {
        "ok": True,
        "status": "working_copy_valid",
        "rows": len(review_rows),
        "checks": checks,
        "predictions_displayed": False,
        "ai_suggestions_displayed": False,
        "raw_logs_displayed": False,
        "ip_addresses_displayed": False,
        "import_ready": False,
    }


def prepare_review_working_copy(
    *,
    pack_path: Path = DEFAULT_PACK_PATH,
    working_path: Path = DEFAULT_WORKING_PATH,
) -> dict[str, Any]:
    if pack_path.resolve() == working_path.resolve():
        raise ValueError("The review working copy must not overwrite the sealed pack.")
    pack_rows, pack_columns = _read_rows(pack_path)
    _assert_safe_blind_source(pack_rows, pack_columns)
    if working_path.exists():
        validation = validate_working_copy(
            pack_path=pack_path,
            working_path=working_path,
        )
        return {**validation, "status": "working_copy_resumed", "created": False}
    _atomic_write_csv(working_path, pack_rows, pack_columns)
    validation = validate_working_copy(
        pack_path=pack_path,
        working_path=working_path,
    )
    return {**validation, "status": "working_copy_created", "created": True}


def _review_values_present(row: dict[str, str]) -> bool:
    return any(
        str(row.get(field) or "").strip()
        for field in (
            "human_decision",
            "human_attack_type",
            "human_confidence",
            "human_notes",
            "human_reviewer",
            "human_reviewed_at",
        )
    )


def review_progress(
    *,
    pack_path: Path = DEFAULT_PACK_PATH,
    working_path: Path = DEFAULT_WORKING_PATH,
) -> dict[str, Any]:
    if not working_path.is_file():
        pack_rows, pack_columns = _read_rows(pack_path)
        _assert_safe_blind_source(pack_rows, pack_columns)
        return {
            "ok": True,
            "status": "working_copy_not_prepared",
            "schema_version": V528_VERSION,
            "total": len(pack_rows),
            "reviewed": 0,
            "remaining": len(pack_rows),
            "invalid": 0,
            "decision_class_counts": {},
            "binary_queue_classes_present": 0,
            "minimum_legitimate_reviews": v527.MIN_REVIEWED_ROWS,
            "enough_for_locked_evaluation": False,
            "invalid_reason_counts": {},
            "working_copy_exists": False,
            "metrics_calculated": False,
            "prediction_counts_returned": False,
            "predictions_displayed": False,
            "ai_suggestions_displayed": False,
            "review_tokens_returned": False,
            "reviewer_identities_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "fingerprints_returned": False,
            "import_ready": False,
            "automatic_import_performed": False,
        }
    validate_working_copy(pack_path=pack_path, working_path=working_path)
    rows, columns = _read_rows(working_path)
    known_tokens = {
        str(row.get("review_token") or "").strip() for row in rows
    }
    decisions: Counter[str] = Counter()
    invalid_reasons: Counter[str] = Counter()
    reviewed = 0
    invalid = 0
    remaining = 0
    for row in rows:
        if not _boolean(row.get("human_reviewed")) and not _review_values_present(row):
            remaining += 1
            continue
        reasons = v527._row_review_reasons(
            row,
            known_tokens=known_tokens,
            blindness_compromised=v527._prediction_exposure_detected(rows, columns),
        )
        if reasons:
            invalid += 1
            invalid_reasons.update(reasons)
            continue
        reviewed += 1
        decisions[str(row.get("human_decision") or "").strip().lower()] += 1
    queue_classes = {
        "needs_review" if decision in v527.QUEUE_DECISIONS else "non_threat"
        for decision in decisions
    }
    enough_for_locked_evaluation = (
        reviewed >= v527.MIN_REVIEWED_ROWS
        and queue_classes == {"needs_review", "non_threat"}
        and invalid == 0
    )
    return {
        "ok": True,
        "status": (
            "ready_for_locked_post_review_evaluation"
            if enough_for_locked_evaluation
            else "human_review_in_progress"
        ),
        "schema_version": V528_VERSION,
        "total": len(rows),
        "reviewed": reviewed,
        "remaining": remaining,
        "invalid": invalid,
        "decision_class_counts": dict(sorted(decisions.items())),
        "binary_queue_classes_present": len(queue_classes),
        "minimum_legitimate_reviews": v527.MIN_REVIEWED_ROWS,
        "enough_for_locked_evaluation": enough_for_locked_evaluation,
        "invalid_reason_counts": dict(sorted(invalid_reasons.items())),
        "working_copy_exists": True,
        "metrics_calculated": False,
        "prediction_counts_returned": False,
        "predictions_displayed": False,
        "ai_suggestions_displayed": False,
        "review_tokens_returned": False,
        "reviewer_identities_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
        "import_ready": False,
        "automatic_import_performed": False,
    }


def save_review_entry(
    *,
    pack_path: Path,
    working_path: Path,
    row_index: int,
    decision: str,
    attack_type: str,
    confidence: int,
    notes: str,
    reviewer: str,
    reviewed_at: datetime | None = None,
) -> dict[str, Any]:
    validate_working_copy(pack_path=pack_path, working_path=working_path)
    rows, columns = _read_rows(working_path)
    if row_index < 0 or row_index >= len(rows):
        raise ValueError("Review row index is outside the working copy.")
    clean_decision = decision.strip().lower()
    updated = dict(rows[row_index])
    updated.update(
        {
            "human_decision": clean_decision,
            "human_attack_type": attack_type.strip().lower(),
            "human_confidence": str(confidence),
            "human_notes": " ".join(notes.strip().split()),
            "human_reviewer": reviewer.strip(),
            "human_reviewed_at": (reviewed_at or datetime.now(UTC)).astimezone(
                UTC
            ).isoformat(),
            "human_must_confirm": "false",
            "human_reviewed": "true",
        }
    )
    known_tokens = {
        str(row.get("review_token") or "").strip() for row in rows
    }
    reasons = v527._row_review_reasons(
        updated,
        known_tokens=known_tokens,
        blindness_compromised=False,
    )
    if reasons:
        raise ValueError(
            "Review entry failed validation: " + ", ".join(reasons)
        )
    rows[row_index] = updated
    _atomic_write_csv(working_path, rows, columns)
    validate_working_copy(pack_path=pack_path, working_path=working_path)
    return review_progress(pack_path=pack_path, working_path=working_path)


def write_progress_report(
    progress: dict[str, Any],
    *,
    progress_path: Path = DEFAULT_PROGRESS_PATH,
) -> None:
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=progress_path.parent,
            prefix=f".{progress_path.name}.",
            suffix=".tmp",
        ) as stream:
            temporary_name = stream.name
            json.dump(progress, stream, indent=2, sort_keys=True)
        os.replace(temporary_name, progress_path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _display_row(
    row: dict[str, str],
    *,
    position: int,
    total: int,
    output: Callable[[str], None],
) -> None:
    output("")
    output(f"Review row {position + 1} of {total}")
    output("-" * 56)
    for field in DISPLAY_EVIDENCE_FIELDS:
        value = str(row.get(field) or "").strip()
        if value:
            output(f"{field.replace('_', ' ').title()}: {value}")
    output("-" * 56)
    output("No detector prediction, rule suggestion, or AI suggestion is shown.")


def run_interactive_review(
    *,
    pack_path: Path = DEFAULT_PACK_PATH,
    working_path: Path = DEFAULT_WORKING_PATH,
    progress_path: Path = DEFAULT_PROGRESS_PATH,
    reviewer: str,
    input_fn: Callable[[str], str] = input,
    output: Callable[[str], None] = print,
) -> dict[str, Any]:
    prepare_review_working_copy(pack_path=pack_path, working_path=working_path)
    while True:
        rows, _columns = _read_rows(working_path)
        pending = [
            index
            for index, row in enumerate(rows)
            if not _boolean(row.get("human_reviewed"))
        ]
        if not pending:
            break
        index = pending[0]
        row = rows[index]
        _display_row(row, position=index, total=len(rows), output=output)
        decision = input_fn(
            "Decision [benign/benign_unusual/needs_context/suspicious/malicious, skip, quit]: "
        ).strip().lower()
        if decision == "quit":
            break
        if decision == "skip":
            # Move the skipped row to the end for this process without altering disk.
            pending = pending[1:]
            if not pending:
                break
            output("Skipped. Re-run later to review this row.")
            break
        attack_type = input_fn(
            "Attack type (use 'none' for benign evidence): "
        ).strip()
        confidence_text = input_fn("Confidence [1-100]: ").strip()
        notes = input_fn("Analyst notes (minimum 8 characters): ").strip()
        confirmation = input_fn(
            "Confirm this is your independent human decision? [yes/no]: "
        ).strip().lower()
        if confirmation not in {"yes", "y"}:
            output("Not saved. The row remains pending.")
            continue
        try:
            confidence = int(confidence_text)
            progress = save_review_entry(
                pack_path=pack_path,
                working_path=working_path,
                row_index=index,
                decision=decision,
                attack_type=attack_type,
                confidence=confidence,
                notes=notes,
                reviewer=reviewer,
            )
        except (TypeError, ValueError) as exc:
            output(str(exc))
            continue
        write_progress_report(progress, progress_path=progress_path)
        output(
            f"Saved. Reviewed {progress['reviewed']} of {progress['total']}; "
            f"{progress['remaining']} remain."
        )
    progress = review_progress(pack_path=pack_path, working_path=working_path)
    write_progress_report(progress, progress_path=progress_path)
    return progress
