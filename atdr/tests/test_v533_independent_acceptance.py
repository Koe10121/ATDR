from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select

from atdr.app.core.config import Settings
from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection import v528_blind_review_helper as review_helper
from atdr.app.services.v524_investigation_gemini_quality_service import (
    disposable_v524_session,
)
from atdr.app.services.v533_independent_acceptance_service import (
    ASSISTANT_RATING_FIELDS,
    ASSISTANT_REVIEW_COLUMNS,
    REQUIRED_ASSISTANT_CONTEXTS,
    V533_VERSION,
    _atomic_write_csv,
    _atomic_write_json,
    _detection_review_summary,
    _protected_digest,
    prepare_assistant_human_review_pack,
    validate_assistant_human_review_pack,
)


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        ASSISTANT_LLM_ENABLED=False,
        ASSISTANT_LLM_PROVIDER="disabled",
        ASSISTANT_LLM_MODEL="",
        ASSISTANT_LLM_API_KEY="private-test-key",
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
        ASSISTANT_REDACT_IPS=True,
    )


def _review_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for index, context_type in enumerate(sorted(REQUIRED_ASSISTANT_CONTEXTS), start=1):
        rows.append(
            {
                "schema_version": V533_VERSION,
                "review_case_id": f"T{index:02d}",
                "context_type": context_type,
                "question": f"Safe question for {context_type}",
                "answer": "Bounded evidence answer. No action was executed.",
                "citations": "/api/alerts/{alert_id}#1",
                "provider_mode": "deterministic_local",
                "external_provider_used": "false",
                "raw_log_context_included": "false",
                "redaction_applied": "true",
                "action_executed": "false",
                "automated_contract_passed": "true",
                "automated_failed_checks": "",
                "import_ready": "false",
                **{field: "" for field in ASSISTANT_RATING_FIELDS},
                "human_overall_decision": "",
                "human_notes": "",
                "human_reviewer": "",
                "human_reviewed_at": "",
                "human_reviewed": "false",
                "human_must_confirm": "true",
            }
        )
    return rows


def _blind_pack(path: Path, count: int = 20) -> None:
    rows = [
        {
            "review_token": f"token-{index:03d}",
            "evidence_role": "untouched_future_validation",
            "evidence_role_is_blind": "true",
            "blind_suggestion_suppressed": "true",
            "raw_log_included": "false",
            "source_ip_included": "false",
            "destination_ip_included": "false",
            "human_decision": "",
            "human_reviewer": "",
            "human_reviewed_at": "",
            "human_reviewed": "false",
            "human_must_confirm": "true",
            "import_ready": "false",
        }
        for index in range(count)
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_review_contract(
    directory: Path,
    rows: list[dict[str, str]],
) -> tuple[Path, Path]:
    review_path = directory / "assistant-review.csv"
    manifest_path = directory / "assistant-review.manifest.json"
    _atomic_write_csv(review_path, rows, ASSISTANT_REVIEW_COLUMNS)
    _atomic_write_json(
        manifest_path,
        {
            "schema_version": V533_VERSION,
            "row_count": len(rows),
            "protected_digest": _protected_digest(rows),
            "human_decisions_created": 0,
            "import_ready": False,
        },
    )
    return review_path, manifest_path


def test_blind_review_status_is_safe_before_working_copy_exists(
    tmp_path: Path,
) -> None:
    pack = tmp_path / "blind-pack.csv"
    working = tmp_path / "working.csv"
    _blind_pack(pack)
    progress = review_helper.review_progress(
        pack_path=pack,
        working_path=working,
    )
    assert progress["status"] == "working_copy_not_prepared"
    assert progress["total"] == 20
    assert progress["reviewed"] == 0
    assert progress["remaining"] == 20
    assert progress["invalid"] == 0
    assert progress["metrics_calculated"] is False
    assert progress["working_copy_exists"] is False


def test_assistant_review_pack_with_blank_human_fields_is_incomplete(
    tmp_path: Path,
) -> None:
    review_path, manifest_path = _write_review_contract(tmp_path, _review_rows())
    report = validate_assistant_human_review_pack(
        review_path=review_path,
        manifest_path=manifest_path,
        secret="private-test-key",
    )
    assert report["ok"] is True
    assert report["incomplete_rows"] == len(REQUIRED_ASSISTANT_CONTEXTS)
    assert report["invalid_rows"] == 0
    assert report["valid_human_reviews"] == 0
    assert report["required_pack_contexts_present"] is True
    assert report["human_acceptance_permitted"] is False
    assert report["human_metrics_calculated"] is False
    assert report["human_metrics"] is None
    assert report["answers_returned"] is False
    assert report["import_ready"] is False


def test_detection_summary_never_reveals_metrics_before_review_gate() -> None:
    summary = _detection_review_summary(
        closure={
            "evidence_inventory": {"real_source_identity_count": 1},
            "historical_evidence": {
                "native_panos_unlabeled_evidence": {
                    "distinct_time_windows": 22,
                    "second_real_device_available": False,
                }
            },
            "evidence_lock_audit": {
                "checks": {
                    "v521_cross_role_exact_overlap_zero": True,
                    "v521_cross_role_near_overlap_zero": True,
                }
            },
        },
        evaluation={
            "review_intake": {
                "enough_for_metrics": False,
                "lock_checks": {
                    "prediction_tokens_unique": True,
                    "predictions_precede_label_access": True,
                },
                "review_copy_checks": {"review_tokens_unique": True},
            },
            "locked_evaluation": {
                "metrics_calculated": True,
                "supervised": {"queue_f1": 0.99},
            },
        },
        progress={
            "total": 40,
            "reviewed": 0,
            "remaining": 40,
            "invalid": 0,
            "binary_queue_classes_present": 0,
            "working_copy_exists": False,
        },
    )
    assert summary["frozen_evaluation_permitted"] is False
    assert summary["frozen_metrics"] is None
    assert summary["prediction_before_label_integrity"] is True
    assert not any(summary["duplicate_or_leakage_findings"].values())


def test_assistant_review_accepts_only_complete_human_provenance(
    tmp_path: Path,
) -> None:
    rows = _review_rows()
    timestamp = datetime(2026, 8, 11, 9, 0, tzinfo=UTC).isoformat()
    for row in rows:
        for field in ASSISTANT_RATING_FIELDS:
            row[field] = "5"
        row.update(
            {
                "human_overall_decision": "accept",
                "human_notes": "",
                "human_reviewer": "independent-reviewer-01",
                "human_reviewed_at": timestamp,
                "human_reviewed": "true",
                "human_must_confirm": "false",
            }
        )
    review_path, manifest_path = _write_review_contract(tmp_path, rows)
    report = validate_assistant_human_review_pack(
        review_path=review_path,
        manifest_path=manifest_path,
    )
    assert report["valid_human_reviews"] == len(REQUIRED_ASSISTANT_CONTEXTS)
    assert report["human_acceptance_permitted"] is True
    assert report["human_metrics_calculated"] is True
    assert report["human_acceptance_passed"] is True
    assert report["reviewer_identities_returned"] is False


def test_assistant_review_rejects_ai_reviewer_and_protected_tampering(
    tmp_path: Path,
) -> None:
    rows = _review_rows()
    timestamp = datetime(2026, 8, 11, 9, 0, tzinfo=UTC).isoformat()
    for row in rows:
        for field in ASSISTANT_RATING_FIELDS:
            row[field] = "5"
        row.update(
            {
                "human_overall_decision": "accept",
                "human_reviewer": "Gemini automated reviewer",
                "human_reviewed_at": timestamp,
                "human_reviewed": "true",
                "human_must_confirm": "false",
            }
        )
    review_path, manifest_path = _write_review_contract(tmp_path, rows)
    rows[0]["answer"] = "Tampered answer"
    with review_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=ASSISTANT_REVIEW_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    report = validate_assistant_human_review_pack(
        review_path=review_path,
        manifest_path=manifest_path,
    )
    assert report["protected_content_integrity_passed"] is False
    assert report["human_acceptance_permitted"] is False
    assert report["human_metrics_calculated"] is False
    assert report["invalid_reason_counts"]["automated_reviewer_not_allowed"]
    assert report["invalid_reason_counts"]["protected_content_integrity_failed"]


def test_assistant_review_preparation_is_private_and_read_only(
    tmp_path: Path,
) -> None:
    review_path = tmp_path / "assistant-review.csv"
    manifest_path = tmp_path / "assistant-review.manifest.json"
    with disposable_v524_session() as db:
        before = {
            "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
            "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
            "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        }
        prepared = prepare_assistant_human_review_pack(
            db,
            settings=_settings(),
            review_path=review_path,
            manifest_path=manifest_path,
        )
        after = {
            "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
            "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
            "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        }

    assert prepared["ok"] is True
    assert prepared["question_count"] >= len(REQUIRED_ASSISTANT_CONTEXTS)
    assert prepared["automated_contract_passed_rows"] == prepared["question_count"]
    assert prepared["provider_used_rows"] == 0
    assert prepared["human_decisions_created"] == 0
    assert prepared["import_ready"] is False
    assert prepared["secrets_exposed"] is False
    assert before == after

    serialized = review_path.read_text(encoding="utf-8")
    assert "private-test-key" not in serialized
    assert "raw evidence" not in serialized.lower()
    validation = validate_assistant_human_review_pack(
        review_path=review_path,
        manifest_path=manifest_path,
        secret="private-test-key",
    )
    assert validation["privacy_checks"] == {
        "raw_log_context_absent": True,
        "ip_addresses_absent": True,
        "absolute_private_paths_absent": True,
        "secrets_absent": True,
        "import_ready_false": True,
        "action_executed_false": True,
    }
