from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.services import evidence_review_service as review_service
from atdr.app.services import v533_independent_acceptance_service as v533
from atdr.app.services import v539_independent_evidence_decision_service as service
from atdr.scripts import run_v536_independent_evidence_activation_decision as legacy_cli


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        ASSISTANT_LLM_ENABLED=False,
        ASSISTANT_LLM_PROVIDER="disabled",
        ASSISTANT_LLM_API_KEY="private-test-secret",
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
    )


def _detection_row(index: int, *, complete: bool) -> dict[str, object]:
    threat = index % 2 == 1
    row: dict[str, object] = {
        "review_token": f"private-token-{index:03d}",
        "evidence_role": "untouched_future_validation",
        "evidence_role_is_blind": True,
        "pattern": "scan_like" if threat else "routine_web",
        "review_priority": "high",
        "event_time_utc": f"2026-05-{20 + (index % 2):02d}T10:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "unknown" if threat else "ssl",
        "action": "deny" if threat else "allow",
        "protocol": "tcp",
        "source_port": 45000 + index,
        "destination_port": 22 if threat else 443,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 5 if threat else 2,
        "threat_severity": "",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 20 if threat else 2,
        "source_deny_count": 12 if threat else 0,
        "source_unique_destinations": 10 if threat else 1,
        "source_unique_ports": 12 if threat else 1,
        "source_unknown_app_count": 10 if threat else 0,
        "source_high_risk_app_count": 4 if threat else 0,
        "destination_repeat_count": 1,
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "human_decision": "suspicious" if complete and threat else "benign" if complete else "",
        "human_attack_type": "port_scan" if complete and threat else "none" if complete else "",
        "human_confidence": "90" if complete else "",
        "human_notes": "Independent evidence supports this human decision." if complete else "",
        "human_reviewer": "human-reviewer" if complete else "",
        "human_reviewed_at": "2026-08-13T10:00:00+00:00" if complete else "",
        "human_must_confirm": not complete,
        "import_ready": False,
        "assisted_suggestion": "",
        "assisted_attack_type": "",
        "assisted_confidence": "",
        "assisted_reason": "",
        "assisted_provenance": "",
        "rule_codes": "",
        "rule_score": "",
        "suggestion_is_weak": False,
        "human_reviewed": complete,
        "blind_suggestion_suppressed": True,
    }
    return row


def _assistant_rows(*, complete: bool) -> list[dict[str, str]]:
    contexts = [
        "alert",
        "log",
        "source",
        "case",
        "ml_governance",
        "safe_response",
        "alert",
        "case",
    ]
    rows: list[dict[str, str]] = []
    for index, context in enumerate(contexts, start=1):
        row = {
            "schema_version": v533.V533_VERSION,
            "review_case_id": f"T{index:02d}",
            "context_type": context,
            "question": f"Summarize the protected {context} evidence.",
            "answer": "Concise evidence-grounded answer. No action was executed.",
            "citations": "/api/alerts/{alert_id}#sanitized",
            "provider_mode": "deterministic_local",
            "response_mode": "direct",
            "word_count": "8",
            "word_limit": "120",
            "provider_failure_category": "",
            "provider_fallback_reason": "",
            "provider_contract_passed": "true",
            "external_provider_used": "false",
            "raw_log_context_included": "false",
            "redaction_applied": "true",
            "action_executed": "false",
            "automated_contract_passed": "true",
            "automated_failed_checks": "",
            "import_ready": "false",
            **{
                field: "5" if complete else ""
                for field in v533.ASSISTANT_RATING_FIELDS
            },
            "human_overall_decision": "accept" if complete else "",
            "human_notes": "",
            "human_reviewer": "human-reviewer" if complete else "",
            "human_reviewed_at": "2026-08-13T10:00:00+00:00" if complete else "",
            "human_reviewed": "true" if complete else "false",
            "human_must_confirm": "false" if complete else "true",
        }
        rows.append(row)
    return rows


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _prepare_paths(
    tmp_path: Path,
    *,
    complete: bool,
    closed: bool,
) -> review_service.EvidenceWorkspacePaths:
    paths = review_service.EvidenceWorkspacePaths(
        evidence_dir=tmp_path,
        detection_pack=tmp_path / "sealed-detection.csv",
        detection_working=tmp_path / "detection-working.csv",
        assistant_review=tmp_path / "assistant-review.csv",
        assistant_manifest=tmp_path / "assistant-manifest.json",
        state=tmp_path / "workspace-state.json",
    )
    detection_pack = [_detection_row(index, complete=False) for index in range(40)]
    detection_working = [
        _detection_row(index, complete=complete) for index in range(40)
    ]
    _write_csv(paths.detection_pack, detection_pack)
    _write_csv(paths.detection_working, detection_working)
    assistant_rows = _assistant_rows(complete=complete)
    v533._atomic_write_csv(
        paths.assistant_review,
        assistant_rows,
        v533.ASSISTANT_REVIEW_COLUMNS,
    )
    v533._atomic_write_json(
        paths.assistant_manifest,
        {
            "schema_version": v533.V533_VERSION,
            "row_count": len(assistant_rows),
            "protected_digest": v533._protected_digest(assistant_rows),
            "human_decisions_created": 0,
            "import_ready": False,
        },
    )
    settings = _settings()
    state = {
        "schema_version": review_service.V537_VERSION,
        "detection": {},
        "assistant": {},
    }
    if complete:
        for workspace in ("detection", "assistant"):
            state[workspace] = {
                "owner_user_id": 1,
                "owner_username": "human-reviewer",
                "started_at": "2026-08-13T09:00:00+00:00",
                "completed_at": "2026-08-13T11:00:00+00:00" if closed else None,
                "revision": 40 if workspace == "detection" else 8,
            }
        state["detection"]["pack_digest"] = review_service._detection_pack_digest(
            paths.detection_pack
        )
        state["assistant"]["pack_digest"] = review_service._assistant_pack_digest(
            paths,
            secret=settings.assistant_llm_api_key,
        )
    review_service._atomic_write_json(paths.state, state)
    return paths


def _db() -> tuple[Session, object]:
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    return Session(engine), engine


def _passing_v536_report() -> dict[str, object]:
    supervised = {
        "rows": 40,
        "queue_precision": 0.9,
        "queue_recall": 0.85,
        "queue_f1": 0.87,
        "benign_like_false_positive_rate": 0.04,
        "suspicious_recall": 0.75,
        "malicious_recall": 0.8,
        "macro_f1": 0.86,
        "weighted_f1": 0.87,
        "review_queue_size": 20,
        "review_queue_rate": 0.5,
        "calibration": {
            "status": "passed",
            "passed": True,
            "brier_score": 0.08,
            "expected_calibration_error": 0.06,
            "max_confidence_accuracy_gap": 0.1,
        },
    }
    return {
        "ok": True,
        "blind_layer_evaluation": {
            "status": "locked_blind_metrics_calculated",
            "metrics_calculated": True,
            "rows": 40,
            "layers": {"supervised": supervised},
        },
        "assistant_human_acceptance": {
            "status": "assistant_human_acceptance_passed",
            "valid_human_reviews": 8,
            "total_rows": 8,
            "human_metrics": {"factual_correctness": 5.0, "concision": 5.0},
            "human_acceptance_passed": True,
        },
        "assistant_automated_acceptance": {
            "provider_measurements": {"calls_used": 0}
        },
        "activation_decision": {
            "decision": "shadow_observation",
            "eligible_for_manual_activation_review": False,
            "blockers": ["independent_comparable_rows"],
        },
        "safety": {
            "raw_logs_sent_to_provider": False,
            "model_activated": False,
            "model_promoted": False,
            "response_actions_created": 0,
        },
    }


def test_preflight_reports_only_safe_aggregate_readiness(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, complete=False, closed=False)
    report = service.get_v539_evaluation_status(
        settings=_settings(),
        paths=paths,
    )

    assert report["status"] == "human_review_required"
    assert report["detection"]["reviewed"] == 0
    assert report["assistant"]["reviewed"] == 0
    assert report["evaluation_execution_count"] == 0
    assert report["safety"]["digests_exposed"] is False
    assert report["safety"]["reviewer_identities_exposed"] is False
    assert not (tmp_path / service.DEFAULT_STATE_PATH.name).exists()
    serialized = json.dumps(report).lower()
    assert "private-token" not in serialized
    assert "private-test-secret" not in serialized
    assert str(tmp_path).lower() not in serialized


def test_frozen_evaluation_requires_formally_closed_reviews(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, complete=True, closed=False)
    db, engine = _db()
    try:
        with pytest.raises(service.FrozenEvidenceDecisionError) as exc_info:
            service.run_v539_frozen_activation_decision(
                db,
                settings=_settings(),
                confirmation=service.V539_EXECUTION_CONFIRMATION,
                paths=paths,
                state_path=tmp_path / "frozen.json",
                write_reports=False,
            )
    finally:
        db.close()
        engine.dispose()
    assert exc_info.value.code == "frozen_evaluation_not_ready"
    assert not (tmp_path / "frozen.json").exists()


def test_one_shot_evaluation_freezes_and_reuses_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _prepare_paths(tmp_path, complete=True, closed=True)
    state_path = tmp_path / "frozen.json"
    calls = 0

    def fake_v536(*args, **kwargs):
        nonlocal calls
        calls += 1
        assert kwargs["execute_provider"] is False
        assert kwargs["write_reports"] is False
        return _passing_v536_report()

    monkeypatch.setattr(
        service,
        "run_v536_independent_evidence_activation_decision",
        fake_v536,
    )
    db, engine = _db()
    try:
        first = service.run_v539_frozen_activation_decision(
            db,
            settings=_settings(),
            confirmation=service.V539_EXECUTION_CONFIRMATION,
            paths=paths,
            state_path=state_path,
            output_dir=tmp_path,
            write_reports=False,
        )
        second = service.run_v539_frozen_activation_decision(
            db,
            settings=_settings(),
            confirmation=service.V539_EXECUTION_CONFIRMATION,
            paths=paths,
            state_path=state_path,
            output_dir=tmp_path,
            write_reports=False,
        )
    finally:
        db.close()
        engine.dispose()

    assert calls == 1
    assert first["executed_now"] is True
    assert second["executed_now"] is False
    assert second["evaluation_execution_count"] == 1
    assert second["evaluation_completed"] is True
    assert second["activation_decision"]["activate_candidate"] is False
    assert second["activation_decision"]["model_activated"] is False
    assert second["activation_decision"]["response_automation_allowed"] is False
    assert second["safety"]["external_provider_called"] is False
    private_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert private_state["evaluation"]["attempt_count"] == 1
    assert private_state["private_contract"]["detection_decision_digest"]
    assert "private_contract" not in json.dumps(second)


def test_tampering_after_freeze_is_rejected(tmp_path: Path, monkeypatch) -> None:
    paths = _prepare_paths(tmp_path, complete=True, closed=True)
    state_path = tmp_path / "frozen.json"
    monkeypatch.setattr(
        service,
        "run_v536_independent_evidence_activation_decision",
        lambda *args, **kwargs: _passing_v536_report(),
    )
    db, engine = _db()
    try:
        service.run_v539_frozen_activation_decision(
            db,
            settings=_settings(),
            confirmation=service.V539_EXECUTION_CONFIRMATION,
            paths=paths,
            state_path=state_path,
            write_reports=False,
        )
    finally:
        db.close()
        engine.dispose()

    rows, columns = service.v528._read_rows(paths.detection_working)
    rows[0]["human_notes"] = "Changed after the frozen evaluation."
    service.v528._atomic_write_csv(paths.detection_working, rows, columns)
    with pytest.raises(service.FrozenEvidenceIntegrityError) as exc_info:
        service.get_v539_evaluation_status(
            settings=_settings(),
            paths=paths,
            state_path=state_path,
        )
    assert exc_info.value.code == "frozen_evidence_changed"


def test_failed_claim_cannot_run_a_second_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _prepare_paths(tmp_path, complete=True, closed=True)
    state_path = tmp_path / "frozen.json"
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("provider payload must not be returned")

    monkeypatch.setattr(
        service,
        "run_v536_independent_evidence_activation_decision",
        fail_once,
    )
    db, engine = _db()
    try:
        with pytest.raises(service.FrozenEvidenceDecisionError):
            service.run_v539_frozen_activation_decision(
                db,
                settings=_settings(),
                confirmation=service.V539_EXECUTION_CONFIRMATION,
                paths=paths,
                state_path=state_path,
                write_reports=False,
            )
        with pytest.raises(service.FrozenEvidenceDecisionError) as second:
            service.run_v539_frozen_activation_decision(
                db,
                settings=_settings(),
                confirmation=service.V539_EXECUTION_CONFIRMATION,
                paths=paths,
                state_path=state_path,
                write_reports=False,
            )
    finally:
        db.close()
        engine.dispose()

    assert calls == 1
    assert second.value.code == "frozen_evaluation_already_claimed"
    private_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert private_state["evaluation"]["status"] == "failed_closed"
    assert private_state["evaluation"]["attempt_count"] == 1


def test_orphaned_cross_process_claim_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _prepare_paths(tmp_path, complete=True, closed=True)
    state_path = tmp_path / "frozen.json"
    service._claim_path(state_path).write_text("claimed", encoding="utf-8")
    calls = 0

    def forbidden_evaluation(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _passing_v536_report()

    monkeypatch.setattr(
        service,
        "run_v536_independent_evidence_activation_decision",
        forbidden_evaluation,
    )
    db, engine = _db()
    try:
        with pytest.raises(service.FrozenEvidenceDecisionError) as exc_info:
            service.run_v539_frozen_activation_decision(
                db,
                settings=_settings(),
                confirmation=service.V539_EXECUTION_CONFIRMATION,
                paths=paths,
                state_path=state_path,
                write_reports=False,
            )
    finally:
        db.close()
        engine.dispose()

    assert calls == 0
    assert exc_info.value.code == "frozen_evaluation_already_claimed"
    status = service.get_v539_evaluation_status(
        settings=_settings(),
        paths=paths,
        state_path=state_path,
    )
    assert status["status"] == "frozen_evaluation_failed_closed"
    assert status["evaluation_execution_count"] == 1


def test_v536_cli_is_a_read_only_v539_preflight_alias(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0

    def safe_status(*, settings):
        nonlocal calls
        calls += 1
        return {
            "ok": True,
            "status": "human_review_required",
            "safety": {
                "model_activated": False,
                "response_actions_written": 0,
            },
        }

    monkeypatch.setattr(legacy_cli, "get_settings", _settings)
    monkeypatch.setattr(legacy_cli, "get_v539_evaluation_status", safe_status)
    monkeypatch.setattr(sys, "argv", ["run_v536", "--pretty"])

    with pytest.raises(SystemExit) as exc_info:
        legacy_cli.main()

    output = json.loads(capsys.readouterr().out)
    assert exc_info.value.code == 0
    assert calls == 1
    assert output["legacy_command"] is True
    assert output["status"] == "human_review_required"
    assert output["safety"]["model_activated"] is False
    assert output["safety"]["response_actions_written"] == 0
    assert "run_v539_independent_evidence_decision" in output["message"]


def test_v536_cli_fails_closed_without_private_error_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_status(*, settings):
        raise service.FrozenEvidenceIntegrityError(
            "frozen_evidence_changed",
            "The frozen evidence changed after the evaluation claim.",
        )

    monkeypatch.setattr(legacy_cli, "get_settings", _settings)
    monkeypatch.setattr(legacy_cli, "get_v539_evaluation_status", fail_status)
    monkeypatch.setattr(sys, "argv", ["run_v536"])

    with pytest.raises(SystemExit) as exc_info:
        legacy_cli.main()

    output = json.loads(capsys.readouterr().out)
    assert exc_info.value.code == 1
    assert output["ok"] is False
    assert output["legacy_command"] is True
    assert output["secrets_exposed"] is False
    assert output["private_paths_exposed"] is False
    assert "digest" not in json.dumps(output).lower()
