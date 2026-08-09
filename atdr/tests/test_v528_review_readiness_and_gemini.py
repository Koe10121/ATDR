from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v526_native_blind_qualification as v526
from atdr.app.detection import v527_blind_review_evaluation as v527
from atdr.app.detection import v528_blind_review_helper as review_helper
from atdr.app.detection.v528_supervised_readiness import (
    run_v528_supervised_readiness_audit,
)
from atdr.app.services import assistant_llm


def _row(index: int) -> dict[str, object]:
    return {
        "review_token": f"token-{index:03d}",
        "evidence_role": "untouched_future_validation",
        "evidence_role_is_blind": True,
        "pattern": "routine_web" if index % 2 == 0 else "scan_like",
        "review_priority": "high",
        "event_time_utc": "2026-05-20T10:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "ssl" if index % 2 == 0 else "unknown",
        "action": "allow" if index % 2 == 0 else "deny",
        "protocol": "tcp",
        "source_port": 45000 + index,
        "destination_port": 443 if index % 2 == 0 else 22,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 2 if index % 2 == 0 else 5,
        "threat_severity": "",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 2 if index % 2 == 0 else 20,
        "source_deny_count": 0 if index % 2 == 0 else 12,
        "source_unique_destinations": 1 if index % 2 == 0 else 10,
        "source_unique_ports": 1 if index % 2 == 0 else 12,
        "source_unknown_app_count": 0 if index % 2 == 0 else 10,
        "source_high_risk_app_count": 0 if index % 2 == 0 else 4,
        "destination_repeat_count": 1,
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "human_decision": "",
        "human_attack_type": "",
        "human_confidence": "",
        "human_notes": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_must_confirm": True,
        "import_ready": False,
        "assisted_suggestion": "",
        "assisted_attack_type": "",
        "assisted_confidence": "",
        "assisted_reason": "",
        "assisted_provenance": "",
        "rule_codes": "",
        "rule_score": "",
        "suggestion_is_weak": False,
        "human_reviewed": False,
        "blind_suggestion_suppressed": True,
    }


def _prediction(index: int) -> dict[str, object]:
    queued = index % 2 == 1
    return {
        "review_token": f"token-{index:03d}",
        "rule_queue": "needs_review" if queued else "non_threat",
        "rule_score": 0.9 if queued else 0.1,
        "isolation_queue": "needs_review" if queued else "non_threat",
        "isolation_score": 0.9 if queued else 0.1,
        "supervised_queue": "needs_review" if queued else "non_threat",
        "supervised_score": 0.9 if queued else 0.1,
        "hybrid_queue": "needs_review" if queued else "non_threat",
        "hybrid_score": 0.9 if queued else 0.1,
    }


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_contracts(directory: Path, count: int = 20) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    rows = [_row(index) for index in range(count)]
    pack = directory / v521.V521_BLIND_PACK
    working = directory / "review-working.csv"
    _write_csv(pack, rows)
    (directory / v521.V521_MANIFEST_LATEST).write_text(
        json.dumps({"blind_pack_fingerprint": v521._pack_fingerprint(rows)}),
        encoding="utf-8",
    )
    (directory / v526.V526_PREDICTION_LOCK).write_text(
        json.dumps(
            {
                "prediction_rows": [_prediction(index) for index in range(count)],
                "predictions_created_before_label_access": True,
                "human_label_fields_included": False,
                "raw_logs_included": False,
                "ip_addresses_included": False,
                "source_path_included": False,
                "secret_values_included": False,
            }
        ),
        encoding="utf-8",
    )
    (directory / v526.V526_LATEST).write_text(
        json.dumps(
            {
                "prediction_frozen_before_label_access": True,
                "prediction_lock_persisted_privately": True,
                "blind_labels_used_for_candidate_selection": False,
            }
        ),
        encoding="utf-8",
    )
    return pack, working


def test_review_helper_save_resume_preserves_sealed_evidence(tmp_path: Path) -> None:
    pack, working = _write_contracts(tmp_path)
    sealed_before = pack.read_bytes()
    prepared = review_helper.prepare_review_working_copy(
        pack_path=pack,
        working_path=working,
    )
    assert prepared["status"] == "working_copy_created"
    assert prepared["predictions_displayed"] is False
    assert prepared["ai_suggestions_displayed"] is False

    progress = review_helper.save_review_entry(
        pack_path=pack,
        working_path=working,
        row_index=0,
        decision="benign",
        attack_type="none",
        confidence=92,
        notes="Independent review found routine allowed web traffic.",
        reviewer="human-analyst",
        reviewed_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC),
    )
    resumed = review_helper.prepare_review_working_copy(
        pack_path=pack,
        working_path=working,
    )
    assert progress["reviewed"] == 1
    assert progress["remaining"] == 19
    assert progress["metrics_calculated"] is False
    assert resumed["status"] == "working_copy_resumed"
    assert pack.read_bytes() == sealed_before

    pack_rows, pack_columns = review_helper._read_rows(pack)
    review_rows, review_columns = review_helper._read_rows(working)
    assert pack_columns == review_columns
    protected = review_helper._protected_columns(pack_columns)
    assert all(
        pack_rows[0][field] == review_rows[0][field] for field in protected
    )
    assert review_rows[0]["import_ready"] == "False"


def test_review_helper_fails_closed_on_assisted_or_modified_evidence(
    tmp_path: Path,
) -> None:
    pack, working = _write_contracts(tmp_path)
    review_helper.prepare_review_working_copy(pack_path=pack, working_path=working)
    rows, columns = review_helper._read_rows(working)
    rows[0]["assisted_suggestion"] = "benign"
    _write_csv(working, rows)
    with pytest.raises(ValueError, match="prediction or assisted evidence"):
        review_helper.validate_working_copy(
            pack_path=pack,
            working_path=working,
        )

    _write_csv(working, [_row(index) for index in range(20)])
    rows, _ = review_helper._read_rows(working)
    rows[0]["application"] = "tampered"
    _write_csv(working, rows)
    with pytest.raises(ValueError, match="sealed evidence contract"):
        review_helper.validate_working_copy(
            pack_path=pack,
            working_path=working,
        )
    assert "prediction" not in " ".join(review_helper.DISPLAY_EVIDENCE_FIELDS)
    assert "rule" not in " ".join(review_helper.DISPLAY_EVIDENCE_FIELDS)


def test_separate_review_copy_is_only_post_review_label_source(
    tmp_path: Path,
) -> None:
    pack, working = _write_contracts(tmp_path)
    review_helper.prepare_review_working_copy(pack_path=pack, working_path=working)
    for index in range(20):
        review_helper.save_review_entry(
            pack_path=pack,
            working_path=working,
            row_index=index,
            decision="benign" if index % 2 == 0 else "malicious",
            attack_type="none" if index % 2 == 0 else "port_scan",
            confidence=90,
            notes="Independent analyst reviewed the structured blind evidence.",
            reviewer="human-analyst",
            reviewed_at=datetime(2026, 8, 1, 10, index, tzinfo=UTC),
        )
    labels, contexts, _predictions, audit = v527.validate_blind_review_intake(
        pack_path=pack,
        review_path=working,
        prediction_lock_path=tmp_path / v526.V526_PREDICTION_LOCK,
        manifest_path=tmp_path / v521.V521_MANIFEST_LATEST,
        v526_result_path=tmp_path / v526.V526_LATEST,
        seal_path=tmp_path / v527.V527_PRIVATE_SEAL,
        write_private_seal=True,
    )
    assert len(labels) == 20
    assert audit["enough_for_metrics"] is True
    assert audit["separate_review_copy_used"] is True
    assert audit["review_copy_contract_passed"] is True
    assert all(not row.get("human_decision") for row in contexts.values())


def test_supervised_readiness_audit_is_read_only_and_conservative(
    tmp_path: Path,
) -> None:
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        before_models = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
        before_responses = int(
            db.scalar(select(func.count(ResponseAction.id))) or 0
        )
        report = run_v528_supervised_readiness_audit(
            db,
            output_dir=tmp_path,
            write_reports=False,
        )
        after_models = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
        after_responses = int(
            db.scalar(select(func.count(ResponseAction.id))) or 0
        )
    assert report["review_gate"] == "human_review_pending"
    assert report["blind_metrics_calculated"] is False
    assert report["safety"]["locked_evidence_opened"] is False
    assert report["safety"]["model_retrained"] is False
    assert report["safety"]["model_activated"] is False
    assert report["safety"]["database_state_unchanged"] is True
    assert before_models == after_models == 0
    assert before_responses == after_responses == 0
    assert len(report["post_review_decision_tree"]) == 5


def _llm_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "ASSISTANT_LLM_ENABLED": True,
        "ASSISTANT_LLM_PROVIDER": "mock",
        "ASSISTANT_LLM_MODEL": "safe-mock",
        "ASSISTANT_LLM_API_KEY": "private-test-key",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": False,
        "ASSISTANT_REDACT_IPS": True,
        "ASSISTANT_LLM_MAX_OUTPUT_TOKENS": 256,
        "ASSISTANT_LLM_MAX_VISIBLE_CHARS": 1200,
        "ASSISTANT_LLM_CIRCUIT_BREAKER_FAILURES": 2,
        "ASSISTANT_LLM_CIRCUIT_BREAKER_COOLDOWN_SECONDS": 60,
        "ASSISTANT_LLM_INPUT_COST_PER_MILLION": 1.0,
        "ASSISTANT_LLM_OUTPUT_COST_PER_MILLION": 2.0,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _llm_request() -> assistant_llm.AssistantLLMRequest:
    return assistant_llm.AssistantLLMRequest(
        question="Why was alert 42 flagged?",
        deterministic_answer="Alert #42 has bounded rule evidence.",
        context_used=["alert_detail"],
        citations=[
            {
                "label": "Alert detail",
                "source": "/api/alerts/{alert_id}",
                "reference_id": "42",
            }
        ],
        suggested_followups=["What should an analyst verify next?"],
        safety=["Read-only decision support; response automation is disabled."],
    )


def test_llm_visible_budget_and_operational_telemetry_are_bounded() -> None:
    settings = _llm_settings()
    assistant_llm.reset_assistant_llm_operational_state(settings)
    result = assistant_llm.maybe_generate_external_answer(
        _llm_request(),
        settings,
    )
    status = assistant_llm.assistant_llm_operational_status(settings)
    assert result.used is True
    assert result.provider_called is True
    assert result.answer is not None
    assert len(result.answer) <= settings.assistant_llm_max_visible_chars
    assert status["status"] == "healthy"
    assert status["calls_attempted"] == 1
    assert status["calls_succeeded"] == 1
    assert status["prompts_stored"] is False
    assert status["answers_stored"] is False
    assert status["raw_logs_stored"] is False
    assert status["secrets_exposed"] is False


def test_llm_usage_cost_telemetry_is_aggregate_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _llm_settings()
    assistant_llm.reset_assistant_llm_operational_state(settings)

    class UsageProvider(assistant_llm.AssistantLLMProvider):
        provider_name = "mock"

        def generate(
            self,
            request: assistant_llm.AssistantLLMRequest,
            settings: Settings,
        ) -> assistant_llm.AssistantLLMResult:
            structured = {
                "summary": "Bounded evidence summary.",
                "evidence": ["Alert #42 has supplied ATDR evidence."],
                "risk_interpretation": ["Analyst verification remains required."],
                "analyst_checks": ["Review the linked evidence."],
                "missing_information": [],
                "safety_notice": "Read-only decision support; response automation remains disabled.",
                "suggested_followups": [],
                "citation_references": ["Alert detail #42"],
            }
            return assistant_llm.AssistantLLMResult(
                used=True,
                provider="mock",
                model="safe-mock",
                answer=assistant_llm._render_structured_answer(structured),
                structured_answer=structured,
                usage={
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "total_tokens": 150,
                },
                provider_called=True,
            )

    monkeypatch.setattr(
        assistant_llm,
        "_provider_for",
        lambda _name: UsageProvider(),
    )
    result = assistant_llm.maybe_generate_external_answer(
        _llm_request(), settings
    )
    status = assistant_llm.assistant_llm_operational_status(settings)
    serialized = json.dumps(status)
    assert result.used is True
    assert status["token_usage"] == {
        "input_tokens": 100,
        "output_tokens": 50,
        "total_tokens": 150,
    }
    assert status["estimated_cost_usd"] == 0.0002
    assert status["prompts_stored"] is False
    assert status["answers_stored"] is False
    assert "private-test-key" not in serialized
    assert "Why was alert" not in serialized


def test_llm_circuit_breaker_fails_to_deterministic_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _llm_settings(ASSISTANT_LLM_PROVIDER="gemini")
    assistant_llm.reset_assistant_llm_operational_state(settings)

    def fail(*args: object, **kwargs: object) -> dict[str, object]:
        raise assistant_llm.AssistantLLMTransportError("provider_timeout")

    monkeypatch.setattr(assistant_llm, "_post_json", fail)
    first = assistant_llm.maybe_generate_external_answer(
        _llm_request(), settings
    )
    second = assistant_llm.maybe_generate_external_answer(
        _llm_request(), settings
    )
    blocked = assistant_llm.maybe_generate_external_answer(
        _llm_request(), settings
    )
    status = assistant_llm.assistant_llm_operational_status(settings)
    assert first.fallback_reason == "provider_timeout"
    assert second.fallback_reason == "provider_timeout"
    assert blocked.fallback_reason == "provider_circuit_open"
    assert blocked.provider_called is False
    assert status["status"] == "circuit_open"
    assert status["calls_attempted"] == 2
    assert status["calls_failed"] == 2
    assert status["fallbacks"] == 3


def test_llm_transport_retries_rate_limit_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"count": 0}

    class Response:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

        def json(self) -> dict[str, object]:
            return {"ok": True}

    def post(*args: object, **kwargs: object) -> Response:
        calls["count"] += 1
        return Response(429 if calls["count"] == 1 else 200)

    monkeypatch.setattr(assistant_llm.requests, "post", post)
    monkeypatch.setattr(assistant_llm.time, "sleep", lambda *_: None)
    value = assistant_llm._post_json(
        "https://provider.invalid",
        headers={},
        params=None,
        payload={},
        timeout=1,
        max_retries=1,
    )
    assert calls["count"] == 2
    assert value["_atdr_transport"]["attempts"] == 2
