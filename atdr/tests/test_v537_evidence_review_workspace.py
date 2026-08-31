from __future__ import annotations

import csv
import json
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import (
    Alert,
    AuditLog,
    DetectionRun,
    MLLabel,
    MLModelRun,
    ResponseAction,
)
from atdr.app.main import app
from atdr.app.routers import evidence_review as evidence_review_router
from atdr.app.services import evidence_review_service as service
from atdr.app.services.user_service import create_user
from atdr.app.services.v533_independent_acceptance_service import (
    ASSISTANT_RATING_FIELDS,
    ASSISTANT_REVIEW_COLUMNS,
    V533_VERSION,
    _atomic_write_csv,
    _atomic_write_json,
    _protected_digest,
)


def _detection_row(index: int) -> dict[str, object]:
    return {
        "review_token": f"private-token-{index:03d}",
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


def _assistant_rows() -> list[dict[str, str]]:
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
    return [
        {
            "schema_version": V533_VERSION,
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
            **{field: "" for field in ASSISTANT_RATING_FIELDS},
            "human_overall_decision": "",
            "human_notes": "",
            "human_reviewer": "",
            "human_reviewed_at": "",
            "human_reviewed": "false",
            "human_must_confirm": "true",
        }
        for index, context in enumerate(contexts, start=1)
    ]


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_private_contracts(paths: service.EvidenceWorkspacePaths) -> None:
    detection_rows = [_detection_row(index) for index in range(4)]
    _write_csv(paths.detection_pack, detection_rows)
    assistant_rows = _assistant_rows()
    _atomic_write_csv(paths.assistant_review, assistant_rows, ASSISTANT_REVIEW_COLUMNS)
    _atomic_write_json(
        paths.assistant_manifest,
        {
            "schema_version": V533_VERSION,
            "row_count": len(assistant_rows),
            "protected_digest": _protected_digest(assistant_rows),
            "human_decisions_created": 0,
            "import_ready": False,
        },
    )


@pytest.fixture()
def workspace_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, sessionmaker[Session], service.EvidenceWorkspacePaths], None, None]:
    paths = service.EvidenceWorkspacePaths(
        evidence_dir=tmp_path,
        detection_pack=tmp_path / "sealed-detection.csv",
        detection_working=tmp_path / "detection-working.csv",
        assistant_review=tmp_path / "assistant-review.csv",
        assistant_manifest=tmp_path / "assistant-manifest.json",
        state=tmp_path / "workspace-state.json",
    )
    _write_private_contracts(paths)
    monkeypatch.setattr(service, "_workspace_paths", lambda: paths)
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "false")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "disabled")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "private-test-secret")
    monkeypatch.setenv("ASSISTANT_ALLOW_RAW_LOG_CONTEXT", "false")
    get_settings.cache_clear()

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        future=True,
    )
    with testing_session() as db:
        create_user(
            db,
            username="reviewer-one",
            password="analyst123",
            role="analyst",
            full_name="Reviewer One",
        )
        create_user(
            db,
            username="reviewer-two",
            password="analyst123",
            role="analyst",
            full_name="Reviewer Two",
        )
        create_user(
            db,
            username="admin",
            password="admin123",
            role="admin",
            full_name="Administrator",
        )
        create_user(
            db,
            username="codex-reviewer",
            password="analyst123",
            role="analyst",
            full_name="Automated Reviewer",
        )

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), testing_session, paths
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
        engine.dispose()


def _login(client: TestClient, username: str, password: str = "analyst123") -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _authoritative_counts(db: Session) -> dict[str, int]:
    return {
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "models": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "detections": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def _detection_payload(revision: int) -> dict[str, object]:
    return {
        "expected_revision": revision,
        "decision_group": "benign_like",
        "decision": "benign",
        "attack_type": "none",
        "confidence": 92,
        "rationale": "Independent human review found routine allowed web traffic.",
        "human_confirmed": True,
    }


def _assistant_payload(revision: int, *, decision: str = "accept") -> dict[str, object]:
    return {
        "expected_revision": revision,
        "scores": {
            "factual_correctness": 5,
            "evidence_grounding": 5,
            "citation_correctness": 5,
            "relevance": 5,
            "concision": 5,
            "actionable_usefulness": 5,
            "privacy": 5,
            "unsafe_action_refusal": 5,
        },
        "overall_decision": decision,
        "notes": "Review requires revision." if decision != "accept" else "",
        "human_confirmed": True,
    }


def test_evidence_review_requires_authentication(workspace_client) -> None:
    client, _, _ = workspace_client
    assert client.get("/api/evidence-review/status").status_code == 401
    assert client.get("/api/evidence-review/evaluation-status").status_code == 401
    assert client.get("/api/evidence-review/blind-evidence/status").status_code == 401
    assert client.get("/api/evidence-review/candidate-freeze/status").status_code == 401
    assert client.get("/api/evidence-review/temporal-stability/status").status_code == 401
    assert (
        client.get("/api/evidence-review/manual-anchor-transfer/status").status_code
        == 401
    )
    assert (
        client.get(
            "/api/evidence-review/manual-anchor-acquisition/status"
        ).status_code
        == 401
    )
    assert client.post("/api/evidence-review/detection/start").status_code == 401
    assert client.get("/api/evidence-review/detection/items/0").status_code == 401
    assert client.post("/api/evidence-review/assistant/start").status_code == 401


def test_blind_evidence_status_is_safe_and_aggregate_only(
    workspace_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_blind_evidence_status",
        lambda: {
            "version": "v5.41-governed-blind-evidence-v1",
            "status": "Insufficient Sources",
            "qualifying_collection_count": 1,
            "independent_source_count": 1,
            "required_source_count": 2,
            "collection_window_count": 1,
            "required_window_count": 3,
            "candidate_rows": 40,
            "target_review_rows": 240,
            "review_pack_available": False,
            "human_reviewed_rows": 0,
            "human_review_complete": False,
            "class_support": {"benign_like": 0, "suspicious": 0, "malicious": 0},
            "prediction_sealed_separately": False,
            "metrics_available": False,
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "raw_logs_exposed": False,
            "ip_addresses_exposed": False,
            "private_paths_exposed": False,
            "source_identities_exposed": False,
            "fingerprints_exposed": False,
            "secrets_exposed": False,
            "message": "Additional independently verified sources are required.",
        },
    )

    response = client.get(
        "/api/evidence-review/blind-evidence/status",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "Insufficient Sources"
    assert payload["source_identities_exposed"] is False
    assert payload["fingerprints_exposed"] is False
    assert payload["secrets_exposed"] is False


def test_candidate_freeze_status_is_safe_and_aggregate_only(
    workspace_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_candidate_freeze_status",
        lambda: {
            "version": "v5.42-development-candidate-freeze-v1",
            "status": "No Candidate Frozen",
            "best_candidate": "hierarchical_two_stage",
            "passing_folds": 0,
            "required_folds": 3,
            "candidate_frozen": False,
            "calibration_status": "weak",
            "blind_evidence_status": "Insufficient Sources",
            "supervised_phases_remaining": 5,
            "blockers": ["Temporal stability gate failed."],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "private_paths_exposed": False,
            "digests_exposed": False,
            "blind_predictions_exposed": False,
            "secrets_exposed": False,
        },
    )

    response = client.get(
        "/api/evidence-review/candidate-freeze/status",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["best_candidate"] == "hierarchical_two_stage"
    assert payload["candidate_frozen"] is False
    assert payload["model_activated"] is False
    assert payload["blind_predictions_exposed"] is False
    assert payload["secrets_exposed"] is False


def test_temporal_stability_status_is_safe_and_aggregate_only(
    workspace_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_temporal_stability_status",
        lambda: {
            "version": "v5.43-development-temporal-stability-repair-v1",
            "status": "No Candidate Frozen",
            "best_variant": "temporal_provenance_balanced_weighting",
            "passing_folds": 0,
            "required_folds": 3,
            "candidate_frozen": False,
            "calibration_status": "weak",
            "queue_stability_status": "unstable",
            "feature_ablation_status": "complete",
            "supervised_phases_remaining": 5,
            "blockers": ["Temporal stability gate failed."],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "private_paths_exposed": False,
            "digests_exposed": False,
            "blind_predictions_exposed": False,
            "secrets_exposed": False,
        },
    )

    response = client.get(
        "/api/evidence-review/temporal-stability/status",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["best_variant"] == "temporal_provenance_balanced_weighting"
    assert payload["passing_folds"] == 0
    assert payload["candidate_frozen"] is False
    assert payload["model_activated"] is False
    assert payload["blind_predictions_exposed"] is False
    assert payload["secrets_exposed"] is False


def test_development_model_repair_status_is_safe_and_aggregate_only(
    workspace_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_v545_status",
        lambda: {
            "version": "v5.45-development-only-supervised-repair-v1",
            "status": "development_repair_incomplete",
            "generated_at": "2026-08-21T00:00:00+00:00",
            "diagnostic_leader": "calibrated_extra_trees_flat_5class",
            "passing_views": 0,
            "required_views": 3,
            "candidate_freeze_ready": False,
            "candidate_frozen": False,
            "isolation_forest_reliable": False,
            "supervised_phases_remaining": 5,
            "blockers": ["Manual-anchor stability gate failed."],
            "lifecycle_state": "shadow_observation",
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        },
    )

    response = client.get(
        "/api/evidence-review/development-model-repair/status",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["diagnostic_leader"] == "calibrated_extra_trees_flat_5class"
    assert payload["passing_views"] == 0
    assert payload["candidate_freeze_ready"] is False
    assert payload["model_activated"] is False
    assert payload["future_labels_opened"] is False
    assert payload["private_paths_returned"] is False
    assert payload["fingerprints_returned"] is False
    assert payload["secrets_exposed"] is False


def test_manual_anchor_transfer_status_is_safe_and_aggregate_only(
    workspace_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_v546_status",
        lambda: {
            "version": "v5.46-manual-anchor-transfer-repair-v1",
            "status": "manual_anchor_transfer_incomplete",
            "generated_at": "2026-08-21T00:00:00+00:00",
            "diagnostic_leader": "manual_anchor_prioritized_extra_trees",
            "passing_views": 1,
            "required_views": 3,
            "manual_anchor_transfer_status": "improved",
            "calibration_status": "weak",
            "manual_anchor_queue_f1": 0.79,
            "manual_anchor_fpr": 0.12,
            "manual_anchor_suspicious_recall": 0.71,
            "manual_anchor_malicious_recall": 0.84,
            "queue_f1_transfer_gap": 0.18,
            "candidate_freeze_ready": False,
            "candidate_frozen": False,
            "isolation_forest_reliable": False,
            "supervised_phases_remaining": 5,
            "blockers": ["Manual-anchor gate failed."],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        },
    )

    response = client.get(
        "/api/evidence-review/manual-anchor-transfer/status",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["manual_anchor_transfer_status"] == "improved"
    assert payload["rules_alert_authoritative"] is True
    assert payload["model_activated"] is False
    assert payload["response_automation_allowed"] is False
    assert payload["private_paths_returned"] is False
    assert payload["fingerprints_returned"] is False
    assert payload["secrets_exposed"] is False


def test_manual_anchor_acquisition_status_is_safe_and_aggregate_only(
    workspace_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_v547_status",
        lambda: {
            "version": "v5.47-prediction-blind-manual-anchor-acquisition-v1",
            "status": "ready_for_human_review",
            "generated_at": "2026-08-21T00:00:00+00:00",
            "selected_rows": 120,
            "target_rows": 120,
            "represented_strata": 8,
            "coverage_counts": {"unknown_transport": 20},
            "coverage_gate_passed": True,
            "review_status": "ready_for_human_review",
            "reviewed_rows": 0,
            "total_review_rows": 120,
            "invalid_review_rows": 0,
            "class_support": {
                "benign_like": 0,
                "suspicious": 0,
                "malicious": 0,
            },
            "ready_for_fixed_revalidation": False,
            "independent_source_count": 1,
            "second_real_source_present": False,
            "development_evidence_only": True,
            "workspace_created": True,
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "predictions_exposed": False,
            "assisted_labels_exposed": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        },
    )

    response = client.get(
        "/api/evidence-review/manual-anchor-acquisition/status",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["selected_rows"] == 120
    assert payload["reviewed_rows"] == 0
    assert payload["development_evidence_only"] is True
    assert payload["predictions_exposed"] is False
    assert payload["model_activated"] is False
    assert payload["response_automation_allowed"] is False
    assert payload["private_paths_returned"] is False
    assert "review_token" not in response.text


def test_frozen_evaluation_status_is_safe_and_aggregate_only(workspace_client) -> None:
    client, _, _ = workspace_client
    headers = _login(client, "reviewer-one")

    response = client.get("/api/evidence-review/evaluation-status", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "human_review_required"
    assert payload["evaluation_execution_count"] == 0
    assert payload["safety"]["digests_exposed"] is False
    assert payload["safety"]["reviewer_identities_exposed"] is False
    assert payload["activation_decision"]["model_activated"] is False
    serialized = response.text.lower()
    assert "private-test-secret" not in serialized
    assert "private-token" not in serialized


def test_detection_review_is_blind_resumable_and_read_only(workspace_client) -> None:
    client, session_factory, _ = workspace_client
    headers = _login(client, "reviewer-one")
    with session_factory() as db:
        before = _authoritative_counts(db)

    started = client.post("/api/evidence-review/detection/start", headers=headers)
    assert started.status_code == 200
    start_payload = started.json()
    item = start_payload["next_item"]
    serialized_evidence = json.dumps(item["evidence"]).lower()
    for forbidden in (
        "review_token",
        "prediction",
        "model_score",
        "rule_score",
        "source_ip",
        "destination_ip",
        "fingerprint",
        "private-test-secret",
    ):
        assert forbidden not in serialized_evidence
    assert item["evidence"]["application"] == "ssl"
    assert item["predictions_exposed"] is False
    assert item["model_scores_exposed"] is False
    assert item["fingerprints_exposed"] is False
    assert item["import_ready"] is False

    saved = client.post(
        "/api/evidence-review/detection/items/0",
        headers=headers,
        json=_detection_payload(start_payload["revision"]),
    )
    assert saved.status_code == 200
    saved_payload = saved.json()
    assert saved_payload["progress"]["reviewed"] == 1
    assert saved_payload["authoritative_mutations"] == {
        "labels": 0,
        "model_runs": 0,
        "detection_runs": 0,
        "alerts": 0,
        "response_actions": 0,
    }
    assert saved_payload["import_performed"] is False
    assert saved_payload["model_activation_performed"] is False
    assert saved_payload["response_action_performed"] is False

    resumed = client.post("/api/evidence-review/detection/start", headers=headers)
    assert resumed.status_code == 200
    assert resumed.json()["progress"]["reviewed"] == 1
    existing = client.get(
        "/api/evidence-review/detection/items/0",
        headers=headers,
    )
    assert existing.status_code == 200
    assert existing.json()["existing_review"]["confidence"] == 92

    with session_factory() as db:
        assert _authoritative_counts(db) == before
        actions = set(db.scalars(select(AuditLog.action)).all())
    assert {"evidence_review_started", "evidence_review_saved"}.issubset(actions)


def test_detection_review_fails_closed_on_overwrite_and_tampering(
    workspace_client,
) -> None:
    client, session_factory, paths = workspace_client
    headers = _login(client, "reviewer-one")
    started = client.post("/api/evidence-review/detection/start", headers=headers).json()
    saved = client.post(
        "/api/evidence-review/detection/items/0",
        headers=headers,
        json=_detection_payload(started["revision"]),
    )
    assert saved.status_code == 200
    overwrite = client.post(
        "/api/evidence-review/detection/items/0",
        headers=headers,
        json=_detection_payload(saved.json()["revision"]),
    )
    assert overwrite.status_code == 409

    rows, columns = service.v528._read_rows(paths.detection_pack)
    rows[1]["application"] = "tampered-value"
    service.v528._atomic_write_csv(paths.detection_pack, rows, columns)
    tampered = client.get("/api/evidence-review/status", headers=headers)
    assert tampered.status_code == 409
    assert "private-token" not in tampered.text
    assert str(paths) not in tampered.text
    with session_factory() as db:
        actions = list(db.scalars(select(AuditLog.action)).all())
    assert "evidence_review_integrity_failed" in actions


def test_malformed_assistant_pack_fails_closed_without_private_details(
    workspace_client,
) -> None:
    client, session_factory, paths = workspace_client
    headers = _login(client, "reviewer-one")
    paths.assistant_manifest.write_text("{not-valid-json", encoding="utf-8")

    response = client.get("/api/evidence-review/status", headers=headers)

    assert response.status_code == 409
    assert "protected-content validation" in response.text
    assert "private-test-secret" not in response.text
    assert str(paths) not in response.text
    with session_factory() as db:
        actions = list(db.scalars(select(AuditLog.action)).all())
    assert "evidence_review_integrity_failed" in actions


def test_workspace_ownership_allows_admin_aggregate_only(workspace_client) -> None:
    client, _, _ = workspace_client
    owner_headers = _login(client, "reviewer-one")
    other_headers = _login(client, "reviewer-two")
    admin_headers = _login(client, "admin", "admin123")
    assert client.post(
        "/api/evidence-review/detection/start",
        headers=owner_headers,
    ).status_code == 200

    admin_status = client.get("/api/evidence-review/status", headers=admin_headers)
    assert admin_status.status_code == 200
    assert admin_status.json()["detection"]["owner_assigned"] is True
    assert admin_status.json()["detection"]["owned_by_current_user"] is False
    assert "owner_username" not in admin_status.text
    assert client.get(
        "/api/evidence-review/detection/items/0",
        headers=admin_headers,
    ).status_code == 403
    assert client.post(
        "/api/evidence-review/detection/start",
        headers=other_headers,
    ).status_code == 403


def test_automated_identity_cannot_submit_human_decisions(workspace_client) -> None:
    client, session_factory, _ = workspace_client
    headers = _login(client, "codex-reviewer")
    response = client.post("/api/evidence-review/detection/start", headers=headers)
    assert response.status_code == 422
    assert "genuine authenticated human" in response.text
    with session_factory() as db:
        rejected = db.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == "evidence_review_rejected"
            )
        )
    assert int(rejected or 0) == 1


def test_assistant_acceptance_saves_completes_and_stays_read_only(
    workspace_client,
) -> None:
    client, session_factory, _ = workspace_client
    headers = _login(client, "reviewer-one")
    with session_factory() as db:
        before = _authoritative_counts(db)

    started = client.post("/api/evidence-review/assistant/start", headers=headers)
    assert started.status_code == 200
    payload = started.json()
    assert payload["progress"]["total"] == 8
    assert payload["next_item"]["raw_log_context_included"] is False
    assert payload["next_item"]["action_executed"] is False
    assert payload["next_item"]["secrets_exposed"] is False
    assert "private-test-secret" not in started.text

    revision = payload["revision"]
    for row_index in range(8):
        saved = client.post(
            f"/api/evidence-review/assistant/items/{row_index}",
            headers=headers,
            json=_assistant_payload(revision),
        )
        assert saved.status_code == 200
        revision = saved.json()["revision"]
    assert saved.json()["progress"]["completed"] is True
    assert saved.json()["progress"]["evaluation_ready"] is True
    completed = client.post(
        "/api/evidence-review/assistant/complete",
        headers=headers,
        json={"expected_revision": revision, "human_confirmed": True},
    )
    assert completed.status_code == 200
    assert completed.json()["response_action_performed"] is False

    with session_factory() as db:
        assert _authoritative_counts(db) == before
        actions = list(db.scalars(select(AuditLog.action)).all())
    assert "evidence_review_completed" in actions
    assert actions.count("evidence_review_saved") >= 8


def test_explicit_confirmation_and_reject_audit_are_required(workspace_client) -> None:
    client, session_factory, _ = workspace_client
    headers = _login(client, "reviewer-one")
    started = client.post("/api/evidence-review/assistant/start", headers=headers).json()
    missing_confirmation = _assistant_payload(started["revision"])
    missing_confirmation.pop("human_confirmed")
    assert client.post(
        "/api/evidence-review/assistant/items/0",
        headers=headers,
        json=missing_confirmation,
    ).status_code == 422

    rejected = client.post(
        "/api/evidence-review/assistant/items/0",
        headers=headers,
        json=_assistant_payload(started["revision"], decision="reject"),
    )
    assert rejected.status_code == 200
    with session_factory() as db:
        audit = db.scalar(
            select(AuditLog).where(AuditLog.action == "evidence_review_rejected")
        )
    assert audit is not None
    assert audit.details["response_action"] is False
    assert "question" not in audit.details
    assert "answer" not in audit.details
