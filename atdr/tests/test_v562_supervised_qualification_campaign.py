from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import (
    Alert,
    AuditLog,
    DetectionRun,
    MLLabel,
    MLModelRun,
    ResponseAction,
    SuppressionRule,
)
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.main import app
from atdr.app.routers import evidence_review as evidence_review_router
from atdr.app.services import v562_supervised_qualification_review_service as service
from atdr.app.services.user_service import create_user


def _pack_row(index: int, *, role: str) -> dict[str, object]:
    coverage = (
        "web_transport_context"
        if index % 2 == 0
        else "high_activity_context"
    )
    return {
        "review_token": f"synthetic-v562-token-{index:03d}",
        "evidence_role": role,
        "coverage_group": coverage,
        "event_time_utc": f"2026-09-{index + 1:02d}T00:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "ssl" if index % 2 == 0 else "unknown-udp",
        "action": "allow" if index % 2 == 0 else "deny",
        "protocol": "tcp" if index % 2 == 0 else "udp",
        "source_port": 45000 + index,
        "destination_port": 443 if index % 2 == 0 else 4040,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 2 if index % 2 == 0 else 4,
        "threat_severity": "none" if index % 2 == 0 else "medium",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 2 if index % 2 == 0 else 20,
        "source_deny_count": 0 if index % 2 == 0 else 10,
        "source_unique_destinations": 1 if index % 2 == 0 else 10,
        "source_unique_ports": 1 if index % 2 == 0 else 12,
        "source_unknown_app_count": 0 if index % 2 == 0 else 10,
        "source_high_risk_app_count": 0 if index % 2 == 0 else 2,
        "destination_repeat_count": 1,
        "predictions_exposed": False,
        "model_scores_exposed": False,
        "rule_recommendations_exposed": False,
        "assisted_labels_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "fingerprints_exposed": False,
        "human_decision": "",
        "human_attack_type": "",
        "human_confidence": "",
        "human_rationale": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_must_confirm": True,
        "human_reviewed": False,
        "import_ready": False,
    }


def _prepare_workspace(output_dir: Path) -> dict[str, Path]:
    roles = [
        "development_fit",
        "development_fit",
        "calibration",
        "threshold_selection",
        "untouched_future_evaluation",
        "untouched_future_evaluation",
    ]
    rows = [_pack_row(index, role=role) for index, role in enumerate(roles)]
    role_counts = {role: roles.count(role) for role in set(roles)}
    v562._prepare_workspace(
        rows,
        selection={
            "selected_rows": len(rows),
            "role_counts": role_counts,
        },
        exclusion={
            "excluded_candidate_families": 180,
            "excluded_event_rows": 228,
        },
        profile={
            "rows_processed": 600,
            "device_sources": {"identified_source_count": 1},
        },
        roles={"distinct_time_windows": 3},
        sample_digest="synthetic-private-source-digest",
        output_dir=output_dir,
    )
    return v562._workspace_paths(output_dir)


@pytest.fixture()
def qualification_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, sessionmaker[Session], dict[str, Path]], None, None]:
    paths = _prepare_workspace(tmp_path)
    monkeypatch.setattr(service, "_paths", lambda: paths)
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_v562_status",
        lambda: v562.get_public_v562_status(tmp_path),
    )

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, future=True)
    with testing_session() as db:
        create_user(
            db,
            username="qualification-reviewer",
            password="analyst123",
            role="analyst",
            full_name="Qualification Reviewer",
        )
        create_user(
            db,
            username="other-reviewer",
            password="analyst123",
            role="analyst",
            full_name="Other Reviewer",
        )
        create_user(
            db,
            username="codex-reviewer",
            password="analyst123",
            role="analyst",
            full_name="Automated Reviewer",
        )

    def override_get_db() -> Generator[Session, None, None]:
        with testing_session() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), testing_session, paths
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _login(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": "analyst123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _payload(revision: int, *, decision: str = "benign") -> dict[str, object]:
    return {
        "expected_revision": revision,
        "decision": decision,
        "attack_type": "network_probe" if decision == "suspicious" else "",
        "confidence": 88,
        "rationale": "Independent assessment of the displayed network evidence.",
        "human_confirmed": True,
    }


def _authoritative_counts(db: Session) -> dict[str, int]:
    return {
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "models": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "detections": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        "suppressions": int(
            db.scalar(select(func.count(SuppressionRule.id))) or 0
        ),
    }


def test_campaign_rejects_consumed_and_duplicate_families() -> None:
    clean = {
        "id": 1,
        "role_rank": 0,
        "_candidate_family": "fresh-family",
        "event_time": "2026-09-01T00:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "app": "ssl",
        "action": "allow",
        "protocol": "tcp",
        "src_port": 45000,
        "dst_port": 443,
        "src_zone": "trust",
        "dst_zone": "untrust",
        "bytes": 1200,
        "bytes_sent": 700,
        "bytes_received": 500,
        "packets": 10,
        "elapsed_time": 2,
        "app_risk": 2,
        "repeat_count": 1,
        "app_characteristic": "",
        "session_end_reason": "aged-out",
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 2,
        "source_deny_count": 0,
        "source_unique_destinations": 1,
        "source_unique_ports": 1,
        "source_unknown_app_count": 0,
        "source_high_risk_app_count": 0,
        "destination_repeat_count": 1,
        "threat_severity": "none",
    }
    duplicate = {**clean, "event_time": "2026-09-01T00:01:00+00:00"}
    consumed = {
        **clean,
        "_candidate_family": "consumed-family",
        "_quarantine_reason": "consumed_v549b_family",
    }

    rows, selection = v562.select_fresh_review_candidates(
        [clean, duplicate, consumed],
        limit=3,
    )

    assert len(rows) == 1
    assert selection["duplicate_families_contained"] is True
    assert selection["exclusion_reasons"] == {
        "consumed_v549b_family": 1,
        "duplicate_family": 1,
    }
    assert rows[0]["predictions_exposed"] is False
    assert rows[0]["assisted_labels_exposed"] is False


def test_protocol_keeps_roles_isolated_and_gates_unchanged(tmp_path: Path) -> None:
    paths = _prepare_workspace(tmp_path)
    protocol = v562.validate_campaign_protocol(tmp_path)
    sealed_rows, _ = v562._read_csv(paths["sealed"])

    assert protocol["fixed_qualification_gates"] == v562.FIXED_QUALIFICATION_GATES
    assert protocol["partition"] == {
        "chronological": True,
        "duplicate_group_isolation": True,
        "roles_assigned_before_labels": True,
        "rows_movable_after_label_opening": False,
        "future_evaluation_labels_sealed": True,
    }
    assert len({row["review_token"] for row in sealed_rows}) == len(sealed_rows)
    assert all(row["human_reviewed"] == "False" for row in sealed_rows)
    assert protocol["second_source_placeholder"] == {
        "role": "second_source_validation",
        "rows": 0,
        "fabricated": False,
    }


def test_status_is_authenticated_redacted_and_fails_second_source_gate(
    qualification_client,
) -> None:
    client, _, _ = qualification_client
    assert (
        client.get("/api/evidence-review/supervised-qualification/status").status_code
        == 401
    )
    headers = _login(client, "qualification-reviewer")

    response = client.get(
        "/api/evidence-review/supervised-qualification/status",
        headers=headers,
    )
    assert response.status_code == 200
    payload = response.json()
    serialized = json.dumps(payload).casefold()
    assert payload["supervised_state"] == "unqualified"
    assert payload["rules_alert_authoritative"] is True
    assert payload["response_mode"] == "simulation_only"
    assert payload["qualification_gates"]["real_source_identities"]["status"] == "fail"
    assert payload["qualification_gates"]["independent_time_windows"]["status"] == "pass"
    assert payload["protocol"]["gates_unchanged"] is True
    for forbidden in (
        "synthetic-private-source-digest",
        "review_token",
        "source_ip",
        "destination_ip",
    ):
        assert forbidden not in serialized
    assert payload["raw_logs_exposed"] is False
    assert payload["fingerprints_exposed"] is False
    assert payload["private_paths_exposed"] is False


def test_review_owner_redaction_revision_and_zero_authoritative_writes(
    qualification_client,
) -> None:
    client, session_factory, _ = qualification_client
    artifacts_before = v55._model_artifact_states()
    owner = _login(client, "qualification-reviewer")
    other = _login(client, "other-reviewer")

    started = client.post(
        "/api/evidence-review/supervised-qualification/start",
        headers=owner,
    )
    assert started.status_code == 200
    start_payload = started.json()
    evidence = json.dumps(start_payload["next_item"]["evidence"]).casefold()
    assert start_payload["progress"]["evaluation_class_support_sealed"] is True
    assert start_payload["progress"]["activation_allowed"] is False
    for forbidden in (
        "review_token",
        "source_ip",
        "destination_ip",
        "raw_log",
        "fingerprint",
        "prediction",
        "model_score",
    ):
        assert forbidden not in evidence

    assert (
        client.get(
            "/api/evidence-review/supervised-qualification/items/0",
            headers=other,
        ).status_code
        == 403
    )
    revision = start_payload["revision"]
    saved = client.post(
        "/api/evidence-review/supervised-qualification/items/0",
        headers=owner,
        json=_payload(revision),
    )
    assert saved.status_code == 200
    assert saved.json()["authoritative_mutations"] == {
        "labels": 0,
        "model_runs": 0,
        "detection_runs": 0,
        "alerts": 0,
        "response_actions": 0,
    }
    conflict = client.post(
        "/api/evidence-review/supervised-qualification/items/1",
        headers=owner,
        json=_payload(revision),
    )
    assert conflict.status_code == 409

    with session_factory() as db:
        assert _authoritative_counts(db) == {
            "labels": 0,
            "models": 0,
            "detections": 0,
            "alerts": 0,
            "responses": 0,
            "suppressions": 0,
        }
        actions = list(db.scalars(select(AuditLog.action)))
        assert "qualification_review_started" in actions
        assert "qualification_review_saved" in actions
        assert "evidence_review_rejected" in actions
    assert v55._model_artifact_states() == artifacts_before


def test_automated_reviewer_and_incomplete_close_fail_closed(
    qualification_client,
) -> None:
    client, _, _ = qualification_client
    automated = _login(client, "codex-reviewer")
    assert (
        client.post(
            "/api/evidence-review/supervised-qualification/start",
            headers=automated,
        ).status_code
        == 422
    )

    owner = _login(client, "qualification-reviewer")
    started = client.post(
        "/api/evidence-review/supervised-qualification/start",
        headers=owner,
    ).json()
    closed = client.post(
        "/api/evidence-review/supervised-qualification/close",
        headers=owner,
        json={
            "expected_revision": started["revision"],
            "human_confirmed": True,
        },
    )
    assert closed.status_code == 409


def test_closed_review_is_immutable_and_evaluation_rows_stay_sealed(
    qualification_client,
) -> None:
    client, _, paths = qualification_client
    headers = _login(client, "qualification-reviewer")
    started = client.post(
        "/api/evidence-review/supervised-qualification/start",
        headers=headers,
    ).json()
    with pytest.raises(v562.V562CampaignError, match="remain sealed"):
        v562.load_reviewed_development_rows(paths["output_dir"])
    revision = started["revision"]
    for row_index in range(6):
        decision = "suspicious" if row_index % 2 else "benign"
        response = client.post(
            f"/api/evidence-review/supervised-qualification/items/{row_index}",
            headers=headers,
            json=_payload(revision, decision=decision),
        )
        assert response.status_code == 200
        revision = response.json()["revision"]

    closed = client.post(
        "/api/evidence-review/supervised-qualification/close",
        headers=headers,
        json={"expected_revision": revision, "human_confirmed": True},
    )
    assert closed.status_code == 200
    assert closed.json()["progress"]["closed"] is True
    assert closed.json()["progress"]["development_ready"] is True

    development_rows = v562.load_reviewed_development_rows(paths["output_dir"])
    assert len(development_rows) == 4
    assert all(
        row["evidence_role"] in v562.DEVELOPMENT_ROLE_NAMES
        for row in development_rows
    )
    assert all(
        row["evidence_role"] != v562.EVALUATION_ROLE_NAME
        for row in development_rows
    )
    repair = v562.get_development_repair_preflight(paths["output_dir"])
    assert repair["strategy_count"] == 8
    assert repair["feature_schema_valid"] is True
    assert repair["checks"]["chronological_roles_locked"] is True
    assert repair["checks"]["duplicate_groups_isolated"] is True
    assert repair["checks"]["provenance_support_sufficient"] is False
    assert repair["training_allowed"] is False
    assert repair["training_executed"] is False
    assert repair["calibration_outcomes_accessed"] is False
    assert repair["threshold_outcomes_accessed"] is False
    assert repair["evaluation_labels_accessed"] is False
    assert repair["evaluation_rows_loaded"] == 0
    assert repair["candidate_frozen"] is False
    assert repair["active_artifact_written"] is False

    immutable = client.post(
        "/api/evidence-review/supervised-qualification/items/0",
        headers=headers,
        json=_payload(closed.json()["revision"]),
    )
    assert immutable.status_code == 409
