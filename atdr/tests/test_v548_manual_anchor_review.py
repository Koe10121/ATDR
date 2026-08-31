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
)
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548
from atdr.app.main import app
from atdr.app.services import v548_manual_anchor_review_service as service
from atdr.app.services.user_service import create_user


def _pack_row(index: int, *, role: str, stratum: str) -> dict[str, object]:
    return {
        "review_token": f"private-review-token-{index:03d}",
        "evidence_role": role,
        "selection_stratum": stratum,
        "review_priority": "manual_anchor_gap",
        "event_time_utc": f"2026-08-01T00:{index:02d}:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "unknown-udp" if index % 2 else "ssl",
        "action": "deny" if index % 2 else "allow",
        "protocol": "udp" if index % 2 else "tcp",
        "source_port": 45000 + index,
        "destination_port": 4040 if index % 2 else 443,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 4 if index % 2 else 2,
        "threat_severity": "medium" if index % 2 else "none",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 20 if index % 2 else 2,
        "source_deny_count": 10 if index % 2 else 0,
        "source_unique_destinations": 10 if index % 2 else 1,
        "source_unique_ports": 12 if index % 2 else 1,
        "source_unknown_app_count": 10 if index % 2 else 0,
        "source_high_risk_app_count": 2 if index % 2 else 0,
        "destination_repeat_count": 1,
        "predictions_exposed": False,
        "model_scores_exposed": False,
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


def _prepare_workspace(output_dir: Path) -> service.ManualAnchorReviewPaths:
    roles = [
        "development_fit",
        "development_fit",
        "calibration",
        "calibration",
        "threshold",
        "threshold",
    ]
    strata = [
        "routine_benign_control",
        "scan_like_behavior",
        "unknown_transport",
        "incomplete_allow_80",
        "quic_443_control",
        "low_signal_suspicious_boundary",
    ]
    rows = [
        _pack_row(index, role=role, stratum=strata[index])
        for index, role in enumerate(roles)
    ]
    v547._prepare_workspace(
        rows,
        {
            "selected_rows": len(rows),
            "target_rows": 120,
            "coverage_gate_passed": False,
            "coverage_counts": dict.fromkeys(strata, 1),
        },
        output_dir=output_dir,
    )
    return service.ManualAnchorReviewPaths(
        output_dir=output_dir,
        sealed_pack=output_dir / v547.V547_SEALED_PACK,
        working_copy=output_dir / v547.V547_WORKING_COPY,
        manifest=output_dir / v547.V547_MANIFEST,
        protocol_lock=output_dir / v548.V548_PROTOCOL_LOCK,
        state=output_dir / v548.V548_REVIEW_STATE,
    )


@pytest.fixture()
def review_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, sessionmaker[Session], service.ManualAnchorReviewPaths], None, None]:
    paths = _prepare_workspace(tmp_path)
    monkeypatch.setattr(service, "_workspace_paths", lambda: paths)

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
        with testing_session() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), testing_session, paths
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _login(
    client: TestClient,
    username: str,
    password: str = "analyst123",
) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _payload(revision: int, *, decision: str = "benign") -> dict[str, object]:
    return {
        "expected_revision": revision,
        "decision": decision,
        "attack_type": "port_scan" if decision == "suspicious" else "",
        "confidence": 90,
        "rationale": "Independent analyst review of the approved evidence fields.",
        "human_confirmed": True,
    }


def _authoritative_counts(db: Session) -> dict[str, int]:
    return {
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "models": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "detections": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def test_manual_anchor_review_requires_authentication(review_client) -> None:
    client, _, _ = review_client
    assert client.get("/api/evidence-review/manual-anchors/status").status_code == 401
    assert client.post("/api/evidence-review/manual-anchors/start").status_code == 401
    assert client.get("/api/evidence-review/manual-anchors/items/0").status_code == 401


def test_protocol_locks_before_evidence_and_only_approved_fields_are_returned(
    review_client,
) -> None:
    client, _, paths = review_client
    headers = _login(client, "reviewer-one")

    started = client.post(
        "/api/evidence-review/manual-anchors/start",
        headers=headers,
    )
    assert started.status_code == 200
    assert paths.protocol_lock.is_file()
    payload = started.json()
    serialized_evidence = json.dumps(payload["next_item"]["evidence"]).casefold()
    assert payload["progress"]["protocol_locked"] is True
    assert payload["progress"]["protocol_valid"] is True
    assert payload["next_item"]["predictions_exposed"] is False
    for forbidden in (
        "review_token",
        "source_ip",
        "destination_ip",
        "raw_log",
        "fingerprint",
        "private-review-token",
    ):
        assert forbidden not in serialized_evidence
    assert payload["next_item"]["raw_logs_exposed"] is False
    assert payload["next_item"]["fingerprints_exposed"] is False

    page = client.get(
        "/api/evidence-review/manual-anchors/items",
        params={"review_state": "pending", "limit": 2},
        headers=headers,
    )
    assert page.status_code == 200
    assert page.json()["filtered_total"] == 6
    assert len(page.json()["items"]) == 2


def test_owner_access_revision_and_audit_are_enforced(review_client) -> None:
    client, session_factory, _ = review_client
    owner = _login(client, "reviewer-one")
    other = _login(client, "reviewer-two")
    started = client.post(
        "/api/evidence-review/manual-anchors/start",
        headers=owner,
    ).json()
    revision = started["revision"]

    assert (
        client.get(
            "/api/evidence-review/manual-anchors/items/0",
            headers=other,
        ).status_code
        == 403
    )
    saved = client.post(
        "/api/evidence-review/manual-anchors/items/0",
        headers=owner,
        json=_payload(revision),
    )
    assert saved.status_code == 200
    assert saved.json()["revision"] == revision + 1
    assert saved.json()["authoritative_mutations"] == {
        "labels": 0,
        "model_runs": 0,
        "detection_runs": 0,
        "alerts": 0,
        "response_actions": 0,
    }
    conflict = client.post(
        "/api/evidence-review/manual-anchors/items/1",
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
        }
        actions = list(db.scalars(select(AuditLog.action)))
        assert "manual_anchor_review_started" in actions
        assert "manual_anchor_review_saved" in actions
        assert "evidence_review_rejected" in actions


def test_automated_reviewer_and_incomplete_closure_are_rejected(review_client) -> None:
    client, _, _ = review_client
    automated = _login(client, "codex-reviewer")
    rejected = client.post(
        "/api/evidence-review/manual-anchors/start",
        headers=automated,
    )
    assert rejected.status_code == 422

    owner = _login(client, "admin", password="admin123")
    started = client.post(
        "/api/evidence-review/manual-anchors/start",
        headers=owner,
    ).json()
    closed = client.post(
        "/api/evidence-review/manual-anchors/close",
        headers=owner,
        json={
            "expected_revision": started["revision"],
            "human_confirmed": True,
        },
    )
    assert closed.status_code == 409


def test_fixed_revalidation_blocks_before_genuine_review_closure(
    review_client,
) -> None:
    _, _, paths = review_client
    result = v548.run_v548_manual_anchor_fixed_revalidation(
        output_dir=paths.output_dir,
        preflight_only=True,
        use_temp_db=True,
    )
    assert result["ok"] is True
    assert result["protocol"]["locked"] is True
    blocked = v548.run_v548_manual_anchor_fixed_revalidation(
        output_dir=paths.output_dir,
        confirmation=v548.MEASURED_CONFIRMATION,
        use_temp_db=True,
    )
    assert blocked["ok"] is False
    assert blocked["status"] == "blocked_review_incomplete"
    assert blocked["evaluation_attempted"] is False
    assert blocked["model_activated"] is False
    assert blocked["response_automation_allowed"] is False


def test_protocol_and_pack_tampering_fail_closed(review_client) -> None:
    client, _, paths = review_client
    headers = _login(client, "reviewer-one")
    assert (
        client.post(
            "/api/evidence-review/manual-anchors/start",
            headers=headers,
        ).status_code
        == 200
    )
    protocol = json.loads(paths.protocol_lock.read_text(encoding="utf-8"))
    protocol["protocol"]["feature_schema"] = ["tampered"]
    paths.protocol_lock.write_text(json.dumps(protocol), encoding="utf-8")
    assert (
        client.get(
            "/api/evidence-review/manual-anchors/items/0",
            headers=headers,
        ).status_code
        == 409
    )


def test_review_state_must_remain_bound_to_locked_protocol(review_client) -> None:
    client, _, paths = review_client
    headers = _login(client, "reviewer-one")
    assert (
        client.post(
            "/api/evidence-review/manual-anchors/start",
            headers=headers,
        ).status_code
        == 200
    )
    state = json.loads(paths.state.read_text(encoding="utf-8"))
    state["protocol_digest"] = "tampered"
    paths.state.write_text(json.dumps(state), encoding="utf-8")
    assert (
        client.get(
            "/api/evidence-review/manual-anchors/items/0",
            headers=headers,
        ).status_code
        == 409
    )


def test_completed_review_closes_and_becomes_immutable(review_client) -> None:
    client, _, _ = review_client
    headers = _login(client, "reviewer-one")
    started = client.post(
        "/api/evidence-review/manual-anchors/start",
        headers=headers,
    ).json()
    revision = started["revision"]
    for row_index in range(6):
        response = client.post(
            f"/api/evidence-review/manual-anchors/items/{row_index}",
            headers=headers,
            json=_payload(
                revision,
                decision="suspicious" if row_index % 2 else "benign",
            ),
        )
        assert response.status_code == 200
        revision = response.json()["revision"]
    assert response.json()["progress"]["completed"] is True

    closed = client.post(
        "/api/evidence-review/manual-anchors/close",
        headers=headers,
        json={"expected_revision": revision, "human_confirmed": True},
    )
    assert closed.status_code == 200
    assert closed.json()["progress"]["closed"] is True
    immutable = client.post(
        "/api/evidence-review/manual-anchors/items/0",
        headers=headers,
        json=_payload(closed.json()["revision"]),
    )
    assert immutable.status_code == 409
