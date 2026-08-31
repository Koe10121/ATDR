from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime
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
from atdr.app.detection import (
    v549a_supplemental_threat_anchor_acquisition as v549a,
)
from atdr.app.main import app
from atdr.app.routers import evidence_review as review_router
from atdr.app.services import (
    v549a_supplemental_threat_anchor_review_service as service,
)
from atdr.app.services.user_service import create_user


def _base_row(index: int, *, role: str, stratum: str) -> dict[str, object]:
    return {
        "review_token": f"sealed-token-{index:03d}",
        "evidence_role": role,
        "selection_stratum": stratum,
        "review_priority": "manual_anchor_gap",
        "event_time_utc": f"2026-08-01T00:{index % 60:02d}:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "ssl",
        "action": "allow",
        "protocol": "tcp",
        "source_port": 45000 + index,
        "destination_port": 443,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 2,
        "threat_severity": "none",
        "session_end_reason": "aged-out",
        "parser_error": False,
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


def _prepare_original_review(output_dir: Path) -> None:
    roles = ["development_fit", "calibration", "threshold"]
    rows = [
        _base_row(index, role=roles[index % 3], stratum="original_anchor")
        for index in range(120)
    ]
    v547._prepare_workspace(
        rows,
        {
            "selected_rows": 120,
            "target_rows": 120,
            "coverage_gate_passed": True,
            "coverage_counts": {"original_anchor": 120},
        },
        output_dir=output_dir,
    )
    v548.lock_fixed_protocol(output_dir)
    working_rows, _ = v547._read_csv(output_dir / v547.V547_WORKING_COPY)
    reviewed_at = datetime.now(UTC).isoformat()
    for index, row in enumerate(working_rows):
        decision = "benign" if index < 92 else "suspicious" if index < 101 else "needs_context"
        row.update(
            {
                "human_decision": decision,
                "human_attack_type": "port_scan" if decision == "suspicious" else "",
                "human_confidence": "90",
                "human_rationale": "Independent human decision based on approved evidence.",
                "human_reviewer": "reviewer-one",
                "human_reviewed_at": reviewed_at,
                "human_must_confirm": True,
                "human_reviewed": True,
                "import_ready": False,
            }
        )
    v547._atomic_write_csv(output_dir / v547.V547_WORKING_COPY, working_rows)
    v548._atomic_write_json(
        output_dir / v548.V548_REVIEW_STATE,
        {
            "schema_version": v548.V548_VERSION,
            "revision": 120,
            "closed_at": reviewed_at,
        },
    )
    status = v549a.validate_original_review_custody(output_dir)
    assert status["review"]["class_support"] == {
        "benign_like": 92,
        "suspicious": 9,
        "malicious": 0,
    }


def _supplemental_row(index: int) -> dict[str, object]:
    role = ["development_fit", "calibration", "threshold"][index % 3]
    row = _base_row(index, role=role, stratum="supplemental_rule_evidence")
    row.update(
        {
            "review_token": f"supplemental-token-{index:03d}",
            "review_priority": "supplemental_threat_anchor",
            "log_type": "THREAT" if index < 10 else "TRAFFIC",
            "application": "unknown-tcp",
            "action": "deny",
            "destination_port": 445,
            "application_risk": 5,
            "threat_severity": "high" if index < 10 else "medium",
            "source_event_count": 25,
            "source_deny_count": 20,
            "source_auth_deny_count": 10,
            "source_unique_destinations": 12,
            "source_unique_ports": 15,
            "bytes_sent": 4000,
            "external_to_internal": True,
            "rule_evidence": "possible_port_scan; multiple_denied_connections",
            "rule_evidence_score": 100,
        }
    )
    return row


def _prepare_supplemental(output_dir: Path, original_output_dir: Path) -> None:
    rows = [_supplemental_row(index) for index in range(16)]
    v549a._prepare_workspace(
        rows,
        {
            "selected_rows": 16,
            "target_rows": 60,
            "coverage_gate_passed": True,
            "coverage_counts": {"supplemental_rule_evidence": 16},
        },
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )


@pytest.fixture()
def supplemental_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[
    tuple[
        TestClient,
        sessionmaker[Session],
        service.SupplementalThreatAnchorReviewPaths,
    ],
    None,
    None,
]:
    original_output_dir = tmp_path / "original"
    supplemental_output_dir = tmp_path / "supplemental"
    _prepare_original_review(original_output_dir)
    _prepare_supplemental(supplemental_output_dir, original_output_dir)
    paths = service.SupplementalThreatAnchorReviewPaths(
        output_dir=supplemental_output_dir,
        sealed_pack=supplemental_output_dir / v549a.V549A_SEALED_PACK,
        working_copy=supplemental_output_dir / v549a.V549A_WORKING_COPY,
        manifest=supplemental_output_dir / v549a.V549A_MANIFEST,
        state=supplemental_output_dir / v549a.V549A_REVIEW_STATE,
        proposed_protocol=supplemental_output_dir / v549a.V549B_PROPOSED_PROTOCOL,
        original_output_dir=original_output_dir,
    )
    monkeypatch.setattr(service, "_workspace_paths", lambda: paths)
    monkeypatch.setattr(
        review_router,
        "get_public_v549a_status",
        lambda: v549a.get_public_v549a_status(
            output_dir=supplemental_output_dir,
            original_output_dir=original_output_dir,
        ),
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


def _review_payload(revision: int, *, decision: str) -> dict[str, object]:
    return {
        "expected_revision": revision,
        "decision": decision,
        "attack_type": (
            "malware_c2"
            if decision == "malicious"
            else "port_scan"
            if decision == "suspicious"
            else ""
        ),
        "confidence": 90,
        "rationale": "Independent analyst decision based on approved deterministic evidence.",
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


def test_selection_excludes_original_reserved_and_duplicate_families(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows: list[dict[str, object]] = []
    for index in range(48):
        row = {
            "id": index,
            "role_rank": 0,
            "_candidate_family": f"family-{index}",
            "_quarantine_reason": None,
            "event_time": "2026-08-01T00:00:00+00:00",
            "log_type": "THREAT" if index < 15 else "TRAFFIC",
            "subtype": "end",
            "app": "unknown-tcp" if index >= 30 else "ssl",
            "action": "deny" if index >= 15 else "allow",
            "protocol": "tcp",
            "src_port": 45000 + index,
            "dst_port": 445,
            "src_zone": "untrust",
            "dst_zone": "trust",
            "app_risk": 5,
            "threat_severity": "high" if index < 15 else "none",
            "source_event_count": 25,
            "source_deny_count": 10,
            "source_auth_deny_count": 10 if 15 <= index < 30 else 0,
            "source_unique_destinations": 12,
            "source_unique_ports": 15,
            "source_high_risk_app_count": 3,
            "parser_error": 0,
        }
        rows.append(row)
    original_token = v549a._original_token_for(
        rows[0], family=str(rows[0]["_candidate_family"])
    )
    rows.append({**rows[1], "id": 100, "_candidate_family": "family-1"})
    rows.append({**rows[2], "id": 101, "role_rank": 4, "_candidate_family": "reserved"})

    def rule_evidence(row: dict[str, object]) -> tuple[list[str], int]:
        if int(row["id"]) < 15:
            return ["paloalto_threat_log"], 80
        if int(row["id"]) < 30:
            return ["brute_force_like_attempts"], 90
        return ["possible_port_scan"], 100

    monkeypatch.setattr(v549a.v56, "_rule_evidence", rule_evidence)
    selected, status = v549a.select_supplemental_candidates(
        rows,
        original_review_tokens={original_token},
        prior_manual_families={"family-3"},
        limit=40,
    )
    assert len(selected) == 40
    assert status["coverage_gate_passed"] is True
    assert status["original_anchor_families_selected"] == 0
    assert status["future_roles_selected"] == 0
    assert status["predictions_used_for_selection"] is False
    assert status["exclusion_reasons"]["closed_v548_anchor_family"] == 1
    assert status["exclusion_reasons"]["prior_manual_anchor_family"] == 1
    assert status["exclusion_reasons"]["duplicate_family"] == 1
    assert status["exclusion_reasons"]["locked_or_reserved_role"] == 1
    columns = {str(key).casefold() for row in selected for key in row}
    assert "prediction" not in columns
    assert "model_prediction" not in columns
    assert "source_ip" not in columns
    assert "destination_ip" not in columns


def test_supplemental_review_is_authenticated_owner_isolated_and_quota_blind(
    supplemental_client,
) -> None:
    client, session_factory, _ = supplemental_client
    assert (
        client.get(
            "/api/evidence-review/supplemental-threat-anchors/status"
        ).status_code
        == 401
    )
    owner = _login(client, "reviewer-one")
    other = _login(client, "reviewer-two")
    acquisition_status = client.get(
        "/api/evidence-review/supplemental-threat-anchors/acquisition-status",
        headers=owner,
    )
    assert acquisition_status.status_code == 200
    review_status = client.get(
        "/api/evidence-review/supplemental-threat-anchors/status",
        headers=owner,
    )
    assert review_status.status_code == 200
    started = client.post(
        "/api/evidence-review/supplemental-threat-anchors/start",
        headers=owner,
    )
    assert started.status_code == 200
    payload = started.json()
    assert payload["progress"]["combined_support_visible"] is False
    assert payload["progress"]["combined_class_support"] == {}
    assert payload["evaluation_execution_count"] == 0
    evidence = json.dumps(payload["next_item"]["evidence"]).casefold()
    assert "possible_port_scan" in evidence
    for forbidden in (
        "review_token",
        "source_ip",
        "destination_ip",
        "raw_log",
        "fingerprint",
        "prediction",
    ):
        assert forbidden not in evidence
    denied = client.get(
        "/api/evidence-review/supplemental-threat-anchors/items/0",
        headers=other,
    )
    assert denied.status_code == 403
    with session_factory() as db:
        actions = set(db.scalars(select(AuditLog.action)).all())
    assert {
        "supplemental_anchor_status_viewed",
        "supplemental_anchor_review_status_viewed",
        "supplemental_anchor_review_started",
        "evidence_review_rejected",
    } <= actions


def test_closed_supplemental_review_combines_support_without_side_effects(
    supplemental_client,
) -> None:
    client, session_factory, paths = supplemental_client
    owner = _login(client, "reviewer-one")
    original_before = v549a._original_private_state(paths.original_output_dir)
    started = client.post(
        "/api/evidence-review/supplemental-threat-anchors/start",
        headers=owner,
    ).json()
    revision = started["revision"]
    for row_index in range(16):
        decision = "malicious" if row_index < 10 else "suspicious"
        response = client.post(
            f"/api/evidence-review/supplemental-threat-anchors/items/{row_index}",
            headers=owner,
            json=_review_payload(revision, decision=decision),
        )
        assert response.status_code == 200
        revision = response.json()["revision"]
    closed = client.post(
        "/api/evidence-review/supplemental-threat-anchors/close",
        headers=owner,
        json={"expected_revision": revision, "human_confirmed": True},
    )
    assert closed.status_code == 200
    progress = closed.json()["progress"]
    assert progress["closed"] is True
    assert progress["combined_support_visible"] is True
    assert progress["combined_class_support"] == {
        "benign_like": 92,
        "suspicious": 15,
        "malicious": 10,
    }
    assert progress["combined_support_passed"] is True
    assert progress["ready_for_relocked_protocol"] is True
    assert paths.proposed_protocol.is_file()
    assert v549a._original_private_state(paths.original_output_dir) == original_before
    assert not (paths.original_output_dir / v548.V548_EXECUTION_CLAIM).exists()
    assert not (paths.original_output_dir / v548.V548_RESULT).exists()
    with session_factory() as db:
        assert _authoritative_counts(db) == {
            "labels": 0,
            "models": 0,
            "detections": 0,
            "alerts": 0,
            "responses": 0,
        }
    immutable = client.post(
        "/api/evidence-review/supplemental-threat-anchors/items/0",
        headers=owner,
        json=_review_payload(closed.json()["revision"], decision="malicious"),
    )
    assert immutable.status_code == 409


def test_threat_decision_requires_attack_type(supplemental_client) -> None:
    client, _, _ = supplemental_client
    owner = _login(client, "reviewer-one")
    started = client.post(
        "/api/evidence-review/supplemental-threat-anchors/start",
        headers=owner,
    ).json()
    payload = _review_payload(started["revision"], decision="malicious")
    payload["attack_type"] = ""
    response = client.post(
        "/api/evidence-review/supplemental-threat-anchors/items/0",
        headers=owner,
        json=payload,
    )
    assert response.status_code == 422


def test_insufficient_support_closes_without_protocol_or_evaluation(
    supplemental_client,
) -> None:
    client, session_factory, paths = supplemental_client
    owner = _login(client, "reviewer-one")
    original_before = v549a._original_private_state(paths.original_output_dir)
    started = client.post(
        "/api/evidence-review/supplemental-threat-anchors/start",
        headers=owner,
    ).json()
    revision = started["revision"]
    for row_index in range(16):
        response = client.post(
            f"/api/evidence-review/supplemental-threat-anchors/items/{row_index}",
            headers=owner,
            json=_review_payload(revision, decision="needs_context"),
        )
        assert response.status_code == 200
        revision = response.json()["revision"]
    closed = client.post(
        "/api/evidence-review/supplemental-threat-anchors/close",
        headers=owner,
        json={"expected_revision": revision, "human_confirmed": True},
    )
    assert closed.status_code == 200
    progress = closed.json()["progress"]
    assert progress["closed"] is True
    assert progress["combined_support_visible"] is True
    assert progress["combined_support_passed"] is False
    assert progress["ready_for_relocked_protocol"] is False
    assert progress["proposed_protocol_created"] is False
    assert not paths.proposed_protocol.exists()
    assert not (paths.original_output_dir / v548.V548_EXECUTION_CLAIM).exists()
    assert not (paths.original_output_dir / v548.V548_RESULT).exists()
    assert v549a._original_private_state(paths.original_output_dir) == original_before
    with session_factory() as db:
        assert _authoritative_counts(db) == {
            "labels": 0,
            "models": 0,
            "detections": 0,
            "alerts": 0,
            "responses": 0,
        }
