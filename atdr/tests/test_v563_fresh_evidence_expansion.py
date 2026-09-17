from __future__ import annotations

import json
import sqlite3
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
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.detection import v563_fresh_evidence_expansion as v563
from atdr.app.main import app
from atdr.app.routers import evidence_review as evidence_review_router
from atdr.app.services import v563_supervised_expansion_review_service as service
from atdr.app.services.user_service import create_user


def _pack_row(
    index: int,
    *,
    role: str,
    token_prefix: str,
    batch_id: str | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "review_token": f"{token_prefix}-{index:03d}",
        "evidence_role": role,
        "coverage_group": (
            "web_transport_context" if index % 2 == 0 else "high_activity_context"
        ),
        "event_time_utc": f"2026-09-{(index % 28) + 1:02d}T00:00:00+00:00",
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
    if batch_id is not None:
        row["review_batch_id"] = batch_id
    return row


def _prepare_v562(output_dir: Path) -> dict[str, Path]:
    roles = [
        "development_fit",
        "development_fit",
        "calibration",
        "threshold_selection",
        "untouched_future_evaluation",
        "untouched_future_evaluation",
    ]
    rows = [
        _pack_row(index, role=role, token_prefix="synthetic-v562")
        for index, role in enumerate(roles)
    ]
    v562._prepare_workspace(
        rows,
        selection={
            "selected_rows": len(rows),
            "role_counts": {role: roles.count(role) for role in set(roles)},
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


def _prepare_v563(
    v562_dir: Path,
    output_dir: Path,
    *,
    primary_tokens: set[str] | None = None,
) -> dict[str, Path]:
    snapshot = v563._v562_snapshot(v562_dir, expected_rows=6)
    roles = [
        "development_fit",
        "development_fit",
        "development_fit",
        "calibration",
        "calibration",
        "threshold_selection",
    ]
    rows = [
        _pack_row(
            index,
            role=role,
            token_prefix="synthetic-v563",
            batch_id="batch-01" if index < 3 else "batch-02",
        )
        for index, role in enumerate(roles)
    ]
    selection = {
        "selected_rows": len(rows),
        "role_counts": {role: roles.count(role) for role in set(roles)},
        "fresh_rows_available": 500,
    }
    v563._prepare_workspace(
        rows,
        selection=selection,
        selected_families={f"supplemental-family-{index}" for index in range(6)},
        original_families={f"original-family-{index}" for index in range(6)},
        v562_snapshot=snapshot,
        source_digest="synthetic-private-source-digest",
        primary_source_tokens=primary_tokens or {"primary-device-token"},
        profile={"rows_processed": 600},
        roles={"distinct_time_windows": 3},
        output_dir=output_dir,
        v562_output_dir=v562_dir,
    )
    return v563._paths(output_dir)


@pytest.fixture()
def expansion_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[
    tuple[TestClient, sessionmaker[Session], dict[str, Path], Path], None, None
]:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    _prepare_v562(v562_dir)
    paths = _prepare_v563(v562_dir, v563_dir)
    monkeypatch.setattr(service, "_paths", lambda: paths)
    monkeypatch.setattr(
        service,
        "_validate_protocol",
        lambda output_dir: v563.validate_expansion_protocol(
            output_dir,
            v562_output_dir=v562_dir,
            expected_original_rows=6,
        ),
    )
    monkeypatch.setattr(
        service,
        "_campaign_status",
        lambda output_dir: v563.get_public_v563_status(
            output_dir,
            v562_output_dir=v562_dir,
        ),
    )
    monkeypatch.setattr(
        evidence_review_router,
        "get_public_v563_status",
        lambda: v563.get_public_v563_status(
            v563_dir,
            v562_output_dir=v562_dir,
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
            username="expansion-reviewer",
            password="analyst123",
            role="analyst",
            full_name="Expansion Reviewer",
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
        yield TestClient(app), testing_session, paths, v562_dir
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


def _candidate(index: int, *, role_rank: int, family: str) -> dict[str, object]:
    return {
        "id": index,
        "role_rank": role_rank,
        "_candidate_family": family,
        "event_time": f"2026-09-{(index % 28) + 1:02d}T00:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "app": "ssl",
        "action": "allow",
        "protocol": "tcp",
        "src_port": 45000 + index,
        "dst_port": 443,
        "src_zone": "trust",
        "dst_zone": "untrust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "app_risk": 2,
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


def test_supplemental_selection_rejects_original_overlap_duplicates_and_evaluation() -> None:
    original = _candidate(1, role_rank=0, family="original-family")
    original_token = v562._candidate_projection(
        original,
        family="original-family",
    )["review_token"]
    rows = [original]
    rows.extend(
        _candidate(index, role_rank=index % 3, family=f"fresh-{index}")
        for index in range(2, 12)
    )
    rows.append(_candidate(20, role_rank=3, family="future-evaluation"))
    rows.append(_candidate(21, role_rank=0, family="fresh-2"))

    selected, summary, families = v563.select_supplemental_review_candidates(
        rows,
        original_review_tokens={str(original_token)},
        limit=9,
        batch_size=3,
    )

    assert len(selected) == 9
    assert len(families) == 9
    assert summary["duplicate_families_contained"] is True
    assert summary["future_evaluation_rows_selected"] == 0
    assert summary["exclusion_reasons"] == {
        "duplicate_family": 1,
        "sealed_future_evaluation_role": 1,
        "selected_v562_evidence": 1,
    }
    assert all(
        row["evidence_role"] in v562.DEVELOPMENT_ROLE_NAMES for row in selected
    )
    assert all(row["predictions_exposed"] is False for row in selected)
    assert {row["review_batch_id"] for row in selected} == {"batch-01"}


def test_append_only_protocol_preserves_original_pack(tmp_path: Path) -> None:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    original_paths = _prepare_v562(v562_dir)
    before = {
        name: path.read_bytes()
        for name, path in original_paths.items()
        if path.is_file()
    }
    _prepare_v563(v562_dir, v563_dir)
    protocol = v563.validate_expansion_protocol(
        v563_dir,
        v562_output_dir=v562_dir,
        expected_original_rows=6,
    )

    assert protocol["append_only"] is True
    assert protocol["total_comparable_capacity"] == 12
    assert protocol["fixed_qualification_gates"] == v562.FIXED_QUALIFICATION_GATES
    assert protocol["partition"]["v562_future_evaluation_labels_sealed"] is True
    assert protocol["evaluation_labels_accessible"] is False
    assert protocol["training_allowed"] is False
    assert all(
        path.read_bytes() == before[name]
        for name, path in original_paths.items()
        if name in before
    )


def test_expansion_api_is_authenticated_redacted_owner_isolated_and_write_safe(
    expansion_client,
) -> None:
    client, session_factory, _, _ = expansion_client
    endpoint = "/api/evidence-review/supervised-qualification/expansion"
    assert client.get(f"{endpoint}/status").status_code == 401
    owner = _login(client, "expansion-reviewer")
    other = _login(client, "other-reviewer")
    artifacts_before = v55._model_artifact_states()

    campaign = client.get(f"{endpoint}/status", headers=owner)
    assert campaign.status_code == 200
    payload = campaign.json()
    serialized = json.dumps(payload).casefold()
    assert payload["supervised_state"] == "unqualified"
    assert payload["development_training_can_begin"] is False
    assert payload["protocol"]["evaluation_labels_sealed"] is True
    assert payload["rules_alert_authoritative"] is True
    assert payload["response_mode"] == "simulation_only"
    for forbidden in (
        "review_token",
        "primary-device-token",
        "source_ip",
        "destination_ip",
        "synthetic-private-source-digest",
    ):
        if forbidden == "review_token":
            assert "synthetic-v562-token" not in serialized
            assert "synthetic-v563-token" not in serialized
        else:
            assert forbidden not in serialized

    started = client.post(
        f"{endpoint}/start",
        headers=owner,
        json={"batch_id": "batch-01"},
    )
    assert started.status_code == 200
    start_payload = started.json()
    assert start_payload["batch_id"] == "batch-01"
    assert start_payload["training_executed"] is False
    assert start_payload["evaluation_executed"] is False
    evidence = json.dumps(start_payload["next_item"]["evidence"]).casefold()
    for forbidden in (
        "review_token",
        "source_ip",
        "destination_ip",
        "prediction",
        "model_score",
        "raw_log",
    ):
        assert forbidden not in evidence

    row_index = start_payload["next_item"]["row_index"]
    assert (
        client.get(
            f"{endpoint}/items/{row_index}?batch_id=batch-01",
            headers=other,
        ).status_code
        == 403
    )
    revision = start_payload["revision"]
    saved = client.post(
        f"{endpoint}/items/{row_index}?batch_id=batch-01",
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
    stale = client.post(
        f"{endpoint}/items/{saved.json()['next_item']['row_index']}?batch_id=batch-01",
        headers=owner,
        json=_payload(revision),
    )
    assert stale.status_code == 409

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
        assert "expansion_review_batch_started" in actions
        assert "expansion_review_saved" in actions
        assert "evidence_review_rejected" in actions
    assert v55._model_artifact_states() == artifacts_before


def test_batch_closure_is_independent_and_immutable(expansion_client) -> None:
    client, _, paths, v562_dir = expansion_client
    owner = _login(client, "expansion-reviewer")
    endpoint = "/api/evidence-review/supervised-qualification/expansion"
    started = client.post(
        f"{endpoint}/start",
        headers=owner,
        json={"batch_id": "batch-01"},
    ).json()
    revision = started["revision"]
    indexes = [0, 1, 2]
    for index in indexes:
        response = client.post(
            f"{endpoint}/items/{index}?batch_id=batch-01",
            headers=owner,
            json=_payload(revision, decision="suspicious" if index == 1 else "benign"),
        )
        assert response.status_code == 200
        revision = response.json()["revision"]

    closed = client.post(
        f"{endpoint}/close?batch_id=batch-01",
        headers=owner,
        json={"expected_revision": revision, "human_confirmed": True},
    )
    assert closed.status_code == 200
    assert closed.json()["progress"]["closed_batch_count"] == 1
    assert closed.json()["progress"]["closed"] is False
    immutable = client.post(
        f"{endpoint}/items/0?batch_id=batch-01",
        headers=owner,
        json=_payload(closed.json()["revision"]),
    )
    assert immutable.status_code == 409
    with pytest.raises(v563.V563ExpansionError, match="every batch closes"):
        v563.load_reviewed_combined_development_rows(
            paths["output_dir"],
            v562_output_dir=v562_dir,
        )


def test_automated_reviewer_is_rejected(expansion_client) -> None:
    client, _, _, _ = expansion_client
    automated = _login(client, "codex-reviewer")
    response = client.post(
        "/api/evidence-review/supervised-qualification/expansion/start",
        headers=automated,
        json={"batch_id": "batch-01"},
    )
    assert response.status_code == 422


def _source_tokens(path: Path, tmp_path: Path) -> set[str]:
    connection = sqlite3.connect(tmp_path / "source-index.sqlite3")
    try:
        result = v56.stream_private_file_to_disposable_index(
            path,
            connection,
            database_url=None,
        )
        assert result["ok"] is True
        return v563._source_identity_tokens(connection)
    finally:
        connection.close()


def test_second_source_preflight_fails_same_device_and_accepts_distinct_device(
    tmp_path: Path,
) -> None:
    primary = tmp_path / "primary.log"
    primary.write_text(
        Path("data/samples/paloalto-demo.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    tokens = _source_tokens(primary, tmp_path)
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir, primary_tokens=tokens)

    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as db:
        same = v563.run_second_source_intake_preflight(
            db,
            second_source_path=primary,
            use_temp_db=True,
            output_dir=v563_dir,
            v562_output_dir=v562_dir,
        )
        distinct = tmp_path / "distinct.log"
        distinct.write_text(
            primary.read_text(encoding="utf-8").replace(
                "000000000001",
                "000000000002",
            ),
            encoding="utf-8",
        )
        independent = v563.run_second_source_intake_preflight(
            db,
            second_source_path=distinct,
            use_temp_db=True,
            output_dir=v563_dir,
            v562_output_dir=v562_dir,
        )
        assert _authoritative_counts(db) == {
            "labels": 0,
            "models": 0,
            "detections": 0,
            "alerts": 0,
            "responses": 0,
            "suppressions": 0,
        }
    engine.dispose()

    assert same["ok"] is False
    assert same["status"] == "failed_closed_not_independent"
    assert independent["ok"] is True
    assert independent["status"] == "independent_second_source_candidate"
    assert independent["candidate"]["independent_from_primary"] is True
    assert independent["candidate_added_to_campaign"] is False
    assert independent["source_gate_updated"] is False
    encoded = json.dumps([same, independent]).casefold()
    for forbidden in (
        str(primary).casefold(),
        str(distinct).casefold(),
        primary.name.casefold(),
        distinct.name.casefold(),
        next(iter(tokens)).casefold(),
    ):
        assert forbidden not in encoded
