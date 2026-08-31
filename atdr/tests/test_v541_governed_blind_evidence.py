from __future__ import annotations

import csv
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from atdr.app.detection import v541_governed_blind_evidence as evidence
from atdr.app.detection import v56_private_panos_model_repair as private_panos


def _event_record(
    *,
    exact_hash: str,
    propagation_hash: str,
    event_time: str | None,
    minute_bucket: str | None,
    role_rank: int = 4,
    quarantine_reason: str | None = None,
    source_token: str = "source-token",
    destination_token: str = "destination-token",
) -> tuple[object, ...]:
    return (
        exact_hash,
        propagation_hash,
        event_time,
        minute_bucket,
        role_rank,
        quarantine_reason,
        source_token,
        destination_token,
        "TRAFFIC",
        "end",
        "ssl",
        "allow",
        "tcp",
        45000,
        443,
        "trust",
        "untrust",
        1200,
        600,
        600,
        10,
        2,
        2,
        1,
        0,
        0,
        0,
        47,
        "traffic_complete",
        "none",
        "",
        "aged-out",
        0,
        0,
        0,
        0,
        0,
        1,
        "device-token",
        1,
        "candidate-near-hash",
    )


def _candidate(index: int) -> dict[str, object]:
    return {
        "review_token": f"review-{index:03d}",
        "source_token": f"source-{index % 2}",
        "window_token": f"window-{index % 3}",
        "exact_hash": f"exact-{index:03d}",
        "near_hash": f"near-{index:03d}",
        "feature_hash": f"feature-{index:03d}",
        "pattern": "routine_web" if index % 2 == 0 else "scan_like",
        "review_priority": "required_human_ground_truth",
        "event_time_utc": f"2026-08-{(index % 20) + 1:02d}T10:00:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "ssl" if index % 2 == 0 else "unknown",
        "action": "allow" if index % 2 == 0 else "deny",
        "protocol": "tcp",
        "source_port": 45000 + index,
        "destination_port": 443 if index % 2 == 0 else 22,
        "source_zone": "trust",
        "destination_zone": "untrust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "application_risk": 2,
        "threat_severity": "none",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_complete",
        "group_size": 1,
        "source_event_count": 1,
        "source_deny_count": 0,
        "source_unique_destinations": 1,
        "source_unique_ports": 1,
        "source_unknown_app_count": 0,
        "source_high_risk_app_count": 0,
        "destination_repeat_count": 1,
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "prediction_included": False,
    }


def _write_ready_collection_workspace(output_dir: Path) -> list[dict[str, object]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates = [_candidate(index) for index in range(evidence.TARGET_REVIEW_ROWS)]
    manifest = evidence._manifest_default()
    manifest["collections"] = [
        {
            "source_token": "source-a",
            "collection_window_token": "window-1",
            "custody_state": "sealed",
            "duplicate_group_state": "contained",
            "candidate_rows": 80,
            "qualifying": True,
        },
        {
            "source_token": "source-b",
            "collection_window_token": "window-2",
            "custody_state": "sealed",
            "duplicate_group_state": "contained",
            "candidate_rows": 80,
            "qualifying": True,
        },
        {
            "source_token": "source-a",
            "collection_window_token": "window-3",
            "custody_state": "sealed",
            "duplicate_group_state": "contained",
            "candidate_rows": 80,
            "qualifying": True,
        },
    ]
    candidate_store = evidence._candidate_store_default()
    candidate_store["rows"] = candidates
    private_state = evidence._private_state_default()
    private_state["candidate_store_digest"] = evidence._candidate_store_digest(
        candidate_store
    )
    private_state["manifest_protected_digest"] = (
        evidence._manifest_protected_digest(manifest)
    )
    evidence._atomic_write_json(output_dir / evidence.V541_MANIFEST, manifest)
    evidence._atomic_write_json(
        output_dir / evidence.V541_CANDIDATES,
        candidate_store,
    )
    evidence._atomic_write_json(
        output_dir / evidence.V541_PRIVATE_STATE,
        private_state,
    )
    return candidates


def test_cutoff_enforcement_is_strict_and_missing_time_fails_closed() -> None:
    connection = sqlite3.connect(":memory:")
    private_panos._create_disposable_schema(connection)
    connection.executemany(
        private_panos.EVENT_INSERT,
        [
            _event_record(
                exact_hash="before",
                propagation_hash="before-near",
                event_time="2026-01-01T09:59:00+00:00",
                minute_bucket="2026-01-01T09:59:00+00:00",
            ),
            _event_record(
                exact_hash="equal",
                propagation_hash="equal-near",
                event_time="2026-01-01T10:00:00+00:00",
                minute_bucket="2026-01-01T10:00:00+00:00",
            ),
            _event_record(
                exact_hash="after",
                propagation_hash="after-near",
                event_time="2026-01-01T10:01:00+00:00",
                minute_bucket="2026-01-01T10:01:00+00:00",
            ),
            _event_record(
                exact_hash="missing",
                propagation_hash="missing-near",
                event_time=None,
                minute_bucket=None,
                quarantine_reason="parser_error_or_missing_time",
            ),
        ],
    )

    result = evidence._apply_cutoff(
        connection,
        cutoff=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
    )

    assert result == {
        "missing_time_rows": 1,
        "at_or_before_cutoff_rows": 2,
        "strictly_after_cutoff_rows": 1,
        "eligible_after_all_exclusions": 1,
    }
    assert connection.execute(
        "SELECT role_rank FROM events WHERE exact_hash='after'"
    ).fetchone()[0] == 0
    connection.close()


def test_source_attestation_requires_a_real_human_and_matching_collection(
    tmp_path: Path,
) -> None:
    attestation = tmp_path / "attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "source_name": "firewall-a",
                "collection_window": "window-1",
                "physical_device_confirmed": True,
                "attested_by": "Human Analyst",
                "attested_at": "2026-08-14T10:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )

    valid = evidence._validate_attestation(
        attestation,
        source_name="firewall-a",
        collection_window="window-1",
    )
    assert valid["valid"] is True
    assert valid["identity_returned"] is False

    value = json.loads(attestation.read_text(encoding="utf-8"))
    value["attested_by"] = "Codex"
    attestation.write_text(json.dumps(value), encoding="utf-8")
    assert evidence._validate_attestation(
        attestation,
        source_name="firewall-a",
        collection_window="window-1",
    )["valid"] is False


def test_candidate_selection_contains_near_duplicates_within_collection() -> None:
    connection = sqlite3.connect(":memory:")
    private_panos._create_disposable_schema(connection)
    connection.executemany(
        private_panos.EVENT_INSERT,
        [
            _event_record(
                exact_hash="first",
                propagation_hash="family-one",
                event_time="2026-08-14T10:00:00+00:00",
                minute_bucket="2026-08-14T10:00:00+00:00",
                role_rank=0,
            ),
            _event_record(
                exact_hash="second",
                propagation_hash="family-two",
                event_time="2026-08-14T10:01:00+00:00",
                minute_bucket="2026-08-14T10:01:00+00:00",
                role_rank=0,
            ),
        ],
    )

    selected, audit = evidence._select_candidates(
        connection,
        source_token="source-a",
        window_token="window-a",
        development_near_hashes=frozenset(),
        existing_rows=[],
        limit=20,
    )

    assert len(selected) == 1
    assert audit["duplicate_families_contained"] is True
    assert audit["exclusion_reasons"]["candidate_near_duplicate"] == 1
    connection.close()


def test_prediction_blind_pack_is_custody_bound_and_not_import_ready(
    tmp_path: Path,
) -> None:
    candidates = _write_ready_collection_workspace(tmp_path)
    predictions = [
        {
            "review_token": row["review_token"],
            "queue_decision": "needs_review",
            "queue_score": 0.8,
            "confidence": 0.7,
        }
        for row in candidates
    ]
    seal = evidence.seal_predictions_separately(
        predictions=predictions,
        candidate_rows=candidates,
        output_dir=tmp_path,
        candidate_contract={"status": "diagnostic_configuration_frozen"},
    )
    pack = evidence.generate_prediction_blind_review_pack(
        candidate_rows=candidates,
        output_dir=tmp_path,
        prediction_seal_digest=seal["seal_digest"],
    )

    rows, columns = evidence._read_csv(tmp_path / evidence.V541_REVIEW_PACK)
    assert len(rows) == evidence.TARGET_REVIEW_ROWS
    assert pack["import_ready"] is False
    assert pack["predictions_exposed"] is False
    assert all(
        part not in column.lower()
        for column in columns
        for part in evidence.FORBIDDEN_REVIEW_COLUMN_PARTS
    )
    serialized = json.dumps(rows).lower()
    assert "queue_decision" not in serialized
    assert "queue_score" not in serialized
    assert "source_ip" not in serialized
    assert "destination_ip" not in serialized
    assert evidence.get_public_blind_evidence_status(output_dir=tmp_path)[
        "status"
    ] == "Ready For Human Review"

    rows[0]["application"] = "tampered"
    with (tmp_path / evidence.V541_REVIEW_PACK).open(
        "w",
        encoding="utf-8",
        newline="",
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(evidence.V541EvidenceError, match="custody"):
        evidence.get_public_blind_evidence_status(output_dir=tmp_path)


def test_prediction_seal_rejects_incomplete_source_and_window_gate(
    tmp_path: Path,
) -> None:
    candidates = _write_ready_collection_workspace(tmp_path)
    manifest = evidence._read_json(
        tmp_path / evidence.V541_MANIFEST,
        default={},
    )
    manifest["collections"] = manifest["collections"][:1]
    private_state = evidence._read_json(
        tmp_path / evidence.V541_PRIVATE_STATE,
        default={},
    )
    private_state["manifest_protected_digest"] = (
        evidence._manifest_protected_digest(manifest)
    )
    evidence._atomic_write_json(tmp_path / evidence.V541_MANIFEST, manifest)
    evidence._atomic_write_json(
        tmp_path / evidence.V541_PRIVATE_STATE,
        private_state,
    )

    with pytest.raises(evidence.V541EvidenceError, match="collection gate"):
        evidence.seal_predictions_separately(
            predictions=[
                {
                    "review_token": row["review_token"],
                    "queue_decision": "needs_review",
                    "queue_score": 0.8,
                    "confidence": 0.7,
                }
                for row in candidates
            ],
            candidate_rows=candidates,
            output_dir=tmp_path,
            candidate_contract={"status": "diagnostic_configuration_frozen"},
        )


def test_rehearsal_never_qualifies_or_writes_authoritative_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample_path = tmp_path / "private.log"
    sample_path.write_text("private raw evidence\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    counts = {
        "raw_logs": 10,
        "normalized_logs": 10,
        "alerts": 2,
        "cases": 1,
        "ml_labels": 4,
        "ml_model_runs": 0,
        "response_actions": 0,
        "audit_logs": 3,
        "detection_runs": 1,
        "ingestion_runs": 1,
    }
    monkeypatch.setattr(evidence.frozen, "_database_counts", lambda _db: dict(counts))
    monkeypatch.setattr(evidence.v55, "_model_artifact_states", lambda: {})
    monkeypatch.setattr(
        evidence,
        "load_v541_development_boundary",
        lambda *_args, **_kwargs: {
            "status": "v5_41_development_boundary_locked",
            "cutoff": datetime(2026, 1, 1, tzinfo=UTC),
            "development_rows": 10,
            "development_exact_hashes": frozenset(),
            "development_near_hashes": frozenset(),
            "development_propagation_hashes": frozenset(),
            "development_source_names": frozenset(),
            "protected_v539_tokens": frozenset(),
            "v539_boundary": {
                "status": "consumed_boundary_locked",
                "schema_version": "v5.39.0",
            },
            "duplicate_isolation_passed": True,
        },
    )

    def fake_stream(
        _sample_path: Path,
        connection: sqlite3.Connection,
        **_kwargs: object,
    ) -> dict[str, object]:
        private_panos._create_disposable_schema(connection)
        connection.execute(
            private_panos.EVENT_INSERT,
            _event_record(
                exact_hash="new-row",
                propagation_hash="new-family",
                event_time="2026-08-14T10:00:00+00:00",
                minute_bucket="2026-08-14T10:00:00+00:00",
            ),
        )
        connection.commit()
        return {
            "ok": True,
            "rows_processed": 1,
            "parser_successes": 1,
            "parser_failures": 0,
            "parser_success_rate": 1.0,
            "schema_profiles": ["traffic_complete"],
            "configured_database_overlap_rows": 0,
        }

    monkeypatch.setattr(
        evidence.v56,
        "stream_private_file_to_disposable_index",
        fake_stream,
    )

    result = evidence.run_v541_blind_evidence_acquisition(
        object(),  # type: ignore[arg-type]
        sample_path=sample_path,
        source_name="rehearsal-source",
        collection_window="historical-window",
        use_temp_db=True,
        rehearsal_only=True,
        output_dir=output_dir,
    )

    assert result["ok"] is True
    assert result["status"] == "rehearsal_complete"
    assert result["qualifying_blind_evidence"] is False
    assert result["qualification"]["reasons"] == [
        "rehearsal_only",
        "source_attestation_missing",
    ]
    assert result["safety"]["configured_database_counts_unchanged"] is True
    assert result["safety"]["labels_written"] == 0
    assert result["safety"]["model_runs_written"] == 0
    assert result["safety"]["detection_runs_written"] == 0
    assert result["safety"]["alerts_written"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert not (output_dir / evidence.V541_MANIFEST).exists()
    serialized = json.dumps(result).lower()
    assert str(sample_path).lower() not in serialized
    assert "private raw evidence" not in serialized
    assert result["lifecycle_state"] == "shadow_observation"


def test_default_public_status_is_safe_and_aggregate_only(tmp_path: Path) -> None:
    status = evidence.get_public_blind_evidence_status(output_dir=tmp_path)

    assert status["status"] == "Designed"
    assert status["metrics_available"] is False
    assert status["model_activated"] is False
    assert status["response_automation_allowed"] is False
    assert status["raw_logs_exposed"] is False
    assert status["source_identities_exposed"] is False
    assert status["fingerprints_exposed"] is False
    assert status["secrets_exposed"] is False
