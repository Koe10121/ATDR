from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v544_chronological_evidence as evidence
from atdr.app.detection import v56_private_panos_model_repair as private_panos


def _chronological_sample(path: Path, *, rows: int = 80) -> None:
    template = Path("data/samples/paloalto-demo.txt").read_text(
        encoding="utf-8"
    ).splitlines()[0]
    started = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
    output = []
    for index in range(rows):
        value = started + timedelta(minutes=index)
        payload_time = value.strftime("%Y/%m/%d %H:%M:%S")
        _, hostname, payload = template.split(" ", 2)
        fields = payload.split(",")
        fields[1] = payload_time
        fields[6] = payload_time
        fields[7] = f"198.51.100.{(index % 200) + 1}"
        fields[8] = f"203.0.113.{(index % 200) + 1}"
        output.append(f"{value.isoformat()} {hostname} {','.join(fields)}")
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def _custody() -> dict:
    return {
        "state": {
            "development_contract": {"status": "locked"},
            "v539_boundary": {"_protected_tokens": frozenset()},
            "v541_boundary": {
                "development_exact_hashes": frozenset(),
                "development_propagation_hashes": frozenset(),
                "cutoff": datetime(2026, 7, 1, tzinfo=UTC),
            },
            "development": {
                "rows": [
                    {"label_source": "manual"},
                    {"label_source": "assisted_rule"},
                ],
                "original_labels": ["benign", "suspicious"],
            },
        },
        "checks": {"all_boundaries_valid": True},
        "all_checks_passed": True,
        "development_rows": 2,
        "v542_candidate_frozen": False,
        "v543_candidate_frozen": False,
    }


def _safe_runtime_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    custody: dict | None = None,
) -> None:
    counts = {
        "raw_logs": 10,
        "normalized_logs": 10,
        "alerts": 1,
        "ml_labels": 2,
        "ml_model_runs": 0,
        "detection_runs": 0,
        "response_actions": 0,
    }
    artifacts = {
        "supervised": {"exists": False},
        "isolation_forest": {"exists": False},
    }
    monkeypatch.setattr(
        evidence,
        "revalidate_v544_custody",
        lambda *_args, **_kwargs: custody or _custody(),
    )
    monkeypatch.setattr(
        evidence.frozen,
        "_database_counts",
        lambda *_args: dict(counts),
    )
    monkeypatch.setattr(
        evidence.v55,
        "_model_artifact_states",
        lambda: dict(artifacts),
    )
    monkeypatch.setattr(
        evidence,
        "_protected_workspace_state",
        lambda **_kwargs: {"protected": "unchanged"},
    )
    monkeypatch.setattr(
        evidence,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///:memory:"),
    )


def test_stream_profile_counts_devices_without_returning_identifiers(tmp_path: Path) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample, rows=16)
    connection = sqlite3.connect(":memory:")

    profile = private_panos.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )

    serialized = json.dumps(profile)
    assert profile["ok"] is True
    assert profile["device_sources"]["identified_source_count"] == 1
    assert profile["device_sources"]["identity_tokens_returned"] is False
    assert "198.51.100." not in serialized
    assert str(sample) not in serialized


def test_candidate_near_contract_is_shared_with_v541() -> None:
    row = {
        "log_type": "TRAFFIC",
        "subtype": "end",
        "app": "ssl",
        "action": "allow",
        "protocol": "tcp",
        "src_port": 50000,
        "dst_port": 443,
        "src_zone": "trust",
        "dst_zone": "untrust",
        "bytes": 1024,
        "packets": 8,
        "elapsed_time": 2,
        "app_risk": 2,
        "threat_severity": "none",
        "session_end_reason": "aged-out",
        "src_ip": "198.51.100.10",
    }

    projection = v541._candidate_projection(
        row,
        exact_hash="exact",
        source_token="source",
        window_token="window",
    )

    assert projection["near_hash"] == private_panos._candidate_near_fingerprint(row)


def test_high_signal_patterns_take_precedence_over_unknown_application() -> None:
    row = {
        "log_type": "TRAFFIC",
        "app": "unknown-udp",
        "action": "allow",
        "protocol": "udp",
        "dst_port": 4040,
        "app_risk": 1,
        "source_unique_ports": 12,
        "source_unique_destinations": 15,
        "source_deny_count": 0,
    }

    assert evidence._pattern_for_row(row, ["possible_port_scan"]) == (
        "scan_like_behavior"
    )
    assert evidence._pattern_for_row(row, ["possible_c2_beacon"]) == (
        "c2_or_exfiltration_evidence"
    )


def test_boundary_quarantine_and_chronological_roles_are_disjoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")
    private_panos.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )
    connection.execute(
        "UPDATE events SET candidate_near_hash='protected-near' WHERE id=1"
    )
    connection.commit()
    exact_hash, propagation_hash, near_hash = connection.execute(
        "SELECT exact_hash, propagation_hash, candidate_near_hash "
        "FROM events ORDER BY id LIMIT 1"
    ).fetchone()
    custody = _custody()
    custody["state"]["v541_boundary"].update(
        {
            "development_exact_hashes": frozenset({exact_hash}),
            "development_propagation_hashes": frozenset({propagation_hash}),
        }
    )
    monkeypatch.setattr(
        evidence,
        "_load_v541_candidate_boundaries",
        lambda *_args: {
            "status": "locked",
            "exact_hashes": frozenset(),
            "near_hashes": frozenset({near_hash}),
            "candidate_rows": 1,
        },
    )

    boundary = evidence._install_protected_boundaries(
        connection,
        custody=custody,
        blind_output_dir=tmp_path,
    )
    roles = private_panos.predeclare_chronological_roles(connection)

    assert boundary["v540_exact_overlap_rows"] >= 1
    assert boundary["v541_candidate_near_overlap_rows"] >= 1
    assert roles["ok"] is True
    assert roles["exact_family_cross_role_count"] == 0
    assert roles["near_family_cross_role_count"] == 0


def test_assisted_pack_never_opens_future_or_creates_human_labels(tmp_path: Path) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")
    private_panos.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )
    assert private_panos.predeclare_chronological_roles(connection)["ok"] is True
    private_panos.build_disposable_behavior_aggregates(connection)

    result = evidence._apply_development_assisted_policy(
        connection,
        review_limit=20,
    )
    rows = result.pop("_review_rows")

    assert result["human_reviewed_true_count"] == 0
    assert result["configured_database_labels_written"] == 0
    assert result["reserved_future_labels_opened"] is False
    assert rows
    assert all(row["human_must_confirm"] is True for row in rows)
    assert all(row["human_reviewed"] is False for row in rows)
    assert all(row["import_ready"] is False for row in rows)
    serialized = json.dumps(rows)
    assert "198.51.100." not in serialized
    assert str(sample) not in serialized


def test_full_runner_is_aggregate_only_and_has_zero_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    _safe_runtime_mocks(monkeypatch)
    monkeypatch.setattr(
        evidence,
        "_load_v541_candidate_boundaries",
        lambda *_args: {
            "status": "none",
            "exact_hashes": frozenset(),
            "near_hashes": frozenset(),
            "candidate_rows": 0,
        },
    )

    result = evidence.run_v544_chronological_evidence_expansion(
        SimpleNamespace(),
        sample_path=sample,
        use_temp_db=True,
        write_output=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["lifecycle_state"] == "shadow_observation"
    assert result["safety"]["all_invariants_passed"] is True
    assert result["safety"]["human_reviewed_labels_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["cohort_manifest"]["reserved_future_labels_opened"] is False
    assert result["review_pack"]["import_ready"] is False
    assert result["model_activated"] is False
    assert result["model_promoted"] is False
    assert str(sample) not in serialized
    assert "198.51.100." not in serialized


def test_private_lock_is_reusable_and_fails_closed_on_tamper(tmp_path: Path) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")
    private_panos.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )
    assert private_panos.predeclare_chronological_roles(connection)["ok"] is True
    private_panos.build_disposable_behavior_aggregates(connection)
    evidence._apply_development_assisted_policy(connection, review_limit=0)
    custody = _custody()

    first = evidence._write_private_lock(
        connection,
        output_dir=tmp_path / "output",
        custody=custody,
    )
    second = evidence._write_private_lock(
        connection,
        output_dir=tmp_path / "output",
        custody=custody,
    )
    lock_path = tmp_path / "output" / evidence.V544_PRIVATE_LOCK
    lock_path.write_bytes(lock_path.read_bytes() + b"tamper")

    assert first["status"] == "private_development_evidence_locked"
    assert second["status"] == "existing_private_lock_reused"
    with pytest.raises(evidence.V544EvidenceError):
        evidence._write_private_lock(
            connection,
            output_dir=tmp_path / "output",
            custody=custody,
        )


def test_preflight_never_returns_private_path_or_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "private.log"
    sample.write_text("private evidence\n", encoding="utf-8")
    _safe_runtime_mocks(monkeypatch)

    result = evidence.run_v544_chronological_evidence_expansion(
        SimpleNamespace(),
        sample_path=sample,
        preflight_only=True,
        write_output=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["private_file"]["path_returned"] is False
    assert result["raw_logs_returned"] is False
    assert result["secrets_exposed"] is False
    assert str(sample) not in serialized
