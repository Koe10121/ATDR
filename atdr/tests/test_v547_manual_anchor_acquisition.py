from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from atdr.app.detection import v547_manual_anchor_acquisition as acquisition


def _row(
    index: int,
    *,
    app: str = "ssl",
    action: str = "allow",
    protocol: str = "tcp",
    destination_port: int = 443,
    role_rank: int = 0,
    family: str | None = None,
) -> dict:
    return {
        "id": index,
        "event_time": f"2026-08-01T00:{index % 60:02d}:00+00:00",
        "role_rank": role_rank,
        "log_type": "TRAFFIC",
        "subtype": "end",
        "app": app,
        "action": action,
        "protocol": protocol,
        "src_port": 40000 + index,
        "dst_port": destination_port,
        "src_zone": "untrust",
        "dst_zone": "trust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "app_risk": 1,
        "parser_error": 0,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "threat_severity": "none",
        "session_end_reason": "aged-out",
        "group_size": 1,
        "source_event_count": 2,
        "source_deny_count": 0,
        "source_unique_destinations": 1,
        "source_unique_ports": 1,
        "source_unknown_app_count": 0,
        "source_high_risk_app_count": 0,
        "destination_repeat_count": 1,
        "_candidate_family": family or f"family-{index}",
        "_quarantine_reason": None,
    }


def _pack_row(index: int = 1) -> dict:
    row = _row(index)
    row["_candidate_family"] = f"family-{index}"
    selected, _ = acquisition.select_manual_anchor_candidates(
        [row],
        manual_families=set(),
        limit=1,
    )
    return selected[0]


def test_coverage_classification_separates_required_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acquisition.v56, "_rule_evidence", lambda _row: ([], 0))

    assert (
        acquisition.classify_coverage_stratum(
            _row(1, app="incomplete", destination_port=80)
        )
        == "incomplete_allow_80"
    )
    assert (
        acquisition.classify_coverage_stratum(
            _row(2, app="unknown-udp", protocol="udp", destination_port=4040)
        )
        == "unknown_transport"
    )
    assert (
        acquisition.classify_coverage_stratum(
            _row(3, app="quic-base", protocol="udp", destination_port=443)
        )
        == "quic_443_control"
    )


def test_selection_excludes_manual_families_future_roles_and_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acquisition.v56, "_rule_evidence", lambda _row: ([], 0))
    rows = [
        _row(1, family="manual-family"),
        _row(2, family="new-family"),
        _row(3, family="new-family"),
        _row(4, family="future-family", role_rank=3),
    ]

    selected, summary = acquisition.select_manual_anchor_candidates(
        rows,
        manual_families={"manual-family"},
        limit=10,
    )

    assert len(selected) == 1
    assert selected[0]["evidence_role"] == "development_fit"
    assert selected[0]["predictions_exposed"] is False
    assert selected[0]["assisted_labels_exposed"] is False
    assert selected[0]["import_ready"] is False
    assert summary["exclusion_reasons"]["existing_manual_anchor_family"] == 1
    assert summary["exclusion_reasons"]["duplicate_family"] == 1
    assert summary["exclusion_reasons"]["future_or_reserved_role"] == 1
    assert summary["future_roles_selected"] == 0


def test_pack_contract_rejects_prediction_and_private_evidence_columns() -> None:
    row = _pack_row()
    row["model_prediction"] = "malicious"

    with pytest.raises(acquisition.V547AcquisitionError):
        acquisition._assert_pack_contract(
            [row],
            list(row),
            sealed=True,
        )


def test_review_progress_rejects_automated_reviewer_and_never_imports(
    tmp_path: Path,
) -> None:
    row = _pack_row()
    selection = {
        "coverage_gate_passed": False,
        "selected_rows": 1,
        "coverage_counts": {"routine_benign_control": 1},
    }
    acquisition._prepare_workspace([row], selection, output_dir=tmp_path)
    working_path = tmp_path / acquisition.V547_WORKING_COPY
    rows, _ = acquisition._read_csv(working_path)
    rows[0].update(
        {
            "human_decision": "benign",
            "human_confidence": "95",
            "human_rationale": "Routine approved web traffic.",
            "human_reviewer": "Codex reviewer",
            "human_reviewed_at": datetime.now(UTC).isoformat(),
            "human_reviewed": "true",
        }
    )
    acquisition._atomic_write_csv(working_path, rows)

    progress = acquisition._review_progress(tmp_path)

    assert progress["reviewed"] == 0
    assert progress["invalid"] == 1
    assert progress["ready_for_fixed_revalidation"] is False
    assert progress["import_ready"] is False
    assert progress["automatic_import_performed"] is False


def test_public_status_is_aggregate_only(tmp_path: Path) -> None:
    row = _pack_row()
    selection = {
        "coverage_gate_passed": False,
        "selected_rows": 1,
        "target_rows": 120,
        "represented_strata": 1,
        "coverage_counts": {"routine_benign_control": 1},
    }
    workspace = acquisition._prepare_workspace(
        [row],
        selection,
        output_dir=tmp_path,
    )
    workspace["status"] = "workspace_reused"
    workspace["created"] = False
    latest = {
        "version": acquisition.V547_VERSION,
        "status": "manual_anchor_coverage_incomplete",
        "generated_at": "2026-08-21T00:00:00+00:00",
        "selection": selection,
        "workspace": workspace,
        "independent_source_count": 1,
        "second_real_source_present": False,
        "private_path": "must-not-leak",
        "fingerprint": "must-not-leak",
    }
    (tmp_path / acquisition.V547_LATEST).write_text(
        json.dumps(latest),
        encoding="utf-8",
    )

    result = acquisition.get_public_v547_status(tmp_path)
    serialized = json.dumps(result)

    assert result["selected_rows"] == 1
    assert result["workspace_created"] is True
    assert result["reviewed_rows"] == 0
    assert result["development_evidence_only"] is True
    assert result["model_activated"] is False
    assert result["predictions_exposed"] is False
    assert result["private_paths_returned"] is False
    assert "must-not-leak" not in serialized
    assert "review_token" not in serialized


def test_full_runner_preserves_authoritative_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "private.log"
    sample.write_text("synthetic\n", encoding="utf-8")
    counts = {
        "raw_logs": 10,
        "normalized_logs": 10,
        "alerts": 1,
        "ml_labels": 2,
        "ml_model_runs": 0,
        "detection_runs": 0,
        "response_actions": 0,
    }
    custody = {
        "prior": {
            "prior": {
                "custody": {
                    "state": {"development": {}, "canonical": {}},
                }
            }
        },
        "all_checks_passed": True,
    }
    monkeypatch.setattr(
        acquisition,
        "revalidate_v547_custody",
        lambda *_a, **_k: custody,
    )
    monkeypatch.setattr(acquisition, "_public_custody", lambda *_a: {"passed": True})
    monkeypatch.setattr(acquisition, "_protected_state", lambda **_k: {"same": True})
    monkeypatch.setattr(acquisition.frozen, "_database_counts", lambda *_a: dict(counts))
    monkeypatch.setattr(
        acquisition.v55,
        "_model_artifact_states",
        lambda: {"supervised": {"exists": False}},
    )
    monkeypatch.setattr(
        acquisition.v56,
        "stream_private_file_to_disposable_index",
        lambda *_a, **_k: {
            "ok": True,
            "rows_processed": 100,
            "parser_successes": 99,
            "parser_failures": 1,
        },
    )
    monkeypatch.setattr(
        acquisition.v544,
        "_install_protected_boundaries",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        acquisition.v56,
        "predeclare_chronological_roles",
        lambda *_a: {"ok": True},
    )
    monkeypatch.setattr(
        acquisition.v56,
        "build_disposable_behavior_aggregates",
        lambda *_a: {},
    )
    monkeypatch.setattr(
        acquisition.v545,
        "_contain_candidate_near_families",
        lambda *_a: {"passed": True},
    )
    monkeypatch.setattr(acquisition, "_manual_anchor_families", lambda *_a: set())
    monkeypatch.setattr(
        acquisition,
        "_load_representatives",
        lambda *_a: [_row(index) for index in range(100)],
    )
    monkeypatch.setattr(acquisition, "_private_source_count", lambda *_a: 1)
    monkeypatch.setattr(acquisition.v56, "_rule_evidence", lambda _row: ([], 0))
    monkeypatch.setattr(
        acquisition,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///:memory:"),
    )

    result = acquisition.run_v547_manual_anchor_acquisition(
        SimpleNamespace(),
        sample_path=sample,
        use_temp_db=True,
        review_limit=80,
        output_dir=tmp_path / "output",
        write_report=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["safety"]["all_invariants_passed"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["alerts_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["future_labels_opened"] is False
    assert result["model_activated"] is False
    assert result["rules_alert_authoritative"] is True
    assert result["workspace"]["review"]["reviewed"] == 0
    assert result["private_reconstruction"] == {
        "parsed_rows": 100,
        "parser_success_rows": 99,
        "parser_failure_rows": 1,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
    }
    assert str(sample) not in serialized
