from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from atdr.app.detection import supervised_detector
from atdr.app.detection import v51_supervised_lifecycle as lifecycle
from atdr.app.detection import v56_private_panos_model_repair as repair


def _sample_lines() -> list[str]:
    return Path("data/samples/paloalto-demo.txt").read_text(
        encoding="utf-8"
    ).splitlines()


def _chronological_sample(path: Path, *, rows: int = 16) -> None:
    template = _sample_lines()[0]
    started = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
    output = []
    for index in range(rows):
        value = started + timedelta(minutes=index)
        syslog = value.isoformat()
        payload_time = value.strftime("%Y/%m/%d %H:%M:%S")
        _, hostname, payload = template.split(" ", 2)
        fields = payload.split(",")
        fields[1] = payload_time
        fields[6] = payload_time
        fields[7] = f"198.51.100.{(index % 200) + 1}"
        fields[8] = f"203.0.113.{(index % 200) + 1}"
        output.append(f"{syslog} {hostname} {','.join(fields)}")
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def _row(**overrides):
    row = {
        "log_type": "TRAFFIC",
        "threat_severity": "none",
        "app": "quic-base",
        "action": "allow",
        "dst_port": 443,
        "app_risk": 2,
        "source_event_count": 2,
        "source_unique_destinations": 1,
        "source_unique_ports": 1,
        "source_deny_count": 0,
        "destination_repeat_count": 1,
        "external_to_internal_flag": 0,
        "parser_error": 0,
        "required_missing_count": 0,
    }
    row.update(overrides)
    return row


def test_streaming_profile_is_bounded_and_redacted(tmp_path):
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")

    result = repair.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
        chunk_size=3,
    )

    serialized = json.dumps(result)
    assert result["ok"] is True
    assert result["rows_processed"] == 16
    assert result["streaming"]["bounded_chunk_size"] == 100
    assert result["streaming"]["entire_file_loaded_in_memory"] is False
    assert result["raw_evidence_returned"] is False
    assert result["private_identifiers_returned"] is False
    assert str(sample) not in serialized
    assert "198.51.100." not in serialized


def test_chronological_roles_keep_duplicate_families_together(tmp_path):
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")
    repair.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )
    first = connection.execute(
        "SELECT exact_hash, propagation_hash FROM events ORDER BY id LIMIT 1"
    ).fetchone()
    connection.execute(
        "UPDATE events SET exact_hash=?, propagation_hash=? "
        "WHERE id=(SELECT MAX(id) FROM events)",
        first,
    )
    connection.commit()

    result = repair.predeclare_chronological_roles(connection)

    roles = connection.execute(
        "SELECT COUNT(DISTINCT role_rank) FROM events WHERE exact_hash=?",
        (first[0],),
    ).fetchone()[0]
    assert result["ok"] is True
    assert result["duplicate_families_contained"] is True
    assert roles == 1


def test_assisted_policy_is_conservative_and_never_human_reviewed():
    benign = repair.assisted_decision(
        _row(),
        rule_codes=[],
        rule_score=0,
    )
    threat = repair.assisted_decision(
        _row(
            log_type="THREAT",
            threat_severity="critical",
            app="unknown-tcp",
        ),
        rule_codes=["paloalto_threat_log"],
        rule_score=30,
    )
    ambiguous = repair.assisted_decision(
        _row(
            app="unknown-udp",
            required_missing_count=3,
        ),
        rule_codes=[],
        rule_score=0,
    )

    assert benign["decision"] == "benign"
    assert benign["provenance"] == "weak_supervision"
    assert threat["decision"] == "malicious"
    assert threat["provenance"] == "vendor_threat_assisted"
    assert ambiguous["decision"] == "needs_context"
    assert ambiguous["training_eligible"] is False
    assert all(
        item["human_reviewed"] is False
        for item in (benign, threat, ambiguous)
    )


def test_disposable_assisted_pipeline_builds_nonhuman_training_rows(
    tmp_path,
):
    sample = tmp_path / "private.log"
    _chronological_sample(sample, rows=24)
    connection = sqlite3.connect(":memory:")
    repair.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )
    roles = repair.predeclare_chronological_roles(connection)
    repair.build_disposable_behavior_aggregates(connection)

    labels = repair.apply_assisted_policy(connection)
    bundle, selection = repair.load_private_role_bundle(
        connection,
        supervised_detector._optional_imports(),
        role_rank=0,
        max_rows=100,
    )

    assert roles["ok"] is True
    assert labels["human_reviewed_true_count"] == 0
    assert labels["configured_database_labels_written"] == 0
    assert selection["future_labels_opened"] is False
    assert len(bundle["rows"]) > 0
    assert all(row["human_reviewed"] is False for row in bundle["rows"])


def test_assisted_weights_stay_below_human_weights():
    bundle = {
        "base_weights": [1.0, 0.55, 0.20],
        "rows": [
            {"human_reviewed": True},
            {"human_reviewed": False},
            {"human_reviewed": False},
        ],
    }

    weights, summary = repair._fit_weights(
        bundle,
        ["non_threat", "needs_review", "non_threat"],
        variant="class_and_provenance",
    )

    assert weights[0] >= 1.0
    assert max(weights[1:]) <= 0.65
    assert summary["assisted_weights_lower_than_human"] is True


def test_future_labels_fail_closed_before_candidate_freeze(
    monkeypatch,
):
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE assisted_groups("
        "representative_id INTEGER, role_rank INTEGER, "
        "training_eligible INTEGER, decision TEXT, provenance TEXT, "
        "group_size INTEGER, human_reviewed INTEGER)"
    )

    with pytest.raises(ValueError, match="sealed"):
        repair.open_future_assisted_summary_after_freeze(
            connection,
            candidate_frozen=False,
        )

    with pytest.raises(ValueError, match="only after candidate freeze"):
        repair.load_private_role_bundle(
            connection,
            supervised_detector._optional_imports(),
            role_rank=3,
            max_rows=10,
            open_future_labels=False,
        )


def test_runner_preflight_creates_no_database_or_artifact_changes(
    monkeypatch,
    tmp_path,
):
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    rows = [
        {
            "index": index,
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc)
            + timedelta(minutes=index),
            "leakage_group": f"group-{index}",
        }
        for index in range(80)
    ]
    dataset = {
        "ok": True,
        "imports": supervised_detector._optional_imports(),
        "rows": rows,
    }
    partition = {
        "fit_idx": list(range(0, 40)),
        "calibration_idx": list(range(40, 50)),
        "threshold_idx": list(range(50, 60)),
        "final_test_idx": list(range(60, 70)),
        "quarantined_idx": list(range(70, 80)),
    }
    counts = {
        "raw_logs": 10,
        "normalized_logs": 10,
        "alerts": 1,
        "ml_labels": 4,
        "ml_model_runs": 2,
        "detection_runs": 3,
        "response_actions": 0,
    }
    artifacts = {
        "supervised": {"exists": False},
        "isolation_forest": {"exists": False},
    }
    monkeypatch.setattr(
        repair.v52,
        "_prepare_dataset",
        lambda *_args, **_kwargs: dataset,
    )
    monkeypatch.setattr(
        repair.frozen,
        "build_frozen_partition",
        lambda *_args, **_kwargs: partition,
    )
    monkeypatch.setattr(
        repair.frozen,
        "audit_partition_leakage",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        repair.frozen,
        "_database_counts",
        lambda *_args: dict(counts),
    )
    monkeypatch.setattr(
        repair.v55,
        "_model_artifact_states",
        lambda: dict(artifacts),
    )
    monkeypatch.setattr(
        repair.v54,
        "build_evidence_lock",
        lambda *_args, **_kwargs: {"overall_fingerprint": "locked"},
    )
    monkeypatch.setattr(
        repair.v54,
        "validate_evidence_lock",
        lambda *_args, **_kwargs: {
            "passed": True,
            "status": "locked_and_matched",
        },
    )

    result = repair.run_v56_private_panos_model_repair(
        SimpleNamespace(),
        sample_path=sample,
        preflight_only=True,
        write_output=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["status"] == "preflight_complete"
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["model_artifacts_unchanged"] is True
    assert result["safety"]["private_file_imported"] is False
    assert str(sample) not in serialized


def test_candidate_freeze_records_no_activation():
    leader = {
        "name": "calibrated_extra_trees",
        "selection_basis": "development_only",
        "_latest_fitted": {
            "status": "evaluated",
            "_model": object(),
            "_threshold": 0.55,
            "_positive_classes": {"needs_review"},
        },
    }

    frozen = repair.freeze_diagnostic_candidate(
        leader,
        role_manifest={"roles": {}},
        evidence_lock={"overall_fingerprint": "lock"},
    )

    assert frozen is not None
    assert frozen["frozen_before_future_label_access"] is True
    assert frozen["eligible_for_activation"] is False
    assert frozen["active_artifact_written"] is False


def test_lifecycle_summary_exposes_only_v56_aggregates(
    monkeypatch,
    tmp_path,
):
    report = {
        "status": "evaluated",
        "generated_at": "2026-07-26T00:00:00+00:00",
        "readiness": {
            "decision": "shadow_observation",
            "blockers": ["single private device"],
        },
        "private_profile": {
            "rows_processed": 773551,
            "configured_database_overlap_rows": 120000,
        },
        "drift_profile": {"status": "Drift Warning"},
        "assisted_labeling": {
            "high_confidence_training_event_count": 500000,
            "human_reviewed_true_count": 0,
        },
        "frozen_diagnostic_candidate": {
            "name": "calibrated_extra_trees"
        },
        "untouched_future_validation": {
            "supervised": {
                "metrics": {
                    "queue_f1": 0.8,
                    "benign_like_false_positive_rate": 0.07,
                    "suspicious_recall": 0.75,
                    "malicious_recall": 0.8,
                },
                "calibration": {
                    "status": "passed",
                    "expected_calibration_error": 0.08,
                },
            },
            "isolation_forest": {
                "metrics": {
                    "benign_like_false_positive_rate": 0.1,
                    "queue_recall": 0.6,
                }
            },
        },
    }
    (tmp_path / repair.V56_LATEST).write_text(
        json.dumps(report),
        encoding="utf-8",
    )
    monkeypatch.setattr(lifecycle, "DEFAULT_OUTPUT_DIR", tmp_path)

    summary = lifecycle._v56_repair_summary()

    assert summary["v56_available"] is True
    assert summary["v56_lifecycle_state"] == "shadow_observation"
    assert summary["v56_assisted_human_reviewed_rows"] == 0
    assert summary["v56_candidate_activated"] is False
    assert summary["v56_response_automation_allowed"] is False
    assert summary["raw_logs_included"] is False
    assert summary["private_identifiers_included"] is False
