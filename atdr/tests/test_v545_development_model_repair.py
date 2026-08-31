from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from atdr.app.detection import v545_development_model_repair as repair
from atdr.app.detection.supervised_detector import _optional_imports


def _bundle(
    *,
    rows: int = 24,
    manual: int = 4,
    family_prefix: str = "family",
    crossing_family: bool = False,
) -> dict:
    imports = _optional_imports()
    assert imports is not None
    pd = imports[1]
    started = datetime(2026, 8, 1, tzinfo=UTC)
    labels = ["benign", "benign_unusual", "suspicious", "malicious"]
    metadata = []
    frames = []
    originals = []
    weights = []
    for index in range(rows):
        label = labels[index % len(labels)]
        family = (
            "crossing-family"
            if crossing_family and index in {0, rows - 1}
            else f"{family_prefix}-{index}"
        )
        timestamp = started + timedelta(minutes=index)
        metadata.append(
            {
                "timestamp": timestamp,
                "app": "quic-base" if label == "benign" else "unknown-udp",
                "action": "allow",
                "dst_port": 443 if label == "benign" else 4040,
                "schema": "test",
                "provenance": "manual" if index < manual else "rule_assisted",
                "human_reviewed": index < manual,
                "group_size": 1,
                "evidence_role": "development_fit",
                "original_label": label,
                "private_source": index >= manual,
                "_duplicate_family": family,
                "pattern": (
                    "benign_quic_443" if label == "benign" else "scan_like_behavior"
                ),
                "log_type": "TRAFFIC",
            }
        )
        frames.append(
            {
                **{field: float(index + 1) for field in repair.v56.V56_NUMERIC_FEATURES},
                **{field: "test" for field in repair.v56.V56_CATEGORICAL_FEATURES},
            }
        )
        originals.append(label)
        weights.append(1.0 if index < manual else 0.45)
    return {
        "frame": pd.DataFrame(frames).reindex(
            columns=[
                *repair.v56.V56_NUMERIC_FEATURES,
                *repair.v56.V56_CATEGORICAL_FEATURES,
            ]
        ),
        "rows": metadata,
        "original_labels": originals,
        "targets": [repair.v56._queue_target(value) for value in originals],
        "base_weights": weights,
    }


def test_anchor_capped_weights_never_let_assisted_labels_dominate() -> None:
    bundle = _bundle(rows=104, manual=4)

    weights, summary = repair._anchor_capped_weights(
        bundle,
        bundle["targets"],
        assisted_cap=0.50,
    )

    assert len(weights) == 104
    assert summary["manual_or_reviewed_rows"] == 4
    assert summary["assisted_rows"] == 100
    assert summary["assisted_to_manual_weight_ratio"] <= 0.50
    assert summary["assisted_labels_dominate_manual_anchors"] is False
    assert summary["labels_rewritten"] is False


def test_temporal_split_collapses_crossing_duplicate_family() -> None:
    imports = _optional_imports()
    assert imports is not None
    bundle = _bundle(rows=24, crossing_family=True)

    segments, audit = repair._split_temporal_families(
        imports,
        bundle,
        segments=3,
    )

    assert audit["status"] == "partitioned"
    assert audit["duplicate_representative_rows_collapsed"] == 1
    assert audit["quarantined_crossing_family_rows"] == 0
    assert audit["duplicate_family_cross_segment_count"] == 0
    families = [
        {
            row["_duplicate_family"]
            for row in segment["rows"]
        }
        for segment in segments
    ]
    assert not (families[0] & families[1])
    assert not (families[0] & families[2])
    assert not (families[1] & families[2])


def test_family_leakage_fails_closed() -> None:
    imports = _optional_imports()
    assert imports is not None
    fit = _bundle(rows=16, family_prefix="fit")
    calibration = _bundle(rows=16, family_prefix="cal")
    threshold = _bundle(rows=16, family_prefix="threshold")
    evaluation = _bundle(rows=16, family_prefix="evaluation")
    evaluation["rows"][0]["_duplicate_family"] = fit["rows"][0]["_duplicate_family"]

    audit = repair._family_leakage(
        {
            "fit": fit,
            "calibration": calibration,
            "threshold": threshold,
            "evaluation": evaluation,
        }
    )

    assert audit["passed"] is False
    assert audit["pair_overlap_counts"]["fit_vs_evaluation"] == 1
    assert audit["family_identifiers_returned"] is False


def test_optional_view_requires_support_for_every_fixed_gate_class() -> None:
    supported = _bundle(rows=24, manual=4)
    view = {
        "fit": supported,
        "calibration": supported,
        "threshold": supported,
        "evaluation": supported,
    }

    assert repair._view_gate_support(view)["passed"] is True

    unsupported = _bundle(rows=24, manual=4)
    keep = [
        index
        for index, value in enumerate(unsupported["original_labels"])
        if value != "suspicious"
    ]
    imports = _optional_imports()
    assert imports is not None
    unsupported = repair._slice_bundle(imports, unsupported, keep)
    view["evaluation"] = unsupported

    audit = repair._view_gate_support(view)

    assert audit["passed"] is False
    assert audit["evaluation_support"]["suspicious_rows"] == 0
    assert audit["labels_returned"] is False
    assert audit["private_identifiers_returned"] is False


def test_private_loader_rejects_future_role_without_reading_labels() -> None:
    imports = _optional_imports()
    assert imports is not None

    with pytest.raises(repair.V545RepairError):
        repair._load_private_role_bundle(
            SimpleNamespace(),
            imports,
            role_rank=3,
            max_rows=20,
        )


def test_candidate_near_families_are_contained_without_opening_labels() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE events(candidate_near_hash TEXT, role_rank INTEGER, "
        "quarantine_reason TEXT)"
    )
    connection.executemany(
        "INSERT INTO events VALUES (?, ?, NULL)",
        [
            ("crossing", 0),
            ("crossing", 2),
            ("crossing", 3),
            ("fit-only", 0),
            ("future-only", 3),
        ],
    )

    result = repair._contain_candidate_near_families(connection)

    assert result["passed"] is True
    assert result["quarantined_candidate_families"] == 1
    assert result["quarantined_event_rows"] == 3
    assert result["quarantined_reserved_future_rows"] == 1
    assert result["labels_inspected"] is False
    assert result["future_labels_opened"] is False
    assert result["family_identifiers_returned"] is False
    assert connection.execute(
        "SELECT COUNT(*) FROM events WHERE candidate_near_hash='crossing' "
        "AND role_rank=4"
    ).fetchone()[0] == 3


def test_freeze_manifest_requires_every_gate(tmp_path: Path) -> None:
    result = repair._freeze_manifest(
        {
            "name": "candidate",
            "selection_basis": "development_only",
            "candidate_freeze_eligible": False,
            "summary": {},
        },
        output_dir=tmp_path,
        custody={
            "private_lock": {"latest": {"cohort_manifest": {"cohorts": {}}}},
            "checks": {},
            "all_checks_passed": True,
            "custody": {"development_rows": 0},
        },
        write_output=True,
    )

    assert result["candidate_frozen"] is False
    assert result["active_artifact_written"] is False
    assert not (tmp_path / repair.V545_FREEZE_MANIFEST).exists()


def test_diagnostic_freeze_writes_recipe_not_model_artifact(tmp_path: Path) -> None:
    leader = {
        "name": "candidate",
        "selection_basis": "development_only",
        "candidate_freeze_eligible": True,
        "summary": {"all_views_passed": True},
        "_latest_fitted": {
            "model_type": "extra_trees",
            "target_mode": "binary_threat_positive",
            "assisted_weight_cap": 0.5,
            "applied_calibration_method": "sigmoid_on_dedicated_calibration_partition",
            "_threshold": 0.7,
        },
    }
    custody = {
        "private_lock": {
            "latest": {
                "cohort_manifest": {
                    "cohorts": {
                        "development_fit": {"rows": 100},
                    }
                }
            }
        },
        "checks": {},
        "all_checks_passed": True,
        "custody": {"development_rows": 10},
    }

    result = repair._freeze_manifest(
        leader,
        output_dir=tmp_path,
        custody=custody,
        write_output=True,
    )
    manifest = json.loads(
        (tmp_path / repair.V545_FREEZE_MANIFEST).read_text(encoding="utf-8")
    )

    assert result["candidate_frozen"] is True
    assert result["active_artifact_written"] is False
    assert manifest["model_artifact_written"] is False
    assert manifest["eligible_for_activation"] is False
    assert manifest["future_labels_opened"] is False
    assert not list(tmp_path.glob("*.joblib"))


def test_full_runner_preserves_database_model_and_response_state(
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
    artifacts = {"supervised": {"exists": False}}
    empty = _bundle(rows=24, manual=4)
    custody = {
        "custody": {
            "state": {"development": {}, "canonical": {}},
            "development_rows": 24,
        },
        "private_lock": {
            "latest": {
                "cohort_manifest": {"cohorts": {}},
            }
        },
        "checks": {"valid": True},
        "all_checks_passed": True,
    }
    monkeypatch.setattr(repair, "revalidate_v545_custody", lambda *_a, **_k: custody)
    monkeypatch.setattr(repair, "_protected_state", lambda **_k: {"same": True})
    monkeypatch.setattr(repair.frozen, "_database_counts", lambda *_a: dict(counts))
    monkeypatch.setattr(repair.v55, "_model_artifact_states", lambda: dict(artifacts))
    monkeypatch.setattr(
        repair.v56,
        "stream_private_file_to_disposable_index",
        lambda *_a, **_k: {
            "ok": True,
            "rows": 24,
            "parser_success_rows": 24,
            "parser_failure_rows": 0,
        },
    )
    monkeypatch.setattr(repair.v544, "_install_protected_boundaries", lambda *_a, **_k: {})
    monkeypatch.setattr(repair.v56, "predeclare_chronological_roles", lambda *_a: {"ok": True})
    monkeypatch.setattr(repair.v56, "build_disposable_behavior_aggregates", lambda *_a: {})
    monkeypatch.setattr(
        repair.v544,
        "_apply_development_assisted_policy",
        lambda *_a, **_k: {
            "status": "complete",
            "reserved_future_labels_opened": False,
            "_review_rows": [],
        },
    )
    monkeypatch.setattr(
        repair.v544,
        "_write_private_lock",
        lambda *_a, **_k: {"status": "existing_private_lock_reused"},
    )
    monkeypatch.setattr(
        repair,
        "_contain_candidate_near_families",
        lambda *_a: {"passed": True},
    )
    monkeypatch.setattr(
        repair,
        "_human_role_bundles",
        lambda *_a, **_k: {
            "development_fit": empty,
            "calibration": empty,
            "threshold": empty,
        },
    )
    monkeypatch.setattr(repair, "_load_private_role_bundle", lambda *_a, **_k: (empty, {}))
    view = {
        "name": "manual_anchor_holdout",
        "evaluation_cohort": "manual",
        "fit": empty,
        "calibration": empty,
        "threshold": empty,
        "evaluation": empty,
        "leakage_audit": {"passed": True},
    }
    monkeypatch.setattr(
        repair,
        "build_development_views",
        lambda *_a, **_k: (
            [view, {**view, "name": "two"}, {**view, "name": "three"}],
            {"status": "ready", "valid_views": 3},
        ),
    )
    monkeypatch.setattr(
        repair,
        "run_model_comparison",
        lambda *_a, **_k: (
            {"status": "evaluated", "views": []},
            None,
        ),
    )
    monkeypatch.setattr(repair, "_isolation_audit", lambda *_a, **_k: {"reliability_passed": False})
    monkeypatch.setattr(
        repair,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///:memory:"),
    )

    result = repair.run_v545_development_model_repair(
        SimpleNamespace(),
        sample_path=sample,
        use_temp_db=True,
        output_dir=tmp_path / "output",
        write_output=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["safety"]["all_invariants_passed"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["future_labels_opened"] is False
    assert result["active_model_artifact_written"] is False
    assert result["model_activated"] is False
    assert result["rules_alert_authoritative"] is True
    assert str(sample) not in serialized


def test_public_status_never_exposes_private_contract_values(tmp_path: Path) -> None:
    latest = {
        "status": "development_repair_incomplete",
        "generated_at": "2026-08-01T00:00:00+00:00",
        "diagnostic_leader": {"name": "candidate", "summary": {"passing_views": 2, "required_views": 4}},
        "candidate_freeze": {"candidate_freeze_ready": False, "candidate_frozen": False},
        "isolation_forest_audit": {"reliability_passed": False},
    }
    (tmp_path / repair.V545_LATEST).write_text(json.dumps(latest), encoding="utf-8")

    result = repair.get_public_v545_status(tmp_path)

    assert result["candidate_freeze_ready"] is False
    assert result["model_activated"] is False
    assert result["future_labels_opened"] is False
    assert result["private_paths_returned"] is False
    assert result["fingerprints_returned"] is False
    assert result["secrets_exposed"] is False
