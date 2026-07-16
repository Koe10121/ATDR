from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection import v398_independent_holdout_validation as v398
from atdr.app.detection import v399_multisource_frozen_revalidation as v399
from atdr.tests.test_v331_noise_reduction import _session


def _internal_rows(count: int = 24) -> list[dict]:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        {
            "index": index,
            "log_id": index + 1,
            "source_name": "local_import",
            "timestamp": started + timedelta(minutes=index),
            "safe_queue_target": "needs_review" if index % 2 else "non_threat",
            "original_label": "suspicious" if index % 2 else "benign",
            "exact_fingerprint": f"internal-exact-{index}",
            "near_fingerprint": f"internal-near-{index}",
            "feature_fingerprint": f"internal-feature-{index}",
            "leakage_group": f"internal-group-{index}",
        }
        for index in range(count)
    ]


def _evaluated_split(split_mode: str) -> dict:
    metrics = {
        "queue_precision": 0.9,
        "queue_recall": 0.9,
        "queue_f1": 0.9,
        "benign_like_false_positive_rate": 0.1,
        "macro_f1": 0.88,
        "weighted_f1": 0.89,
        "suspicious_recall": 0.85,
        "malicious_recall": 0.8,
        "review_queue_rate": 0.5,
    }
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition_sizes": {"fit": 8, "calibration": 4, "threshold": 4, "final_test": 12},
        "leakage_audit": {
            "passed": True,
            "fingerprint_overlap": {"exact_fingerprint": 0, "near_fingerprint": 0, "feature_fingerprint": 0},
            "source_disjoint_from_internal": True,
            "chronology_passed": True,
            "final_target_class_diversity_passed": True,
            "final_labels_used_for_fit_calibration_or_threshold": False,
        },
        "strategies": [
            {
                "name": v399.PRIMARY_CANDIDATE,
                "status": "evaluated",
                "metrics": metrics,
                "calibration": {
                    "passed": True,
                    "brier_score": 0.08,
                    "expected_calibration_error": 0.04,
                    "max_confidence_accuracy_gap": 0.08,
                },
                "bootstrap_95_percent": {},
                "error_patterns": {},
            }
        ],
    }


def test_v399_evidence_generator_is_reproducible_source_and_time_separated():
    base_time = datetime(2026, 7, 1, tzinfo=timezone.utc)
    first = v399.build_evidence_records(base_time=base_time, seed=399, rows_per_source=24)
    second = v399.build_evidence_records(base_time=base_time, seed=399, rows_per_source=24)

    assert first == second
    assert len(first) == 72
    assert {row["source_name"] for row in first} == {str(spec["source_name"]) for spec in v399.SOURCE_SPECS}
    assert {row["collection_window"] for row in first} == {"window_1", "window_2", "window_3", "window_4"}
    assert all(row["evidence_kind"] == "synthetic" for row in first)
    assert all(row["human_reviewed"] is False for row in first)
    assert all(row["import_ready"] is False for row in first)
    assert {row["parser_profile"] for row in first} == {"generic_syslog", "palo_alto"}


def test_v399_overlap_is_quarantined_and_never_accepted(monkeypatch):
    monkeypatch.setattr(v399, "MIN_ACCEPTED_ROWS", 10)
    records = v399.build_evidence_records(
        base_time=datetime(2026, 7, 1, tzinfo=timezone.utc),
        rows_per_source=16,
    )
    external = v399._external_feature_dataset(records)
    try:
        first = external["rows"][0]
        internal = {
            "rows": [
                {
                    **_internal_rows(1)[0],
                    "exact_fingerprint": first["exact_fingerprint"],
                    "near_fingerprint": first["near_fingerprint"],
                    "feature_fingerprint": first["feature_fingerprint"],
                }
            ]
        }
        audit = v399.audit_and_quarantine_independence(internal, external)

        assert audit["passed"] is True
        assert audit["quarantined_rows"] >= 1
        assert 0 in audit["quarantined_indices"]
        assert 0 not in audit["accepted_indices"]
        assert all(value == 0 for value in audit["internal_overlap_after_quarantine"].values())
        assert records[0]["independence_status"] == "quarantined"
    finally:
        v399._close_external_dataset(external)


def test_v399_final_splits_remain_external_grouped_and_label_isolated(monkeypatch):
    monkeypatch.setattr(v399, "MIN_ACCEPTED_ROWS", 10)
    internal = {"rows": _internal_rows()}
    records = v399.build_evidence_records(
        base_time=datetime(2026, 7, 1, tzinfo=timezone.utc),
        rows_per_source=24,
    )
    external = v399._external_feature_dataset(records)
    try:
        audit = v399.audit_and_quarantine_independence(internal, external)
        splits = v399.build_external_final_splits(external, audit)

        assert set(splits) == set(v399.V399_SPLITS)
        for split_mode, indices in splits.items():
            leakage = v399._split_leakage_audit(internal, external, indices, split_mode=split_mode)
            assert leakage["passed"] is True
            assert leakage["source_disjoint_from_internal"] is True
            assert leakage["chronology_passed"] is True
            assert leakage["final_labels_used_for_fit_calibration_or_threshold"] is False
            assert leakage["external_fit_rows"] == 0
            assert leakage["external_calibration_rows"] == 0
            assert leakage["external_threshold_rows"] == 0
    finally:
        v399._close_external_dataset(external)


def test_v399_readiness_is_candidate_only_even_when_synthetic_checks_pass():
    splits = [_evaluated_split(split_mode) for split_mode in v399.V399_SPLITS]
    comparison = v398._strategy_comparison(splits)
    evidence = {
        "passed": True,
        "accepted_rows": 720,
        "accepted_source_count": 3,
        "accepted_collection_window_count": 4,
    }

    readiness = v399._readiness(splits, comparison, evidence)

    assert readiness["synthetic_independence_passed"] is True
    assert readiness["external_independent_validation_passed"] is False
    assert readiness["decision"] == "candidate_only"
    assert readiness["production_promoted"] is False
    assert readiness["model_activated"] is False
    assert readiness["model_artifact_written"] is False
    assert readiness["response_automation_allowed"] is False


def test_v399_runner_writes_non_importable_evidence_without_side_effects(tmp_path, monkeypatch):
    rows = _internal_rows()
    dataset = {
        "ok": True,
        "rows": rows,
        "labels": [],
        "logs": [],
        "targets": [row["safe_queue_target"] for row in rows],
        "original_labels": [row["original_label"] for row in rows],
        "label_provenance": {"reviewed_latest_rows": len(rows)},
    }
    partition = {
        "fit_idx": list(range(0, 8)),
        "calibration_idx": list(range(8, 12)),
        "threshold_idx": list(range(12, 16)),
        "final_test_idx": list(range(16, 24)),
    }
    freeze = {
        "ok": True,
        "status": "frozen",
        "split_mode": v399.INTERNAL_FREEZE_SPLIT,
        "partition": partition,
        "leakage_audit": {"passed": True},
        "partition_hash": "frozen-hash",
        "partition_sizes": {"fit": 8, "calibration": 4, "threshold": 4, "reserved_internal_final": 8},
        "external_rows_used_for_fit": 0,
        "external_rows_used_for_calibration": 0,
        "external_rows_used_for_threshold_selection": 0,
        "internal_reserved_final_used_for_fit_or_tuning": False,
        "final_test_labels_used_for_fit_calibration_or_threshold": False,
    }
    frozen_candidates = {
        "primary": {"threshold_selection": {"selected_threshold": 0.5, "used_final_test_labels": False}},
        "logistic": {"threshold_selection": {"selected_threshold": 0.5, "used_final_test_labels": False}},
        "anomaly": {"threshold_selection": {"selected_threshold": 0.5, "used_final_test_labels": False}},
        "hybrid_threshold": {"selected_threshold": 0.5, "used_final_test_labels": False},
        "majority_class": "needs_review",
    }
    monkeypatch.setattr(v399, "MIN_ACCEPTED_ROWS", 10)
    monkeypatch.setattr(v398, "_build_dataset", lambda db, min_samples: dataset)
    monkeypatch.setattr(v399, "_internal_freeze", lambda current: freeze)
    monkeypatch.setattr(v399, "_fit_frozen_candidates", lambda current, current_freeze: dict(frozen_candidates))
    monkeypatch.setattr(
        v399,
        "_evaluate_external_split",
        lambda internal, external, candidates, split_mode, final_indices: _evaluated_split(split_mode),
    )
    monkeypatch.setattr(v398, "_artifact_state", lambda: {"exists": False, "name": "supervised_classifier.joblib"})

    with _session() as db:
        before = {
            "labels": db.scalar(select(func.count(MLLabel.id))),
            "models": db.scalar(select(func.count(MLModelRun.id))),
            "responses": db.scalar(select(func.count(ResponseAction.id))),
        }
        result = v399.run_v399_multisource_frozen_revalidation(
            db,
            output_dir=tmp_path,
            rows_per_source=16,
        )
        after = {
            "labels": db.scalar(select(func.count(MLLabel.id))),
            "models": db.scalar(select(func.count(MLModelRun.id))),
            "responses": db.scalar(select(func.count(ResponseAction.id))),
        }

    latest = tmp_path / v399.V399_LATEST
    latest_text = latest.read_text(encoding="utf-8")
    assert result["ok"] is True
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["label_integrity"]["human_reviewed_external_rows"] == 0
    assert result["label_integrity"]["labels_imported"] == 0
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["active_artifact_unchanged"] is True
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before == after
    assert latest.exists()
    assert '"raw_line"' not in latest_text
    assert '"src_ip"' not in latest_text
    assert list(tmp_path.glob("v3_99_independent_multisource_validation_*.md"))
    assert list(tmp_path.glob("v3_99_leakage_audit_*.md"))
    source_csv = next((tmp_path / "v3_99_evidence").rglob("*.csv"))
    csv_text = source_csv.read_text(encoding="utf-8")
    assert "human_reviewed,import_ready" in csv_text
    assert ",False,False," in csv_text
