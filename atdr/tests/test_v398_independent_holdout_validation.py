from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection import v398_independent_holdout_validation as v398
from atdr.tests.test_v331_noise_reduction import _session


def _rows(*, sources: int = 8, rows_per_source: int = 16) -> list[dict]:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = []
    for source_number in range(sources):
        for offset in range(rows_per_source):
            index = len(rows)
            target = "needs_review" if offset % 2 else "non_threat"
            rows.append(
                {
                    "index": index,
                    "log_id": index + 1,
                    "source_name": f"source-{source_number}",
                    "timestamp": started + timedelta(minutes=index),
                    "safe_queue_target": target,
                    "exact_fingerprint": f"exact-{index}",
                    "near_fingerprint": f"near-{index}",
                    "feature_fingerprint": f"feature-{index}",
                    "leakage_group": f"group-{index}",
                }
            )
    return rows


def _evaluated_split(split_mode: str, *, f1: float = 0.9, fpr: float = 0.05) -> dict:
    metrics = {
        "queue_precision": 0.9,
        "queue_recall": 0.9,
        "queue_f1": f1,
        "benign_like_false_positive_rate": fpr,
        "macro_f1": 0.9,
        "weighted_f1": 0.9,
        "suspicious_recall": 0.85,
        "malicious_recall": 0.85,
        "review_queue_rate": 0.5,
    }
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition": {"partition_id": f"partition-{split_mode}"},
        "partition_sizes": {"fit": 40, "calibration": 15, "threshold": 15, "final_test": 30, "quarantined": 0},
        "partition_target_distributions": {},
        "leakage_audit": {"passed": True, "status": "passed", "unacceptable_overlap_count": 0},
        "strategies": [
            {
                "name": v398.PRIMARY_CANDIDATE,
                "status": "evaluated",
                "metrics": metrics,
                "calibration": {"passed": True, "brier_score": 0.1, "expected_calibration_error": 0.05},
                "threshold_selection": {
                    "threshold": 0.5,
                    "selected_on": "threshold_selection_partition_only",
                    "used_final_test_labels": False,
                },
            }
        ],
    }


def test_v398_groups_exact_near_and_feature_duplicates_together():
    rows = _rows(sources=2, rows_per_source=4)
    rows[1]["exact_fingerprint"] = rows[0]["exact_fingerprint"]
    rows[2]["near_fingerprint"] = rows[1]["near_fingerprint"]
    rows[3]["feature_fingerprint"] = rows[2]["feature_fingerprint"]

    summary = v398.assign_leakage_groups(rows)

    assert rows[0]["leakage_group"] == rows[1]["leakage_group"]
    assert rows[1]["leakage_group"] == rows[2]["leakage_group"]
    assert rows[2]["leakage_group"] == rows[3]["leakage_group"]
    assert summary["duplicate_exact_fingerprint_groups"] == 1
    assert summary["duplicate_near_fingerprint_groups"] == 1
    assert summary["duplicate_feature_fingerprint_groups"] == 1


def test_v398_leakage_audit_fails_closed_on_duplicate_final_evidence():
    rows = _rows(sources=2, rows_per_source=4)
    rows[7]["exact_fingerprint"] = rows[0]["exact_fingerprint"]
    partition = {
        "status": "partitioned",
        "split_mode": "random_seed_7",
        "fit_idx": [0, 1],
        "calibration_idx": [2, 3],
        "threshold_idx": [4, 5],
        "final_test_idx": [6, 7],
        "quarantined_idx": [],
    }

    audit = v398.audit_partition_leakage(rows, partition)

    assert audit["passed"] is False
    assert audit["status"] == "failed_closed"
    assert audit["unacceptable_overlap_count"] >= 1


def test_v398_source_holdout_is_source_disjoint_and_repeatable():
    rows = _rows()

    first = v398.build_frozen_partition(rows, split_mode="source_holdout")
    second = v398.build_frozen_partition(rows, split_mode="source_holdout")
    audit = v398.audit_partition_leakage(rows, first)
    development = first["fit_idx"] + first["calibration_idx"] + first["threshold_idx"]
    development_sources = {rows[index]["source_name"] for index in development}
    final_sources = {rows[index]["source_name"] for index in first["final_test_idx"]}

    assert first["partition_id"] == second["partition_id"]
    assert development_sources.isdisjoint(final_sources)
    assert audit["passed"] is True
    assert audit["source_overlap_with_final_test"] == 0
    assert first["final_test_labels_used_for_training"] is False
    assert first["final_test_labels_used_for_calibration"] is False
    assert first["final_test_labels_used_for_threshold_selection"] is False


def test_v398_threshold_selection_is_threshold_partition_only():
    selection = v398.select_threshold(
        ["non_threat", "needs_review", "needs_review", "non_threat"],
        [0.1, 0.9, 0.8, 0.2],
    )

    assert selection["selected_on"] == "threshold_selection_partition_only"
    assert selection["used_final_test_labels"] is False
    assert selection["threshold_rows"] == 4


def test_v398_readiness_never_promotes_without_external_independence():
    splits = [_evaluated_split(split_mode) for split_mode in v398.V398_SPLITS]
    comparison = v398._strategy_comparison(splits)

    readiness = v398._readiness(splits, comparison)

    assert readiness["internal_holdout_gates_passed"] is True
    assert readiness["external_independent_validation_passed"] is False
    assert readiness["decision"] == "candidate_only"
    assert readiness["production_promoted"] is False
    assert readiness["model_activated"] is False
    assert readiness["model_artifact_written"] is False
    assert readiness["response_automation_allowed"] is False


def test_v398_runner_writes_ignored_reports_without_side_effects(tmp_path, monkeypatch):
    rows = _rows(sources=2, rows_per_source=4)
    frame = SimpleNamespace()
    dataset = {
        "ok": True,
        "rows": rows,
        "frame": frame,
        "logs": [],
        "targets": [row["safe_queue_target"] for row in rows],
        "original_labels": ["benign" if row["safe_queue_target"] == "non_threat" else "suspicious" for row in rows],
        "feature_generation_seconds": 0.0,
        "feature_meta": {
            "numeric_features": ["feature"],
            "categorical_features": [],
            "excluded_features": sorted(v398.LEAKAGE_UNSAFE_FEATURES),
        },
        "label_provenance": {
            "reviewed_latest_rows": len(rows),
            "weak_or_unreviewed_latest_rows_excluded": 0,
        },
    }
    splits = {split_mode: _evaluated_split(split_mode) for split_mode in v398.V398_SPLITS}
    monkeypatch.setattr(v398, "_build_dataset", lambda db, min_samples: dataset)
    monkeypatch.setattr(v398, "_run_split", lambda current, split_mode: splits[split_mode])
    monkeypatch.setattr(v398, "_artifact_state", lambda: {"exists": False, "name": "candidate.joblib"})

    with _session() as db:
        before = {
            "labels": db.scalar(select(func.count(MLLabel.id))),
            "models": db.scalar(select(func.count(MLModelRun.id))),
            "responses": db.scalar(select(func.count(ResponseAction.id))),
        }
        result = v398.run_v398_independent_holdout_validation(db, output_dir=tmp_path, min_samples=4)
        after = {
            "labels": db.scalar(select(func.count(MLLabel.id))),
            "models": db.scalar(select(func.count(MLModelRun.id))),
            "responses": db.scalar(select(func.count(ResponseAction.id))),
        }

    assert result["ok"] is True
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["external_independent_benchmark"]["performed"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["active_artifact_unchanged"] is True
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before == after
    assert (tmp_path / v398.V398_LATEST).exists()
    assert list(tmp_path.glob("v3_98_holdout_validation_*.md"))
    assert list(tmp_path.glob("v3_98_leakage_audit_*.md"))
    assert "raw_line" not in (tmp_path / v398.V398_LATEST).read_text(encoding="utf-8")
