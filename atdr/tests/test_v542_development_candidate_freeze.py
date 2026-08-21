from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from atdr.app.detection import v542_development_candidate_freeze as freeze


def _evaluated_result(*, queue_rate: float = 0.25) -> dict:
    return {
        "status": "evaluated",
        "applied_calibration_method": "sigmoid_prefit",
        "post_prediction_guard_used": False,
        "metrics": {
            "queue_precision": 0.91,
            "queue_recall": 0.90,
            "queue_f1": 0.90,
            "benign_like_false_positive_rate": 0.05,
            "suspicious_recall": 0.88,
            "malicious_recall": 0.86,
            "macro_f1": 0.85,
            "weighted_f1": 0.88,
            "review_queue_rate": queue_rate,
            "false_positive": 2,
            "false_negative": 3,
        },
        "calibration": {
            "brier_score": 0.08,
            "expected_calibration_error": 0.06,
            "max_confidence_accuracy_gap": 0.09,
        },
        "threshold_selection": {
            "selected_profile": "balanced",
            "selected_threshold": 0.5,
        },
        "error_patterns": {
            "false_positives": {"rows": 2},
            "false_negatives": {"rows": 3},
        },
        "active_artifact_written": False,
    }


def _fold_dataset() -> dict:
    rows = [
        {
            "app": "ssl",
            "action": "allow",
            "label_source": "manual",
            "v540_evidence_family": "routine_encrypted",
        }
        for _ in range(16)
    ]
    return {
        "rows": rows,
        "targets": ["non_threat"] * 8 + ["needs_review"] * 8,
        "original_labels": ["benign"] * 8 + ["suspicious"] * 8,
        "frame": pd.DataFrame([{"feature": index} for index in range(16)]),
    }


def _folds(dataset: dict) -> list[dict]:
    partition = {
        "fit_idx": [0, 1, 8, 9],
        "calibration_idx": [2, 3, 10, 11],
        "threshold_idx": [4, 5, 12, 13],
        "final_test_idx": [6, 7, 14, 15],
    }
    return [
        {
            "fold": index,
            "prefix_share": share,
            "status": "partitioned",
            "dataset": dataset,
            "partition": partition,
            "leakage_audit": {
                "passed": True,
                "partition_sizes": {key: len(value) for key, value in partition.items()},
            },
        }
        for index, share in enumerate((0.7, 0.85, 1.0), start=1)
    ]


def test_candidate_set_is_predeclared_and_excludes_v540_duplicate_variant() -> None:
    assert [item["name"] for item in freeze.PREDECLARED_STRATEGIES] == [
        "calibrated_extra_trees",
        "calibrated_hist_gradient_boosting",
        "calibrated_logistic_regression",
        "three_class_soc_queue",
        "hierarchical_two_stage",
    ]
    assert "binary_threat_queue" not in {
        item["name"] for item in freeze.PREDECLARED_STRATEGIES
    }


def test_fixed_gate_requires_metrics_calibration_leakage_and_no_guard() -> None:
    passing = freeze._fixed_fold_gate(
        _evaluated_result(),
        leakage_passed=True,
    )
    guarded = _evaluated_result()
    guarded["post_prediction_guard_used"] = True

    assert passing["passed"] is True
    assert freeze._fixed_fold_gate(guarded, leakage_passed=True)["passed"] is False
    assert (
        freeze._fixed_fold_gate(_evaluated_result(), leakage_passed=False)["passed"]
        is False
    )


def test_fixed_comparison_requires_every_fold_and_stable_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _fold_dataset()
    monkeypatch.setattr(freeze.v55, "build_nested_temporal_folds", lambda _: _folds(dataset))
    monkeypatch.setattr(
        freeze.v540,
        "_fit_strategy",
        lambda _dataset, _partition, spec: {
            "name": spec["name"],
            **_evaluated_result(queue_rate=0.25),
        },
    )

    result = freeze.run_fixed_candidate_comparison(dataset)

    assert result["strategy_count"] == 5
    assert result["required_folds"] == 3
    assert result["locked_final_rows_used"] == 0
    assert result["v539_rows_used"] == 0
    assert result["v541_blind_rows_used"] == 0
    assert all(
        summary["eligible_for_diagnostic_freeze"]
        for summary in result["strategy_summaries"].values()
    )


def test_candidate_freeze_is_immutable_and_fails_closed_on_tamper(
    tmp_path: Path,
) -> None:
    contract = {
        "schema_version": freeze.V542_VERSION,
        "status": "diagnostic_configuration_frozen",
        "strategy": {"name": "calibrated_extra_trees"},
    }
    artifact = {"model": "diagnostic-only", "active": False}

    first = freeze.seal_immutable_candidate(
        artifact=artifact,
        candidate_contract=contract,
        output_dir=tmp_path,
    )
    reused = freeze.seal_immutable_candidate(
        artifact=artifact,
        candidate_contract=contract,
        output_dir=tmp_path,
    )

    assert first["candidate_frozen"] is True
    assert first["active"] is False
    assert reused["reused_existing_freeze"] is True
    with pytest.raises(freeze.V542FreezeError, match="different immutable candidate"):
        freeze.seal_immutable_candidate(
            artifact=artifact,
            candidate_contract={**contract, "threshold": 0.7},
            output_dir=tmp_path,
        )

    (tmp_path / freeze.V542_CANDIDATE_ARTIFACT).write_bytes(b"tampered")
    with pytest.raises(freeze.V542FreezeError, match="integrity"):
        freeze.get_public_candidate_freeze_status(output_dir=tmp_path)


def test_public_status_is_aggregate_and_hides_private_state(tmp_path: Path) -> None:
    result = {
        "version": freeze.V542_VERSION,
        "readiness": {
            "status": "No Candidate Frozen",
            "candidate_frozen": False,
            "supervised_phases_remaining": 5,
            "blockers": ["Temporal stability gate failed."],
        },
        "best_development_candidate": {
            "name": "hierarchical_two_stage",
            "summary": {
                "passing_folds": 0,
                "required_folds": 3,
                "calibration_ranges": {
                    "expected_calibration_error": {"max": 0.4},
                    "max_confidence_accuracy_gap": {"max": 0.5},
                },
            },
        },
        "blind_evidence_status": {"status": "Designed"},
    }
    (tmp_path / freeze.V542_LATEST).write_text(json.dumps(result), encoding="utf-8")

    public = freeze.get_public_candidate_freeze_status(output_dir=tmp_path)
    serialized = json.dumps(public)

    assert public["candidate_frozen"] is False
    assert public["best_candidate"] == "hierarchical_two_stage"
    assert public["calibration_status"] == "weak"
    assert public["model_activated"] is False
    assert public["blind_predictions_exposed"] is False
    assert "sha256" not in serialized
    assert "path" not in serialized.lower() or public["private_paths_exposed"] is False


def test_fail_closed_readiness_keeps_all_authoritative_counts_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    counts = {
        "ml_labels": 10,
        "ml_model_runs": 2,
        "detection_runs": 3,
        "alerts": 4,
        "response_actions": 0,
    }
    dataset = _fold_dataset()
    state = {
        "development": dataset,
        "canonical": {},
        "exclusion": {},
        "feature_audit": {},
        "v539_boundary": {"status": "consumed_boundary_locked"},
        "v541_boundary": {"cutoff": None},
        "blind_status": {
            "status": "Designed",
            "candidate_rows": 0,
            "independent_source_count": 0,
            "required_source_count": 2,
            "collection_window_count": 0,
            "required_window_count": 3,
            "human_review_complete": False,
        },
        "boundary_checks": {
            "all": True,
            "v541_custody_status_valid": True,
        },
    }
    comparison = {
        "strategy_summaries": {
            "calibrated_extra_trees": {
                "eligible_for_diagnostic_freeze": False,
                "passing_folds": 0,
                "required_folds": 3,
                "review_queue_rate_stability_passed": False,
                "metric_ranges": {},
                "calibration_ranges": {},
                "threshold_profiles": [],
            }
        }
    }
    monkeypatch.setattr(freeze.frozen, "_database_counts", lambda _db: dict(counts))
    monkeypatch.setattr(freeze.v55, "_model_artifact_states", lambda: {"active": None})
    monkeypatch.setattr(freeze, "_workspace_states", lambda _path: {"state": "same"})
    monkeypatch.setattr(freeze, "build_v542_development_state", lambda _db, **_: state)
    monkeypatch.setattr(freeze, "run_fixed_candidate_comparison", lambda _: comparison)
    monkeypatch.setattr(
        freeze,
        "diagnose_instability",
        lambda *_: {"status": "diagnosed", "root_causes": ["Temporal instability."]},
    )

    result = freeze.run_v542_candidate_freeze_readiness(
        object(),
        write_output=False,
        output_dir=tmp_path,
    )

    assert result["status"] == "no_candidate_frozen"
    assert result["readiness"]["lifecycle_state"] == "shadow_observation"
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["alerts_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["rules_alert_authoritative"] is True
