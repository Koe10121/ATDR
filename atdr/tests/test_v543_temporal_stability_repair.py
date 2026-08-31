from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from atdr.app.detection import v543_temporal_stability_repair as repair


def _metrics(*, queue_rate: float = 0.25) -> dict:
    return {
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
    }


def _evaluated_result(name: str, *, queue_rate: float = 0.25) -> dict:
    result = {
        "status": "evaluated",
        "name": name,
        "applied_calibration_method": "sigmoid_prefit",
        "post_prediction_guard_used": False,
        "metrics": _metrics(queue_rate=queue_rate),
        "calibration": {
            "brier_score": 0.08,
            "expected_calibration_error": 0.06,
            "max_confidence_accuracy_gap": 0.09,
        },
        "threshold_selection": {
            "selected_profile": "balanced",
            "selected_threshold": 0.5,
        },
        "active_artifact_written": False,
    }
    result["fixed_freeze_gate"] = repair.v542._fixed_fold_gate(
        result,
        leakage_passed=True,
    )
    return result


def _dataset() -> dict:
    rows = []
    for index in range(16):
        rows.append(
            {
                "timestamp": pd.Timestamp("2026-01-01") + pd.Timedelta(index, "m"),
                "leakage_group": "shared" if index < 2 else f"group-{index}",
                "label_source": "manual" if index % 2 == 0 else "assisted_rule",
                "app": "ssl",
                "action": "allow",
                "v540_evidence_family": "routine_encrypted",
            }
        )
    return {
        "rows": rows,
        "targets": ["non_threat"] * 8 + ["needs_review"] * 8,
        "original_labels": ["benign"] * 8 + ["suspicious"] * 4 + ["malicious"] * 4,
        "frame": pd.DataFrame(
            {
                "app_risk": list(range(16)),
                "protocol": ["tcp"] * 16,
                "action": ["allow"] * 16,
                "app": ["ssl"] * 16,
                "src_zone": ["trust"] * 16,
                "dst_zone": ["untrust"] * 16,
                "v337_traffic_family": ["routine"] * 16,
                "v540_evidence_family": ["routine_encrypted"] * 16,
            }
        ),
        "feature_meta": {
            "numeric_features": ["app_risk"],
            "categorical_features": [
                "protocol",
                "action",
                "app",
                "src_zone",
                "dst_zone",
                "v337_traffic_family",
                "v540_evidence_family",
            ],
        },
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
        for index, share in enumerate((0.70, 0.85, 1.0), start=1)
    ]


def test_repair_contract_has_exactly_five_predeclared_variants_and_unchanged_gates() -> None:
    assert [item["name"] for item in repair.PREDECLARED_REPAIR_VARIANTS] == [
        "hierarchical_two_stage_baseline",
        "inverse_duplicate_cluster_weighting",
        "temporal_provenance_balanced_weighting",
        "stronger_assisted_label_downweighting",
        "compact_stable_feature_hierarchical",
    ]
    assert repair.FIXED_FREEZE_GATES == repair.v542.FIXED_FREEZE_GATES


def test_inverse_duplicate_weighting_reduces_multirow_cluster_influence() -> None:
    dataset = _dataset()
    indices = list(range(len(dataset["rows"])))
    weights, audit = repair.build_variant_weights(
        dataset,
        indices,
        dataset["targets"],
        "inverse_duplicate_cluster",
    )

    assert weights[0] < weights[2]
    assert audit["multirow_duplicate_group_count"] == 1
    assert audit["labels_rewritten"] is False


def test_weighting_and_calibration_diagnostics_are_deterministic() -> None:
    dataset = _dataset()
    indices = list(range(len(dataset["rows"])))

    first_weights, first_audit = repair.build_variant_weights(
        dataset,
        indices,
        dataset["targets"],
        "temporal_provenance_balanced",
    )
    second_weights, second_audit = repair.build_variant_weights(
        dataset,
        indices,
        dataset["targets"],
        "temporal_provenance_balanced",
    )
    calibration = repair.frozen._calibration_report(
        ["non_threat", "needs_review", "non_threat", "needs_review"],
        [0.1, 0.9, 0.2, 0.8],
    )

    assert first_weights == second_weights
    assert first_audit == second_audit
    assert calibration["brier_score"] == pytest.approx(0.025, abs=0.0001)
    assert calibration["expected_calibration_error"] == pytest.approx(0.15, abs=0.0001)
    assert calibration["max_confidence_accuracy_gap"] >= 0


def test_compact_feature_contract_is_predeclared_and_contains_no_forbidden_features() -> None:
    contract = repair._feature_contract(_dataset(), "compact_stable")

    selected = set(contract["numeric_features"]) | set(
        contract["categorical_features"]
    )
    assert contract["selection_predeclared"] is True
    assert selected
    assert not selected.intersection(repair.FORBIDDEN_FEATURE_NAMES)
    assert contract["evaluation_labels_used_for_selection"] is False


def test_comparison_requires_all_folds_and_stable_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset()
    monkeypatch.setattr(repair.v55, "build_nested_temporal_folds", lambda _: _folds(dataset))
    monkeypatch.setattr(
        repair,
        "analyze_feature_ablation",
        lambda *_: {
            "full_feature_count": 8,
            "compact_feature_count": 8,
            "top_numeric_distribution_shifts": [],
            "categorical_distribution_shifts": [],
            "source_specific_or_constant_features": [],
            "potential_label_leakage_features": [],
        },
    )
    monkeypatch.setattr(
        repair,
        "_fit_variant",
        lambda _dataset, _partition, spec: _evaluated_result(spec["name"]),
    )

    result = repair.run_repair_comparison(dataset)

    assert result["variant_count"] == 5
    assert result["required_folds"] == 3
    assert result["locked_final_rows_used"] == 0
    assert result["v539_rows_used"] == 0
    assert result["v541_blind_rows_used"] == 0
    assert all(
        summary["eligible_for_diagnostic_freeze"]
        for summary in result["variant_summaries"].values()
    )


def test_public_status_is_aggregate_and_hides_private_state(tmp_path: Path) -> None:
    result = {
        "version": repair.V543_VERSION,
        "readiness": {
            "status": "No Candidate Frozen",
            "candidate_frozen": False,
            "supervised_phases_remaining": 5,
            "blockers": ["Temporal stability gate failed."],
        },
        "best_repair_variant": {
            "name": "compact_stable_feature_hierarchical",
            "summary": {
                "passing_folds": 1,
                "required_folds": 3,
                "review_queue_rate_stability_passed": False,
                "calibration_ranges": {
                    "expected_calibration_error": {"max": 0.4},
                    "max_confidence_accuracy_gap": {"max": 0.5},
                },
            },
        },
        "development_comparison": {
            "feature_ablation_summary": {"folds_audited": 3}
        },
    }
    (tmp_path / repair.V543_LATEST).write_text(json.dumps(result), encoding="utf-8")

    public = repair.get_public_temporal_stability_status(output_dir=tmp_path)
    serialized = json.dumps(public).lower()

    assert public["best_variant"] == "compact_stable_feature_hierarchical"
    assert public["candidate_frozen"] is False
    assert public["calibration_status"] == "weak"
    assert public["queue_stability_status"] == "unstable"
    assert public["model_activated"] is False
    assert public["blind_predictions_exposed"] is False
    assert "sha256" not in serialized
    assert "artifact_path" not in serialized


def test_candidate_freeze_is_immutable_and_fails_closed_on_tamper(
    tmp_path: Path,
) -> None:
    contract = {
        "schema_version": repair.V543_VERSION,
        "status": "diagnostic_configuration_frozen",
        "variant": {"name": "compact_stable_feature_hierarchical"},
    }
    artifact = {"model": "diagnostic-only", "active": False}

    first = repair.seal_immutable_candidate(
        artifact=artifact,
        candidate_contract=contract,
        output_dir=tmp_path,
    )
    reused = repair.seal_immutable_candidate(
        artifact=artifact,
        candidate_contract=contract,
        output_dir=tmp_path,
    )

    assert first["candidate_frozen"] is True
    assert first["active"] is False
    assert reused["reused_existing_freeze"] is True
    with pytest.raises(repair.V543RepairError, match="different immutable"):
        repair.seal_immutable_candidate(
            artifact=artifact,
            candidate_contract={**contract, "threshold": 0.7},
            output_dir=tmp_path,
        )

    (tmp_path / repair.V543_CANDIDATE_ARTIFACT).write_bytes(b"tampered")
    with pytest.raises(repair.V543RepairError, match="integrity"):
        repair.get_public_temporal_stability_status(output_dir=tmp_path)


def test_fail_closed_run_keeps_authoritative_state_unchanged(
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
    state = {
        "development": _dataset(),
        "v543_boundary_checks": {"custody": True},
        "v542_report_present": True,
        "v542_candidate_frozen": False,
        "blind_status": {
            "independent_source_count": 0,
            "required_source_count": 2,
            "collection_window_count": 0,
            "required_window_count": 3,
            "human_review_complete": False,
        },
    }
    comparison = {
        "variant_summaries": {
            "hierarchical_two_stage_baseline": {
                "eligible_for_diagnostic_freeze": False,
                "passing_folds": 0,
                "required_folds": 3,
                "metric_ranges": {},
                "calibration_ranges": {},
            }
        },
        "views": [],
        "feature_ablation_summary": {},
    }
    monkeypatch.setattr(repair.frozen, "_database_counts", lambda _db: dict(counts))
    monkeypatch.setattr(repair.v55, "_model_artifact_states", lambda: {"active": None})
    monkeypatch.setattr(repair, "_workspace_state", lambda _path: {"state": "same"})
    monkeypatch.setattr(repair.v542, "_workspace_states", lambda _path: {"state": "same"})
    monkeypatch.setattr(repair.v542, "_file_state", lambda _path: {"state": "same"})
    monkeypatch.setattr(repair, "build_v543_development_state", lambda _db, **_: state)
    monkeypatch.setattr(repair, "run_repair_comparison", lambda _: comparison)
    monkeypatch.setattr(repair, "select_best_repair", lambda _: None)
    monkeypatch.setattr(
        repair,
        "diagnose_repair",
        lambda *_: {"status": "diagnosed", "root_causes": ["Temporal instability."]},
    )

    result = repair.run_v543_temporal_stability_repair(
        object(),
        write_output=False,
        output_dir=tmp_path,
    )

    assert result["status"] == "no_candidate_frozen"
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["detection_runs_created"] == 0
    assert result["safety"]["alerts_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["rules_alert_authoritative"] is True
