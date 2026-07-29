from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pandas as pd
import pytest

from atdr.app.detection import supervised_detector
from atdr.app.detection import v51_supervised_lifecycle as lifecycle
from atdr.app.detection import v55_development_model_repair as repair


def _dataset(rows: int = 160) -> dict:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    evidence_rows = []
    labels = []
    logs = []
    frame_rows = []
    targets = []
    original_labels = []
    for index in range(rows):
        positive = index % 4 in {0, 1}
        original = "suspicious" if index % 8 == 0 else "malicious" if index % 8 == 1 else "benign"
        target = "needs_review" if positive else "non_threat"
        evidence_rows.append(
            {
                "index": index,
                "label_id": index + 1000,
                "log_id": index + 1,
                "original_label": original,
                "safe_queue_target": target,
                "reviewed": True,
                "label_source": "manual" if index % 3 else "assisted_rule",
                "source_name": "source-a" if index % 2 else "source-b",
                "network_zone_group": "zone:inside->outside",
                "timestamp": started + timedelta(minutes=index),
                "app": "ssl" if index % 2 else "quic-base",
                "action": "allow",
                "dst_port": 443,
                "exact_fingerprint": f"{index:064x}",
                "near_fingerprint": f"near-{index}",
                "feature_fingerprint": f"feature-{index}",
                "leakage_group": f"group-{index}",
            }
        )
        labels.append(SimpleNamespace(label_source=evidence_rows[-1]["label_source"]))
        logs.append(SimpleNamespace(id=index + 1))
        frame_rows.append(
            {
                "bytes": 100 + index,
                "packets": 2 + index % 5,
                "app": evidence_rows[-1]["app"],
                "action": "allow",
            }
        )
        targets.append(target)
        original_labels.append(original)
    return {
        "ok": True,
        "imports": supervised_detector._optional_imports(),
        "labels": labels,
        "logs": logs,
        "frame": pd.DataFrame(frame_rows),
        "rows": evidence_rows,
        "targets": targets,
        "original_labels": original_labels,
        "feature_meta": {
            "numeric_features": ["bytes", "packets"],
            "categorical_features": ["app", "action"],
        },
        "label_provenance": {},
    }


def _canonical_partition() -> dict:
    return {
        "status": "partitioned",
        "split_mode": "temporal_holdout",
        "fit_idx": list(range(0, 70)),
        "calibration_idx": list(range(70, 90)),
        "threshold_idx": list(range(90, 110)),
        "final_test_idx": list(range(110, 145)),
        "quarantined_idx": list(range(145, 160)),
    }


def test_development_dataset_excludes_locked_and_quarantined_evidence():
    dataset = _dataset()

    development = repair.build_development_dataset(
        dataset,
        _canonical_partition(),
    )

    assert len(development["rows"]) == 110
    assert development["locked_indices_included"] is False
    assert development["locked_label_count"] == 0
    assert max(development["governed_indices"]) == 109
    assert not set(development["governed_indices"]) & set(range(110, 160))


def test_nested_temporal_folds_keep_duplicate_groups_isolated():
    dataset = _dataset()
    development = repair.build_development_dataset(
        dataset,
        _canonical_partition(),
    )

    folds = repair.build_nested_temporal_folds(development)

    assert len(folds) == 3
    assert all(fold["status"] == "partitioned" for fold in folds)
    assert all(fold["leakage_audit"]["passed"] for fold in folds)
    assert all(fold["locked_indices_included"] is False for fold in folds)
    for fold in folds:
        partition = fold["partition"]
        groups_by_role = [
            {
                fold["dataset"]["rows"][index]["leakage_group"]
                for index in partition[key]
            }
            for key in (
                "fit_idx",
                "calibration_idx",
                "threshold_idx",
                "final_test_idx",
            )
        ]
        assert all(
            not left & right
            for position, left in enumerate(groups_by_role)
            for right in groups_by_role[position + 1 :]
        )


def test_provenance_balanced_weights_are_bounded():
    dataset = _dataset(40)

    weights, summary = repair._provenance_balanced_weights(
        dataset,
        list(range(40)),
    )

    assert len(weights) == 40
    assert min(weights) >= 0.25
    assert max(weights) <= 4.0
    assert summary["strategy"] == "inverse_provenance_frequency_clipped"


def test_candidate_freeze_is_required_before_locked_final(monkeypatch):
    dataset = _dataset()
    called = []
    monkeypatch.setattr(
        repair,
        "_fit_pipeline",
        lambda *_args, **_kwargs: called.append(True)
        or {
            "status": "evaluated",
            "metrics": {},
            "calibration": {},
        },
    )

    with pytest.raises(ValueError, match="frozen"):
        repair.evaluate_locked_final_once(
            dataset,
            _canonical_partition(),
            {
                "frozen_before_locked_final": False,
                "candidate": repair.CANDIDATE_SPECS[0],
            },
        )

    assert called == []


def test_v55_governance_summary_exposes_only_aggregate_status(
    monkeypatch,
    tmp_path,
):
    report = {
        "status": "evaluated",
        "generated_at": "2026-07-26T00:00:00+00:00",
        "readiness": {
            "decision": "shadow_observation",
            "candidate_selected": False,
            "blockers": ["development gates failed"],
        },
        "selected_development_leader": {
            "name": "three_class_soc_queue_extra_trees",
            "passed_all_development_gates": False,
        },
        "isolation_forest_audit": {
            "benign_like_false_positive_rate_estimate": 0.27,
            "threat_detection_rate_estimate": 0.08,
        },
        "locked_final_regression": {
            "supervised": {
                "result": {
                    "metrics": {
                        "queue_f1": 0.49,
                        "benign_like_false_positive_rate": 0.08,
                        "suspicious_recall": 0.38,
                        "malicious_recall": 0.41,
                    },
                    "calibration": {"status": "weak"},
                }
            }
        },
    }
    path = tmp_path / "v5_5_development_model_repair_latest.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(lifecycle, "DEFAULT_OUTPUT_DIR", tmp_path)

    summary = lifecycle._v55_repair_summary()

    assert summary["v55_available"] is True
    assert summary["v55_lifecycle_state"] == "shadow_observation"
    assert summary["v55_candidate_selected"] is False
    assert summary["v55_model_activated"] is False
    assert summary["v55_locked_queue_f1"] == 0.49
    assert summary["raw_logs_included"] is False
    assert summary["private_identifiers_included"] is False


def test_runner_stays_shadow_and_creates_no_side_effects(monkeypatch):
    dataset = _dataset()
    partition = _canonical_partition()
    development = repair.build_development_dataset(dataset, partition)
    counts = {
        "raw_logs": 160,
        "normalized_logs": 160,
        "alerts": 2,
        "ml_labels": 160,
        "ml_model_runs": 3,
        "detection_runs": 4,
        "response_actions": 0,
    }
    artifacts = {
        "supervised": {
            "exists": True,
            "artifact_name": "supervised.joblib",
            "size_bytes": 10,
            "sha256": "supervised",
            "path_returned": False,
        },
        "isolation_forest": {
            "exists": True,
            "artifact_name": "isolation.joblib",
            "size_bytes": 10,
            "sha256": "isolation",
            "path_returned": False,
        },
    }
    comparison = {
        "locked_labels_used_for_selection": False,
        "views": [
            {
                "fold": "development_source_holdout",
                "status": "failed_closed",
            }
        ],
        "strategy_summaries": {
            "calibrated_extra_trees": {
                "passing_temporal_folds": 0,
                "evaluated_temporal_folds": 3,
                "all_temporal_folds_passed": False,
                "metric_ranges": {
                    "queue_f1": {"min": 0.7, "max": 0.8},
                    "benign_like_false_positive_rate": {
                        "min": 0.1,
                        "max": 0.2,
                    },
                    "suspicious_recall": {"min": 0.7, "max": 0.8},
                    "malicious_recall": {"min": 0.7, "max": 0.8},
                    "review_queue_rate": {"min": 0.2, "max": 0.3},
                },
                "calibration_ranges": {
                    "expected_calibration_error": {
                        "min": 0.1,
                        "max": 0.2,
                    }
                },
            }
        },
    }
    leader = {
        "name": "calibrated_extra_trees",
        "passed_all_development_gates": False,
        "summary": comparison["strategy_summaries"]["calibrated_extra_trees"],
    }
    freeze = {
        "candidate": repair.CANDIDATE_SPECS[0],
        "freeze_fingerprint": "freeze",
        "frozen_before_locked_final": True,
        "eligible_for_activation": False,
    }
    monkeypatch.setattr(repair.v52, "_prepare_dataset", lambda *_args, **_kwargs: dataset)
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
    monkeypatch.setattr(repair.frozen, "_database_counts", lambda *_args: dict(counts))
    monkeypatch.setattr(repair, "_model_artifact_states", lambda: dict(artifacts))
    monkeypatch.setattr(
        repair.v54,
        "build_evidence_lock",
        lambda *_args, **_kwargs: {"ok": True, "roles": {}},
    )
    monkeypatch.setattr(
        repair.v54,
        "validate_evidence_lock",
        lambda *_args, **_kwargs: {
            "passed": True,
            "status": "locked_and_matched",
        },
    )
    monkeypatch.setattr(
        repair,
        "build_development_dataset",
        lambda *_args, **_kwargs: development,
    )
    monkeypatch.setattr(
        repair,
        "audit_isolation_forest_development",
        lambda *_args, **_kwargs: {
            "status": "evaluated",
            "benign_like_false_positive_rate_estimate": 0.2,
        },
    )
    monkeypatch.setattr(
        repair,
        "run_development_comparison",
        lambda *_args, **_kwargs: comparison,
    )
    monkeypatch.setattr(
        repair,
        "select_diagnostic_leader",
        lambda *_args, **_kwargs: leader,
    )
    monkeypatch.setattr(
        repair,
        "freeze_diagnostic_candidate",
        lambda *_args, **_kwargs: freeze,
    )
    monkeypatch.setattr(
        repair,
        "evaluate_locked_final_once",
        lambda *_args, **_kwargs: {
            "status": "evaluated",
            "result": {
                "metrics": {},
                "calibration": {},
                "development_gate": {"passed": False},
            },
        },
    )
    monkeypatch.setattr(
        repair,
        "audit_isolation_forest_locked_final",
        lambda *_args, **_kwargs: {"status": "evaluated"},
    )

    result = repair.run_v55_development_model_repair(
        SimpleNamespace(),
        write_output=False,
    )

    assert result["ok"] is True
    assert result["lifecycle_state"] == "shadow_observation"
    assert result["readiness"]["candidate_selected"] is False
    assert result["readiness"]["eligible_for_activation"] is False
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["response_automation_allowed"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["model_artifacts_unchanged"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["detection_runs_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["safety"]["ml_changed_authoritative_alerts"] is False
