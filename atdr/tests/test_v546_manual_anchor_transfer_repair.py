from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from atdr.app.detection import v546_manual_anchor_transfer_repair as repair
from atdr.app.detection.supervised_detector import _optional_imports


def _bundle(*, rows: int = 24, manual: int = 8) -> dict:
    imports = _optional_imports()
    assert imports is not None
    pd = imports[1]
    started = datetime(2026, 8, 1, tzinfo=UTC)
    labels = ["benign", "benign_unusual", "suspicious", "malicious"]
    metadata: list[dict] = []
    frames: list[dict] = []
    originals: list[str] = []
    weights: list[float] = []
    for index in range(rows):
        label = labels[index % len(labels)]
        benign = label in {"benign", "benign_unusual"}
        metadata.append(
            {
                "timestamp": started + timedelta(minutes=index),
                "app": "quic-base" if benign else "unknown-udp",
                "action": "allow" if benign else "deny",
                "dst_port": 443 if benign else 4040,
                "schema": "test",
                "provenance": "manual" if index < manual else "rule_assisted",
                "human_reviewed": index < manual,
                "group_size": 1,
                "evidence_role": "development_fit",
                "original_label": label,
                "private_source": index >= manual,
                "_duplicate_family": f"family-{index}",
                "pattern": "benign_quic_443" if benign else "scan_like_behavior",
                "log_type": "TRAFFIC",
            }
        )
        frame = {
            field: float(index + 1)
            for field in repair.v56.V56_NUMERIC_FEATURES
        }
        frame.update(
            {
                field: "test"
                for field in repair.v56.V56_CATEGORICAL_FEATURES
            }
        )
        frame.update(
            {
                "protocol": "udp" if benign else "tcp",
                "dst_port": 443 if benign else 4040,
                "hour_of_day": index % 24,
                "src_ip_5min_log_count": 10,
                "src_ip_5min_unique_dst_ports": 1 if benign else 8,
                "src_ip_5min_unique_dst_ips": 1 if benign else 7,
                "src_ip_5min_unknown_app_count": 0 if benign else 8,
                "src_ip_5min_high_risk_app_count": 0 if benign else 4,
                "src_ip_5min_deny_count": 0 if benign else 8,
                "v56_rule_evidence_score": 0 if benign else 80,
                "v56_threat_record_flag": 0 if benign else 1,
                "v56_scan_pressure": 0.1 if benign else 0.9,
                "v56_vendor_severity_score": 0 if benign else 4,
                "parser_confidence_score": 1,
                "bytes": 1000,
                "packets": 10,
                "v56_destination_repeat_count": 1,
            }
        )
        frames.append(frame)
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


def test_transfer_features_are_runtime_derivable_and_exclude_provenance() -> None:
    imports = _optional_imports()
    assert imports is not None
    bundle = repair.augment_bundle(imports, _bundle())

    assert bundle["frame"]["v546_quic_443_allow_flag"].iloc[0] == 1
    assert bundle["frame"]["v546_rule_support_flag"].iloc[2] == 1
    assert bundle["frame"]["v546_context_profile"].iloc[0] == "quic_web"
    assert "provenance" not in repair.V546_NUMERIC_FEATURES
    assert "provenance" not in repair.V546_CATEGORICAL_FEATURES
    assert "source_id" not in repair.V546_CATEGORICAL_FEATURES


def test_transfer_weighting_keeps_assisted_evidence_below_manual_anchors() -> None:
    bundle = _bundle(rows=80, manual=8)

    _, summary = repair._transfer_weights(
        bundle,
        bundle["targets"],
        assisted_cap=0.50,
        manual_multiplier=1.5,
    )

    assert summary["assisted_to_manual_weight_ratio"] <= 0.50
    assert summary["assisted_labels_dominate_manual_anchors"] is False
    assert summary["labels_rewritten"] is False


def test_fit_rebalancing_is_deterministic_and_never_rewrites_labels() -> None:
    imports = _optional_imports()
    assert imports is not None
    bundle = _bundle(rows=80, manual=8)

    first, first_summary = repair._rebalance_fit_bundle(
        imports,
        bundle,
        target_mode="flat_5class",
        assisted_to_manual_ratio=2.0,
    )
    second, second_summary = repair._rebalance_fit_bundle(
        imports,
        bundle,
        target_mode="flat_5class",
        assisted_to_manual_ratio=2.0,
    )

    assert first["original_labels"] == second["original_labels"]
    assert first_summary == second_summary
    assert first_summary["labels_rewritten"] is False
    assert first_summary["output_rows"] <= first_summary["input_rows"]


def test_threshold_selection_uses_only_supplied_threshold_partition() -> None:
    bundle = _bundle(rows=24, manual=8)
    scores = [0.05 if target == "benign_like" else 0.95 for target in bundle["targets"]]

    result = repair._select_global_threshold(bundle, scores)

    assert result["selected_on"] == "threshold_partition_only"
    assert result["used_evaluation_labels"] is False
    assert result["future_labels_used"] is False
    assert 0 < result["selected_threshold"] < 1


def test_v546_keeps_v545_fixed_freeze_gates_unchanged() -> None:
    assert repair.FIXED_FREEZE_GATES == repair.v545.FIXED_FREEZE_GATES


def test_recipe_freeze_never_writes_a_model_artifact(tmp_path: Path) -> None:
    leader = {
        "name": "manual_anchor_candidate",
        "selection_basis": "development_only_fixed_gates",
        "candidate_freeze_eligible": True,
        "summary": {"all_views_passed": True},
        "_latest_fitted": {
            "model_type": "extra_trees",
            "target_mode": "flat_5class",
            "feature_set": "v546_transfer",
            "applied_calibration_method": "sigmoid_manual_preferred",
            "threshold_selection": {
                "selection_partition": "threshold_only",
                "evaluation_labels_used": False,
            },
        },
    }

    result = repair._freeze_recipe(
        leader,
        output_dir=tmp_path,
        write_output=True,
    )
    manifest = json.loads(
        (tmp_path / repair.V546_FREEZE_MANIFEST).read_text(encoding="utf-8")
    )

    assert result["candidate_frozen"] is True
    assert result["active_artifact_written"] is False
    assert manifest["eligible_for_activation"] is False
    assert manifest["model_artifact_written"] is False
    assert not list(tmp_path.glob("*.joblib"))


def test_full_runner_preserves_labels_models_alerts_and_responses(
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
    bundle = _bundle(rows=24, manual=8)
    custody = {
        "prior": {
            "custody": {
                "state": {"development": {}, "canonical": {}},
            }
        },
        "v545_lock": {"latest": {}},
        "all_checks_passed": True,
    }
    monkeypatch.setattr(repair, "revalidate_v546_custody", lambda *_a, **_k: custody)
    monkeypatch.setattr(repair, "_public_custody", lambda *_a, **_k: {"passed": True})
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
    monkeypatch.setattr(repair.v545, "_contain_candidate_near_families", lambda *_a: {"passed": True})
    monkeypatch.setattr(
        repair.v545,
        "_human_role_bundles",
        lambda *_a, **_k: {
            "development_fit": bundle,
            "calibration": bundle,
            "threshold": bundle,
        },
    )
    monkeypatch.setattr(
        repair.v545,
        "_load_private_role_bundle",
        lambda *_a, **_k: (bundle, {"selected_representative_rows": 24}),
    )
    monkeypatch.setattr(
        repair,
        "diagnose_manual_anchor_transfer",
        lambda *_a, **_k: {"status": "evaluated", "future_labels_opened": False},
    )
    view = {
        "name": "manual_anchor_holdout",
        "evaluation_cohort": "manual",
        "fit": bundle,
        "calibration": bundle,
        "threshold": bundle,
        "evaluation": bundle,
        "leakage_audit": {"passed": True},
    }
    monkeypatch.setattr(
        repair.v545,
        "build_development_views",
        lambda *_a, **_k: (
            [view, {**view, "name": "two"}, {**view, "name": "three"}],
            {"status": "ready", "valid_views": 3},
        ),
    )
    monkeypatch.setattr(
        repair,
        "run_transfer_model_comparison",
        lambda *_a, **_k: ({"status": "evaluated", "views": []}, None),
    )
    monkeypatch.setattr(repair, "_v545_baseline", lambda *_a: {"available": True})
    monkeypatch.setattr(repair, "_before_after_transfer", lambda *_a: {"improved": False})
    monkeypatch.setattr(repair, "_aggregate_residuals", lambda *_a: {"status": "empty"})
    monkeypatch.setattr(repair, "_isolation_audit", lambda *_a, **_k: {"reliability_passed": False})
    monkeypatch.setattr(
        repair,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///:memory:"),
    )

    result = repair.run_v546_manual_anchor_transfer_repair(
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
    assert result["safety"]["alerts_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["future_labels_opened"] is False
    assert result["active_model_artifact_written"] is False
    assert result["model_activated"] is False
    assert result["rules_alert_authoritative"] is True
    assert str(sample) not in serialized


def test_public_status_never_exposes_private_contract_values(tmp_path: Path) -> None:
    latest = {
        "status": "manual_anchor_transfer_incomplete",
        "generated_at": "2026-08-21T00:00:00+00:00",
        "diagnostic_leader": {
            "name": "candidate",
            "summary": {
                "passing_views": 1,
                "required_views": 3,
                "assisted_label_sensitivity": {
                    "queue_f1_absolute_gap": 0.2,
                },
            },
        },
        "model_comparison": {
            "views": [
                {
                    "name": "manual_anchor_holdout",
                    "strategies": [
                        {
                            "name": "candidate",
                            "status": "evaluated",
                            "metrics": {
                                "queue_f1": 0.75,
                                "benign_like_false_positive_rate": 0.12,
                                "suspicious_recall": 0.7,
                                "malicious_recall": 0.82,
                            },
                            "calibration": {"status": "weak"},
                        }
                    ],
                }
            ]
        },
        "before_after_transfer": {"manual_anchor_transfer_improved": True},
        "candidate_freeze": {
            "candidate_freeze_ready": False,
            "candidate_frozen": False,
        },
        "isolation_forest_audit": {"reliability_passed": False},
        "readiness": {"supervised_phases_remaining": 5, "blockers": ["gate"]},
        "private_path": "must-not-leak",
        "fingerprint": "must-not-leak",
    }
    (tmp_path / repair.V546_LATEST).write_text(
        json.dumps(latest),
        encoding="utf-8",
    )

    result = repair.get_public_v546_status(tmp_path)
    serialized = json.dumps(result)

    assert result["manual_anchor_transfer_status"] == "improved"
    assert result["manual_anchor_queue_f1"] == 0.75
    assert result["manual_anchor_fpr"] == 0.12
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["future_labels_opened"] is False
    assert result["private_paths_returned"] is False
    assert result["fingerprints_returned"] is False
    assert "must-not-leak" not in serialized
