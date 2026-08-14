from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pandas as pd
import pytest

from atdr.app.detection import supervised_detector
from atdr.app.detection import v540_development_supervised_repair as repair
from atdr.app.services import evidence_review_service as review_service


def _dataset(rows: int = 200) -> dict:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    evidence_rows = []
    labels = []
    logs = []
    frame_rows = []
    targets = []
    original_labels = []
    for index in range(rows):
        positive = index % 4 in {0, 1}
        original = (
            "suspicious"
            if index % 8 == 0
            else "malicious"
            if index % 8 == 1
            else "benign"
        )
        target = "needs_review" if positive else "non_threat"
        app = "quic-base" if index % 5 == 0 else "unknown-udp" if index % 7 == 0 else "ssl"
        protocol = "udp" if app in {"quic-base", "unknown-udp"} else "tcp"
        label_source = "manual" if index % 3 else "assisted_rule"
        evidence_rows.append(
            {
                "index": index,
                "label_id": index + 1000,
                "log_id": index + 1,
                "original_label": original,
                "safe_queue_target": target,
                "reviewed": True,
                "label_source": label_source,
                "source_name": "source-a" if index % 2 else "source-b",
                "network_zone_group": "zone:inside->outside",
                "timestamp": started + timedelta(minutes=index),
                "app": app,
                "action": "allow",
                "dst_port": 443,
                "exact_fingerprint": f"{index:064x}",
                "near_fingerprint": f"near-{index}",
                "feature_fingerprint": f"feature-{index}",
                "leakage_group": f"group-{index}",
            }
        )
        labels.append(SimpleNamespace(label_source=label_source))
        logs.append(
            SimpleNamespace(
                id=index + 1,
                generated_time=started + timedelta(minutes=index),
                receive_time=None,
                start_time=None,
                log_type="TRAFFIC",
                subtype="end",
                app=app,
                action="allow",
                protocol=protocol,
                src_port=50000 + index,
                dst_port=443,
                src_zone="inside",
                dst_zone="outside",
                app_risk=1,
                bytes=1000 + index,
                packets=10 + index % 5,
                src_ip=f"source-{index}",
            )
        )
        frame_rows.append(
            {
                "bytes": 1000 + index,
                "packets": 10 + index % 5,
                "app": app,
                "action": "allow",
                "v398_local_rule_score": 0.0 if index % 4 else 40.0,
                "src_ip_5min_unique_dst_ports": index % 9,
                "src_ip_15min_unique_dst_ports": index % 11,
                "src_ip_5min_unique_dst_ips": index % 7,
                "src_ip_15min_unique_dst_ips": index % 10,
                "scanning_like_behavior_score": (index % 5) * 20,
                "v337_anomaly_signal_flag": int(index % 13 == 0),
                "src_ip_5min_high_risk_app_count": 0,
                "required_field_missing_count": 0,
                "parser_warning_count": 0,
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
            "numeric_features": [
                "bytes",
                "packets",
                "v398_local_rule_score",
                "src_ip_5min_unique_dst_ports",
                "src_ip_15min_unique_dst_ports",
                "src_ip_5min_unique_dst_ips",
                "src_ip_15min_unique_dst_ips",
                "scanning_like_behavior_score",
                "v337_anomaly_signal_flag",
                "src_ip_5min_high_risk_app_count",
                "required_field_missing_count",
                "parser_warning_count",
            ],
            "categorical_features": ["app", "action"],
        },
        "label_provenance": {},
    }


def _write_v539_contract(tmp_path):
    pack_path = tmp_path / "sealed.csv"
    columns = [
        "review_token",
        "evidence_role",
        "evidence_role_is_blind",
        "blind_suggestion_suppressed",
        "raw_log_included",
        "source_ip_included",
        "destination_ip_included",
        "human_decision",
        "human_reviewer",
        "human_reviewed_at",
        "human_reviewed",
        "human_must_confirm",
        "import_ready",
    ]
    with pack_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for index in range(repair.EXPECTED_DETECTION_ROWS):
            writer.writerow(
                {
                    "review_token": f"protected-{index:03d}",
                    "evidence_role": "untouched_future_validation",
                    "evidence_role_is_blind": "true",
                    "blind_suggestion_suppressed": "true",
                    "raw_log_included": "false",
                    "source_ip_included": "false",
                    "destination_ip_included": "false",
                    "human_decision": "",
                    "human_reviewer": "",
                    "human_reviewed_at": "",
                    "human_reviewed": "false",
                    "human_must_confirm": "true",
                    "import_ready": "false",
                }
            )
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "schema_version": repair.V539_VERSION,
                "evaluation": {"status": "completed", "attempt_count": 1},
                "review_contract": {
                    "both_reviews_closed": True,
                    "owner_contracts_valid": True,
                    "detection_rows": repair.EXPECTED_DETECTION_ROWS,
                },
                "private_contract": {
                    "detection_pack_digest": review_service._detection_pack_digest(
                        pack_path
                    )
                },
            }
        ),
        encoding="utf-8",
    )
    return state_path, pack_path


def test_v539_boundary_is_integrity_checked_and_public_projection_is_safe(tmp_path):
    state_path, pack_path = _write_v539_contract(tmp_path)

    boundary = repair.load_v539_consumed_boundary(
        state_path=state_path,
        pack_path=pack_path,
    )
    public = repair._public_boundary(boundary)

    assert boundary["status"] == "consumed_boundary_locked"
    assert len(boundary["_protected_tokens"]) == repair.EXPECTED_DETECTION_ROWS
    assert public["tokens_returned"] is False
    assert public["digests_returned"] is False
    assert "_protected_tokens" not in public
    assert "detection_pack_digest" not in json.dumps(public)


def test_v539_boundary_fails_closed_when_pack_changes(tmp_path):
    state_path, pack_path = _write_v539_contract(tmp_path)
    content = pack_path.read_text(encoding="utf-8")
    pack_path.write_text(
        content.replace("protected-000", "protected-changed", 1),
        encoding="utf-8",
    )

    with pytest.raises(repair.V540EvidenceBoundaryError):
        repair.load_v539_consumed_boundary(
            state_path=state_path,
            pack_path=pack_path,
        )


def test_consumed_rows_are_excluded_before_modeling(monkeypatch):
    dataset = _dataset(20)
    protected = frozenset({"protected-a", "protected-b"})
    tokens = ["eligible"] * 20
    tokens[3] = "protected-a"
    tokens[11] = "protected-b"
    lookup = {id(log): tokens[index] for index, log in enumerate(dataset["logs"])}
    monkeypatch.setattr(
        repair,
        "_v539_review_token_for_log",
        lambda log: lookup[id(log)],
    )

    filtered, audit = repair.exclude_v539_consumed_evidence(
        dataset,
        {"status": "consumed_boundary_locked", "_protected_tokens": protected},
    )

    assert len(filtered["rows"]) == 18
    assert audit["matched_and_excluded_rows"] == 2
    assert audit["protected_rows_used_for_fit"] == 0
    assert audit["protected_labels_read"] is False
    assert {row["source_dataset_index"] for row in filtered["rows"]}.isdisjoint(
        {3, 11}
    )


def test_feature_repair_distinguishes_routine_quic_from_scan_context():
    dataset = _dataset(12)
    dataset["frame"].loc[0, "v398_local_rule_score"] = 0
    dataset["frame"].loc[0, "src_ip_15min_unique_dst_ports"] = 1
    dataset["frame"].loc[0, "src_ip_15min_unique_dst_ips"] = 1
    dataset["frame"].loc[0, "scanning_like_behavior_score"] = 0
    dataset["frame"].loc[5, "v398_local_rule_score"] = 50
    dataset["frame"].loc[5, "src_ip_15min_unique_dst_ports"] = 12
    dataset["frame"].loc[5, "src_ip_15min_unique_dst_ips"] = 10

    enriched, audit = repair.augment_v540_features(dataset)

    assert enriched["frame"].loc[0, "v540_quic_443_allow_flag"] == 1
    assert enriched["frame"].loc[0, "v540_routine_encrypted_allow_flag"] == 1
    assert enriched["frame"].loc[5, "v540_scan_context_flag"] == 1
    assert enriched["frame"].loc[5, "v540_routine_encrypted_allow_flag"] == 0
    assert audit["post_prediction_guard_used"] is False
    assert repair.V540_CATEGORICAL_FEATURE in enriched["feature_meta"][
        "categorical_features"
    ]


def test_fixed_threshold_profiles_do_not_use_evaluation_or_v539_labels():
    selected = repair.select_fixed_threshold_profile(
        ["non_threat", "non_threat", "needs_review", "needs_review"],
        [0.1, 0.3, 0.8, 0.95],
    )

    assert selected["selected_profile"] in {
        item["name"] for item in repair.FIXED_THRESHOLD_PROFILES
    }
    assert selected["fixed_profiles_only"] is True
    assert selected["used_v539_labels"] is False
    assert selected["used_nested_evaluation_labels"] is False


def test_calibrated_strategy_emits_metrics_without_artifact_write():
    dataset, _ = repair.augment_v540_features(_dataset(200))
    partition = {
        "fit_idx": list(range(0, 100)),
        "calibration_idx": list(range(100, 130)),
        "threshold_idx": list(range(130, 160)),
        "final_test_idx": list(range(160, 200)),
    }

    result = repair._fit_strategy(dataset, partition, repair.STRATEGY_SPECS[0])

    assert result["status"] == "evaluated"
    assert result["applied_calibration_method"].startswith("sigmoid_")
    assert "expected_calibration_error" in result["calibration"]
    assert result["threshold_selection"]["fixed_profiles_only"] is True
    assert result["protected_v539_rows_used"] == 0
    assert result["active_artifact_written"] is False


def test_nested_temporal_folds_keep_rebuilt_duplicate_groups_isolated():
    dataset, _ = repair.augment_v540_features(_dataset(200))
    dataset["rows"][10]["exact_fingerprint"] = dataset["rows"][11][
        "exact_fingerprint"
    ]
    repair.frozen.assign_leakage_groups(dataset["rows"])

    folds = repair.v55.build_nested_temporal_folds(dataset)

    assert len(folds) == 3
    assert all(fold["status"] == "partitioned" for fold in folds)
    for fold in folds:
        partition = fold["partition"]
        roles = [
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
            for position, left in enumerate(roles)
            for right in roles[position + 1 :]
        )


def test_development_error_summary_exposes_patterns_not_rows_or_sources():
    comparison = {
        "views": [
            {
                "strategies": [
                    {
                        "name": "candidate",
                        "status": "evaluated",
                        "error_patterns": {
                            "false_positives": {
                                "rows": 2,
                                "top_families": [["routine_encrypted_allow", 2]],
                                "top_apps": [["quic-base", 2]],
                            },
                            "false_negatives": {
                                "rows": 1,
                                "top_families": [["scan_like_behavior", 1]],
                                "top_apps": [["unknown-udp", 1]],
                            },
                        },
                    }
                ]
            }
        ]
    }

    result = repair.summarize_development_errors(
        comparison,
        {"name": "candidate"},
    )

    assert result["false_positive_observations_across_folds"] == 2
    assert result["false_negative_observations_across_folds"] == 1
    assert result["source_names_returned"] is False
    assert result["row_identifiers_returned"] is False


def test_candidate_metadata_freezes_only_after_all_development_gates_pass():
    dataset, _ = repair.augment_v540_features(_dataset(40))
    failed = {
        "name": repair.STRATEGY_SPECS[0]["name"],
        "passed_all_development_gates": False,
        "summary": {},
    }
    passed = {**failed, "passed_all_development_gates": True}

    assert repair.freeze_diagnostic_candidate_metadata(failed, dataset) is None
    frozen = repair.freeze_diagnostic_candidate_metadata(passed, dataset)

    assert frozen is not None
    assert frozen["model_artifact_written"] is False
    assert frozen["active_artifact_written"] is False
    assert frozen["v539_evaluated"] is False
    assert frozen["eligible_for_activation"] is False


def test_new_blind_design_contains_no_predictions_or_automatic_labels():
    dataset, _ = repair.augment_v540_features(_dataset(40))

    design = repair.design_new_blind_evidence_protocol(dataset)

    assert design["status"] == "designed_not_collected"
    assert design["predictions_in_pack"] is False
    assert design["automatic_labels_in_pack"] is False
    assert design["human_labels_created"] == 0
    assert design["import_ready"] is False
    assert design["v539_rows_reused"] is False


def test_runner_preserves_database_artifacts_v539_and_response_state(
    monkeypatch,
    tmp_path,
):
    dataset = _dataset(200)
    development, feature_audit = repair.augment_v540_features(dataset)
    state_path = tmp_path / "state.json"
    pack_path = tmp_path / "pack.csv"
    state_path.write_text("state", encoding="utf-8")
    pack_path.write_text("pack", encoding="utf-8")
    counts = {
        "raw_logs": 200,
        "normalized_logs": 200,
        "alerts": 3,
        "ml_labels": 200,
        "ml_model_runs": 4,
        "detection_runs": 5,
        "response_actions": 0,
    }
    artifacts = {"supervised": {"exists": False}, "isolation_forest": {"exists": False}}
    boundary = {
        "status": "consumed_boundary_locked",
        "schema_version": repair.V539_VERSION,
        "evaluation_status": "completed",
        "evaluation_attempt_count": 1,
        "protected_detection_rows": 40,
        "protected_token_count": 40,
        "pack_integrity_matched": True,
        "both_reviews_closed": True,
        "owner_contracts_valid": True,
        "_protected_tokens": frozenset({"protected"}),
    }
    monkeypatch.setattr(repair, "load_v539_consumed_boundary", lambda **_kwargs: boundary)
    monkeypatch.setattr(repair.v52, "_prepare_dataset", lambda *_args, **_kwargs: dataset)
    monkeypatch.setattr(
        repair,
        "exclude_v539_consumed_evidence",
        lambda *_args, **_kwargs: (
            dataset,
            {
                "configured_reviewed_rows": 200,
                "protected_token_count": 40,
                "matched_and_excluded_rows": 0,
                "eligible_after_v539_exclusion": 200,
                "protected_rows_used_for_fit": 0,
                "protected_rows_used_for_calibration": 0,
                "protected_rows_used_for_threshold_selection": 0,
                "protected_rows_used_for_model_selection": 0,
                "protected_labels_read": False,
                "protected_predictions_read": False,
                "protected_errors_read": False,
                "protected_identities_returned": False,
            },
        ),
    )
    monkeypatch.setattr(
        repair.frozen,
        "build_frozen_partition",
        lambda *_args, **_kwargs: {
            "fit_idx": list(range(0, 100)),
            "calibration_idx": list(range(100, 130)),
            "threshold_idx": list(range(130, 160)),
            "final_test_idx": list(range(160, 190)),
            "quarantined_idx": list(range(190, 200)),
        },
    )
    monkeypatch.setattr(
        repair.frozen,
        "audit_partition_leakage",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        repair.v55,
        "build_development_dataset",
        lambda *_args, **_kwargs: development,
    )
    monkeypatch.setattr(
        repair,
        "augment_v540_features",
        lambda *_args, **_kwargs: (development, feature_audit),
    )
    monkeypatch.setattr(
        repair,
        "run_development_comparison",
        lambda *_args, **_kwargs: {"strategy_summaries": {}},
    )
    monkeypatch.setattr(repair, "select_best_diagnostic_strategy", lambda *_args: None)
    monkeypatch.setattr(repair.frozen, "_database_counts", lambda *_args: dict(counts))
    monkeypatch.setattr(repair.v55, "_model_artifact_states", lambda: dict(artifacts))

    result = repair.run_v540_development_supervised_repair(
        SimpleNamespace(),
        write_output=False,
        state_path=state_path,
        pack_path=pack_path,
    )

    assert result["ok"] is True
    assert result["lifecycle_state"] == "shadow_observation"
    assert result["v539_evaluated"] is False
    assert result["safety"]["v539_evaluator_called"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["model_artifacts_unchanged"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["detection_runs_created"] == 0
    assert result["safety"]["alerts_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["response_automation_allowed"] is False
