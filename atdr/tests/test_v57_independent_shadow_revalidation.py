from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from atdr.app.detection import supervised_detector
from atdr.app.detection import v51_supervised_lifecycle as lifecycle
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v57_independent_shadow_revalidation as v57


class _PredictablePipeline:
    method = "sigmoid"
    classes_ = ["needs_review", "non_threat"]
    feature_names_in_ = ["dst_port", "app"]
    estimator = SimpleNamespace(
        steps=[
            ("preprocess", SimpleNamespace()),
            ("model", SimpleNamespace()),
        ]
    )

    def predict_proba(self, frame):
        return [[0.8, 0.2] for _ in range(len(frame))]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _valid_manifest(sample_sha256: str = "new-sha") -> dict:
    return {
        "manifest_version": v57.V57_MANIFEST_VERSION,
        "evidence_id": "independent-lab-evidence",
        "status": "ready_for_predictions",
        "schema_family": "native_panos_syslog",
        "collection_provenance": "advisor-controlled two-device collection",
        "license_or_owner_permission": "owner approved",
        "files": {"sample_sha256": sample_sha256},
        "independence": {
            "real_device_count": 2,
            "independent_time_window_count": 2,
            "prior_evidence_overlap_rows": 0,
            "cross_role_duplicate_groups": 0,
            "overlap_audit_completed": True,
            "overlap_audit_method": (
                "fingerprint_comparison_against_v53_v56"
            ),
        },
        "labels": {
            "status": "sealed",
            "available_to_prediction_runner": False,
        },
        "prediction_before_label_protocol": True,
        "advisor_signoff": {
            "protocol_acknowledged": True,
            "approved": False,
        },
    }


def _qualified_profile() -> dict:
    return {
        "configured_database_overlap_rows": 0,
        "parser_successes": 200,
        "chronological_profile_ok": True,
        "observed_distinct_time_windows": 12,
    }


def test_evidence_lock_audit_verifies_roles_and_artifact(tmp_path):
    v53_lock = tmp_path / "v53-lock.json"
    v53_lock.write_text(
        json.dumps(
            {
                "roles": {
                    "fit": {"rows": 10},
                    "calibration": {"rows": 2},
                    "threshold": {"rows": 2},
                    "temporal_final": {"rows": 4},
                },
                "external_evidence": {"passed_v49_gates": False},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "v5_4_development_evidence_manifest_latest.json").write_text(
        '{"version":"v5.4"}',
        encoding="utf-8",
    )
    (tmp_path / "v5_5_development_model_repair_latest.json").write_text(
        '{"version":"v5.5"}',
        encoding="utf-8",
    )
    artifact = tmp_path / "candidate.joblib"
    artifact.write_bytes(b"frozen-candidate")
    protocol = {
        "roles": {
            "development_fit": {
                "rows": 100,
                "representative_families": 90,
                "time_windows": 5,
                "aggregate_fingerprint": "fit",
            },
            "calibration": {
                "rows": 20,
                "representative_families": 18,
                "time_windows": 1,
                "aggregate_fingerprint": "calibration",
            },
            "threshold": {
                "rows": 20,
                "representative_families": 19,
                "time_windows": 1,
                "aggregate_fingerprint": "threshold",
            },
            "untouched_future_validation": {
                "rows": 30,
                "representative_families": 27,
                "time_windows": 2,
                "aggregate_fingerprint": "future",
            },
        },
        "duplicate_families_contained": True,
    }
    report = {
        "chronological_protocol": protocol,
        "diagnostic_candidate_artifact": {
            "artifact_name": artifact.name,
            "sha256": _sha256(artifact),
        },
        "frozen_diagnostic_candidate": {
            "frozen_before_future_label_access": True
        },
        "untouched_future_validation": {
            "used_for_candidate_selection": False
        },
    }
    (tmp_path / v56.V56_LATEST).write_text(
        json.dumps(report),
        encoding="utf-8",
    )
    (tmp_path / "v5_6_private_evidence_manifest_latest.json").write_text(
        json.dumps({"chronological_protocol": protocol}),
        encoding="utf-8",
    )

    result = v57.audit_evidence_locks(
        output_dir=tmp_path,
        current_lock_validation={"passed": True},
        v53_lock_path=v53_lock,
    )

    assert result["passed"] is True
    assert result["reusable_for_fresh_independent_validation"] is False
    assert result["fingerprints_exposed"] is False
    v57._write_evidence_lock_audit(tmp_path, result)
    recorded = json.loads(
        (tmp_path / v57.V57_EVIDENCE_LOCK_AUDIT).read_text(
            encoding="utf-8"
        )
    )
    assert recorded["passed"] is True
    assert recorded["fingerprints"]["v53_roles"]["fit"] is None
    assert recorded["private_paths_included"] is False
    assert recorded["raw_logs_included"] is False


def test_frozen_candidate_is_immutable_and_never_active(tmp_path):
    imports = supervised_detector._optional_imports()
    artifact_path = tmp_path / "candidate.joblib"
    imports[0].dump(
        {
            "pipeline": _PredictablePipeline(),
            "candidate_name": "calibrated_candidate",
            "version": "v5.6",
            "threshold": 0.5,
            "label_policy": "assisted-not-human",
            "active": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
        artifact_path,
    )
    before = _sha256(artifact_path)
    lock_audit = {
        "passed": True,
        "_artifact_path": artifact_path,
        "_v56_report": {
            "frozen_diagnostic_candidate": {
                "freeze_fingerprint": "candidate-freeze"
            },
            "chronological_protocol": {
                "roles": {
                    "development_fit": {
                        "rows": 10,
                        "aggregate_fingerprint": "fit",
                    }
                }
            },
        },
    }

    result = v57.freeze_v56_candidate(
        imports,
        output_dir=tmp_path,
        lock_audit=lock_audit,
        development_sample_sha256="development-only",
        write_output=True,
    )

    assert result["ok"] is True
    assert result["artifact_unchanged"] is True
    assert result["active"] is False
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
    assert result["post_prediction_guard_used"] is False
    assert (
        result["actual_threats_suppressed_by_post_prediction_guard"] == 0
    )
    assert _sha256(artifact_path) == before


def test_reused_v56_evidence_fails_independence_qualification():
    manifest = _valid_manifest(sample_sha256="same")

    result = v57.qualify_independent_evidence(
        manifest,
        profile=_qualified_profile(),
        sample_sha256="same",
        development_sample_sha256="same",
        matches_v56_role_signature=True,
    )

    assert result["eligible_for_predictions"] is False
    assert result["status"] == "independent_evidence_required"
    assert result["checks"]["not_same_v56_file"] is False
    assert result["checks"]["not_same_v56_role_signature"] is False


def test_valid_two_device_manifest_can_freeze_predictions():
    manifest = _valid_manifest()

    result = v57.qualify_independent_evidence(
        manifest,
        profile=_qualified_profile(),
        sample_sha256="new-sha",
        development_sample_sha256="old-sha",
        matches_v56_role_signature=False,
    )

    assert result["eligible_for_predictions"] is True
    assert result["eligible_for_label_reveal"] is False


def test_tiny_or_chronologically_invalid_evidence_fails_closed():
    result = v57.qualify_independent_evidence(
        _valid_manifest(),
        profile={
            "configured_database_overlap_rows": 0,
            "parser_successes": 20,
            "chronological_profile_ok": False,
            "observed_distinct_time_windows": 1,
        },
        sample_sha256="new-sha",
        development_sample_sha256="old-sha",
        matches_v56_role_signature=False,
    )

    assert result["eligible_for_predictions"] is False
    assert result["checks"]["minimum_parsed_rows_observed"] is False
    assert result["checks"]["chronological_profile_observed"] is False
    assert result["checks"]["minimum_observed_time_windows"] is False


def test_label_reveal_manifest_state_can_pass_independence_qualification():
    manifest = _valid_manifest()
    manifest["status"] = "ready_for_label_reveal"
    manifest["labels"]["status"] = "complete_and_sealed"

    result = v57.qualify_independent_evidence(
        manifest,
        profile=_qualified_profile(),
        sample_sha256="new-sha",
        development_sample_sha256="old-sha",
        matches_v56_role_signature=False,
        label_reveal_mode=True,
    )

    assert result["eligible_for_predictions"] is True
    assert result["checks"]["manifest_workflow_status_valid"] is True
    assert result["checks"]["label_workflow_state_valid"] is True


def test_label_reveal_fails_without_prediction_freeze(tmp_path):
    manifest = _valid_manifest()
    manifest["labels"] = {
        "status": "complete_and_sealed",
        "provenance": "human_reviewed",
        "ground_truth_confirmed": True,
    }
    manifest["advisor_signoff"]["approved"] = True

    result = v57._qualify_label_reveal(
        manifest,
        freeze={},
        predictions_path=None,
        label_path=None,
        sample_sha256="sample",
        candidate_sha256="candidate",
    )

    assert result["passed"] is False
    assert result["checks"]["prediction_freeze_present"] is False
    assert result["status"] == "failed_closed_label_reveal_not_authorized"


def test_prediction_freeze_hides_predictions_from_review_pack(tmp_path):
    imports = supervised_detector._optional_imports()
    manifest_path = tmp_path / "evidence.json"
    manifest = _valid_manifest(sample_sha256="sample")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    bundle = {
        "frame": pd.DataFrame(
            [{"dst_port": 443, "app": "ssl"}],
        ),
        "rows": [
            {
                "row_id": 1,
                "source_group": "source-a",
                "time_window_group": "window-a",
                "log_type": "TRAFFIC",
                "subtype": "end",
                "app": "ssl",
                "action": "allow",
                "protocol": "tcp",
                "src_port": 50000,
                "dst_port": 443,
                "direction": "internal_to_external",
                "schema_bucket": "traffic_complete",
                "rule_codes": [],
                "rule_evidence_score": 0,
                "source_event_count": 1,
                "source_unique_destinations": 1,
                "source_unique_ports": 1,
                "source_deny_count": 0,
                "group_size": 1,
            }
        ],
    }
    candidate = {
        "_pipeline": _PredictablePipeline(),
        "_artifact": {"threshold": 0.5},
        "_manifest": {"artifact_sha256": "candidate"},
        "candidate_name": "calibrated_candidate",
    }

    result = v57._write_prediction_freeze(
        imports,
        output_dir=tmp_path,
        evidence_manifest=manifest,
        evidence_manifest_path=manifest_path,
        sample_sha256="sample",
        candidate=candidate,
        bundle=bundle,
    )
    freeze_before = _sha256(tmp_path / v57.V57_PREDICTION_FREEZE)
    second = v57._write_prediction_freeze(
        imports,
        output_dir=tmp_path,
        evidence_manifest=manifest,
        evidence_manifest_path=manifest_path,
        sample_sha256="sample",
        candidate=candidate,
        bundle=bundle,
    )

    freeze = json.loads(
        (tmp_path / v57.V57_PREDICTION_FREEZE).read_text(encoding="utf-8")
    )
    review = (tmp_path / freeze["review_pack_file_name"]).read_text(
        encoding="utf-8"
    )
    assert result["predictions_frozen_before_labels"] is True
    assert result["labels_revealed"] is False
    assert "prediction" not in review.splitlines()[0]
    assert "human_confirmed" in review.splitlines()[0]
    assert second["status"] == "predictions_already_frozen"
    assert _sha256(tmp_path / v57.V57_PREDICTION_FREEZE) == freeze_before


def test_assisted_label_cannot_be_loaded_as_ground_truth(tmp_path):
    label_path = tmp_path / "labels.csv"
    with label_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "review_token",
                "human_decision",
                "label_provenance",
                "human_confirmed",
                "reviewer_id",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "review_token": "token",
                "human_decision": "malicious",
                "label_provenance": "codex_assisted",
                "human_confirmed": "true",
                "reviewer_id": "reviewer",
            }
        )

    labels, result = v57._load_confirmed_labels(
        label_path,
        expected_tokens={"token"},
    )

    assert labels == {}
    assert result["complete"] is False
    assert result["invalid_rows"]["invalid_provenance"] == 1
    assert result["ai_generated_labels_marked_human_reviewed"] is False


def test_blind_label_reveal_is_one_shot_and_reports_fixed_metrics(
    monkeypatch,
    tmp_path,
):
    predictions = [
        {
            "review_token": "threat-token",
            "prediction": "needs_review",
            "threat_score": 0.9,
            "source_group": "source-a",
            "time_window_group": "window-a",
            "app": "unknown",
            "action": "deny",
            "dst_port": 22,
            "schema_bucket": "traffic_complete",
            "log_type": "TRAFFIC",
        },
        {
            "review_token": "benign-token",
            "prediction": "non_threat",
            "threat_score": 0.1,
            "source_group": "source-b",
            "time_window_group": "window-b",
            "app": "ssl",
            "action": "allow",
            "dst_port": 443,
            "schema_bucket": "traffic_complete",
            "log_type": "TRAFFIC",
        },
    ]
    prediction_path = tmp_path / "predictions.jsonl"
    prediction_path.write_text(
        "".join(
            f"{json.dumps(row, sort_keys=True)}\n" for row in predictions
        ),
        encoding="utf-8",
    )
    label_path = tmp_path / "labels.csv"
    with label_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "review_token",
                "human_decision",
                "attack_type",
                "label_provenance",
                "human_confirmed",
                "reviewer_id",
            ],
        )
        writer.writeheader()
        writer.writerows(
            [
                {
                    "review_token": "threat-token",
                    "human_decision": "malicious",
                    "attack_type": "scan",
                    "label_provenance": "human_reviewed",
                    "human_confirmed": "true",
                    "reviewer_id": "reviewer-a",
                },
                {
                    "review_token": "benign-token",
                    "human_decision": "benign",
                    "attack_type": "none",
                    "label_provenance": "human_reviewed",
                    "human_confirmed": "true",
                    "reviewer_id": "reviewer-a",
                },
            ]
        )
    manifest_path = tmp_path / "manifest.json"
    manifest = _valid_manifest(sample_sha256="sample")
    manifest["labels"] = {
        "status": "complete_and_sealed",
        "available_to_prediction_runner": False,
        "file": label_path.name,
        "provenance": "human_reviewed",
        "ground_truth_confirmed": True,
    }
    manifest["advisor_signoff"]["approved"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    freeze = {
        "evidence_id": manifest["evidence_id"],
        "predictions_frozen_before_labels": True,
        "labels_revealed": False,
        "evidence_sample_sha256": "sample",
        "candidate_artifact_sha256": "candidate",
        "evidence_contract_fingerprint": (
            v57._independent_contract_fingerprint(manifest)
        ),
        "predictions_file_name": prediction_path.name,
        "predictions_sha256": _sha256(prediction_path),
    }
    (tmp_path / v57.V57_PREDICTION_FREEZE).write_text(
        json.dumps(freeze),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        v57,
        "_evaluate_isolation_forest",
        lambda *_args, **_kwargs: {
            "status": "evaluated_independently",
            "advisory_only": True,
            "active_artifact_written": False,
        },
    )
    candidate = {
        "_manifest": {"artifact_sha256": "candidate"},
    }
    bundle = {"frame": pd.DataFrame([{}, {}]), "rows": [{}, {}]}

    first = v57._evaluate_revealed_labels(
        supervised_detector._optional_imports(),
        output_dir=tmp_path,
        evidence_manifest=manifest,
        evidence_manifest_path=manifest_path,
        sample_sha256="sample",
        candidate=candidate,
        bundle=bundle,
        lock_audit={"_v56_report": {}},
    )
    second = v57._evaluate_revealed_labels(
        supervised_detector._optional_imports(),
        output_dir=tmp_path,
        evidence_manifest=manifest,
        evidence_manifest_path=manifest_path,
        sample_sha256="sample",
        candidate=candidate,
        bundle=bundle,
        lock_audit={"_v56_report": {}},
    )

    sealed = json.loads(
        (tmp_path / v57.V57_PREDICTION_FREEZE).read_text(encoding="utf-8")
    )
    assert first["status"] == "evaluated_blind_once"
    assert first["metrics"]["queue_f1"] == 1.0
    assert first["post_prediction_guard"]["used"] is False
    assert sealed["labels_revealed"] is True
    assert sealed["blind_evaluation_completed"] is True
    assert second["status"] == "failed_closed_label_reveal_not_authorized"
    assert (
        second["label_reveal"]["checks"]["labels_not_previously_revealed"]
        is False
    )


def test_disposable_index_keeps_duplicate_families_contained(tmp_path):
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")
    v56.stream_private_file_to_disposable_index(
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

    protocol = v56.predeclare_chronological_roles(connection)

    assert protocol["duplicate_families_contained"] is True
    assert protocol["exact_family_cross_role_count"] == 0
    assert protocol["near_family_cross_role_count"] == 0


def test_readiness_stays_shadow_without_independent_validation():
    result = v57._readiness(
        lock_audit={"passed": True},
        candidate={
            "post_prediction_guard_used": False,
            "actual_threats_suppressed_by_post_prediction_guard": 0,
        },
        qualification={"eligible_for_predictions": False},
        validation=None,
        safety={
            "database_counts_unchanged": True,
            "model_artifacts_unchanged": True,
            "response_actions_created": 0,
        },
    )

    assert result["lifecycle_state"] == "shadow_observation"
    assert result["all_fixed_gates_passed"] is False
    assert result["automatic_activation_allowed"] is False
    assert result["response_automation_allowed"] is False
    assert (
        result["checks"][
            "no_post_prediction_guard_threat_suppression"
        ]
        is True
    )


def test_readiness_fails_closed_when_post_prediction_guard_is_present():
    result = v57._readiness(
        lock_audit={"passed": True},
        candidate={
            "post_prediction_guard_used": True,
            "actual_threats_suppressed_by_post_prediction_guard": 0,
        },
        qualification={"eligible_for_predictions": True},
        validation={
            "status": "evaluated_blind_once",
            "metrics": {
                "queue_f1": 1.0,
                "benign_like_false_positive_rate": 0.0,
                "suspicious_recall": 1.0,
                "malicious_recall": 1.0,
            },
            "calibration": {
                "expected_calibration_error": 0.0,
                "max_confidence_accuracy_gap": 0.0,
            },
        },
        safety={
            "database_counts_unchanged": True,
            "model_artifacts_unchanged": True,
            "response_actions_created": 0,
        },
    )

    assert result["all_fixed_gates_passed"] is False
    assert (
        result["checks"][
            "no_post_prediction_guard_threat_suppression"
        ]
        is False
    )


def test_lifecycle_summary_exposes_only_v57_aggregates(
    monkeypatch,
    tmp_path,
):
    report = {
        "status": "independent_evidence_required",
        "generated_at": "2026-07-26T00:00:00+00:00",
        "frozen_candidate": {
            "candidate_name": "calibrated_hist_gradient_boosting",
            "model_type": "HistGradientBoostingClassifier",
            "calibration_method": "sigmoid",
            "threshold": 0.3,
        },
        "independent_evidence": {
            "status": "independent_evidence_required",
            "eligible_for_predictions": False,
            "source_device_count": 1,
            "independent_time_window_count": 1,
        },
        "prediction_freeze": {"status": "not_run"},
        "blind_validation": {
            "status": "not_run_independent_evidence_required"
        },
        "readiness": {
            "lifecycle_state": "shadow_observation",
            "blockers": ["independent source time evidence"],
        },
    }
    (tmp_path / v57.V57_LATEST).write_text(
        json.dumps(report),
        encoding="utf-8",
    )
    monkeypatch.setattr(lifecycle, "DEFAULT_OUTPUT_DIR", tmp_path)

    summary = lifecycle._v57_revalidation_summary()

    assert summary["v57_available"] is True
    assert summary["v57_lifecycle_state"] == "shadow_observation"
    assert summary["v57_evidence_qualified"] is False
    assert summary["v57_candidate_activated"] is False
    assert summary["v57_rules_alert_authoritative"] is True
    assert summary["v57_response_automation_allowed"] is False
    assert summary["raw_logs_included"] is False
    assert summary["private_identifiers_included"] is False


def test_runner_preflight_has_no_configured_state_side_effects(
    monkeypatch,
    tmp_path,
):
    sample = tmp_path / "private.log"
    sample.write_text("synthetic\n", encoding="utf-8")
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
        "supervised": {"exists": True, "sha256": "same"},
        "isolation_forest": {"exists": True, "sha256": "same"},
    }
    monkeypatch.setattr(
        v57.v52,
        "_prepare_dataset",
        lambda *_args, **_kwargs: {"ok": True},
    )
    monkeypatch.setattr(
        v57.v54,
        "build_evidence_lock",
        lambda *_args, **_kwargs: {"lock": "same"},
    )
    monkeypatch.setattr(
        v57.v54,
        "validate_evidence_lock",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        v57,
        "audit_evidence_locks",
        lambda **_kwargs: {
            "passed": True,
            "status": "locked_and_matched",
            "_fingerprints": {"v56_role_signature": "prior"},
            "_v56_report": {},
        },
    )
    monkeypatch.setattr(
        v57,
        "freeze_v56_candidate",
        lambda *_args, **_kwargs: {
            "ok": True,
            "status": "frozen_diagnostic_candidate_ready",
            "candidate_name": "candidate",
            "_manifest": {"artifact_sha256": "candidate"},
            "_pipeline": _PredictablePipeline(),
            "_artifact": {"threshold": 0.5},
        },
    )
    monkeypatch.setattr(
        v57,
        "_prepare_independent_index",
        lambda *_args, **_kwargs: (
            {
                "ok": True,
                "status": "complete_file_streamed",
                "rows_processed": 1,
                "parser_successes": 1,
                "parser_failures": 0,
                "configured_database_overlap_rows": 0,
                "exact_duplicate_rows": 0,
                "near_duplicate_rows": 0,
            },
            {"roles": {}},
            "prior",
        ),
    )
    monkeypatch.setattr(
        v57.frozen,
        "_database_counts",
        lambda *_args: dict(counts),
    )
    monkeypatch.setattr(
        v57.v55,
        "_model_artifact_states",
        lambda: dict(artifacts),
    )

    result = v57.run_v57_independent_shadow_revalidation(
        SimpleNamespace(),
        sample_path=sample,
        output_dir=tmp_path,
        preflight_only=True,
        write_output=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["status"] == "independent_evidence_required"
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["model_artifacts_unchanged"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert str(sample) not in serialized
    assert result["privacy"]["row_fingerprints_returned"] is False
