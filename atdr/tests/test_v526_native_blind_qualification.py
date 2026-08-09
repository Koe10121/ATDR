from __future__ import annotations

import csv
import json
from pathlib import Path

from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v522_supervised_model_rebuild as v522
from atdr.app.detection import v526_native_blind_qualification as blind


def _blind_row(index: int, *, decision: str = "", reviewed: bool = False) -> dict[str, object]:
    return {
        "review_token": f"token-{index:03d}",
        "evidence_role": "untouched_future_validation",
        "evidence_role_is_blind": True,
        "pattern": "routine_web" if index % 2 == 0 else "scan_like",
        "review_priority": "high",
        "event_time_utc": f"2026-05-20T10:{index % 60:02d}:00+00:00",
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": "ssl" if index % 2 == 0 else "unknown",
        "action": "allow" if index % 2 == 0 else "deny",
        "protocol": "tcp",
        "source_port": 40000 + index,
        "destination_port": 443 if index % 2 == 0 else 22,
        "source_zone": "untrust",
        "destination_zone": "trust",
        "bytes": 1200,
        "packets": 12,
        "elapsed_time": 4,
        "application_risk": 2 if index % 2 == 0 else 5,
        "threat_severity": "",
        "session_end_reason": "aged-out",
        "parser_error": False,
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 2 if index % 2 == 0 else 30,
        "source_deny_count": 0 if index % 2 == 0 else 20,
        "source_unique_destinations": 1 if index % 2 == 0 else 12,
        "source_unique_ports": 1 if index % 2 == 0 else 15,
        "source_unknown_app_count": 0 if index % 2 == 0 else 20,
        "source_high_risk_app_count": 0 if index % 2 == 0 else 5,
        "destination_repeat_count": 1,
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "human_decision": decision,
        "human_attack_type": "",
        "human_confidence": "",
        "human_notes": "",
        "human_reviewer": "independent-reviewer" if reviewed else "",
        "human_reviewed_at": "2026-08-01T10:00:00+00:00" if reviewed else "",
        "human_must_confirm": True,
        "import_ready": False,
        "assisted_suggestion": "",
        "assisted_attack_type": "",
        "assisted_confidence": "",
        "assisted_reason": "",
        "assisted_provenance": "",
        "rule_codes": "",
        "rule_score": "",
        "suggestion_is_weak": False,
        "human_reviewed": reviewed,
        "blind_suggestion_suppressed": True,
    }


def _write_pack(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_evidence_contracts(
    directory: Path,
    sample: Path,
    rows: list[dict[str, object]],
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    _write_pack(directory / v521.V521_BLIND_PACK, rows)
    manifest = {
        "version": v521.V521_MANIFEST_VERSION,
        "source_file_sha256": v521._file_sha256(sample),
        "role_locks": {
            name: {"rows": 1}
            for name in (
                "development_fit",
                "calibration",
                "threshold",
                "untouched_future_validation",
                "quarantine",
            )
        },
        "blind_pack_fingerprint": v521._pack_fingerprint(rows),
        "blind_suggestions_generated": False,
        "blind_decisions_opened": False,
        "human_reviewed_rows_created": 0,
        "configured_database_accessed": False,
        "exact_family_cross_role_count": 0,
        "near_family_cross_role_count": 0,
    }
    (directory / v521.V521_MANIFEST_LATEST).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    candidate = {
        "name": "hierarchical_two_stage_extra_trees",
        "selection_basis": "development_only",
        "target_mode": "hierarchical_two_stage",
        "model_type": "extra_trees",
        "threshold": 0.4,
        "calibration_method": "sigmoid_on_dedicated_calibration_partition",
        "frozen_before_blind_label_access": True,
        "blind_labels_used_for_selection": False,
        "eligible_for_activation": False,
        "active_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
    }
    (directory / v522.V522_LATEST).write_text(
        json.dumps(
            {
                "ok": True,
                "lifecycle_state": "shadow_observation",
                "frozen_shadow_candidate": candidate,
            }
        ),
        encoding="utf-8",
    )


def _prediction(index: int, *, queued: bool) -> dict[str, object]:
    queue = "needs_review" if queued else "non_threat"
    score = 0.9 if queued else 0.1
    return {
        "review_token": f"token-{index:03d}",
        "pattern": "scan_like" if queued else "routine_web",
        "app": "unknown" if queued else "ssl",
        "action": "deny" if queued else "allow",
        "dst_port": 22 if queued else 443,
        "schema": "traffic_full",
        "log_type": "TRAFFIC",
        "rule_queue": queue,
        "rule_score": score,
        "isolation_queue": queue,
        "isolation_score": score,
        "supervised_queue": queue,
        "supervised_score": score,
        "hybrid_queue": queue,
        "hybrid_score": score,
    }


def test_feature_phase_does_not_retain_human_decisions(tmp_path: Path) -> None:
    pack = tmp_path / "blind.csv"
    _write_pack(pack, [_blind_row(0, decision="malicious", reviewed=True)])

    rows, audit = blind.load_blind_features_before_labels(pack)

    assert audit["label_fields_retained_for_prediction"] is False
    assert blind.LABEL_FIELDS.isdisjoint(rows[0])
    assert "malicious" not in json.dumps(rows)
    assert rows[0]["evidence_role"] == "untouched_future_validation"


def test_blind_eligibility_detects_pack_lock_mismatch(tmp_path: Path) -> None:
    pack = tmp_path / "blind.csv"
    source_rows = [_blind_row(0)]
    _write_pack(pack, source_rows)
    features, audit = blind.load_blind_features_before_labels(pack)
    manifest = {
        "version": v521.V521_MANIFEST_VERSION,
        "blind_decisions_opened": False,
        "blind_suggestions_generated": False,
        "human_reviewed_rows_created": 0,
        "configured_database_accessed": False,
        "blind_pack_fingerprint": "changed",
        "exact_family_cross_role_count": 0,
        "near_family_cross_role_count": 0,
    }

    result = blind.audit_blind_eligibility(manifest, features, audit)

    assert result["passed"] is False
    assert result["checks"]["pack_fingerprint_matches_lock"] is False
    assert result["fingerprints_returned"] is False


def test_unreviewed_blind_pack_never_produces_performance_metrics(
    tmp_path: Path,
) -> None:
    pack = tmp_path / "blind.csv"
    _write_pack(pack, [_blind_row(index) for index in range(40)])
    labels, label_audit = blind._open_human_labels_after_prediction(pack)

    result = blind.evaluate_predictions_after_label_open(
        [_prediction(index, queued=index % 2 == 1) for index in range(40)],
        labels,
        label_audit,
    )

    assert label_audit["genuine_human_labels"] == 0
    assert result["metrics_calculated"] is False
    assert result["layers"] == {}
    assert result["error_analysis"]["false_positive_claims_made"] is False
    assert result["error_analysis"]["false_negative_claims_made"] is False


def test_assisted_values_are_not_accepted_as_human_labels(tmp_path: Path) -> None:
    row = _blind_row(0)
    row["assisted_suggestion"] = "malicious"
    row["suggestion_is_weak"] = True
    pack = tmp_path / "blind.csv"
    _write_pack(pack, [row])

    labels, audit = blind._open_human_labels_after_prediction(pack)

    assert labels == {}
    assert audit["genuine_human_labels"] == 0
    assert audit["assisted_or_weak_labels_counted_as_human"] == 0


def test_legitimate_balanced_human_labels_enable_one_time_metrics(
    tmp_path: Path,
) -> None:
    rows = [
        _blind_row(
            index,
            decision="malicious" if index % 2 else "benign",
            reviewed=True,
        )
        for index in range(20)
    ]
    pack = tmp_path / "blind.csv"
    _write_pack(pack, rows)
    labels, label_audit = blind._open_human_labels_after_prediction(pack)

    result = blind.evaluate_predictions_after_label_open(
        [_prediction(index, queued=index % 2 == 1) for index in range(20)],
        labels,
        label_audit,
    )

    assert label_audit["enough_for_metrics"] is True
    assert result["metrics_calculated"] is True
    assert result["layers"]["supervised"]["metrics"]["queue_f1"] == 1.0
    assert result["layers"]["supervised"]["metrics"]["benign_like_false_positive_rate"] == 0.0
    assert result["layers"]["supervised"]["metrics"]["malicious_recall"] == 1.0


def test_preflight_is_redacted_and_does_not_open_labels(tmp_path: Path) -> None:
    sample = tmp_path / "private-customer-firewall.log"
    sample.write_text("private placeholder\n", encoding="utf-8")
    evidence = tmp_path / "ignored-evidence"
    rows = [_blind_row(index) for index in range(12)]
    _write_evidence_contracts(evidence, sample, rows)

    result = blind.run_v526_native_blind_qualification(
        None,
        sample_path=sample,
        use_temp_db=True,
        evidence_dir=evidence,
        output_dir=tmp_path / "output",
        preflight_only=True,
    )

    serialized = json.dumps(result)
    assert result["ok"] is True
    assert result["status"] == "native_blind_preflight_complete"
    assert result["prediction_executed"] is False
    assert result["blind_label_fields_opened"] is False
    assert str(sample) not in serialized
    assert sample.name not in serialized
    assert "token-" not in serialized
    assert result["private_identifiers_returned"] is False
    assert result["fingerprints_returned"] is False


def test_full_protocol_has_no_database_model_or_response_side_effects(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = tmp_path / "private.log"
    sample.write_text("private placeholder\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    output = tmp_path / "output"
    rows = [_blind_row(index) for index in range(20)]
    _write_evidence_contracts(evidence, sample, rows)
    counts = {
        "raw_logs": 10,
        "normalized_logs": 10,
        "alerts": 1,
        "ml_labels": 2,
        "ml_model_runs": 3,
        "response_actions": 0,
        "detection_runs": 1,
        "audit_logs": 4,
    }
    monkeypatch.setattr(blind.frozen, "_database_counts", lambda _db: dict(counts))
    monkeypatch.setattr(blind.v55, "_model_artifact_states", lambda: {"active": "unchanged"})

    def prediction_phase(_db, **kwargs):
        assert all(blind.LABEL_FIELDS.isdisjoint(row) for row in kwargs["blind_rows"])
        predictions = [
            _prediction(index, queued=index % 2 == 1)
            for index in range(len(kwargs["blind_rows"]))
        ]
        return predictions, {
            "status": "predictions_frozen_before_human_label_access",
            "rows": len(predictions),
            "layers": {
                name: blind._prediction_summary(predictions, name)
                for name in ("rule", "isolation", "supervised", "hybrid")
            },
            "labels_accessed": False,
            "prediction_lock_created": True,
        }

    monkeypatch.setattr(blind, "_run_prediction_phase", prediction_phase)

    result = blind.run_v526_native_blind_qualification(
        object(),
        sample_path=sample,
        use_temp_db=True,
        evidence_dir=evidence,
        output_dir=output,
    )

    assert result["ok"] is True
    assert result["prediction_frozen_before_label_access"] is True
    assert result["blind_labels_used_for_candidate_selection"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["model_artifacts_unchanged"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["automatic_response_enabled"] is False
    assert (output / blind.V526_LATEST).is_file()
    assert (output / blind.V526_PREDICTION_LOCK).is_file()
    lock_text = (output / blind.V526_PREDICTION_LOCK).read_text(
        encoding="utf-8"
    )
    assert str(sample) not in lock_text
    assert sample.name not in lock_text
    assert "raw_line" not in lock_text
    assert "source_ip" not in lock_text
    assert "destination_ip" not in lock_text
    assert "human_decision" not in lock_text
    assert result["prediction_lock_path_returned"] is False

    second = blind.run_v526_native_blind_qualification(
        object(),
        sample_path=sample,
        use_temp_db=True,
        evidence_dir=evidence,
        output_dir=output,
    )
    assert second["status"] == "failed_closed_blind_qualification_already_consumed"


def test_missing_prediction_lock_can_be_repaired_only_before_ground_truth(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = tmp_path / "private.log"
    sample.write_text("private placeholder\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    output = tmp_path / "output"
    rows = [_blind_row(index) for index in range(20)]
    _write_evidence_contracts(evidence, sample, rows)
    output.mkdir()
    (output / blind.V526_LATEST).write_text(
        json.dumps(
            {
                "blind_label_fields_opened": True,
                "label_audit": {"genuine_human_labels": 0},
                "blind_evaluation": {"metrics_calculated": False},
            }
        ),
        encoding="utf-8",
    )
    counts = {
        "raw_logs": 1,
        "normalized_logs": 1,
        "alerts": 0,
        "ml_labels": 0,
        "ml_model_runs": 0,
        "response_actions": 0,
        "detection_runs": 0,
        "audit_logs": 0,
    }
    monkeypatch.setattr(blind.frozen, "_database_counts", lambda _db: dict(counts))
    monkeypatch.setattr(blind.v55, "_model_artifact_states", lambda: {})
    monkeypatch.setattr(
        blind,
        "_run_prediction_phase",
        lambda _db, **kwargs: (
            [
                _prediction(index, queued=index % 2 == 1)
                for index in range(len(kwargs["blind_rows"]))
            ],
            {
                "status": "predictions_frozen_before_human_label_access",
                "rows": len(kwargs["blind_rows"]),
                "layers": {},
                "labels_accessed": False,
                "prediction_lock_created": True,
            },
        ),
    )

    result = blind.run_v526_native_blind_qualification(
        object(),
        sample_path=sample,
        use_temp_db=True,
        evidence_dir=evidence,
        output_dir=output,
    )

    assert result["ok"] is True
    assert result["prelock_protocol_repair"] is True
    assert result["prelock_protocol_repair_ground_truth_observed"] is False
    assert (output / blind.V526_PRELOCK_RECORD).is_file()
    assert (output / blind.V526_PREDICTION_LOCK).is_file()
