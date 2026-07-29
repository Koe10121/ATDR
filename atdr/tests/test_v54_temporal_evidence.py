from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v54_temporal_evidence as evidence


def _dataset() -> dict:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = []
    logs = []
    for index in range(12):
        assisted = index in {0, 1}
        rows.append(
            {
                "index": index,
                "label_id": index + 100,
                "log_id": index + 1,
                "original_label": "benign" if index % 3 else "suspicious",
                "safe_queue_target": "needs_review"
                if index % 3 == 0
                else "non_threat",
                "reviewed": True,
                "label_source": "assisted_rule" if assisted else "manual",
                "source_name": "source-one",
                "network_zone_group": "zone:inside->outside",
                "timestamp": started + timedelta(minutes=index),
                "app": "quic-base" if index % 2 else "incomplete",
                "action": "allow",
                "dst_port": 443 if index % 2 else 80,
                "exact_fingerprint": f"{index:064x}",
                "near_fingerprint": f"near-{index}",
                "feature_fingerprint": f"feature-{index}",
                "leakage_group": f"group-{index}",
                "target_reason": "reviewed_label",
            }
        )
        logs.append(
            SimpleNamespace(
                id=index + 1,
                app=rows[-1]["app"],
                app_category="internet-utility",
                action="allow",
                subtype="end",
                session_end_reason="aged-out",
                action_source="from-policy",
                dst_port=rows[-1]["dst_port"],
                protocol="udp" if rows[-1]["app"] == "quic-base" else "tcp",
                log_type="TRAFFIC",
                src_zone="inside",
                dst_zone="outside",
                src_ip="192.0.2.1",
                dst_ip="198.51.100.2",
                src_port=50000,
                bytes=100,
                bytes_sent=50,
                bytes_received=50,
                packets=4,
                packets_sent=2,
                packets_received=2,
                repeat_count=1,
                app_risk=1,
                app_characteristic=None,
                is_anomaly=False,
                generated_time=rows[-1]["timestamp"],
                receive_time=None,
                high_res_timestamp=None,
                start_time=None,
                raw_log=None,
            )
        )
    return {
        "ok": True,
        "rows": rows,
        "logs": logs,
        "labels": [],
        "targets": [row["safe_queue_target"] for row in rows],
        "label_provenance": {},
    }


def _partition() -> dict:
    return {
        "fit_idx": [0, 1, 2, 3, 4],
        "calibration_idx": [5, 6],
        "threshold_idx": [7],
        "final_test_idx": [8, 9],
        "quarantined_idx": [10, 11],
    }


def test_development_manifest_excludes_locked_and_quarantined_rows():
    dataset = _dataset()

    manifest = evidence.build_development_manifest(dataset, _partition())
    summary = manifest["summary"]

    assert summary["development_rows"] == 8
    assert summary["excluded_rows"] == 4
    assert summary["development_final_overlap"] == 0
    assert summary["locked_final_rows_used_for_development"] is False
    assert summary["external_evidence_used_for_development"] is False
    assert summary["exclusion_reasons"] == {
        "locked_v5_3_temporal_final": 2,
        "duplicate_or_near_duplicate_quarantine": 2,
    }
    assisted = next(
        row
        for row in manifest["rows"]
        if row["label_provenance"] == "assisted_rule"
    )
    assert assisted["review_state"] == "assisted_or_weak_review_record"
    assert assisted["human_reviewed"] is False


def test_development_manifest_detects_duplicate_row_fingerprints():
    dataset = _dataset()
    dataset["rows"][1] = {
        **dataset["rows"][0],
        "index": 1,
    }

    manifest = evidence.build_development_manifest(dataset, _partition())

    assert manifest["summary"]["duplicate_development_row_fingerprints"] == 1


def test_lock_validation_passes_exact_projection_and_fails_changed_role(tmp_path):
    current = {
        "version": "v5.4-evidence-lock-v1",
        "dataset_fingerprint": "dataset",
        "reviewed_latest_rows": 10,
        "temporal_partition_id": "partition",
        "roles": {
            role: {"rows": 2, "fingerprint": f"fingerprint-{role}"}
            for role in evidence.ROLE_INDEX_KEYS
        },
        "rolling_future_roles": [
            {"role": "rolling_temporal_1", "rows": 2, "fingerprint": "rolling"}
        ],
        "external_evidence": {
            "available": True,
            "passed_v49_gates": False,
            "fingerprint": "external",
        },
        "model_artifacts": [
            {
                "role": "governed_supervised_artifact",
                "exists": True,
                "artifact_name": "candidate.joblib",
                "size_bytes": 10,
                "sha256": "artifact",
            }
        ],
        "locked_final_labels_used_for_tuning": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(
        json.dumps(evidence._lock_projection(current)),
        encoding="utf-8",
    )

    passed = evidence.validate_evidence_lock(current, lock_path=lock_path)
    changed = json.loads(json.dumps(current))
    changed["roles"]["temporal_final"]["fingerprint"] = "changed"
    failed = evidence.validate_evidence_lock(changed, lock_path=lock_path)

    assert passed["status"] == "locked_and_matched"
    assert passed["passed"] is True
    assert failed["status"] == "lock_mismatch_failed_closed"
    assert "role:temporal_final" in failed["mismatches"]


def test_shadow_drift_states_are_conservative():
    insufficient = evidence.classify_shadow_drift(
        observed_rows=20,
        distribution_distances={},
        missingness_delta=0.0,
        ood_rate=0.0,
        score_median_shift=0.0,
        queue_rate_delta=0.0,
    )
    warning = evidence.classify_shadow_drift(
        observed_rows=200,
        distribution_distances={"application": 0.30},
        missingness_delta=0.0,
        ood_rate=0.0,
        score_median_shift=0.0,
        queue_rate_delta=0.0,
    )
    ood = evidence.classify_shadow_drift(
        observed_rows=200,
        distribution_distances={"schema": 0.60},
        missingness_delta=0.0,
        ood_rate=0.0,
        score_median_shift=0.0,
        queue_rate_delta=0.0,
    )

    assert insufficient["status"] == "Insufficient Evidence"
    assert warning["status"] == "Drift Warning"
    assert ood["status"] == "OOD Warning"


def test_private_temporal_preflight_never_returns_path_raw_lines_or_ips():
    path = (
        PROJECT_ROOT
        / "data"
        / "samples"
        / "scenarios"
        / "port_scan_like_traffic.txt"
    )

    result = evidence.inspect_private_temporal_regimes(path, max_lines=10)
    rendered = json.dumps(result, default=str)

    assert result["ok"] is True
    assert result["path_returned"] is False
    assert result["raw_evidence_returned"] is False
    assert result["private_identifiers_returned"] is False
    assert result["secrets_exposed"] is False
    assert str(path) not in rendered
    assert "203.0.113.44" not in rendered
    assert "192.0.2." not in rendered


def test_assisted_review_pack_is_never_import_ready_or_human_reviewed():
    dataset = _dataset()
    manifest = evidence.build_development_manifest(dataset, _partition())

    rows = evidence.build_assisted_review_pack(dataset, manifest, limit=20)

    assert rows
    assert all(row["human_must_confirm"] is True for row in rows)
    assert all(row["human_reviewed"] is False for row in rows)
    assert all(row["import_ready"] is False for row in rows)
    assert all(row["suggestion_is_weak"] is True for row in rows)
    assert all(row["raw_log_included"] is False for row in rows)
    assert all(row["ip_address_included"] is False for row in rows)


def test_v54_runner_keeps_lifecycle_shadow_and_creates_no_side_effects(
    monkeypatch,
):
    dataset = _dataset()
    partition = _partition()
    counts = {
        "raw_logs": 12,
        "normalized_logs": 12,
        "alerts": 1,
        "ml_labels": 12,
        "ml_model_runs": 1,
        "detection_runs": 1,
        "response_actions": 0,
    }
    artifact = {
        "exists": True,
        "name": "candidate.joblib",
        "size_bytes": 10,
        "modified_ns": 1,
    }
    monkeypatch.setattr(evidence.v52, "_prepare_dataset", lambda *_args, **_kwargs: dataset)
    monkeypatch.setattr(
        evidence.frozen,
        "build_frozen_partition",
        lambda *_args, **_kwargs: partition,
    )
    monkeypatch.setattr(
        evidence.frozen,
        "audit_partition_leakage",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(evidence.frozen, "_database_counts", lambda *_args: dict(counts))
    monkeypatch.setattr(evidence.frozen, "_artifact_state", lambda: dict(artifact))
    monkeypatch.setattr(
        evidence,
        "build_evidence_lock",
        lambda *_args, **_kwargs: {"ok": True},
    )
    monkeypatch.setattr(
        evidence,
        "validate_evidence_lock",
        lambda *_args, **_kwargs: {
            "passed": True,
            "status": "locked_and_matched",
        },
    )
    monkeypatch.setattr(
        evidence,
        "audit_chronological_evidence",
        lambda *_args, **_kwargs: {
            "roles": {"fit": {"source_identity_count": 1}},
            "problems": [],
        },
    )
    monkeypatch.setattr(
        evidence.v53,
        "diagnose_temporal_failure",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        evidence,
        "build_shadow_drift",
        lambda *_args, **_kwargs: {
            "status": "Insufficient Evidence",
            "findings": [],
        },
    )

    result = evidence.run_v54_temporal_evidence_preparation(
        SimpleNamespace(),
        write_output=False,
        write_review_pack=False,
    )

    assert result["ok"] is True
    assert result["lifecycle_state"] == "shadow_observation"
    assert result["readiness"]["candidate_selected"] is False
    assert result["readiness"]["eligible_for_activation"] is False
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["response_automation_allowed"] is False
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["model_runs_created"] == 0
    assert result["safety"]["detection_runs_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert result["safety"]["active_model_artifact_written"] is False
