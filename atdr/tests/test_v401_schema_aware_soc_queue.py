from __future__ import annotations

import csv
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from sqlalchemy import func, select

from atdr.app.db.models import DetectionRun, MLLabel, MLModelRun, ResponseAction
from atdr.app.detection import v401_schema_aware_soc_queue as v401
from atdr.app.detection.schema_contracts import (
    get_schema_contract,
    normalize_common_features,
    validate_schema_row,
)
from atdr.tests.test_v331_noise_reduction import _session


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_flow_sample(path: Path, *, rows: int = 8) -> None:
    fieldnames = [
        "evidence_id",
        "provider_file",
        "provider_day",
        "provider_row_number",
        "provider_label",
        "atdr_label",
        "queue_target",
        "severity_target",
        "human_reviewed",
        "import_ready",
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "TotLen Fwd Pkts",
        "TotLen Bwd Pkts",
        "Flow Bytes/s",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index in range(rows):
            threat = index % 2 == 1
            writer.writerow(
                {
                    "evidence_id": f"2018-02-15:{index + 1}",
                    "provider_file": "provider-development.csv",
                    "provider_day": "2018-02-15",
                    "provider_row_number": index + 1,
                    "provider_label": "Bot" if threat else "Benign",
                    "atdr_label": "malicious" if threat else "benign",
                    "queue_target": "needs_review" if threat else "non_threat",
                    "severity_target": "malicious" if threat else "benign",
                    "human_reviewed": False,
                    "import_ready": False,
                    "Dst Port": 4000 + index,
                    "Protocol": 6 if index % 3 else 17,
                    "Timestamp": f"15/02/2018 10:{index:02d}:00",
                    "Flow Duration": 1_000_000 + index,
                    "Tot Fwd Pkts": 3 + index,
                    "Tot Bwd Pkts": 2 + index,
                    "TotLen Fwd Pkts": 300 + index,
                    "TotLen Bwd Pkts": 200 + index,
                    "Flow Bytes/s": 500 + index,
                }
            )


def _partition_rows(*, sources: int = 8, rows_per_source: int = 16) -> list[dict]:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows: list[dict] = []
    for source in range(sources):
        for offset in range(rows_per_source):
            index = len(rows)
            threat = offset % 2 == 1
            rows.append(
                {
                    "index": index,
                    "log_id": f"flow-{index}",
                    "evidence_id": f"flow-{index}",
                    "source_name": f"provider-source-{source}",
                    "provider_file": f"provider-source-{source}.csv",
                    "timestamp": started + timedelta(minutes=index),
                    "safe_queue_target": "needs_review" if threat else "non_threat",
                    "severity_target": "malicious" if threat else "benign",
                    "exact_fingerprint": f"exact-{index}",
                    "near_fingerprint": f"near-{index // 2}",
                    "feature_fingerprint": f"feature-{index}",
                }
            )
    v401.v398.assign_leakage_groups(rows)
    return rows


def _evaluated_split(split_mode: str, name: str = "schema_routed_firewall_plus_flow_ensemble") -> dict:
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "strategies": [
            {
                "name": name,
                "status": "evaluated",
                "metrics": {
                    "queue_precision": 0.90,
                    "queue_recall": 0.88,
                    "queue_f1": 0.89,
                    "benign_like_false_positive_rate": 0.08,
                    "suspicious_recall": 0.82,
                    "malicious_recall": 0.86,
                    "macro_f1": 0.88,
                    "weighted_f1": 0.89,
                    "review_queue_rate": 0.48,
                },
                "calibration": {"passed": True, "brier_score": 0.1},
                "threshold_selection": {
                    "selected_threshold": 0.5,
                    "selected_on": "threshold_selection_partition_only",
                    "used_final_test_labels": False,
                },
                "details": {"active_artifact_written": False},
                "_scores": [0.1, 0.9],
                "_predictions": ["non_threat", "needs_review"],
            }
        ],
    }


def test_v401_lock_and_development_boundary_reject_locked_and_reserved_files(tmp_path, monkeypatch):
    locked_root = tmp_path / "locked"
    locked_root.mkdir()
    locked = locked_root / "locked.csv"
    locked.write_text("locked evidence", encoding="utf-8")
    expected = _sha256(locked)
    monkeypatch.setattr(v401.v400, "V400_EVIDENCE_DIR", locked_root)
    monkeypatch.setattr(v401, "LOCKED_V400_FILES", {locked.name: expected})

    assert v401.verify_v400_evidence_lock(locked_root)["ok"] is True
    with pytest.raises(RuntimeError, match="locked/reserved input"):
        v401.enforce_development_role_boundary([locked])

    reserved = tmp_path / str(v401.RESERVED_FUTURE_BENCHMARK["reserved_file"])
    reserved.write_text("must stay untouched", encoding="utf-8")
    with pytest.raises(RuntimeError, match="reserved_future_benchmark"):
        v401.enforce_development_role_boundary([reserved])


def test_v401_schema_contracts_reject_invented_provider_identity():
    provider = get_schema_contract("provider_flow")
    firewall = get_schema_contract("palo_alto")
    assert "src_ip" in provider.unavailable_fields
    assert "src_ip" in firewall.required_fields

    validation = validate_schema_row(
        "provider_flow",
        {
            "timestamp": datetime.now(timezone.utc),
            "src_ip": "192.0.2.10",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes_sent": 10,
            "bytes_received": 20,
            "packets": 3,
            "duration_seconds": 1,
        },
    )
    assert validation["valid"] is False
    assert validation["invented_unavailable_fields"] == ["src_ip"]

    with pytest.raises(ValueError, match="cannot supply unavailable"):
        normalize_common_features(
            "provider_flow",
            {
                "timestamp": datetime.now(timezone.utc),
                "src_ip": "192.0.2.10",
                "dst_port": 443,
                "protocol": "tcp",
                "bytes_sent": 10,
                "bytes_received": 20,
                "packets": 3,
                "duration_seconds": 1,
            },
        )


def test_v401_flow_adapter_preserves_missingness_without_inventing_fields(tmp_path):
    sample = tmp_path / "sample.csv"
    _write_flow_sample(sample)

    dataset = v401.build_flow_development_dataset(sample)

    assert dataset["ok"] is True
    assert dataset["label_integrity"]["human_reviewed_rows"] == 0
    assert dataset["label_integrity"]["import_ready_rows"] == 0
    assert dataset["feature_meta"]["unavailable_fields_not_invented"] is True
    assert "missing__flow_bytes_s" in dataset["frame"].columns
    assert all("src_ip" not in row for row in dataset["rows"])
    assert all(row["app"] == "unavailable" for row in dataset["rows"])
    assert dataset["leakage_group_summary"]["group_count"] > 0


def test_v401_provider_rule_matrix_marks_unsupported_rules_unavailable(tmp_path):
    sample = tmp_path / "sample.csv"
    _write_flow_sample(sample)
    dataset = v401.build_flow_development_dataset(sample)

    scores, details = v401._flow_rule_scores(dataset, [0, 1, 2, 3], [4, 5, 6, 7])

    assert len(scores) == 4
    assert "port_scan_behavior" in details["unavailable_rules"]
    assert "deny_drop_action" in details["unavailable_rules"]
    assert details["unavailable_rules_scored_as_negative"] is False


@pytest.mark.parametrize("mode", ["source_group_holdout", "random_seed_7", "random_seed_17", "random_seed_42"])
def test_v401_development_roles_are_row_and_fingerprint_disjoint(mode):
    rows = _partition_rows()
    partition = v401.build_development_partition({"rows": rows}, split_mode=mode)

    assert partition["status"] == "ready"
    assert partition["audit"]["passed"] is True
    assert partition["detailed_leakage_audit"]["passed"] is True
    assert max(partition["audit"]["pairwise_row_overlap"].values()) == 0
    assert max(partition["audit"]["pairwise_group_overlap"].values()) == 0


def test_v401_internal_partition_assigns_builder_leakage_groups():
    rows = _partition_rows()
    for row in rows:
        row.pop("leakage_group")

    prepared = v401._internal_partition({"rows": rows}, "random_seed_7")

    assert prepared["status"] == "ready"
    assert all("leakage_group" in row for row in rows)
    assert prepared["leakage_audit"]["passed"] is True


def test_v401_strategy_selection_is_diagnostic_only():
    comparison = v401.build_strategy_comparison(
        [_evaluated_split(f"random_seed_{seed}") for seed in (7, 17, 42)]
    )
    selection = v401.select_diagnostic_candidates(comparison)

    assert selection["best_cross_schema_diagnostic"]["name"] == "schema_routed_firewall_plus_flow_ensemble"
    assert selection["selection_used_v400_final_labels"] is False
    assert selection["activation_allowed"] is False


def test_v401_prefit_calibration_supports_string_multiclass_labels():
    from sklearn.ensemble import ExtraTreesClassifier

    frame = pd.DataFrame({"feature": list(range(18))})
    targets = ["benign", "suspicious", "malicious"] * 6
    model = ExtraTreesClassifier(n_estimators=8, random_state=401)
    model.fit(frame.iloc[:9], targets[:9])

    calibrated = v401._calibrate_prefit(model, frame, list(range(9, 18)), targets)

    assert sorted(calibrated.classes_) == ["benign", "malicious", "suspicious"]
    assert calibrated.predict_proba(frame.iloc[:3]).shape == (3, 3)


def test_v401_runner_remains_read_only_and_candidate_only(tmp_path, monkeypatch):
    development_dir = tmp_path / "development"
    development_dir.mkdir()
    sample_path = development_dir / "sample.csv"
    _write_flow_sample(sample_path)
    flow_rows = [
        {
            "original_label": "benign" if index % 2 == 0 else "malicious",
            "provider_label": "Benign" if index % 2 == 0 else "Bot",
        }
        for index in range(8)
    ]
    flow = {
        "ok": True,
        "rows": flow_rows,
        "targets": ["non_threat" if index % 2 == 0 else "needs_review" for index in range(8)],
        "accepted_rows": 8,
        "duplicate_rows_quarantined": 0,
        "schema_violations": [],
        "feature_meta": {"numeric_features": ["feature"], "missingness_indicator_count": 1},
        "label_integrity": {
            "provider_ground_truth": True,
            "human_reviewed_rows": 0,
            "import_ready_rows": 0,
            "operational_database_imported_rows": 0,
            "v400_locked_labels_used": 0,
        },
    }
    internal = {
        "ok": True,
        "rows": [],
        "logs": [],
        "targets": [],
        "imports": (None, pd),
        "feature_meta": {"numeric_features": [], "categorical_features": []},
    }
    verified_files = [{"file_name": "development.csv", "sha256": "safe"}]
    lock = {"ok": True, "status": "locked_and_verified", "verified": []}
    split = _evaluated_split("random_seed_7")
    monkeypatch.setattr(v401, "verify_v400_evidence_lock", lambda: dict(lock))
    monkeypatch.setattr(
        v401,
        "verify_development_files",
        lambda _path: {
            "ok": True,
            "status": "verified_development_only",
            "files": verified_files,
            "role_boundary": {"passed": True},
        },
    )
    monkeypatch.setattr(v401.v398, "_build_dataset", lambda _db, min_samples: internal)
    monkeypatch.setattr(
        v401,
        "build_development_sample",
        lambda *_args, **_kwargs: {
            "sample_path": sample_path,
            "sample_sha256": _sha256(sample_path),
            "sampled_rows": 8,
            "class_distribution": {"benign": 4, "malicious": 4},
            "queue_distribution": {"needs_review": 4, "non_threat": 4},
            "provider_label_distribution": {"Benign": 4, "Bot": 4},
            "sampling": {"development_only": True},
        },
    )
    monkeypatch.setattr(v401, "build_flow_development_dataset", lambda _path: flow)
    monkeypatch.setattr(v401, "evaluate_flow_split", lambda *_args, **kwargs: dict(split) | {"split_mode": kwargs["split_mode"]})
    monkeypatch.setattr(v401, "evaluate_firewall_split", lambda *_args, **kwargs: dict(split) | {"split_mode": kwargs["split_mode"]})
    monkeypatch.setattr(v401, "build_pooled_common_dataset", lambda *_args: {"ok": True})
    monkeypatch.setattr(v401, "evaluate_pooled_schema_split", lambda *_args, **kwargs: dict(split) | {"split_mode": kwargs["split_mode"]})
    monkeypatch.setattr(v401, "combine_schema_routed_result", lambda *_args, **kwargs: dict(split) | {"split_mode": kwargs["split_mode"]})
    monkeypatch.setattr(v401, "evaluate_schema_holdout", lambda *_args, **kwargs: dict(split) | {"split_mode": f"schema_holdout_{kwargs['heldout_schema']}"})
    monkeypatch.setattr(v401.v398, "_artifact_state", lambda: {"exists": False, "name": "none"})

    with _session() as db:
        before = {
            "labels": db.scalar(select(func.count(MLLabel.id))),
            "models": db.scalar(select(func.count(MLModelRun.id))),
            "detections": db.scalar(select(func.count(DetectionRun.id))),
            "responses": db.scalar(select(func.count(ResponseAction.id))),
        }
        result = v401.run_v401_schema_aware_soc_queue(
            db,
            development_dir=development_dir,
            output_dir=tmp_path / "reports",
            rows_per_provider_label=10,
            min_samples=4,
        )
        after = {
            "labels": db.scalar(select(func.count(MLLabel.id))),
            "models": db.scalar(select(func.count(MLModelRun.id))),
            "detections": db.scalar(select(func.count(DetectionRun.id))),
            "responses": db.scalar(select(func.count(ResponseAction.id))),
        }

    assert result["ok"] is True
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["active_artifact_unchanged"] is True
    assert result["safety"]["response_actions_created"] == 0
    assert before == after
    assert (tmp_path / "reports" / v401.V401_LATEST).exists()
