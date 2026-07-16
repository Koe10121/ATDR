import csv
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from atdr.app.detection import v400_provider_blinded_external_validation as v400


def _write_provider_file(path: Path, labels: list[str]) -> dict:
    header = [
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "TotLen Fwd Pkts",
        "TotLen Bwd Pkts",
        "Label",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for index, label in enumerate(labels, start=1):
            writer.writerow(
                [
                    400 + index,
                    6 if index % 2 else 17,
                    f"14/02/2018 10:{index:02d}:00",
                    1_000_000 * index,
                    index,
                    index + 1,
                    index * 100,
                    index * 50,
                    label,
                ]
            )
    payload = path.read_bytes()
    return {
        "file_name": path.name,
        "provider_day": "2018-02-14",
        "public_url": "https://example.invalid/provider.csv",
        "expected_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "s3_etag": "test",
        "s3_last_modified": "2018-10-11T00:00:00Z",
        "official_scenario": "test fixture",
    }


def test_v400_feature_sampling_is_label_independent(tmp_path, monkeypatch):
    path = tmp_path / "provider.csv"
    spec = _write_provider_file(path, ["Benign", "FTP-BruteForce", "Benign", "SSH-Bruteforce"])
    monkeypatch.setattr(v400, "SOURCE_FILES", (spec,))

    first = v400.build_feature_only_sample(tmp_path, rows_per_file=3, seed=400, stamp="first")
    first_contents = Path(first["feature_path"]).read_text(encoding="utf-8")
    _write_provider_file(path, ["Infilteration", "Benign", "Infilteration", "Benign"])
    second = v400.build_feature_only_sample(tmp_path, rows_per_file=3, seed=400, stamp="second")

    assert first_contents == Path(second["feature_path"]).read_text(encoding="utf-8")
    assert "Label" not in first["feature_columns"]
    assert first["sampling"]["label_independent"] is True
    assert first["sampling"]["label_values_consulted"] is False


def test_v400_adapter_maps_only_available_provider_fields(tmp_path):
    feature_path = tmp_path / "features.csv"
    with feature_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "evidence_id",
                "provider_file",
                "provider_day",
                "provider_row_number",
                "Dst Port",
                "Protocol",
                "Timestamp",
                "Flow Duration",
                "Tot Fwd Pkts",
                "Tot Bwd Pkts",
                "TotLen Fwd Pkts",
                "TotLen Bwd Pkts",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "evidence_id": "2018-02-14:1",
                "provider_file": "provider.csv",
                "provider_day": "2018-02-14",
                "provider_row_number": 1,
                "Dst Port": 443,
                "Protocol": 6,
                "Timestamp": "14/02/2018 10:30:00",
                "Flow Duration": 2_000_000,
                "Tot Fwd Pkts": 3,
                "Tot Bwd Pkts": 4,
                "TotLen Fwd Pkts": 500,
                "TotLen Bwd Pkts": 250,
            }
        )
    internal = {
        "feature_meta": {
            "numeric_features": [
                "src_port",
                "dst_port",
                "bytes",
                "bytes_sent",
                "bytes_received",
                "packets",
                "elapsed_time",
                "app_risk",
                "hour_of_day",
                "is_after_hours",
                "v398_local_rule_score",
                *v400.ENRICHMENT_NUMERIC,
            ],
            "categorical_features": ["protocol", "action", "app", "src_zone", "dst_zone", "v337_traffic_family"],
        }
    }
    dataset = v400.build_external_feature_dataset(
        feature_path,
        internal_dataset=internal,
        frozen_rule_thresholds={"byte_outlier_threshold": 10_000_000.0, "packet_outlier_threshold": 50_000.0},
    )

    assert dataset["ok"] is True
    assert dataset["records"][0]["src_ip"] is None
    assert dataset["records"][0]["dst_ip"] is None
    assert dataset["frame"].iloc[0]["dst_port"] == 443
    assert dataset["frame"].iloc[0]["bytes"] == 750
    assert dataset["frame"].iloc[0]["packets"] == 7
    assert dataset["frame"].iloc[0]["protocol"] == "tcp"
    assert dataset["frame"].iloc[0]["app"] == "unavailable"
    assert dataset["feature_meta"]["source_identity_policy"] == "provider_file_day_not_network_source_ip"


class _DummyModel:
    classes_ = ["needs_review", "non_threat"]

    def predict_proba(self, frame):
        return [[0.8, 0.2] for _row in range(len(frame))]


def test_v400_predictions_freeze_before_labels_and_contain_no_labels(tmp_path):
    external = {
        "frame": pd.DataFrame([{"feature": 1.0}]),
        "rows": [
            {
                "evidence_id": "2018-02-14:1",
                "provider_file": "provider.csv",
                "provider_row_number": 1,
            }
        ],
        "rule_scores": [0.0],
    }
    threshold = {
        "selected_threshold": 0.5,
        "selected_on": "internal_only",
        "used_final_test_labels": False,
    }
    candidates = {
        "primary": {"model": _DummyModel(), "threshold_selection": threshold},
        "logistic": {"model": _DummyModel(), "threshold_selection": threshold},
        "anomaly": {"score_external": lambda _frame, indices: [0.2 for _index in indices], "threshold_selection": threshold},
        "hybrid_threshold": threshold,
        "majority_class": "non_threat",
    }

    frozen = v400.freeze_predictions(external, candidates, [0], evidence_dir=tmp_path, stamp="test")
    contents = Path(frozen["prediction_path"]).read_text(encoding="utf-8")

    assert frozen["external_labels_loaded_before_prediction_freeze"] is False
    assert "provider_label" not in contents
    assert "original_label" not in contents
    assert frozen["external_rows_used_for_fit"] == 0
    assert frozen["external_rows_used_for_calibration"] == 0
    assert frozen["external_rows_used_for_threshold_selection"] == 0


def test_v400_label_reveal_requires_intact_frozen_predictions(tmp_path, monkeypatch):
    provider = tmp_path / "provider.csv"
    spec = _write_provider_file(provider, ["Benign", "FTP-BruteForce"])
    monkeypatch.setattr(v400, "SOURCE_FILES", (spec,))
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text('{"evidence_id":"2018-02-14:1"}\n', encoding="utf-8")
    frozen = {
        "prediction_path": predictions,
        "prediction_sha256": v400._file_sha256(predictions),
        "prediction_frozen_at": "2000-01-01T00:00:00+00:00",
    }

    revealed = v400.reveal_labels_after_prediction_freeze(
        tmp_path,
        selected_rows={provider.name: {1, 2}},
        prediction_freeze=frozen,
        stamp="test",
    )
    assert revealed["prediction_frozen_before_label_read"] is True
    assert revealed["labels"]["2018-02-14:1"]["human_reviewed"] is False
    assert revealed["labels"]["2018-02-14:1"]["import_ready"] is False

    predictions.write_text("tampered", encoding="utf-8")
    with pytest.raises(RuntimeError, match="hash changed"):
        v400.reveal_labels_after_prediction_freeze(
            tmp_path,
            selected_rows={provider.name: {1}},
            prediction_freeze=frozen,
            stamp="tampered",
        )


def test_v400_overlap_quarantines_internal_and_v399_references():
    internal = {"rows": [{"exact_fingerprint": "internal", "near_fingerprint": "n1", "feature_fingerprint": "f1"}]}
    synthetic = {"rows": [{"exact_fingerprint": "synthetic", "near_fingerprint": "n2", "feature_fingerprint": "f2"}]}
    external = {
        "rows": [
            {"exact_fingerprint": "external", "near_fingerprint": "n3", "feature_fingerprint": "f3"},
            {"exact_fingerprint": "internal", "near_fingerprint": "n4", "feature_fingerprint": "f4"},
            {"exact_fingerprint": "other", "near_fingerprint": "n2", "feature_fingerprint": "f5"},
        ]
    }

    result = v400.audit_external_overlap(internal, synthetic, external)

    assert result["passed"] is True
    assert result["accepted_indices"] == [0]
    assert result["quarantined_indices"] == [1, 2]
    assert result["remaining_overlap_after_quarantine"]["internal_reviewed"]["exact_fingerprint"] == 0
    assert result["remaining_overlap_after_quarantine"]["v399_synthetic"]["near_fingerprint"] == 0


def test_v400_rule_matrix_does_not_fabricate_missing_firewall_fields():
    assert v400.RULE_APPLICABILITY["possible_port_scan"] == "unavailable_missing_source_ip"
    assert v400.RULE_APPLICABILITY["deny_drop_action"] == "unavailable_missing_action"
    assert v400.RULE_APPLICABILITY["high_bytes_outlier"].startswith("applicable")
    assert v400.RULE_APPLICABILITY["high_packets_outlier"].startswith("applicable")


def test_v400_readiness_and_safety_remain_candidate_only(tmp_path, monkeypatch):
    feature_path = tmp_path / "features.csv"
    feature_path.write_text("evidence_id\nrow-1\n", encoding="utf-8")
    internal = {
        "ok": True,
        "rows": [{"log_id": 1}],
        "logs": [],
        "feature_meta": {"numeric_features": [], "categorical_features": []},
    }
    external = {
        "ok": True,
        "rows": [
            {
                "evidence_id": "row-1",
                "provider_file": "provider.csv",
                "provider_day": "2018-02-14",
                "provider_row_number": 1,
                "source_name": "provider",
                "timestamp": None,
            }
        ],
        "feature_meta": {},
    }
    monkeypatch.setattr(v400, "verify_provider_files", lambda _path: {"ok": True, "files": []})
    monkeypatch.setattr(v400.v398, "_database_counts", lambda _db: {"labels": 10, "models": 2, "responses": 0})
    monkeypatch.setattr(v400.v398, "_artifact_state", lambda: {"exists": False})
    monkeypatch.setattr(v400.v398, "_build_dataset", lambda _db, min_samples: internal)
    monkeypatch.setattr(v400.v398, "assign_leakage_groups", lambda _rows: {})
    monkeypatch.setattr(
        v400.v399,
        "_internal_freeze",
        lambda _dataset: {
            "ok": True,
            "split_mode": "random_seed_42",
            "partition": {"fit_idx": []},
            "partition_hash": "frozen",
            "partition_sizes": {},
        },
    )
    monkeypatch.setattr(
        v400,
        "build_feature_only_sample",
        lambda *_args, **_kwargs: {
            "feature_path": feature_path,
            "feature_sha256": v400._file_sha256(feature_path),
            "sampled_rows": 1,
            "feature_columns": [],
            "files": [],
            "sampling": {"label_independent": True},
        },
    )
    monkeypatch.setattr(v400, "_frozen_rule_thresholds", lambda *_args: {"byte_outlier_threshold": 1.0, "packet_outlier_threshold": 1.0})
    monkeypatch.setattr(v400, "build_external_feature_dataset", lambda *_args, **_kwargs: external)
    monkeypatch.setattr(v400, "_synthetic_reference_dataset", lambda _dataset: {"rows": []})
    monkeypatch.setattr(v400.v399, "_close_external_dataset", lambda _dataset: None)
    monkeypatch.setattr(
        v400,
        "audit_external_overlap",
        lambda *_args: {
            "passed": True,
            "attempted_rows": 1,
            "accepted_rows": 1,
            "quarantined_rows": 0,
            "accepted_indices": [0],
            "quarantined_indices": [],
        },
    )
    monkeypatch.setattr(v400.v399, "_fit_frozen_candidates", lambda *_args: {"primary": {"threshold_selection": {}}, "logistic": {"threshold_selection": {}}, "anomaly": {"threshold_selection": {}}, "hybrid_threshold": {}})
    prediction_file = tmp_path / "predictions.jsonl"
    prediction_file.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        v400,
        "freeze_predictions",
        lambda *_args, **_kwargs: {
            "prediction_path": prediction_file,
            "prediction_sha256": v400._file_sha256(prediction_file),
            "prediction_frozen_at": "2000-01-01T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(
        v400,
        "reveal_labels_after_prediction_freeze",
        lambda *_args, **_kwargs: {
            "labels": {},
            "label_sha256": "labels",
            "label_row_count": 1,
            "label_read_started_at": "2000-01-01T00:00:01+00:00",
            "prediction_frozen_before_label_read": True,
            "class_distribution": {"benign": 1},
            "provider_label_distribution": {"Benign": 1},
        },
    )
    monkeypatch.setattr(
        v400,
        "attach_revealed_labels",
        lambda *_args: {"scored_indices": [0], "unsupported_indices": [], "scored_rows": 1, "unsupported_rows": 0},
    )
    monkeypatch.setattr(
        v400,
        "evaluate_external_predictions",
        lambda *_args: {"split_results": [], "stability": {}, "worst_primary": {}},
    )
    session = SimpleNamespace(new=set(), dirty=set(), deleted=set())

    result = v400.run_v400_provider_blinded_external_validation(
        session,
        evidence_dir=tmp_path,
        output_dir=tmp_path,
        write_output=False,
    )

    assert result["ok"] is True
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["readiness"]["production_promoted"] is False
    assert result["readiness"]["model_activated"] is False
    assert result["readiness"]["response_automation_allowed"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["response_actions_created"] == 0
