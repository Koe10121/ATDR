import csv
import hashlib
from pathlib import Path

import pandas as pd

from atdr.app.detection import v519_independent_labeled_validation as v519


def _write_provider_file(path: Path, labels: list[str]) -> dict:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(v519.REQUIRED_COLUMNS)
        for index, label in enumerate(labels, start=1):
            writer.writerow(
                [
                    f"2011/08/15 17:{index:02d}:00.000000",
                    "1.5",
                    "tcp" if index % 2 else "udp",
                    f"192.0.2.{index}",
                    str(1000 + index),
                    "->",
                    f"198.51.100.{index}",
                    str(4000 + index),
                    "CON",
                    "0",
                    "0",
                    str(index + 2),
                    str(index * 500),
                    str(index * 300),
                    label,
                ]
            )
    return {
        "logical_name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _provider_fixture(tmp_path: Path, labels: list[str]) -> dict:
    files = []
    for spec in v519.SOURCE_FILES:
        files.append(_write_provider_file(tmp_path / spec["logical_name"], labels))
    return {
        "manifest_version": v519.V519_MANIFEST_VERSION,
        "identity_sha256": "fixture-identity",
        "files": files,
    }


def _public_sample_rows(sample: dict) -> list[dict]:
    return [
        {
            key: value
            for key, value in row.items()
            if key not in {"exact_hash", "near_group"}
        }
        for row in sample["rows"]
    ]


def test_v519_feature_sampling_is_label_sealed(tmp_path):
    manifest = _provider_fixture(
        tmp_path,
        ["From-Normal", "From-Botnet", "Background"],
    )
    first = v519.build_label_sealed_feature_sample(
        tmp_path,
        manifest,
        rows_per_scenario=3,
    )
    _provider_fixture(
        tmp_path,
        ["From-Botnet", "Background", "From-Normal"],
    )
    second = v519.build_label_sealed_feature_sample(
        tmp_path,
        manifest,
        rows_per_scenario=3,
    )

    assert first["ok"] is True
    assert first["labels_accessed"] is False
    assert first["labels_used_for_sampling"] is False
    assert first["labels_used_for_features"] is False
    assert _public_sample_rows(first) == _public_sample_rows(second)


def test_v519_provider_taxonomy_is_binary_and_ambiguous_safe():
    threat = v519._provider_truth(
        "From-Botnet-V46-TCP",
        scenario_id="ctu13-scenario-05",
    )
    normal = v519._provider_truth(
        "From-Normal-V46",
        scenario_id="ctu13-scenario-05",
    )
    inbound = v519._provider_truth(
        "To-Botnet-V46",
        scenario_id="ctu13-scenario-05",
    )
    background = v519._provider_truth(
        "flow=To-Background-CVUT-WebServer",
        scenario_id="ctu13-scenario-05",
    )
    wrapped_threat = v519._provider_truth(
        "flow=From-Botnet-V46-TCP",
        scenario_id="ctu13-scenario-05",
    )

    assert threat["truth"] == "needs_review"
    assert normal["truth"] == "non_threat"
    assert inbound["eligibility"] == "excluded"
    assert background["eligibility"] == "excluded"
    assert wrapped_threat["truth"] == "needs_review"
    assert "suspicious" not in {threat["truth"], normal["truth"]}
    assert "malicious" not in {threat["truth"], normal["truth"]}


class _DummyPipeline:
    classes_ = ["needs_review", "non_threat"]

    def predict_proba(self, frame):
        return [[0.8, 0.2] for _index in range(len(frame))]


def test_v519_prediction_freeze_precedes_one_shot_label_reveal(tmp_path):
    manifest = _provider_fixture(
        tmp_path,
        ["From-Botnet", "From-Normal", "Background"],
    )
    manifest_path = tmp_path / "manifest.json"
    v519._write_json(manifest_path, manifest)
    sample = v519.build_label_sealed_feature_sample(
        tmp_path,
        manifest,
        rows_per_scenario=3,
    )
    candidate = {
        "_pipeline": _DummyPipeline(),
        "_artifact_hash": "candidate-fixture",
        "threshold": 0.5,
    }
    imports = (None, pd)

    prediction = v519.freeze_predictions(
        imports,
        output_dir=tmp_path,
        manifest_path=manifest_path,
        manifest=manifest,
        candidate=candidate,
        feature_sample=sample,
    )
    assert prediction["ok"] is True
    assert prediction["labels_revealed"] is False
    assert all("192.0.2" not in str(row) for row in prediction["rows"])
    assert all("198.51.100" not in str(row) for row in prediction["rows"])

    revealed = v519.reveal_provider_labels_once(
        tmp_path,
        output_dir=tmp_path,
        prediction_freeze=prediction,
    )
    assert revealed["ok"] is True
    assert revealed["prediction_frozen_before_label_read"] is True
    assert revealed["labels_used_for_tuning"] is False

    repeated = v519.reveal_provider_labels_once(
        tmp_path,
        output_dir=tmp_path,
        prediction_freeze=prediction,
    )
    assert repeated["ok"] is False
    assert repeated["status"] == "failed_closed_blind_labels_already_revealed"


def test_v519_evaluation_is_conservative_and_rule_partial():
    predictions = [
        {
            "review_token": "one",
            "scenario_id": "ctu13-scenario-05",
            "prediction": "needs_review",
            "threat_score": 0.9,
            "rule_prediction": "non_threat",
            "source_group": "source-a",
            "protocol": "tcp",
            "dst_port": 443,
            "bytes_bucket": 3,
            "packets_bucket": 1,
        },
        {
            "review_token": "two",
            "scenario_id": "ctu13-scenario-05",
            "prediction": "non_threat",
            "threat_score": 0.1,
            "rule_prediction": "non_threat",
            "source_group": "source-b",
            "protocol": "udp",
            "dst_port": 53,
            "bytes_bucket": 2,
            "packets_bucket": 1,
        },
        {
            "review_token": "three",
            "scenario_id": "ctu13-scenario-05",
            "prediction": "non_threat",
            "threat_score": 0.2,
            "rule_prediction": "non_threat",
            "source_group": "source-c",
            "protocol": "tcp",
            "dst_port": 80,
            "bytes_bucket": 2,
            "packets_bucket": 1,
        },
    ]
    labels = {
        "one": {
            "truth": "needs_review",
            "eligibility": "comparable",
            "provider_class": "from_botnet",
            "attack_family": "virut_botnet",
        },
        "two": {
            "truth": "non_threat",
            "eligibility": "comparable",
            "provider_class": "from_normal",
            "attack_family": "normal",
        },
        "three": {
            "truth": "abstain",
            "eligibility": "excluded",
            "provider_class": "ambiguous_background",
            "attack_family": "ambiguous",
        },
    }

    result = v519.evaluate_blind_predictions(predictions, labels)

    assert result["status"] == "evaluated_blind_once"
    assert result["metrics"]["threat_positive_f1"] == 1.0
    assert result["metrics"]["suspicious_recall"] is None
    assert result["metrics"]["malicious_recall"] is None
    assert result["partial_deterministic_rule_baseline"]["status"] == "partial_schema_only"
    assert result["schema_transfer"]["status"] == "ood_warning"
    assert result["labels_used_for_tuning"] is False


def test_v519_execute_requires_explicit_confirmation():
    result = v519.run_v519_independent_labeled_validation(
        object(),
        dataset_path=Path("unused"),
        manifest_path=Path("unused"),
        execute=True,
        confirm=False,
    )

    assert result["ok"] is False
    assert result["status"] == "failed_closed_execute_requires_confirm"
    assert result["lifecycle_state"] == "shadow_observation"


def test_v519_adapter_recovery_is_one_shot(tmp_path):
    v519._write_json(
        tmp_path / v519.V519_STATE,
        {
            "labels_revealed": True,
            "adapter_recovery_completed": True,
        },
    )

    result = v519.run_v519_label_adapter_recovery(
        object(),
        dataset_path=tmp_path,
        output_dir=tmp_path,
        write_output=False,
    )

    assert result["ok"] is False
    assert result["status"] == "failed_closed_adapter_recovery_already_completed"
    assert result["fresh_blind_claim"] is False


def test_v519_fails_closed_on_any_authoritative_database_write(monkeypatch, tmp_path):
    baseline = {
        "ml_labels": 4,
        "ml_model_runs": 3,
        "detection_runs": 2,
        "alerts": 1,
        "response_actions": 0,
    }

    monkeypatch.setattr(
        v519,
        "create_or_verify_evidence_manifest",
        lambda *_args, **_kwargs: {
            "ok": True,
            "status": "manifest_identity_verified",
            "manifest": {"dataset_id": "independent-test-evidence"},
        },
    )
    monkeypatch.setattr(
        v519,
        "audit_prior_evidence_and_load_candidate",
        lambda **_kwargs: {
            "ok": True,
            "status": "frozen_candidate_verified",
            "active": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
    )
    monkeypatch.setattr(
        v519,
        "build_label_sealed_feature_sample",
        lambda *_args, **_kwargs: {
            "ok": True,
            "status": "label_sealed_feature_sample_ready",
            "sampled_rows": 1,
            "files": [],
            "duplicate_audit": {},
        },
    )
    monkeypatch.setattr(
        v519.v55,
        "_model_artifact_states",
        lambda: {"active_artifact": None},
    )

    for changed_counter in baseline:
        after = dict(baseline)
        after[changed_counter] += 1
        snapshots = iter((dict(baseline), after))
        monkeypatch.setattr(
            v519.frozen,
            "_database_counts",
            lambda _db, snapshots=snapshots: next(snapshots),
        )

        result = v519.run_v519_independent_labeled_validation(
            object(),
            dataset_path=tmp_path,
            manifest_path=tmp_path / "manifest.json",
            output_dir=tmp_path,
            write_output=False,
        )

        assert result["ok"] is False
        assert result["safety"]["configured_database_unchanged"] is False
        assert result["safety"][
            {
                "ml_labels": "labels_created",
                "ml_model_runs": "model_runs_created",
                "detection_runs": "detection_runs_created",
                "alerts": "alerts_created",
                "response_actions": "response_actions_created",
            }[changed_counter]
        ] == 1
