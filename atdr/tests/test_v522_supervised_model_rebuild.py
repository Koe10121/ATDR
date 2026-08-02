from __future__ import annotations

import json
import sqlite3
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from atdr.app.detection import supervised_detector
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v522_supervised_model_rebuild as rebuild
from atdr.app.detection import v56_private_panos_model_repair as v56


def _chronological_sample(path: Path, *, rows: int = 96) -> None:
    template = Path("data/samples/paloalto-demo.txt").read_text(encoding="utf-8").splitlines()[0]
    started = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
    output: list[str] = []
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


def _empty_frame(rows: int, *, all_null_first: bool = False) -> pd.DataFrame:
    values: dict[str, list[object]] = {}
    for position, field in enumerate(v56.V56_NUMERIC_FEATURES):
        if all_null_first and position == 0:
            values[field] = [None] * rows
        else:
            values[field] = [float((index + position) % 11) for index in range(rows)]
    for position, field in enumerate(v56.V56_CATEGORICAL_FEATURES):
        values[field] = [f"value-{(index + position) % 3}" for index in range(rows)]
    return pd.DataFrame(values)


def _bundle(rows: int, *, all_null_first: bool = False) -> dict:
    labels = [
        ("benign", "non_threat"),
        ("benign_unusual", "non_threat"),
        ("suspicious", "needs_review"),
        ("malicious", "needs_review"),
    ]
    originals = [labels[index % len(labels)][0] for index in range(rows)]
    targets = [labels[index % len(labels)][1] for index in range(rows)]
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return {
        "frame": _empty_frame(rows, all_null_first=all_null_first),
        "rows": [
            {
                "timestamp": started + timedelta(minutes=index),
                "app": "synthetic-app",
                "action": "allow" if index % 2 == 0 else "deny",
                "dst_port": 443 if index % 2 == 0 else 22,
                "schema": "parsed",
                "provenance": "manual",
                "human_reviewed": True,
                "group_size": 1,
                "original_label": originals[index],
                "source_identity": f"source-{index % 2}",
            }
            for index in range(rows)
        ],
        "original_labels": originals,
        "targets": targets,
        "base_weights": [1.0] * rows,
    }


def test_development_policy_never_labels_future_role(tmp_path: Path) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample)
    connection = sqlite3.connect(":memory:")
    v56.stream_private_file_to_disposable_index(
        sample,
        connection,
        database_url="sqlite:///:memory:",
    )
    v56.predeclare_chronological_roles(connection)
    v56.build_disposable_behavior_aggregates(connection)

    result = rebuild.apply_development_only_assisted_policy(connection)

    assert result["human_reviewed_true_count"] == 0
    assert result["future_role_rows_labeled"] == 0
    assert result["future_role_opened"] is False
    assert result["blind_pack_opened"] is False
    assert connection.execute("SELECT COUNT(*) FROM events WHERE role_rank=3").fetchone()[0] > 0
    assert connection.execute("SELECT COUNT(*) FROM assisted_groups WHERE role_rank=3").fetchone()[0] == 0


def test_governed_provenance_does_not_treat_reviewed_flag_as_authorship(
    monkeypatch,
) -> None:
    imports = supervised_detector._optional_imports()
    template = {role: _bundle(2) for role in ("development_fit", "calibration", "threshold")}
    monkeypatch.setattr(
        rebuild.v56,
        "build_human_role_bundles",
        lambda *_args, **_kwargs: template,
    )
    rows = [
        {
            "reviewed": True,
            "label_source": "manual",
            "source_name": "source-a",
        },
        {
            "reviewed": True,
            "label_source": "rule_assisted",
            "source_name": "source-b",
        },
        {
            "reviewed": True,
            "label_source": "manual",
            "source_name": "source-a",
        },
        {
            "reviewed": True,
            "label_source": "hybrid_assisted",
            "source_name": "source-b",
        },
        {
            "reviewed": True,
            "label_source": "reviewed_import",
            "source_name": "source-a",
        },
        {
            "reviewed": False,
            "label_source": "ml_assisted",
            "source_name": "source-b",
        },
    ]
    dataset = {"imports": imports, "rows": rows}
    partition = {
        "fit_idx": [0, 1],
        "calibration_idx": [2, 3],
        "threshold_idx": [4, 5],
    }

    bundles, summary = rebuild._governed_bundles_with_provenance(
        dataset,
        partition,
    )

    assert summary["genuinely_human_reviewed_rows"] == 3
    assert summary["assisted_or_weak_rows"] == 3
    assert summary["reviewed_flag_not_treated_as_human_authorship"] is True
    assert bundles["development_fit"]["rows"][0]["human_reviewed"] is True
    assert bundles["development_fit"]["rows"][1]["human_reviewed"] is False
    assert bundles["development_fit"]["base_weights"][0] == 1.0
    assert bundles["development_fit"]["base_weights"][1] < 1.0


def test_feature_stabilization_keeps_contract_without_all_null_warning() -> None:
    view = {
        "name": "all_null_regression",
        "fit": _bundle(40, all_null_first=True),
        "calibration": _bundle(20, all_null_first=True),
        "threshold": _bundle(20, all_null_first=True),
        "evaluation": _bundle(20, all_null_first=True),
    }

    stabilized, report = rebuild._stabilize_view(view)

    field = v56.V56_NUMERIC_FEATURES[0]
    assert report["all_null_numeric_defaults"] == [field]
    assert report["feature_columns_dropped"] == []
    assert stabilized["fit"]["frame"][field].isna().sum() == 0
    assert report["feature_count"] == 40


def test_actual_model_comparison_freezes_only_in_memory_shadow_candidate() -> None:
    imports = supervised_detector._optional_imports()
    view = {
        "name": "synthetic_development_view",
        "fit": _bundle(80),
        "calibration": _bundle(40),
        "threshold": _bundle(40),
        "evaluation": _bundle(40),
        "uses_future_validation": False,
        "uses_locked_v53": False,
    }

    comparison, leader = v56.run_supervised_development_comparison(
        imports,
        [view],
    )
    candidate = rebuild._candidate_public(
        leader,
        warning_report=rebuild._warning_summary([]),
    )

    assert comparison["status"] == "evaluated"
    assert len(comparison["candidate_summaries"]) == len(v56.V56_CANDIDATE_SPECS)
    assert candidate is not None
    assert candidate["frozen_before_blind_label_access"] is True
    assert candidate["blind_labels_used_for_selection"] is False
    assert candidate["eligible_for_activation"] is False
    assert candidate["active_artifact_written"] is False
    assert candidate["model_activated"] is False
    assert candidate["model_promoted"] is False


def test_stability_selection_does_not_prefer_one_weak_policy_pass() -> None:
    def summary(*, f1: float, fpr: float, suspicious: float, ece: float) -> dict:
        return {
            "evaluated_views": 4,
            "passing_views": 1,
            "all_views_passed": False,
            "metric_ranges": {
                "queue_f1": {"minimum": f1},
                "benign_like_false_positive_rate": {"maximum": fpr},
                "suspicious_recall": {"minimum": suspicious},
                "malicious_recall": {"minimum": 1.0},
            },
            "calibration_ranges": {
                "expected_calibration_error": {"maximum": ece},
                "max_confidence_accuracy_gap": {"maximum": 0.4},
            },
        }

    strategies = [
        {
            "status": "evaluated",
            "name": "unstable_one_pass",
            "model_type": "hist_gradient_boosting",
            "target_mode": "binary_soc_queue",
            "calibration_method": "sigmoid",
            "threshold_selection": {"selected_threshold": 0.9},
        },
        {
            "status": "evaluated",
            "name": "stable_candidate",
            "model_type": "extra_trees",
            "target_mode": "hierarchical_two_stage",
            "calibration_method": "sigmoid",
            "threshold_selection": {"selected_threshold": 0.4},
        },
    ]
    comparison = {
        "candidate_summaries": {
            "unstable_one_pass": summary(
                f1=0.44,
                fpr=0.43,
                suspicious=0.03,
                ece=0.52,
            ),
            "stable_candidate": summary(
                f1=0.81,
                fpr=0.05,
                suspicious=0.50,
                ece=0.37,
            ),
        },
        "views": [{"name": "manual_provenance_holdout", "strategies": strategies}],
    }

    selected = rebuild._select_stability_leader(comparison)

    assert selected is not None
    assert selected["name"] == "stable_candidate"
    assert selected["selection_basis"].startswith("predeclared_cross_view")


def test_environment_warning_is_not_a_model_quality_blocker() -> None:
    warning = warnings.WarningMessage(
        message=UserWarning("Could not find the number of physical cores; returning logical cores"),
        category=UserWarning,
        filename="test.py",
        lineno=1,
        file=None,
        line=None,
    )

    report = rebuild._warning_summary([warning])

    assert report["count"] == 1
    assert report["informational_count"] == 1
    assert report["quality_count"] == 0


def test_preflight_reproduces_v521_lock_without_side_effects(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = tmp_path / "private.log"
    evidence_dir = tmp_path / "ignored-evidence"
    _chronological_sample(sample)
    prepared = v521.run_v521_native_panos_evidence(
        sample_path=sample,
        use_temp_db=True,
        output_dir=evidence_dir,
        review_limit=40,
    )
    assert prepared["ok"] is True

    rows = [
        {
            "index": index,
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index),
            "leakage_group": f"group-{index}",
        }
        for index in range(80)
    ]
    dataset = {"ok": True, "rows": rows}
    partition = {
        "fit_idx": list(range(0, 40)),
        "calibration_idx": list(range(40, 50)),
        "threshold_idx": list(range(50, 60)),
        "final_test_idx": list(range(60, 70)),
        "quarantined_idx": list(range(70, 80)),
    }
    counts = {
        "raw_logs": 10,
        "normalized_logs": 10,
        "alerts": 1,
        "ml_labels": 4,
        "ml_model_runs": 2,
        "detection_runs": 3,
        "response_actions": 0,
    }
    artifacts = {"supervised": {"exists": False}}
    monkeypatch.setattr(rebuild.v52, "_prepare_dataset", lambda *_a, **_k: dataset)
    monkeypatch.setattr(
        rebuild.frozen,
        "build_frozen_partition",
        lambda *_a, **_k: partition,
    )
    monkeypatch.setattr(
        rebuild.frozen,
        "audit_partition_leakage",
        lambda *_a, **_k: {"passed": True},
    )
    monkeypatch.setattr(
        rebuild.frozen,
        "_database_counts",
        lambda *_a: dict(counts),
    )
    monkeypatch.setattr(
        rebuild.v55,
        "_model_artifact_states",
        lambda: dict(artifacts),
    )
    monkeypatch.setattr(
        rebuild.v54,
        "build_evidence_lock",
        lambda *_a, **_k: {"ok": True},
    )
    monkeypatch.setattr(
        rebuild.v54,
        "validate_evidence_lock",
        lambda *_a, **_k: {"passed": True, "status": "matched"},
    )

    result = rebuild.run_v522_supervised_model_rebuild(
        SimpleNamespace(),
        sample_path=sample,
        use_temp_db=True,
        evidence_dir=evidence_dir,
        output_dir=evidence_dir,
        preflight_only=True,
        write_output=False,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["status"] == "preflight_complete"
    assert result["native_evidence"]["role_lock_reproduced"] is True
    assert result["native_evidence"]["blind_pack_opened"] is False
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["model_artifacts_unchanged"] is True
    assert result["safety"]["labels_created"] == 0
    assert result["safety"]["response_actions_created"] == 0
    assert str(sample) not in serialized
    assert sample.name not in serialized
    assert "source_file_sha256" not in serialized


def test_runner_fails_closed_without_temp_db_and_redacts_path(tmp_path: Path) -> None:
    sample = tmp_path / "secret-private.log"
    _chronological_sample(sample)

    result = rebuild.run_v522_supervised_model_rebuild(
        SimpleNamespace(),
        sample_path=sample,
        use_temp_db=False,
        output_dir=tmp_path,
    )

    serialized = json.dumps(result)
    assert result["ok"] is False
    assert result["status"] == "failed_closed_temp_db_acknowledgement_required"
    assert str(sample) not in serialized
    assert sample.name not in serialized
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
