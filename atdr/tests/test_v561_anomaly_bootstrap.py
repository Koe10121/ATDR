from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from atdr.app.services import v561_anomaly_bootstrap_service as bootstrap


def _copy_committed_samples(destination: Path) -> Path:
    source = Path(__file__).resolve().parents[2] / "data" / "samples" / "scenarios"
    target = destination / "data" / "samples" / "scenarios"
    target.mkdir(parents=True)
    for name in bootstrap.COMMITTED_SYNTHETIC_FILES:
        shutil.copy2(source / name, target / name)
    return target


def test_committed_synthetic_preflight_is_reproducible_and_private():
    root = Path(__file__).resolve().parents[2]

    first = bootstrap.inspect_anomaly_evidence(
        project_root=root,
        use_committed_synthetic_sample=True,
    )
    second = bootstrap.inspect_anomaly_evidence(
        project_root=root,
        use_committed_synthetic_sample=True,
    )

    assert first.public == second.public
    assert first.public["passed"] is True
    assert first.public["observed_rows"] == 45
    assert first.public["eligible_baseline_rows"] == 41
    assert first.public["exclusion_reasons"] == {"unresolved_application": 4}
    encoded = json.dumps(first.public)
    assert str(root) not in encoded
    assert "192.0.2." not in encoded
    assert first.public["source_paths_exposed"] is False
    assert first.public["raw_logs_exposed"] is False
    assert first.public["fingerprints_exposed"] is False


def test_preflight_rejects_insufficient_invalid_and_duplicate_evidence(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    source_root = Path(__file__).resolve().parents[2] / "data" / "samples" / "scenarios"
    valid_line = (source_root / "normal_allowed_traffic.txt").read_text(encoding="utf-8").splitlines()[0]

    insufficient = root / "insufficient.log"
    insufficient.write_text("\n".join([valid_line] * 2), encoding="utf-8")
    result = bootstrap.inspect_anomaly_evidence(
        project_root=root,
        evidence_path=insufficient,
    )
    assert result.public["passed"] is False
    assert result.public["gates"]["minimum_eligible_rows"] is False

    invalid = root / "invalid.log"
    invalid.write_text("\n".join(f"invalid record {index}" for index in range(25)), encoding="utf-8")
    result = bootstrap.inspect_anomaly_evidence(project_root=root, evidence_path=invalid)
    assert result.public["gates"]["parser_quality"] is False
    assert result.public["gates"]["schema_completeness"] is False

    duplicate = root / "duplicate.log"
    duplicate.write_text("\n".join([valid_line] * 25), encoding="utf-8")
    result = bootstrap.inspect_anomaly_evidence(project_root=root, evidence_path=duplicate)
    assert result.public["gates"]["duplicate_containment"] is False


def test_execute_requires_exact_confirmation_and_protects_existing_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    root = tmp_path / "project"
    _copy_committed_samples(root)
    artifact = root / "atdr" / "models" / "isolation_forest.joblib"
    monkeypatch.setattr(bootstrap, "_git_ignored", lambda *_args, **_kwargs: True)

    report = bootstrap.run_governed_anomaly_bootstrap(
        project_root=root,
        use_committed_synthetic_sample=True,
        execute=True,
        confirmation="wrong",
        artifact_path=artifact,
    )
    assert report["status"] == "execution_confirmation_required"
    assert report["executed"] is False
    assert not artifact.exists()

    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"protected-existing-artifact")
    with pytest.raises(bootstrap.AnomalyBootstrapError, match="already exists"):
        bootstrap.run_governed_anomaly_bootstrap(
            project_root=root,
            use_committed_synthetic_sample=True,
            execute=True,
            confirmation=bootstrap.EXECUTION_CONFIRMATION,
            artifact_path=artifact,
        )
    assert artifact.read_bytes() == b"protected-existing-artifact"


def test_destination_must_be_inside_project_and_git_ignored(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    root = tmp_path / "project"
    _copy_committed_samples(root)
    inside = root / "atdr" / "models" / "isolation_forest.joblib"
    monkeypatch.setattr(bootstrap, "_git_ignored", lambda *_args, **_kwargs: False)

    with pytest.raises(bootstrap.AnomalyBootstrapError, match="Git-ignored"):
        bootstrap.run_governed_anomaly_bootstrap(
            project_root=root,
            use_committed_synthetic_sample=True,
            artifact_path=inside,
        )

    outside = tmp_path / "outside.joblib"
    monkeypatch.setattr(bootstrap, "_git_ignored", lambda *_args, **_kwargs: True)
    with pytest.raises(bootstrap.AnomalyBootstrapError, match="inside the project"):
        bootstrap.run_governed_anomaly_bootstrap(
            project_root=root,
            use_committed_synthetic_sample=True,
            artifact_path=outside,
        )


def test_governed_bootstrap_uses_disposable_storage_and_stays_advisory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    root = tmp_path / "project"
    _copy_committed_samples(root)
    artifact = root / "atdr" / "models" / "isolation_forest.joblib"
    monkeypatch.setattr(bootstrap, "_git_ignored", lambda *_args, **_kwargs: True)

    report = bootstrap.run_governed_anomaly_bootstrap(
        project_root=root,
        use_committed_synthetic_sample=True,
        execute=True,
        confirmation=bootstrap.EXECUTION_CONFIRMATION,
        artifact_path=artifact,
    )

    assert report["ok"] is True
    assert report["executed"] is True
    assert report["status"] == "governed_advisory_anomaly_bootstrap_complete"
    assert artifact.is_file()
    manifest_path = bootstrap.anomaly_manifest_path(artifact)
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert bootstrap._manifest_is_valid(manifest) is True
    assert manifest == bootstrap._deterministic_manifest(
        bootstrap.inspect_anomaly_evidence(
            project_root=root,
            use_committed_synthetic_sample=True,
        ),
        contamination=bootstrap.get_settings().ml_contamination,
        acceptance=report["acceptance"],
    )
    assert manifest["validation"]["evidence_gates_passed"] is True
    assert manifest["validation"]["advisory_scoring_passed"] is True
    assert manifest["validation"]["model_driven_alerts"] == 0
    assert manifest["validation"]["detection_runs_created"] == 0
    malformed_manifest = json.loads(json.dumps(manifest))
    malformed_manifest["evidence"]["parse_rate"] = "not-a-rate"
    assert bootstrap._manifest_is_valid(malformed_manifest) is False
    assert report["current_capability"]["label"] == "Advisory anomaly model available"
    assert report["current_capability"]["threat_accuracy_validated"] is False
    assert report["acceptance"]["rules_alert_authoritative"] is True
    assert report["acceptance"]["model_driven_alerts"] == 0
    assert report["acceptance"]["model_driven_suppressions"] == 0
    assert report["acceptance"]["labels_created"] == 0
    assert report["acceptance"]["model_runs_created"] == 0
    assert report["acceptance"]["detection_runs_created"] == 0
    assert report["acceptance"]["response_actions_created"] == 0
    assert report["acceptance"]["hybrid_decision_support_only"] is True
    assert report["acceptance"]["model_only_alert_creation_allowed"] is False
    assert report["acceptance"]["supervised_state"] == "unqualified"
    assert report["acceptance"]["supervised_model_activated"] is False
    assert report["acceptance"]["response_state"] == "simulation_only"
    assert report["acceptance"]["real_firewall_blocking_enabled"] is False
    assert report["temporary_storage_cleaned"] is True
    assert not list(root.rglob("bootstrap.db"))


def test_atomic_replacement_restores_existing_files_on_install_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    artifact = tmp_path / "isolation_forest.joblib"
    manifest = tmp_path / "isolation_forest.bootstrap.json"
    pending_artifact = tmp_path / ".pending-isolation_forest.joblib"
    pending_manifest = tmp_path / ".pending-isolation_forest.bootstrap.json"
    artifact.write_bytes(b"old-artifact")
    manifest.write_text("old-manifest", encoding="utf-8")
    pending_artifact.write_bytes(b"new-artifact")
    pending_manifest.write_text("new-manifest", encoding="utf-8")
    real_replace = bootstrap.os.replace

    def fail_manifest_install(source: Path, destination: Path) -> None:
        if Path(source) == pending_manifest and Path(destination) == manifest:
            raise OSError("simulated install interruption")
        real_replace(source, destination)

    monkeypatch.setattr(bootstrap.os, "replace", fail_manifest_install)
    with pytest.raises(OSError, match="simulated install interruption"):
        bootstrap._atomic_install(
            pending_artifact=pending_artifact,
            artifact_path=artifact,
            pending_manifest=pending_manifest,
            manifest_path=manifest,
            replace_existing=True,
        )

    assert artifact.read_bytes() == b"old-artifact"
    assert manifest.read_text(encoding="utf-8") == "old-manifest"
    assert not list(tmp_path.glob(".backup-*"))
    assert not list(tmp_path.glob(".pending-*"))


def test_status_is_read_only_and_does_not_train(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    artifact = root / "atdr" / "models" / "isolation_forest.joblib"

    missing = bootstrap.anomaly_bootstrap_status(
        project_root=root,
        artifact_path=artifact,
    )
    assert missing["label"] == "Advisory anomaly model unavailable"
    assert missing["bootstrap_required"] is True
    assert missing["threat_accuracy_validated"] is False
    assert not artifact.exists()

    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"legacy")
    legacy = bootstrap.anomaly_bootstrap_status(
        project_root=root,
        artifact_path=artifact,
    )
    assert legacy["label"] == "Advisory anomaly model available"
    assert legacy["state"] == "legacy_artifact_advisory_only"
    assert legacy["bootstrap_required"] is True


def test_normal_setup_and_start_never_execute_anomaly_training():
    root = Path(__file__).resolve().parents[2]
    setup_source = (root / "scripts" / "setup_team.ps1").read_text(encoding="utf-8")
    start_source = (root / "scripts" / "start_system.ps1").read_text(encoding="utf-8")

    assert "run_v561_governed_anomaly_bootstrap" not in setup_source
    assert "GOVERNED_ADVISORY_ANOMALY_BOOTSTRAP" not in setup_source
    assert "-Execute -Confirm GOVERNED_ADVISORY_ANOMALY_BOOTSTRAP" not in start_source
    assert "Advisory anomaly model unavailable" in start_source
    assert bootstrap.CORRECTIVE_COMMAND in start_source


def test_safe_error_never_exposes_unexpected_exception_details(tmp_path: Path):
    private_path = tmp_path / "private-evidence.log"
    report = bootstrap.safe_bootstrap_error(RuntimeError(f"failed at {private_path}"))

    encoded = json.dumps(report)
    assert str(private_path) not in encoded
    assert report["status"] == "bootstrap_failed_safely"
    assert report["source_paths_exposed"] is False
    assert report["model_activated"] is False
    assert report["response_actions_created"] == 0
