from __future__ import annotations

import json
from pathlib import Path

from atdr.app.services import v560_clean_machine_acceptance_service as acceptance


def test_preflight_is_remote_clone_focused_path_safe_and_read_only(monkeypatch, tmp_path: Path):
    root = tmp_path / "source workspace"
    root.mkdir()
    package = tmp_path / "approved-shell.zip"
    package.write_bytes(b"fixture")

    monkeypatch.setattr(acceptance.os, "name", "nt")
    monkeypatch.setattr(acceptance, "_command", lambda name: name)
    monkeypatch.setattr(acceptance, "_python311_command", lambda _root: (["py", "-3.11"], "Python 3.11.9"))
    monkeypatch.setattr(
        acceptance,
        "_tool_version",
        lambda command, cwd: (True, "v20.19.0" if command[0] == "node" else "10.8.2"),
    )
    monkeypatch.setattr(
        acceptance,
        "_git_text",
        lambda _root, arguments: (
            "https://code.invalid/team/atdr.git"
            if arguments == ["remote", "get-url", "origin"]
            else "a" * 40
        ),
    )
    monkeypatch.setattr(acceptance, "_working_tree_clean", lambda _root: False)
    monkeypatch.setattr(acceptance, "_tcp_available", lambda port: port == 27017)
    monkeypatch.setattr(acceptance, "_port_is_free", lambda port: port in acceptance.REQUIRED_PORTS)
    monkeypatch.setattr(
        acceptance,
        "verify_shell_package",
        lambda **_kwargs: {"ok": True, "release_version": "1.4.0-atdr.1"},
    )

    report = acceptance.build_clean_machine_preflight(root=root, shell_package=package)

    assert report["ok"] is True
    assert report["status"] == "ready_for_disposable_acceptance"
    assert report["observations"]["authoritative_worktree_clean"] is False
    assert report["configured_database_accessed"] is False
    assert report["configured_shell_modified"] is False
    assert str(root) not in json.dumps(report)
    assert str(package) not in json.dumps(report)


def test_clone_hygiene_rejects_private_or_generated_state(tmp_path: Path, monkeypatch):
    clone = tmp_path / "ATDR"
    clone.mkdir()
    (clone / "README.md").write_text("safe", encoding="utf-8")
    monkeypatch.setattr(acceptance, "_working_tree_clean", lambda _root: True)
    assert all(acceptance._clone_hygiene(clone).values())

    (clone / ".env").write_text("PRIVATE=value", encoding="utf-8")
    report = acceptance._clone_hygiene(clone)
    assert report["private_file_absent"] is False

    (clone / ".env").unlink()
    (clone / "ml_baseline_reviews").mkdir()
    report = acceptance._clone_hygiene(clone)
    assert report["generated_directories_absent"] is False


def test_disposable_provider_profile_is_synthetic_and_bounded(tmp_path: Path):
    profile = acceptance._write_disposable_provider_profile(tmp_path)
    backend = acceptance._dotenv(profile.root / "backend-node/.env.local")
    frontend = acceptance._dotenv(profile.root / "frontend-vue/.env.localdev")

    assert profile.mongo_database.startswith("atdr_v560_")
    assert backend["PROJECT_ENV"] == "disposable"
    assert backend["PROJECT_AUTH_REQUIRE_2FA"] == "true"
    assert backend["IAM_SDK_BASE_URL"] == "https://iam.invalid"
    assert backend["GOOGLE_CLIENT_ID"] == frontend["VUE_APP_CLIENTID"]
    assert not any("replace" in value.lower() for value in backend.values())
    assert all(value not in json.dumps({"configured": True}) for value in profile.secret_values)


def test_temp_cleanup_refuses_outside_target_and_handles_verified_tree(tmp_path: Path):
    temp_root = tmp_path / "temporary-root"
    temp_root.mkdir()
    verified = temp_root / "atdr-v560-safe"
    verified.mkdir()
    (verified / "nested").mkdir()
    (verified / "nested/file.txt").write_text("data", encoding="utf-8")
    outside = tmp_path / "atdr-v560-outside"
    outside.mkdir()

    assert acceptance.remove_verified_temp_workspace(outside, temp_root=temp_root) is False
    assert outside.exists()
    assert acceptance.remove_verified_temp_workspace(verified, temp_root=temp_root) is True
    assert not verified.exists()


def test_packaged_handoff_contract_requires_auth_one_time_exchange_and_secret_safety(tmp_path: Path):
    route = tmp_path / "backend-node/server/Project/atdr/atdr_handoff.routes.js"
    service = tmp_path / "backend-node/server/Project/atdr/service/atdr_handoff.js"
    route.parent.mkdir(parents=True)
    service.parent.mkdir(parents=True)
    route.write_text(
        "\n".join(
            (
                "router.post('/start', account.onCheckAuthorization, handler);",
                "router.post('/exchange', handler);",
                "handoff.exchange(code, secret);",
                "const message = 'ATDR handoff request could not be completed.';",
            )
        ),
        encoding="utf-8",
    )
    service.write_text(
        "\n".join(
            (
                "crypto.timingSafeEqual(left, right);",
                "const filter = { consumedAt: null, expiresAt: { $gt: consumedAt } };",
                "model.findOneAndUpdate(filter, update);",
                "settings.allowedDomains;",
                "return { secretsExposed: false };",
            )
        ),
        encoding="utf-8",
    )

    assert acceptance._packaged_handoff_contract(tmp_path) is True
    route.write_text("router.post('/start', handler);", encoding="utf-8")
    assert acceptance._packaged_handoff_contract(tmp_path) is False


def test_analyst_summary_requires_concise_grounded_fallback_and_zero_actions():
    report = {
        "ok": True,
        "scenario_count": 1,
        "scenarios": [
            {
                "passed": True,
                "parser_normalization": {"raw_logs": 8, "normalized_logs": 8},
                "alert_count": 1,
                "checks": [
                    {"name": "source_health_visible", "passed": True},
                    {"name": "why_flagged_present", "passed": True},
                    {"name": "investigation_evidence_linked", "passed": True},
                ],
                "assistant": {
                    "passed": True,
                    "conversation_turns": 3,
                    "responses": [
                        {
                            "response_mode": mode,
                            "citation_count": 1,
                            "external_provider_used": False,
                            "raw_log_context_included": False,
                            "redaction_applied": True,
                        }
                        for mode in ("alert_explanation", "related_logs", "safe_next_step")
                    ],
                    "authoritative_row_deltas": {
                        "alerts": 0,
                        "detection_runs": 0,
                        "labels": 0,
                        "model_runs": 0,
                        "response_actions": 0,
                    },
                },
                "response_safety": {"simulate_response": False, "response_actions_created": 0},
                "audit_summary": {"response_actions_created": 0},
            }
        ],
    }

    summary = acceptance._analyst_workflow_summary(report)
    assert summary["passed"] is True
    assert summary["assistant_turns"] == 3
    assert summary["response_actions_created"] == 0
    report["scenarios"][0]["assistant"]["responses"][1]["external_provider_used"] = True
    assert acceptance._analyst_workflow_summary(report)["passed"] is False


def test_public_report_redaction_rejects_paths_addresses_and_secret_field_names():
    assert acceptance._public_report_is_redacted({"ok": True, "status": "safe"}) is True
    assert acceptance._public_report_is_redacted({"path": "C:\\Users\\Person\\private"}) is False
    assert acceptance._public_report_is_redacted({"address": "192.0.2.1"}) is False
    assert acceptance._public_report_is_redacted({"client_secret": "hidden"}) is False


def test_v561_anomaly_bootstrap_extension_is_explicit_and_preserves_v560_default():
    default_stages = acceptance.clean_machine_stage_names()
    extended_stages = acceptance.clean_machine_stage_names(
        exercise_anomaly_bootstrap=True,
    )

    assert len(default_stages) == 27
    assert len(extended_stages) == 32
    assert "anomaly_unavailable_before_bootstrap" not in default_stages
    assert "anomaly_no_silent_training" in extended_stages
    assert "anomaly_bootstrap_preflight" in extended_stages
    assert "anomaly_bootstrap_advisory_ready" in extended_stages
    assert "anomaly_artifact_cleanup" in extended_stages


def test_v561_clean_machine_contract_requires_every_advisory_safety_invariant(
    tmp_path: Path,
):
    artifact = tmp_path / "isolation_forest.joblib"
    manifest = tmp_path / "isolation_forest.bootstrap.json"
    artifact.write_bytes(b"disposable")
    manifest.write_text("{}", encoding="utf-8")

    def valid_report() -> dict:
        return {
            "status": "governed_advisory_anomaly_bootstrap_complete",
            "current_capability": {
                "state": "governed_advisory_ready",
                "threat_accuracy_validated": False,
                "supervised_model_activated": False,
            },
            "acceptance": {
                "model_driven_alerts": 0,
                "model_driven_suppressions": 0,
                "labels_created": 0,
                "model_runs_created": 0,
                "detection_runs_created": 0,
                "response_actions_created": 0,
                "rules_alert_authoritative": True,
                "hybrid_decision_support_only": True,
                "model_only_alert_creation_allowed": False,
                "supervised_state": "unqualified",
                "supervised_model_activated": False,
                "response_state": "simulation_only",
                "real_firewall_blocking_enabled": False,
            },
        }

    assert acceptance._anomaly_bootstrap_contract_ready(
        valid_report(),
        artifact_path=artifact,
        manifest_path=manifest,
    )

    unsafe_variants = (
        ("current_capability", "threat_accuracy_validated", True),
        ("current_capability", "supervised_model_activated", True),
        ("acceptance", "model_driven_alerts", 1),
        ("acceptance", "model_driven_suppressions", 1),
        ("acceptance", "labels_created", 1),
        ("acceptance", "model_runs_created", 1),
        ("acceptance", "detection_runs_created", 1),
        ("acceptance", "response_actions_created", 1),
        ("acceptance", "rules_alert_authoritative", False),
        ("acceptance", "hybrid_decision_support_only", False),
        ("acceptance", "model_only_alert_creation_allowed", True),
        ("acceptance", "supervised_state", "active"),
        ("acceptance", "supervised_model_activated", True),
        ("acceptance", "response_state", "automatic"),
        ("acceptance", "real_firewall_blocking_enabled", True),
    )
    for section, field, value in unsafe_variants:
        report = valid_report()
        report[section][field] = value
        assert not acceptance._anomaly_bootstrap_contract_ready(
            report,
            artifact_path=artifact,
            manifest_path=manifest,
        )
