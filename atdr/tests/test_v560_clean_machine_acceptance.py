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
