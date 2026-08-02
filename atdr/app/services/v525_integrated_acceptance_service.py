from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.services.assistant_service import assistant_status
from atdr.app.services.v523_live_source_acceptance_service import (
    run_v523_live_source_acceptance,
)
from atdr.app.services.v524_investigation_gemini_quality_service import (
    run_v524_quality_lock,
)
from atdr.scripts.run_e2e_workflow_validation import run_e2e_workflow_validation
from atdr.scripts.run_v48_product_acceptance import run_v48_product_acceptance


V525_VERSION = "v5.25.0"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
DEFAULT_V524_EVIDENCE = DEFAULT_OUTPUT_DIR / "v5_24_investigation_gemini_quality_latest.json"
_PRIVATE_PATH_PATTERN = re.compile(
    r"(?i)(?:[a-z]:[\\/](?:users|home)[\\/]|/(?:users|home)/|paloalto-firewall\(1\)\.log)"
)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _all_true(values: dict[str, Any]) -> bool:
    return all(bool(value) for value in values.values())


def _repository_contract() -> dict[str, Any]:
    required_paths = (
        "scripts/setup_team.ps1",
        "scripts/setup_team.cmd",
        "scripts/start_system.ps1",
        "scripts/start_system.cmd",
        "scripts/check_system.ps1",
        "scripts/stop_system.ps1",
        "config/mfu-shell-contract.json",
        ".env.example",
        ".env.shell.example",
        "requirements.txt",
        "frontend/package.json",
        "frontend/src/App.tsx",
        "frontend/tests/smoke.spec.ts",
        "atdr/tests/test_iam_rbac.py",
        "atdr/tests/test_v43_portable_shell_runtime.py",
        "atdr/tests/test_v46_mfu_shell_distribution.py",
    )
    files_present = all((PROJECT_ROOT / path).is_file() for path in required_paths)
    start_source = (PROJECT_ROOT / "scripts/start_system.ps1").read_text(encoding="utf-8")
    setup_source = (PROJECT_ROOT / "scripts/setup_team.ps1").read_text(encoding="utf-8")
    app_source = (PROJECT_ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    smoke_source = (PROJECT_ROOT / "frontend/tests/smoke.spec.ts").read_text(encoding="utf-8")
    rbac_source = (PROJECT_ROOT / "atdr/tests/test_iam_rbac.py").read_text(encoding="utf-8")
    checks = {
        "required_files_present": files_present,
        "startup_fails_closed_on_unsafe_response_mode": "RESPONSE_SIMULATION must remain true" in start_source,
        "startup_requires_shell_auth_contract": "Get-MissingShellAuthFields" in start_source,
        "team_setup_has_non_mutating_dry_run": "[switch]$DryRun" in setup_source,
        "team_setup_preserves_existing_config": "UpdateExistingConfig" in setup_source,
        "admin_routes_guarded": "AdminRoute" in app_source and "/users" in app_source and "/demo" in app_source,
        "role_navigation_tested": "analyst cannot access admin routes" in smoke_source,
        "responsive_overflow_tested": "scrollWidth" in smoke_source and "clientWidth" in smoke_source,
        "assistant_route_present": "/assistant" in app_source,
        "backend_rbac_source_tested": "test_frontend_has_admin_route_guard_and_role_aware_navigation" in rbac_source,
    }
    return {
        "passed": _all_true(checks),
        "checks": checks,
        "startup_commands_changed": False,
        "private_configuration_returned": False,
    }


def _product_summary(result: dict[str, Any]) -> dict[str, Any]:
    ingestion = result.get("ingestion") or {}
    recovery = result.get("recovery") or {}
    detection = result.get("detection") or {}
    investigation = result.get("investigation") or {}
    assistant = result.get("assistant") or {}
    return {
        "passed": bool(result.get("ok")),
        "status": result.get("status"),
        "attempted": int(ingestion.get("attempted") or 0),
        "raw_logs_imported": int(ingestion.get("raw_logs_imported") or 0),
        "normalized_logs_created": int(ingestion.get("normalized_logs_created") or 0),
        "parse_failures": int(ingestion.get("parse_failures") or 0),
        "duplicates_tracked": int(ingestion.get("duplicate_raw_logs") or 0),
        "source_links_complete": int(ingestion.get("missing_source_links") or 0) == 0,
        "raw_evidence_preserved": int(ingestion.get("empty_raw_evidence") or 0) == 0,
        "interruption_recovered": bool(
            (recovery.get("bulk_graceful_interruption") or {}).get("resume_completed")
        ),
        "cancellation_recovered": bool((recovery.get("cancellation_resume") or {}).get("ok")),
        "stale_lease_failed_closed": bool((recovery.get("stale_lease") or {}).get("ok")),
        "rule_alert_created": int((detection.get("first_run") or {}).get("created_alerts") or 0) >= 1,
        "deduplication_recorded": int(
            (detection.get("second_run") or {}).get("deduplicated_alert_updates") or 0
        )
        >= 1,
        "investigation_source_traceable": bool(investigation.get("source_traceable")),
        "case_available": bool(investigation.get("case_id")),
        "why_flagged_available": bool(investigation.get("why_flagged_available")),
        "assistant_safe_and_grounded": bool(assistant.get("ok")),
        "configured_database_unchanged": bool(result.get("current_database_unchanged")),
        "temporary_artifacts_removed": bool(result.get("temp_artifacts_removed")),
        "response_actions_created": int((result.get("counts") or {}).get("response_actions") or 0),
        "labels_created": int((result.get("counts") or {}).get("labels") or 0),
        "model_runs_created": int((result.get("counts") or {}).get("model_runs") or 0),
        "secrets_exposed": bool(result.get("secrets_exposed")),
    }


def _workflow_summary(result: dict[str, Any]) -> dict[str, Any]:
    scenarios = list(result.get("scenarios") or [])
    response_rows = [item.get("response_safety") or {} for item in scenarios]
    audit_rows = [item.get("audit_summary") or {} for item in scenarios]
    detection_rows = [item.get("detection") or {} for item in scenarios]
    return {
        "passed": bool(result.get("ok")),
        "scenario_count": int(result.get("scenario_count") or 0),
        "passed_count": int(result.get("passed_count") or 0),
        "rules_alert_authoritative": all(
            bool(item.get("rule_detection_authoritative")) for item in detection_rows
        ),
        "ml_requested_as_decision_support": all(bool(item.get("use_ml")) for item in detection_rows),
        "missing_justification_denied": all(
            bool(item.get("missing_justification_denied")) for item in response_rows
        ),
        "protected_target_denied": all(bool(item.get("protected_ip_denied")) for item in response_rows),
        "analyst_approved_action_simulated": all(bool(item.get("approved_simulated")) for item in response_rows),
        "response_audits_recorded": all(
            int(item.get("audit_entries_for_target") or 0) > 0
            and int(item.get("audit_entries_for_protected_ip") or 0) > 0
            for item in response_rows
        ),
        "simulated_response_records": sum(
            int(item.get("response_actions_created") or 0) for item in audit_rows
        ),
        "automatic_response_enabled": bool((result.get("safety") or {}).get("automatic_response_enabled")),
        "real_firewall_blocking_enabled": bool(
            (result.get("safety") or {}).get("real_firewall_blocking_enabled")
        ),
    }


def _transport_summary(result: dict[str, Any]) -> dict[str, Any]:
    scope = result.get("scope") or {}
    channels = result.get("channels") or {}
    detection = result.get("detection") or {}
    investigation = result.get("investigation") or {}
    return {
        "passed": bool(result.get("ok")),
        "status": result.get("status"),
        "file_import_passed": bool((channels.get("file_import") or {}).get("passed")),
        "api_upload_passed": bool((channels.get("api_upload") or {}).get("passed")),
        "resumable_import_passed": bool(
            (channels.get("resumable_import") or {}).get("resume_completed")
        ),
        "backpressure_enforced": bool(
            (channels.get("resumable_import") or {}).get("backpressure_enforced")
        ),
        "local_udp_transport_passed": bool(scope.get("local_loopback_transport_validated")),
        "non_loopback_transport_validated": bool(scope.get("second_laptop_transport_validated")),
        "real_device_validated": bool(scope.get("real_device_validated")),
        "rules_alert_authoritative": bool(detection.get("rules_alert_authoritative")),
        "alert_created": int(detection.get("first_created") or 0) >= 1,
        "deduplication_recorded": int(detection.get("second_deduplicated") or 0) >= 1,
        "source_traceable": bool(investigation.get("source_traceable")),
        "why_flagged_available": bool(investigation.get("why_flagged_available")),
        "analyst_next_steps_available": bool(investigation.get("analyst_next_steps_available")),
        "configured_database_unchanged": not bool(result.get("configured_database_modified")),
        "temporary_artifacts_removed": bool(result.get("temporary_artifacts_removed")),
        "secrets_exposed": bool(result.get("secrets_exposed")),
    }


def _assistant_summary(result: dict[str, Any], *, evidence_mode: str) -> dict[str, Any]:
    measurements = result.get("provider_measurements") or {}
    safety = result.get("safety") or {}
    return {
        "passed": bool(result.get("phase_complete")),
        "status": result.get("status"),
        "evidence_mode": evidence_mode,
        "provider": result.get("provider") or "disabled",
        "provider_ready": bool(result.get("provider_ready")),
        "question_count": int(result.get("question_count") or 0),
        "passed_checks": int(result.get("passed_checks") or 0),
        "total_checks": int(result.get("total_checks") or 0),
        "provider_calls_used": int(measurements.get("calls_used") or 0),
        "latency_ms_median": measurements.get("latency_ms_median"),
        "latency_ms_p95": measurements.get("latency_ms_p95"),
        "usage_totals": measurements.get("usage_totals") or {},
        "raw_logs_disabled": bool(safety.get("raw_logs_disabled")),
        "ip_redaction_enabled": bool(safety.get("ip_redaction_enabled")),
        "assistant_read_only": bool(safety.get("assistant_read_only")),
        "rules_remain_alert_authoritative": bool(safety.get("rules_remain_alert_authoritative")),
        "model_activated": bool(safety.get("model_activated")),
        "model_promoted": bool(safety.get("model_promoted")),
        "response_automation_allowed": bool(safety.get("response_automation_allowed")),
        "real_firewall_blocking_enabled": bool(safety.get("real_firewall_blocking_enabled")),
        "mutation_deltas": result.get("mutation_deltas") or {},
        "secrets_exposed": bool(result.get("secrets_exposed")),
    }


def _load_v524_evidence(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {
            "status": "v5_24_quality_evidence_unavailable",
            "phase_complete": False,
            "provider": "unavailable",
            "provider_ready": False,
            "secrets_exposed": False,
        }
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {
            "status": "v5_24_quality_evidence_invalid",
            "phase_complete": False,
            "provider": "invalid",
            "provider_ready": False,
            "secrets_exposed": False,
        }
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    mutations = (
        report.get("mutation_deltas")
        if isinstance(report.get("mutation_deltas"), dict)
        else {}
    )
    safety = report.get("safety") if isinstance(report.get("safety"), dict) else {}
    measurements = (
        report.get("provider_measurements")
        if isinstance(report.get("provider_measurements"), dict)
        else {}
    )
    valid = bool(
        report.get("schema_version") == "v5.24.0"
        and report.get("status") == "v5_24_quality_lock_passed"
        and report.get("phase_complete")
        and str(report.get("provider") or "").lower() == "gemini"
        and int(report.get("question_count") or 0) == 6
        and len(checks) == 11
        and _all_true(checks)
        and int(measurements.get("calls_used") or 0) == 6
        and not report.get("raw_log_context_allowed")
        and report.get("redaction_enabled")
        and not report.get("secrets_exposed")
        and mutations
        and all(int(value or 0) == 0 for value in mutations.values())
        and safety.get("assistant_read_only")
        and safety.get("raw_logs_disabled")
        and safety.get("ip_redaction_enabled")
        and safety.get("rules_remain_alert_authoritative")
        and not safety.get("model_activated")
        and not safety.get("model_promoted")
        and not safety.get("response_automation_allowed")
        and not safety.get("real_firewall_blocking_enabled")
    )
    if valid:
        return report
    return {
        "status": "v5_24_quality_evidence_failed_validation",
        "phase_complete": False,
        "provider": str(report.get("provider") or "invalid"),
        "provider_ready": False,
        "secrets_exposed": False,
    }


def build_v525_report(
    *,
    product: dict[str, Any],
    workflow: dict[str, Any],
    transport: dict[str, Any],
    assistant: dict[str, Any],
    repository: dict[str, Any],
    assistant_evidence_mode: str,
) -> dict[str, Any]:
    checks = {
        "collection_and_normalization_passed": bool(
            product.get("passed")
            and product.get("raw_logs_imported") == product.get("attempted")
            and product.get("normalized_logs_created") == product.get("attempted")
            and product.get("source_links_complete")
            and product.get("raw_evidence_preserved")
        ),
        "failure_and_recovery_passed": bool(
            product.get("interruption_recovered")
            and product.get("cancellation_recovered")
            and product.get("stale_lease_failed_closed")
            and transport.get("resumable_import_passed")
            and transport.get("backpressure_enforced")
        ),
        "implemented_ingestion_channels_passed": bool(
            transport.get("file_import_passed")
            and transport.get("api_upload_passed")
            and transport.get("local_udp_transport_passed")
        ),
        "rule_detection_and_deduplication_passed": bool(
            product.get("rule_alert_created")
            and product.get("deduplication_recorded")
            and workflow.get("rules_alert_authoritative")
            and transport.get("rules_alert_authoritative")
            and transport.get("alert_created")
            and transport.get("deduplication_recorded")
        ),
        "ml_remains_decision_support": bool(
            workflow.get("ml_requested_as_decision_support")
            and assistant.get("rules_remain_alert_authoritative")
            and not assistant.get("model_activated")
            and not assistant.get("model_promoted")
        ),
        "investigation_traceability_passed": bool(
            product.get("investigation_source_traceable")
            and product.get("case_available")
            and product.get("why_flagged_available")
            and transport.get("source_traceable")
            and transport.get("why_flagged_available")
            and transport.get("analyst_next_steps_available")
        ),
        "gemini_quality_lock_passed": bool(
            assistant_evidence_mode in {"fresh_provider", "locked_v5_24"}
            and assistant.get("passed")
        ),
        "assistant_privacy_and_read_only_passed": bool(
            assistant.get("raw_logs_disabled")
            and assistant.get("ip_redaction_enabled")
            and assistant.get("assistant_read_only")
            and not assistant.get("response_automation_allowed")
            and not assistant.get("real_firewall_blocking_enabled")
            and not assistant.get("secrets_exposed")
            and all(int(value or 0) == 0 for value in (assistant.get("mutation_deltas") or {}).values())
        ),
        "analyst_simulated_response_and_audit_passed": bool(
            workflow.get("passed")
            and workflow.get("missing_justification_denied")
            and workflow.get("protected_target_denied")
            and workflow.get("analyst_approved_action_simulated")
            and workflow.get("response_audits_recorded")
            and int(workflow.get("simulated_response_records") or 0) > 0
        ),
        "no_automatic_or_real_response": bool(
            not workflow.get("automatic_response_enabled")
            and not workflow.get("real_firewall_blocking_enabled")
        ),
        "no_authoritative_model_or_label_writes": bool(
            int(product.get("labels_created") or 0) == 0
            and int(product.get("model_runs_created") or 0) == 0
            and int(product.get("response_actions_created") or 0) == 0
        ),
        "configured_database_preserved": bool(
            product.get("configured_database_unchanged")
            and product.get("temporary_artifacts_removed")
            and transport.get("configured_database_unchanged")
            and transport.get("temporary_artifacts_removed")
        ),
        "startup_teammate_rbac_ui_contracts_present": bool(repository.get("passed")),
        "no_secret_exposure": bool(
            not product.get("secrets_exposed")
            and not transport.get("secrets_exposed")
            and not assistant.get("secrets_exposed")
            and not repository.get("private_configuration_returned")
        ),
    }
    external_gates = {
        "non_loopback_sender": {
            "status": "owner_deferred",
            "satisfied": bool(transport.get("non_loopback_transport_validated")),
            "required_for": "external transport acceptance",
        },
        "real_firewall_or_router": {
            "status": "not_observed",
            "satisfied": bool(transport.get("real_device_validated")),
            "required_for": "real-device interoperability claim",
        },
        "independent_human_native_labels": {
            "status": "not_provided",
            "satisfied": False,
            "required_for": "supervised promotion reconsideration",
        },
        "mfu_iam_preproduction": {
            "status": "not_evaluated_by_v5_25",
            "satisfied": False,
            "required_for": "provider-backed university IAM acceptance",
        },
        "approved_shared_host": {
            "status": "not_evaluated_by_v5_25",
            "satisfied": False,
            "required_for": "deployment and disaster-recovery acceptance",
        },
        "gemini_privacy_quota_and_key_governance": {
            "status": "provider_quality_passed_governance_open",
            "satisfied": False,
            "required_for": "shared deployment of external assistance",
        },
    }
    local_complete = _all_true(checks)
    if assistant_evidence_mode == "unavailable":
        status = "v5_25_gemini_quality_evidence_required"
    elif local_complete:
        status = "v5_25_integrated_acceptance_passed_external_gates_open"
    else:
        status = "v5_25_integrated_acceptance_failed"
    report = {
        "schema_version": V525_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": status,
        "ok": local_complete,
        "phase_complete": local_complete,
        "local_product_closure_complete": local_complete,
        "production_ready": False,
        "supervised_lifecycle": "shadow_observation",
        "rules_alert_authoritative": True,
        "response_mode": "simulated_analyst_approved_only",
        "checks": checks,
        "passed_checks": sum(bool(value) for value in checks.values()),
        "total_checks": len(checks),
        "failed_checks": [name for name, value in checks.items() if not value],
        "collection": product,
        "workflow": workflow,
        "live_source": transport,
        "assistant": assistant,
        "repository_contract": repository,
        "external_gates": external_gates,
        "external_gate_count": len(external_gates),
        "safety": {
            "configured_database_modified": False,
            "model_activated": False,
            "model_promoted": False,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "raw_log_context_allowed": False,
            "ip_redaction_enabled": True,
            "secrets_exposed": False,
        },
    }
    serialized = json.dumps(report, default=str)
    output_private = bool(_PRIVATE_PATH_PATTERN.search(serialized) or _IP_PATTERN.search(serialized))
    report["privacy"] = {
        "private_path_or_address_returned": output_private,
        "raw_evidence_returned": False,
        "secrets_exposed": False,
    }
    if output_private:
        report["checks"]["no_secret_exposure"] = False
        report["failed_checks"] = [name for name, value in report["checks"].items() if not value]
        report["passed_checks"] = sum(bool(value) for value in report["checks"].values())
        report["ok"] = False
        report["phase_complete"] = False
        report["local_product_closure_complete"] = False
        report["status"] = "v5_25_privacy_contract_failed"
    return report


def run_v525_integrated_acceptance(
    *,
    settings: Settings,
    use_temp_db: bool,
    execute_provider: bool,
    log_count: int = 5_000,
    preflight_only: bool = False,
    temp_parent: Path | None = None,
    assistant_evidence_path: Path | None = DEFAULT_V524_EVIDENCE,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_reports: bool = True,
) -> dict[str, Any]:
    repository = _repository_contract()
    provider = assistant_status(settings)
    locked_assistant_evidence = _load_v524_evidence(assistant_evidence_path)
    locked_assistant_ready = bool(locked_assistant_evidence.get("phase_complete"))
    if preflight_only:
        return {
            "schema_version": V525_VERSION,
            "status": "v5_25_preflight_passed" if repository["passed"] else "v5_25_preflight_failed",
            "ok": bool(repository["passed"]),
            "phase_complete": False,
            "use_temp_db_required": True,
            "provider_enabled": bool(provider.get("llm_enabled")),
            "provider_configured": bool(provider.get("llm_provider_configured")),
            "model_configured": bool(provider.get("llm_model_configured")),
            "secret_configured": bool(provider.get("llm_secret_configured")),
            "locked_v5_24_assistant_evidence_ready": locked_assistant_ready,
            "secrets_exposed": False,
            "repository_contract": repository,
            "production_ready": False,
        }
    if not use_temp_db:
        return {
            "schema_version": V525_VERSION,
            "status": "explicit_temp_database_required",
            "ok": False,
            "phase_complete": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
            "production_ready": False,
        }

    product_result = run_v48_product_acceptance(
        use_temp_db=True,
        log_count=log_count,
        simulate_interruption=True,
        run_detection_enabled=True,
        test_assistant=True,
        test_backup_restore=True,
        temp_parent=temp_parent,
    )
    workflow_result = run_e2e_workflow_validation(
        scenarios=["port_scan_like_traffic"],
        source_name="v525-integrated-firewall",
        use_temp_db=True,
        simulate_response=True,
        response_reason="v5.25 disposable analyst-approved response validation.",
        write_output=False,
    )
    transport_result = run_v523_live_source_acceptance(
        use_temp_db=True,
        transport_mode="local_loopback",
        message_count=5,
        temp_parent=temp_parent,
        write_output=False,
    )
    if execute_provider:
        assistant_result = run_v524_quality_lock(
            settings=settings,
            execute_provider=True,
            provider_interval_seconds=(
                12.5 if settings.assistant_llm_provider.strip().lower() == "gemini" else 0.0
            ),
            write_reports=False,
        )
        assistant_evidence_mode = "fresh_provider"
    else:
        assistant_result = locked_assistant_evidence
        assistant_evidence_mode = "locked_v5_24" if locked_assistant_ready else "unavailable"
    report = build_v525_report(
        product=_product_summary(product_result),
        workflow=_workflow_summary(workflow_result),
        transport=_transport_summary(transport_result),
        assistant=_assistant_summary(assistant_result, evidence_mode=assistant_evidence_mode),
        repository=repository,
        assistant_evidence_mode=assistant_evidence_mode,
    )
    if write_reports:
        _write_reports(report, output_dir=output_dir)
    return report


def _write_reports(report: dict[str, Any], *, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    serialized = json.dumps(report, indent=2, sort_keys=True, default=str)
    (output_dir / "v5_25_integrated_acceptance_latest.json").write_text(
        serialized,
        encoding="utf-8",
    )
    (output_dir / f"v5_25_integrated_acceptance_{stamp}.json").write_text(
        serialized,
        encoding="utf-8",
    )
    lines = [
        "# v5.25 Integrated Acceptance",
        "",
        f"- Status: `{report['status']}`",
        f"- Local phase complete: `{str(report['phase_complete']).lower()}`",
        f"- Checks: `{report['passed_checks']}/{report['total_checks']}`",
        "- Rules remain alert-authoritative.",
        "- Supervised ML remains shadow-only decision support.",
        "- Response remains simulated and analyst-approved.",
        "- Production readiness is not claimed.",
        "",
        "## Open External Gates",
        "",
    ]
    for name, gate in report["external_gates"].items():
        lines.append(f"- `{name}`: `{gate['status']}` ({gate['required_for']}).")
    (output_dir / f"v5_25_integrated_acceptance_{stamp}.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
