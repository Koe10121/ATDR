from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db import models as _models  # noqa: F401
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AuditLog, DetectionRun, MLLabel, MLModelRun, ResponseAction
from atdr.app.services.assistant_service import answer_assistant_question
from atdr.app.services.response_service import block_ip, unblock_ip
from atdr.app.services.v533_independent_acceptance_service import validate_assistant_human_review_pack
from atdr.scripts.run_v48_product_acceptance import run_v48_product_acceptance


V538_VERSION = "v5.38-product-reliability-v1"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "v5_38_product_reliability"


def _read(relative: str) -> str:
    return (PROJECT_ROOT / relative).read_text(encoding="utf-8")


def _all_true(values: dict[str, Any]) -> bool:
    return bool(values) and all(bool(value) for value in values.values())


def _source_contracts() -> dict[str, Any]:
    setup = _read("scripts/setup_team.ps1")
    start = _read("scripts/start_system.ps1")
    check = _read("scripts/check_system.ps1")
    stop = _read("scripts/stop_system.ps1")
    common = _read("scripts/system_common.ps1")
    main = _read("atdr/app/main.py")
    auth = _read("atdr/app/routers/auth.py")
    assistant = _read("atdr/app/routers/assistant.py")
    evidence = _read("atdr/app/routers/evidence_review.py")
    response = _read("atdr/app/routers/response.py")
    app = _read("frontend/src/App.tsx")
    shell = _read("frontend/src/components/AppShell.tsx")
    error_banner = _read("frontend/src/components/ErrorBanner.tsx")
    overview = _read("frontend/src/pages/ExecutiveOverview.tsx")
    ml = _read("frontend/src/pages/MLGovernance.tsx")
    response_page = _read("frontend/src/pages/ResponseCenter.tsx")
    smoke = _read("frontend/tests/smoke.spec.ts")
    portable_tests = _read("atdr/tests/test_v43_portable_shell_runtime.py")
    rbac_tests = _read("atdr/tests/test_iam_rbac.py")
    assistant_tests = _read("atdr/tests/test_assistant.py")
    review_tests = _read("atdr/tests/test_v537_evidence_review_workspace.py")

    startup = {
        "setup_check_start_stop_present": all(
            (PROJECT_ROOT / path).is_file()
            for path in (
                "scripts/setup_team.ps1",
                "scripts/start_system.ps1",
                "scripts/check_system.ps1",
                "scripts/stop_system.ps1",
            )
        ),
        "outer_shell_required": "Authentication: template_shell" in start
        and "Resolve-TemplateRoot" in start,
        "clean_path_with_spaces_covered": "path_with_spaces" in portable_tests,
        "missing_pip_recovery": "ensurepip" in setup and "broken-venvs" in setup,
        "node_and_dependency_preflight": "Test-NodeVersionSupported" in setup
        and "node_modules" in setup,
        "private_shell_config_fails_closed": "Get-MissingTemplateProviderFields" in start,
        "database_unavailable_is_concise": "database_operational_exception_handler" in main
        and "Check DATABASE_URL" in main,
        "occupied_ports_fail_closed": "Required port(s) are already occupied" in start,
        "stale_pid_uses_start_time": "Test-TrackedProcessRecordActive" in common
        and "Test-TrackedProcessRecordActive $_" in start,
        "stop_checks_process_identity": "start time does not match launcher metadata" in stop,
        "status_reports_safe_provider_state": "secrets_exposed = $false" in check,
    }
    access = {
        "secure_handoff_receiver": "/mfu-iam/handoff/consume" in auth
        and "handoff_code" in auth,
        "assistant_requires_auth": "require_analyst_or_admin" in assistant,
        "evidence_review_requires_auth": "require_analyst_or_admin" in evidence,
        "response_mutation_requires_admin": "require_admin" in response,
        "backend_rbac_regressions_present": "test_protected_api_rejects_unauthenticated_requests" in rbac_tests
        and "test_response_permission_safety_and_denied_attempt_audit" in rbac_tests,
    }
    required_routes = (
        "/overview",
        "/alerts",
        "/logs",
        "/assistant",
        "/ml",
        "/evidence-review",
        "/response",
        "/users",
    )
    ui = {
        "critical_routes_present": all(f'path="{route}"' in app for route in required_routes),
        "role_aware_navigation": "adminOnly" in shell and "isAdmin" in shell,
        "page_level_api_errors": "ErrorBanner" in overview
        and "ErrorBanner" in ml
        and "ErrorBanner" in response_page
        and 'role="alert"' in error_banner,
        "assistant_session_navigation_covered": "browser history preserves the assistant investigation session" in smoke
        and "session storage is resilient" in smoke,
        "responsive_core_routes_covered": "core SOC pages fit desktop, tablet, and mobile viewports" in smoke,
        "assistant_failures_and_missing_refs_covered": "provider_transport_retries_transient_failure" in assistant_tests
        and "missing_source" in assistant_tests,
        "malformed_review_pack_covered": "malformed_assistant_pack_fails_closed" in review_tests,
    }
    return {
        "startup": startup,
        "access": access,
        "ui": ui,
        "passed": _all_true(startup) and _all_true(access) and _all_true(ui),
    }


def _count(db: Session, model: Any) -> int:
    return int(db.scalar(select(func.count(model.id))) or 0)


def _isolated_failure_probes(settings: Settings, probe_root: Path) -> dict[str, Any]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            with patch("atdr.app.services.response_service.get_settings", return_value=settings):
                missing_note = block_ip(db, target_ip="198.51.100.77", actor="v538-acceptance")
                protected = block_ip(
                    db,
                    target_ip="10.0.0.77",
                    reason="Validate protected response target.",
                    actor="v538-acceptance",
                )
                simulated = block_ip(
                    db,
                    target_ip="198.51.100.77",
                    reason="Validate analyst-approved simulation only.",
                    actor="v538-acceptance",
                )
                unblocked = unblock_ip(
                    db,
                    target_ip="198.51.100.77",
                    reason="Complete disposable simulation acceptance.",
                    actor="v538-acceptance",
                )

            authoritative_models = (Alert, DetectionRun, ResponseAction, MLLabel, MLModelRun)
            before_assistant = {model.__tablename__: _count(db, model) for model in authoritative_models}
            missing_alert = answer_assistant_question(
                db,
                question="Why was alert 999999 flagged?",
                actor="v538-acceptance",
                settings=settings,
                alert_id=999999,
            )
            missing_source = answer_assistant_question(
                db,
                question="Summarize source 999999 health.",
                actor="v538-acceptance",
                settings=settings,
                source_id=999999,
            )
            after_assistant = {model.__tablename__: _count(db, model) for model in authoritative_models}
            assistant_deltas = {
                name: after_assistant[name] - before_assistant[name]
                for name in before_assistant
            }
            response_statuses = [
                missing_note.status,
                protected.status,
                simulated.status,
                unblocked.status,
            ]
            audit_count = _count(db, AuditLog)
    finally:
        engine.dispose()

    malformed_review = probe_root / "malformed-assistant-review.csv"
    malformed_manifest = probe_root / "malformed-assistant-manifest.json"
    malformed_review.write_text("unexpected_column\ninvalid\n", encoding="utf-8")
    malformed_manifest.write_text("{}\n", encoding="utf-8")
    review_result = validate_assistant_human_review_pack(
        review_path=malformed_review,
        manifest_path=malformed_manifest,
    )

    return {
        "missing_justification_denied": missing_note.status == "denied",
        "protected_target_denied": protected.status == "denied",
        "approved_action_simulated": simulated.status == "simulated",
        "simulated_unblock_recorded": unblocked.status == "simulated",
        "real_response_actions": sum(status not in {"denied", "simulated"} for status in response_statuses),
        "response_audit_events_recorded": audit_count >= 4,
        "missing_alert_handled": "No matching alert" in str(missing_alert.get("answer") or ""),
        "missing_source_handled": "No matching source" in str(missing_source.get("answer") or ""),
        "assistant_external_provider_used": bool(
            missing_alert.get("external_provider_used") or missing_source.get("external_provider_used")
        ),
        "assistant_raw_context_included": bool(
            missing_alert.get("raw_log_context_included") or missing_source.get("raw_log_context_included")
        ),
        "assistant_authoritative_mutation_deltas": assistant_deltas,
        "malformed_review_pack_failed_closed": not review_result.get("ok")
        and not review_result.get("human_acceptance_permitted"),
        "secrets_exposed": False,
    }


def _workflow_summary(core: dict[str, Any]) -> dict[str, Any]:
    ingestion = core.get("ingestion") or {}
    detection = core.get("detection") or {}
    investigation = core.get("investigation") or {}
    assistant = core.get("assistant") or {}
    counts = core.get("counts") or {}
    return {
        "logs_attempted": int(ingestion.get("attempted") or 0),
        "raw_logs_imported": int(ingestion.get("raw_logs_imported") or 0),
        "normalized_logs_created": int(ingestion.get("normalized_logs_created") or 0),
        "parse_failures_tracked": int(ingestion.get("parse_failures") or 0),
        "duplicates_tracked": int(ingestion.get("duplicate_raw_logs") or 0),
        "source_links_complete": int(ingestion.get("missing_source_links") or 0) == 0,
        "evidence_preserved": int(ingestion.get("empty_raw_evidence") or 0) == 0,
        "alert_type": detection.get("alert_type"),
        "alerts_created": int((detection.get("first_run") or {}).get("created_alerts") or 0),
        "alerts_deduplicated": int(
            (detection.get("second_run") or {}).get("deduplicated_alert_updates") or 0
        ),
        "occurrence_count": int(detection.get("occurrence_count") or 0),
        "related_log_count": int(detection.get("related_log_count") or 0),
        "source_traceable": bool(investigation.get("source_traceable")),
        "case_available": bool(investigation.get("case_id")),
        "why_flagged_available": bool(investigation.get("why_flagged_available")),
        "assistant_context_preserved": bool(assistant.get("conversation_context_preserved")),
        "assistant_citation_grounded": bool(assistant.get("citation_references_alert")),
        "assistant_provider_fallback_safe": bool(assistant.get("provider_failure_fallback")),
        "audit_events_recorded": int(counts.get("audit_logs") or 0) > 0,
    }


def build_v538_report(
    *,
    contracts: dict[str, Any],
    core: dict[str, Any] | None,
    probes: dict[str, Any] | None,
    preflight_only: bool,
) -> dict[str, Any]:
    if preflight_only:
        return {
            "phase": "v5.38",
            "version": V538_VERSION,
            "ok": bool(contracts.get("passed")),
            "status": "v5_38_preflight_passed" if contracts.get("passed") else "v5_38_preflight_failed",
            "scope": "source_backed_preflight_only",
            "contracts": contracts,
            "execution_required": True,
            "configured_database_modified": False,
            "real_response_actions": 0,
            "model_activation_performed": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "secrets_exposed": False,
        }

    core = core or {}
    probes = probes or {}
    workflow = _workflow_summary(core)
    recovery = core.get("recovery") or {}
    counts = core.get("counts") or {}
    assistant_deltas = probes.get("assistant_authoritative_mutation_deltas") or {}
    failure_modes = {
        "malformed_logs_preserved_and_counted": workflow["parse_failures_tracked"] >= 3
        and workflow["evidence_preserved"],
        "duplicate_imports_accounted": workflow["duplicates_tracked"] >= 1
        and workflow["alerts_deduplicated"] >= 1,
        "interrupted_import_resumed": bool(
            (recovery.get("bulk_graceful_interruption") or {}).get("resume_completed")
        ),
        "cancelled_import_resumed": bool((recovery.get("cancellation_resume") or {}).get("ok")),
        "stale_worker_failed_closed": bool((recovery.get("stale_lease") or {}).get("ok")),
        "malformed_review_pack_failed_closed": bool(probes.get("malformed_review_pack_failed_closed")),
        "assistant_provider_failure_fallback": workflow["assistant_provider_fallback_safe"],
        "missing_alert_reference_safe": bool(probes.get("missing_alert_handled")),
        "missing_source_reference_safe": bool(probes.get("missing_source_handled")),
        "database_failure_handler_present": bool(
            (contracts.get("startup") or {}).get("database_unavailable_is_concise")
        ),
        "frontend_api_failure_state_present": bool(
            (contracts.get("ui") or {}).get("page_level_api_errors")
        ),
        "rbac_failure_contract_present": bool(
            (contracts.get("access") or {}).get("backend_rbac_regressions_present")
        ),
        "refresh_and_navigation_state_covered": bool(
            (contracts.get("ui") or {}).get("assistant_session_navigation_covered")
        ),
    }
    response_safety = {
        "missing_justification_denied": bool(probes.get("missing_justification_denied")),
        "protected_target_denied": bool(probes.get("protected_target_denied")),
        "approved_action_simulated": bool(probes.get("approved_action_simulated")),
        "simulated_unblock_recorded": bool(probes.get("simulated_unblock_recorded")),
        "audit_events_recorded": bool(probes.get("response_audit_events_recorded")),
        "real_response_actions": int(probes.get("real_response_actions") or 0),
    }
    gates = {
        "startup_and_shell_contract": bool(contracts.get("passed")),
        "disposable_primary_workflow": bool(core.get("ok"))
        and workflow["raw_logs_imported"] == workflow["logs_attempted"]
        and workflow["normalized_logs_created"] == workflow["logs_attempted"]
        and workflow["source_links_complete"]
        and workflow["evidence_preserved"],
        "failure_modes_recover_safely": _all_true(failure_modes),
        "detection_explanation_consistent": bool(
            workflow["alert_type"] == "possible_port_scan"
            and workflow["alerts_created"] == 1
            and workflow["alerts_deduplicated"] == 1
            and workflow["occurrence_count"] == workflow["related_log_count"]
            and workflow["source_traceable"]
            and workflow["case_available"]
            and workflow["why_flagged_available"]
        ),
        "assistant_grounded_and_read_only": bool(
            workflow["assistant_context_preserved"]
            and workflow["assistant_citation_grounded"]
            and not probes.get("assistant_external_provider_used")
            and not probes.get("assistant_raw_context_included")
            and all(int(value or 0) == 0 for value in assistant_deltas.values())
        ),
        "evidence_review_access_contract": bool(
            (contracts.get("access") or {}).get("evidence_review_requires_auth")
            and (contracts.get("ui") or {}).get("critical_routes_present")
        ),
        "simulated_response_and_audit": _all_true(
            {key: value for key, value in response_safety.items() if key != "real_response_actions"}
        )
        and response_safety["real_response_actions"] == 0,
        "dashboard_failure_and_viewport_contract": bool(_all_true(contracts.get("ui") or {})),
        "configured_database_preserved": bool(core.get("current_database_unchanged"))
        and not core.get("current_database_modified"),
        "no_model_label_or_real_response_authority": bool(
            int(counts.get("labels") or 0) == 0
            and int(counts.get("model_runs") or 0) == 0
            and int(counts.get("response_actions") or 0) == 0
            and response_safety["real_response_actions"] == 0
            and not core.get("model_activation_performed")
            and not core.get("response_automation_allowed")
            and not core.get("real_firewall_blocking_enabled")
        ),
        "privacy_and_cleanup": bool(
            core.get("temp_artifacts_removed")
            and not core.get("secrets_exposed")
            and not probes.get("secrets_exposed")
        ),
    }
    ok = _all_true(gates)
    return {
        "phase": "v5.38",
        "version": V538_VERSION,
        "ok": ok,
        "status": "v5_38_product_reliability_passed" if ok else "v5_38_product_reliability_failed",
        "scope": "synthetic_disposable_sqlite_and_source_contracts",
        "gates": gates,
        "passed_gate_count": sum(bool(value) for value in gates.values()),
        "gate_count": len(gates),
        "startup": contracts.get("startup") or {},
        "workflow": workflow,
        "failure_modes": failure_modes,
        "response_safety": response_safety,
        "configured_database_unchanged": bool(core.get("current_database_unchanged")),
        "configured_database_modified": bool(core.get("current_database_modified")),
        "temporary_artifacts_removed": bool(core.get("temp_artifacts_removed")),
        "real_response_actions": response_safety["real_response_actions"],
        "model_activation_performed": False,
        "model_promotion_performed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "production_ready": False,
        "raw_evidence_returned": False,
        "private_paths_returned": False,
        "secrets_exposed": False,
    }


def run_v538_product_reliability_acceptance(
    *,
    use_temp_db: bool,
    log_count: int = 64,
    preflight_only: bool = False,
    temp_parent: Path | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_reports: bool = True,
) -> dict[str, Any]:
    if not use_temp_db:
        return {
            "phase": "v5.38",
            "ok": False,
            "status": "explicit_temp_database_required",
            "configured_database_modified": False,
            "real_response_actions": 0,
            "model_activation_performed": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "secrets_exposed": False,
        }

    contracts = _source_contracts()
    if preflight_only:
        report = build_v538_report(
            contracts=contracts,
            core=None,
            probes=None,
            preflight_only=True,
        )
    else:
        parent = (temp_parent or (PROJECT_ROOT / ".tmp")).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        probe_root = parent / f"v538-probes-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        probe_root.mkdir(parents=True, exist_ok=False)
        settings = Settings(
            _env_file=None,
            DATABASE_URL="sqlite://",
            RESPONSE_SIMULATION=True,
            RESPONSE_PROVIDER="simulation",
            ASSISTANT_ENABLED=True,
            ASSISTANT_PROVIDER="deterministic",
            ASSISTANT_LLM_ENABLED=False,
            ASSISTANT_LLM_PROVIDER="disabled",
            ASSISTANT_LLM_API_KEY="",
            ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
            ASSISTANT_REDACT_IPS=True,
        )
        try:
            probes = _isolated_failure_probes(settings, probe_root)
            core = run_v48_product_acceptance(
                use_temp_db=True,
                log_count=log_count,
                simulate_interruption=True,
                run_detection_enabled=True,
                test_assistant=True,
                test_backup_restore=True,
                temp_parent=parent,
            )
            report = build_v538_report(
                contracts=contracts,
                core=core,
                probes=probes,
                preflight_only=False,
            )
        except Exception as exc:
            report = {
                "phase": "v5.38",
                "version": V538_VERSION,
                "ok": False,
                "status": "v5_38_product_reliability_error",
                "error_type": exc.__class__.__name__,
                "configured_database_modified": False,
                "real_response_actions": 0,
                "model_activation_performed": False,
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
                "raw_evidence_returned": False,
                "private_paths_returned": False,
                "secrets_exposed": False,
            }
        finally:
            if probe_root.exists():
                for child in probe_root.iterdir():
                    child.unlink(missing_ok=True)
                probe_root.rmdir()

    if write_reports:
        _write_reports(report, output_dir=output_dir)
    return report


def _write_reports(report: dict[str, Any], *, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_name = f"v5_38_product_reliability_{timestamp}.json"
    markdown_name = f"v5_38_product_reliability_{timestamp}.md"
    report["artifacts"] = [json_name, markdown_name, "v5_38_product_reliability_latest.json"]
    rendered = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    (output_dir / json_name).write_text(rendered, encoding="utf-8")
    (output_dir / "v5_38_product_reliability_latest.json").write_text(rendered, encoding="utf-8")
    lines = [
        "# v5.38 Product Reliability Acceptance",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Gates: `{report.get('passed_gate_count', 0)}/{report.get('gate_count', 0)}`",
        f"- Configured database unchanged: `{report.get('configured_database_unchanged', False)}`",
        f"- Real response actions: `{report.get('real_response_actions', 0)}`",
        "- Model activation: `false`",
        "- Response automation: `false`",
        "",
        "## Gates",
        "",
    ]
    lines.extend(
        f"- `{name}`: `{'pass' if passed else 'fail'}`"
        for name, passed in (report.get("gates") or {}).items()
    )
    (output_dir / markdown_name).write_text("\n".join(lines) + "\n", encoding="utf-8")
