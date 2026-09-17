from __future__ import annotations

import argparse
import json
from typing import Any

from atdr.app.core.config import get_settings
from atdr.app.detection.v5631_advisor_demo_reliability import (
    _optional_ml_imports,
    evaluate_controlled_model,
    load_controlled_evidence,
)
from atdr.app.services.v561_anomaly_bootstrap_service import anomaly_bootstrap_status
from atdr.scripts.evaluate_assistant_qa import evaluate_assistant_qa
from atdr.scripts.run_v557_analyst_workflow_acceptance import (
    run_v557_analyst_workflow_acceptance,
)
from atdr.scripts.test_assistant_llm_provider import build_report as build_provider_report


VERSION = "v5.63.1-advisor-demo-acceptance-v1"


def _anomaly_stage() -> dict[str, Any]:
    settings = get_settings()
    status = anomaly_bootstrap_status(artifact_path=settings.resolved_model_path)
    imports = _optional_ml_imports()
    if imports is None or not settings.resolved_model_path.is_file():
        return {
            "passed": False,
            "state": status["state"],
            "reason": "advisory_anomaly_capability_unavailable",
            "decision_support_only": True,
            "rules_alert_authoritative": True,
        }
    try:
        model = imports[0].load(settings.resolved_model_path)
        controlled = load_controlled_evidence()
        metrics = evaluate_controlled_model(model, imports, controlled)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "passed": False,
            "state": "unavailable",
            "reason": "advisory_anomaly_scoring_failed",
            "error_type": exc.__class__.__name__,
            "decision_support_only": True,
            "rules_alert_authoritative": True,
        }
    return {
        "passed": metrics["rows_scored"] > 0,
        "state": "active_advisory",
        "capability_state": status["state"],
        "governed_manifest_valid": status["governed_manifest_valid"],
        "rows_scored": metrics["rows_scored"],
        "controlled_benign_anomaly_rate": metrics[
            "controlled_benign_anomaly_rate"
        ],
        "controlled_suspicious_scenario_recall": metrics[
            "controlled_suspicious_scenario_recall"
        ],
        "controlled_malicious_scenario_recall": metrics[
            "controlled_malicious_scenario_recall"
        ],
        "threat_accuracy_validated": False,
        "decision_support_only": True,
        "rules_alert_authoritative": True,
        "model_driven_alerts": 0,
        "model_driven_suppressions": 0,
    }


def run_advisor_demo_acceptance(
    *,
    use_temp_db: bool,
    execute_provider_probe: bool = False,
) -> dict[str, Any]:
    if not use_temp_db:
        return {
            "version": VERSION,
            "ok": False,
            "status": "explicit_temp_database_required",
            "configured_database_accessed": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }

    workflow = run_v557_analyst_workflow_acceptance()
    assistant_quality = evaluate_assistant_qa()
    anomaly = _anomaly_stage()
    provider = build_provider_report(execute=execute_provider_probe)
    workflow_stages = workflow.get("stages") or {}
    stages = {
        "ingestion": bool((workflow_stages.get("ingestion") or {}).get("passed")),
        "parsing_and_normalization": bool(
            (workflow_stages.get("parsing_and_normalization") or {}).get("passed")
        ),
        "authoritative_rule_detection": bool(
            (workflow_stages.get("detection") or {}).get("passed")
        ),
        "advisory_anomaly_scoring": bool(anomaly.get("passed")),
        "alert_explanation_and_evidence": bool(
            (workflow_stages.get("explanation_and_related_evidence") or {}).get(
                "passed"
            )
        ),
        "analyst_recommendation_and_case_handoff": bool(
            (workflow_stages.get("case_investigation") or {}).get("passed")
        ),
        "soc_assistant_quality": bool(assistant_quality.get("ok")),
        "gemini_provider": bool(provider.get("ok")),
        "simulated_response": bool(
            (workflow_stages.get("simulated_response") or {}).get("passed")
        ),
        "audit_history": bool(
            (workflow_stages.get("audit_history") or {}).get("passed")
        ),
    }
    failed_stages = [name for name, passed in stages.items() if not passed]
    return {
        "version": VERSION,
        "ok": bool(workflow.get("ok") and not failed_stages),
        "status": (
            "advisor_demo_acceptance_passed"
            if workflow.get("ok") and not failed_stages
            else "advisor_demo_acceptance_failed"
        ),
        "scope": "disposable_controlled_lab_workflow",
        "stages": stages,
        "failed_stages": failed_stages,
        "workflow": {
            "checks": workflow.get("checks"),
            "database_mode": workflow.get("database_mode"),
            "configured_database_accessed": workflow.get(
                "configured_database_accessed"
            ),
        },
        "anomaly": anomaly,
        "assistant_quality": {
            "passed": assistant_quality.get("ok"),
            "quality_dimensions": assistant_quality.get("quality_dimensions"),
            "answer_quality_cases": assistant_quality.get("answer_quality_cases"),
            "answer_concision": assistant_quality.get("answer_concision"),
            "followup_sequences": len(
                assistant_quality.get("conversation_sequence_results") or []
            ),
            "zero_authoritative_side_effects": (
                assistant_quality.get("quality_dimensions") or {}
            ).get("zero_authoritative_side_effects"),
        },
        "provider": {
            "probe_requested": execute_provider_probe,
            "ok": provider.get("ok"),
            "provider": provider.get("provider"),
            "enabled": provider.get("llm_enabled"),
            "configured": provider.get("provider_configured"),
            "model_configured": provider.get("model_configured"),
            "api_key_configured": provider.get("api_key_configured"),
            "executed_provider_call": provider.get("executed_provider_call"),
            "structured_output_valid": provider.get("structured_output_valid"),
            "raw_log_context_included": provider.get(
                "raw_log_context_included",
                False,
            ),
            "redaction_enabled": provider.get("redaction_enabled"),
            "secrets_exposed": provider.get("secrets_exposed"),
        },
        "runtime_truth": {
            "rules": "active_authoritative",
            "isolation_forest": "active_advisory"
            if anomaly.get("passed")
            else "unavailable",
            "supervised": "unqualified",
            "hybrid": "advisory_only",
            "response": "simulation_only",
        },
        "safety": {
            "current_database_accessed": False,
            "current_database_modified": False,
            "raw_logs_exposed": False,
            "private_paths_exposed": False,
            "network_addresses_exposed": False,
            "secrets_exposed": False,
            "model_activated_or_promoted": False,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
        },
        "limitations": [
            "Controlled synthetic scenarios do not establish independent real-world accuracy.",
            "Supervised ML remains unqualified and is not active at runtime.",
            "MFU provider acceptance and physical-firewall validation are deferred.",
        ],
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the disposable ATDR advisor demonstration acceptance."
    )
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument(
        "--execute-provider-probe",
        action="store_true",
        help="Run one bounded Gemini/provider probe when privately configured.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_advisor_demo_acceptance(
        use_temp_db=args.use_temp_db,
        execute_provider_probe=args.execute_provider_probe,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, default=str))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
