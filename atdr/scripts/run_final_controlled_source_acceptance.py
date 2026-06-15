import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.readiness import (
    readiness_gate_v8_fresh_blind_validation,
)
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.lock_v20_candidate import (
    DEFAULT_OUTPUT_DIR,
    lock_v20_candidate,
)
from atdr.scripts.performance_smoke import run_performance_smoke
from atdr.scripts.run_controlled_real_source_validation import (
    run_controlled_real_source_validation,
)
from atdr.scripts.run_v15_ai_readiness_validation import _latest_validation_status
from atdr.scripts.run_v17_external_generalization import (
    _latest_report_path,
    _load_json,
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _render_report(report: dict[str, Any]) -> str:
    blind = report["fresh_blind_revalidation"]
    metrics = blind.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    controlled = report["controlled_real_source_validation"]
    readiness = report["readiness_gate_v8"]
    return "\n".join(
        [
            "# ATDR v2.0 Final Controlled Validation Report",
            "",
            f"- Generated: {report['generated_at']}",
            f"- Candidate: `{report['candidate']['name']}`",
            f"- Candidate hash: `{report['candidate']['hash']}`",
            "- Production promoted: false",
            "- Model activated: false",
            "- Response automation: disabled",
            "- Real firewall blocking: disabled",
            "",
            "## Fresh Blind Revalidation",
            "",
            f"- Passed: {blind.get('passed')}",
            f"- Rows: {blind.get('row_count')}",
            f"- Threat precision: {metrics.get('threat_positive_precision')}",
            f"- Threat recall: {metrics.get('threat_positive_recall')}",
            f"- Threat F1: {metrics.get('threat_positive_f1')}",
            f"- Benign-like FPR: {metrics.get('benign_false_positive_rate')}",
            f"- Suspicious recall: {(per_class.get('suspicious') or {}).get('recall')}",
            f"- Malicious recall: {(per_class.get('malicious') or {}).get('recall')}",
            "",
            "## Controlled Source Acceptance",
            "",
            f"- Passed: {controlled.get('controlled_real_source_validated')}",
            f"- Raw logs preserved: {controlled.get('raw_logs')}",
            f"- Normalized logs: {controlled.get('normalized_logs')}",
            f"- Parse successes: {controlled.get('parse_success')}",
            f"- Parse failures tracked: {controlled.get('parse_failures')}",
            f"- Alerts: {controlled.get('alert_count')}",
            f"- Cases: {controlled.get('case_count')}",
            f"- Deduplicated alerts: {controlled.get('alerts_deduplicated')}",
            f"- Automatic responses: {(controlled.get('response_and_audit_safety') or {}).get('automatic_response_actions')}",
            "",
            "## Readiness v8",
            "",
            f"- Decision: `{readiness['decision']}`",
            f"- Checks: {readiness['passed']}/{readiness['total']}",
            f"- Final controlled validation passed: {report['final_controlled_validation_passed']}",
            "",
            "This report locks the final controlled lab evidence. It does not "
            "certify production deployment, real-device forwarding, or real "
            "firewall enforcement.",
        ]
    )


def run_final_controlled_source_acceptance(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    candidate_lock = lock_v20_candidate(
        output_dir=output_dir,
        write_output=write_output,
    )
    blind = _load_json(
        _latest_report_path(
            output_dir,
            "v2_0_fresh_blind_revalidation_*.json",
        )
    )
    controlled = run_controlled_real_source_validation(
        output_dir=output_dir,
        write_output=write_output,
    )
    performance = run_performance_smoke(feature_limit=10)
    performance_healthy = bool(performance.get("ok")) and not performance.get(
        "warnings"
    )
    controlled_validations_passed = bool(_latest_validation_status()["passed"])
    holdout = blind.get("fresh_blind_holdout") or {}
    metrics = blind.get("metrics") or {}
    calibration = (blind.get("calibration") or {}).get("metrics") or {}
    acceptance_checks = [
        {
            "name": "candidate_lock_valid",
            "passed": bool(candidate_lock.get("ok")),
        },
        {
            "name": "fresh_blind_revalidation_passed",
            "passed": bool(
                (blind.get("readiness_gate_v8") or {}).get(
                    "fresh_blind_revalidated"
                )
            ),
        },
        {
            "name": "source_registration_and_health",
            "passed": bool(controlled.get("controlled_real_source_validated"))
            and all(
                (item.get("source_health") in {"healthy", "warning", "error"})
                for item in controlled.get("scenarios", [])
            ),
        },
        {
            "name": "raw_logs_preserved",
            "passed": int(controlled.get("raw_logs") or 0) > 0,
        },
        {
            "name": "parser_profile_and_fallback_tracked",
            "passed": int(controlled.get("parse_success") or 0) > 0
            and int(controlled.get("parse_failures") or 0) > 0,
        },
        {
            "name": "detection_alerts_cases_created",
            "passed": int(controlled.get("alert_count") or 0) > 0
            and int(controlled.get("case_count") or 0) > 0,
        },
        {
            "name": "why_flagged_available",
            "passed": any(
                item.get("why_flagged_available")
                for item in controlled.get("scenarios", [])
            ),
        },
        {
            "name": "protected_ip_denial_audited",
            "passed": bool(
                (controlled.get("response_and_audit_safety") or {}).get(
                    "protected_ip_denied"
                )
            )
            and bool(
                (controlled.get("response_and_audit_safety") or {}).get(
                    "audit_recorded"
                )
            ),
        },
        {
            "name": "response_remained_simulated",
            "passed": bool(
                (controlled.get("response_and_audit_safety") or {}).get(
                    "approved_simulated"
                )
            )
            and not bool(
                (controlled.get("response_and_audit_safety") or {}).get(
                    "real_firewall_changed"
                )
            ),
        },
        {
            "name": "no_automatic_response",
            "passed": int(
                (controlled.get("response_and_audit_safety") or {}).get(
                    "automatic_response_actions"
                )
                or 0
            )
            == 0,
        },
    ]
    acceptance_passed = all(item["passed"] for item in acceptance_checks)
    v18 = _load_json(
        _latest_report_path(
            output_dir,
            "v1_8_external_benchmark_finalization_*.json",
        )
    )
    readiness = readiness_gate_v8_fresh_blind_validation(
        candidate_lock_valid=bool(candidate_lock.get("ok")),
        fresh_blind_label_count=int(holdout.get("row_count") or 0),
        fresh_blind_source_count=int(holdout.get("source_count") or 0),
        fresh_blind_scenario_count=int(holdout.get("scenario_count") or 0),
        fresh_blind_metrics=metrics,
        calibration_status=str(calibration.get("status") or "missing"),
        exact_overlap_passed=bool(
            (holdout.get("previous_holdout_overlap") or {}).get(
                "exact_overlap_passed"
            )
        ),
        threshold_tuning_performed=bool(
            blind.get("threshold_tuning_performed")
        ),
        uses_source_or_scenario_identity=bool(
            blind.get("uses_source_or_scenario_identity")
        ),
        controlled_real_source_passed=bool(
            controlled.get("controlled_real_source_validated")
        ),
        final_controlled_acceptance_passed=acceptance_passed,
        controlled_validations_passed=controlled_validations_passed,
        performance_smoke_healthy=performance_healthy,
        external_benchmark_passed=bool(
            (v18.get("readiness_gate_v6") or {}).get(
                "external_benchmark_validated"
            )
        ),
    )
    report = {
        "ok": acceptance_passed,
        "status": "passed" if acceptance_passed else "review_required",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidate": {
            "name": candidate_lock.get("candidate_name"),
            "hash": candidate_lock.get("candidate_hash"),
            "lock_valid": bool(candidate_lock.get("ok")),
        },
        "fresh_blind_revalidation": {
            "available": bool(blind),
            "passed": bool(
                (blind.get("readiness_gate_v8") or {}).get(
                    "fresh_blind_revalidated"
                )
            ),
            "row_count": int(holdout.get("row_count") or 0),
            "metrics": metrics,
            "calibration": calibration,
            "threshold_tuning_performed": bool(
                blind.get("threshold_tuning_performed")
            ),
        },
        "controlled_real_source_validation": controlled,
        "acceptance_checks": acceptance_checks,
        "final_controlled_validation_passed": acceptance_passed,
        "performance_smoke": {
            "healthy": performance_healthy,
            "warnings": performance.get("warnings") or [],
            "timings": performance.get("timings") or {},
        },
        "readiness_gate_v8": readiness,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "real_device_forwarding_validated": False,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        acceptance_json = (
            output_dir
            / f"v2_0_final_controlled_source_acceptance_{stamp}.json"
        )
        acceptance_md = (
            output_dir
            / f"v2_0_final_controlled_source_acceptance_{stamp}.md"
        )
        final_json = (
            output_dir / f"final_controlled_validation_report_{stamp}.json"
        )
        final_md = (
            output_dir / f"final_controlled_validation_report_{stamp}.md"
        )
        rendered = _render_report(report)
        serialized = json.dumps(report, indent=2, default=json_default)
        acceptance_json.write_text(serialized, encoding="utf-8")
        final_json.write_text(serialized, encoding="utf-8")
        acceptance_md.write_text(rendered, encoding="utf-8")
        final_md.write_text(rendered, encoding="utf-8")
        report["paths"] = {
            "json": str(acceptance_json),
            "markdown": str(acceptance_md),
            "final_json": str(final_json),
            "final_markdown": str(final_md),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run final controlled source acceptance for the frozen v2.0 "
            "decision-support candidate."
        )
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_final_controlled_source_acceptance(
        output_dir=Path(args.output_dir),
        write_output=not args.no_report,
    )
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=json_default,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
