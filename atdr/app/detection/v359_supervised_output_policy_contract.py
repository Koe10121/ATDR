import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import training_dataset_diagnostics
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v332_guard_validation import _safe_float
from atdr.app.detection.v355_severity_target_policy_reframing import V355_LATEST
from atdr.app.detection.v357_queue_rule_hybrid_agreement import V357_LATEST


V359_LATEST = "v3_59_supervised_output_policy_contract_latest.json"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _status_from_bool(value: bool, *, passed: str = "passed", failed: str = "needs_work") -> str:
    return passed if value else failed


def _v355_queue_metrics(v355: dict[str, Any] | None) -> dict[str, Any]:
    if not v355:
        return {"available": False, "status": "missing"}
    strategy = (v355.get("strategy_comparison") or {}).get("binary_review_queue_queue_only") or {}
    stability = strategy.get("stability") or {}
    ranges = stability.get("metric_ranges") or {}
    calibration = strategy.get("best_calibration") or {}
    readiness = v355.get("readiness") or {}
    evaluated = int(stability.get("evaluated_splits") or 0)
    passing = int(stability.get("passing_splits") or 0)
    f1_min = _safe_float((ranges.get("queue_f1") or {}).get("min"))
    recall_min = _safe_float((ranges.get("queue_recall") or {}).get("min"))
    precision_min = _safe_float((ranges.get("queue_precision") or {}).get("min"))
    fpr_max = _safe_float((ranges.get("benign_like_false_positive_rate") or {}).get("max"), 1.0)
    calibration_ok = str(calibration.get("status") or "").lower() == "passed"
    split_ok = evaluated > 0 and passing == evaluated
    metric_ok = f1_min >= 0.95 and recall_min >= 0.90 and precision_min >= 0.90 and fpr_max <= 0.05
    return {
        "available": True,
        "phase": v355.get("phase") or "v3.55",
        "status": _status_from_bool(split_ok and metric_ok and calibration_ok, passed="stable", failed="unstable"),
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "evaluated_splits": evaluated,
        "passing_splits": passing,
        "queue_f1_min": f1_min,
        "queue_recall_min": recall_min,
        "queue_precision_min": precision_min,
        "benign_like_false_positive_rate_max": fpr_max,
        "calibration_status": calibration.get("status") or "unknown",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "blockers": readiness.get("blockers") or [],
    }


def _v355_exact_severity_metrics(v355: dict[str, Any] | None) -> dict[str, Any]:
    if not v355:
        return {"available": False, "status": "missing"}
    comparisons = v355.get("strategy_comparison") or {}
    severity_rows = []
    stable_count = 0
    for name, payload in sorted(comparisons.items()):
        if name == "binary_review_queue_queue_only":
            continue
        stability = payload.get("stability") or {}
        evaluated = int(stability.get("evaluated_splits") or 0)
        passing = int(stability.get("passing_splits") or 0)
        stable = evaluated > 0 and passing == evaluated
        stable_count += 1 if stable else 0
        ranges = stability.get("metric_ranges") or {}
        severity_rows.append(
            {
                "name": name,
                "evaluated_splits": evaluated,
                "passing_splits": passing,
                "stable": stable,
                "policy_positive_f1_min": (ranges.get("policy_positive_f1") or ranges.get("threat_positive_f1") or {}).get("min"),
                "false_positive_rate_max": (ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                "critical_recall_min": (ranges.get("critical_recall_min") or {}).get("min"),
            }
        )
    return {
        "available": True,
        "status": "stable" if stable_count else "unstable",
        "stable_policy_count": stable_count,
        "evaluated_policy_count": len(severity_rows),
        "policies": severity_rows,
    }


def _v357_agreement_metrics(v357: dict[str, Any] | None) -> dict[str, Any]:
    if not v357:
        return {"available": False, "status": "missing"}
    aggregate = v357.get("aggregate") or {}
    readiness = v357.get("readiness") or {}
    safety = v357.get("safety") or {}
    evaluated = int(aggregate.get("evaluated_splits") or 0)
    passing = int(aggregate.get("passing_splits") or 0)
    f1_min = _safe_float(aggregate.get("queue_f1_min"))
    fpr_max = _safe_float(aggregate.get("queue_false_positive_rate_max"), 1.0)
    agreement_min = _safe_float(aggregate.get("agreement_rate_min"))
    ece_max = _safe_float(aggregate.get("calibration_ece_max"), 1.0)
    usable = evaluated > 0 and passing >= max(1, evaluated - 1) and f1_min >= 0.95 and fpr_max <= 0.05 and agreement_min >= 0.85
    return {
        "available": True,
        "phase": v357.get("phase") or "v3.57",
        "status": _status_from_bool(usable, passed="usable_with_review", failed="needs_work"),
        "readiness_decision": readiness.get("decision") or "diagnostic_only",
        "evaluated_splits": evaluated,
        "passing_splits": passing,
        "queue_f1_min": f1_min,
        "queue_false_positive_rate_max": fpr_max,
        "agreement_rate_min": agreement_min,
        "calibration_ece_max": ece_max,
        "category_counts": aggregate.get("category_counts") or {},
        "top_evidence_only_patterns": aggregate.get("top_evidence_only_patterns") or [],
        "top_queue_only_patterns": aggregate.get("top_queue_only_patterns") or [],
        "blockers": (readiness.get("blockers") or []) + (aggregate.get("blockers") or []),
        "safety": {
            "production_promoted": bool(safety.get("production_promoted", False)),
            "model_activated": bool(safety.get("model_activated", False)),
            "model_artifact_written": bool(safety.get("model_artifact_written", False)),
            "labels_written": bool(safety.get("labels_written", False)),
            "raw_logs_included": bool(safety.get("raw_logs_included", False)),
            "response_automation_allowed": bool(safety.get("response_automation_allowed", False)),
        },
    }


def build_supervised_output_policy_contract(
    *,
    v355: dict[str, Any] | None,
    v357: dict[str, Any] | None,
    training_diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    queue = _v355_queue_metrics(v355)
    exact = _v355_exact_severity_metrics(v355)
    agreement = _v357_agreement_metrics(v357)
    upstream_missing = [
        name
        for name, metrics in {
            "v3.55 severity target policy reframing": queue,
            "v3.57 queue-vs-rule/hybrid agreement": agreement,
        }.items()
        if not metrics.get("available")
    ]
    queue_stable = queue.get("status") == "stable"
    agreement_usable = agreement.get("status") == "usable_with_review"
    exact_unstable = exact.get("status") != "stable"
    contract_ready = bool(queue_stable and agreement_usable and exact_unstable and not upstream_missing)
    allowed_outputs = {
        "soc_review_queue_score": {
            "status": "allowed_for_decision_support" if contract_ready else "diagnostic_only",
            "meaning": "Estimate whether a log or alert should enter SOC analyst review.",
            "allowed_surfaces": ["ML Governance", "SOC Assistant", "alert explanation", "review prioritization"],
            "not_allowed": ["automatic response", "production promotion", "human-reviewed label creation"],
        },
        "exact_severity_or_attack_label": {
            "status": "explanation_or_ranking_only",
            "meaning": "Use as supporting context after deterministic evidence, not as a final classifier.",
            "allowed_surfaces": ["assistant explanation", "alert detail supporting context", "analyst review notes"],
            "not_allowed": ["model activation gate", "automatic response", "production accuracy claim"],
        },
        "rule_hybrid_evidence": {
            "status": "primary_detection_evidence",
            "meaning": "Rule, anomaly, hybrid, and parser evidence remain primary for alert creation and analyst explanation.",
            "allowed_surfaces": ["alert creation", "Why flagged", "SOC Assistant citations"],
            "not_allowed": ["bypassing analyst approval for response"],
        },
    }
    blocked_uses = [
        "automatic response from supervised ML output",
        "real firewall blocking from supervised ML output",
        "production promotion based on queue diagnostics alone",
        "marking AI-generated labels as human-reviewed",
        "using exact suspicious/malicious/needs_context labels as stable production classes",
        "sending raw logs to an external assistant or LLM by default",
    ]
    checks = [
        {"name": "v3.55 queue policy report available", "passed": queue.get("available") is True, "value": queue.get("available")},
        {"name": "queue target stable across splits", "passed": queue_stable, "value": queue.get("status")},
        {"name": "v3.57 agreement report available", "passed": agreement.get("available") is True, "value": agreement.get("available")},
        {"name": "queue/evidence agreement usable with review", "passed": agreement_usable, "value": agreement.get("status")},
        {"name": "exact severity policies remain non-authoritative", "passed": exact_unstable, "value": exact.get("status")},
        {"name": "contract forbids automatic response", "passed": True, "value": "blocked"},
        {"name": "contract forbids label auto-review", "passed": True, "value": "blocked"},
    ]
    blockers = [item["name"] for item in checks if not item["passed"]]
    decision = "decision_support_contract_ready" if contract_ready else "diagnostic_contract_only"
    return {
        "decision": decision,
        "contract_ready_for_runtime_activation": False,
        "contract_ready_for_dashboard_guidance": contract_ready,
        "recommended_supervised_strategy": "binary_soc_review_queue",
        "exact_classification_policy": "explanation_or_ranking_only",
        "queue": queue,
        "queue_evidence_agreement": agreement,
        "exact_severity": exact,
        "allowed_outputs": allowed_outputs,
        "blocked_uses": blocked_uses,
        "checks": checks,
        "checks_passed": sum(1 for item in checks if item["passed"]),
        "checks_total": len(checks),
        "blockers": blockers,
        "upstream_missing": upstream_missing,
        "training_diagnostics": training_diagnostics or {},
        "safety_statement": (
            "Supervised ML may guide SOC review prioritization only. Deterministic rule/hybrid evidence, "
            "human analyst judgment, simulated response controls, and audit logging remain authoritative."
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    contract = result["contract"]
    queue = contract["queue"]
    agreement = contract["queue_evidence_agreement"]
    exact = contract["exact_severity"]
    lines = [
        "# v3.59 Supervised Output Policy Contract",
        "",
        "## Status",
        "",
        f"- Decision: `{contract['decision']}`",
        f"- Recommended supervised strategy: `{contract['recommended_supervised_strategy']}`",
        f"- Exact classification policy: `{contract['exact_classification_policy']}`",
        f"- Checks: `{contract['checks_passed']} / {contract['checks_total']}`",
        "",
        "## Queue Policy Evidence",
        "",
        f"- Status: `{queue.get('status')}`",
        f"- Splits: `{queue.get('passing_splits')} / {queue.get('evaluated_splits')}`",
        f"- Queue F1 min: `{queue.get('queue_f1_min')}`",
        f"- Queue FPR max: `{queue.get('benign_like_false_positive_rate_max')}`",
        f"- Calibration: `{queue.get('calibration_status')}`",
        "",
        "## Queue / Evidence Agreement",
        "",
        f"- Status: `{agreement.get('status')}`",
        f"- Splits: `{agreement.get('passing_splits')} / {agreement.get('evaluated_splits')}`",
        f"- Agreement min: `{agreement.get('agreement_rate_min')}`",
        f"- Evidence-only patterns: `{agreement.get('top_evidence_only_patterns')}`",
        "",
        "## Exact Severity Policy",
        "",
        f"- Status: `{exact.get('status')}`",
        f"- Stable exact-severity policies: `{exact.get('stable_policy_count')} / {exact.get('evaluated_policy_count')}`",
        "- Exact suspicious/malicious/needs_context separation remains explanation/ranking only.",
        "",
        "## Allowed Outputs",
        "",
    ]
    for name, payload in contract["allowed_outputs"].items():
        lines.append(f"- `{name}`: `{payload['status']}` - {payload['meaning']}")
    lines.extend(
        [
            "",
            "## Blocked Uses",
            "",
            *[f"- {item}" for item in contract["blocked_uses"]],
            "",
            "## Safety",
            "",
            f"```json\n{json.dumps(result['safety'], indent=2, default=str)}\n```",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v359_supervised_output_policy_contract(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    v355 = _read_json(output / V355_LATEST)
    v357 = _read_json(output / V357_LATEST)
    diagnostics = training_dataset_diagnostics(db)
    contract = build_supervised_output_policy_contract(
        v355=v355,
        v357=v357,
        training_diagnostics={
            "total_label_rows": diagnostics.get("total_label_rows"),
            "trainable_latest_rows": diagnostics.get("trainable_latest_rows"),
            "excluded_from_training": diagnostics.get("excluded_from_training"),
            "superseded_label_rows": diagnostics.get("superseded_label_rows"),
            "missing_log_rows": diagnostics.get("missing_log_rows"),
            "non_trainable_label_rows": diagnostics.get("non_trainable_label_rows"),
            "missing_timestamp_latest_rows": diagnostics.get("missing_timestamp_latest_rows"),
            "feature_excluded_rows": diagnostics.get("feature_excluded_rows"),
        },
    )

    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    stamp = _stamp()
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.59",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contract": contract,
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "labels_written": before_labels != after_labels,
            "raw_logs_included": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "ml_labels_before": before_labels,
            "ml_labels_after": after_labels,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
    }
    report_path = output / f"v3_59_supervised_output_policy_contract_{stamp}.md"
    latest_path = output / V359_LATEST
    result["report_path"] = str(report_path)
    result["latest_summary_path"] = str(latest_path)
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
