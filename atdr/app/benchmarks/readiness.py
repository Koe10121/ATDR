from typing import Any


def _metric(metrics: dict[str, Any], *keys: str, default: float = 0.0) -> float:
    current: Any = metrics
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    try:
        return float(current)
    except (TypeError, ValueError):
        return default


def readiness_gate_v2(
    *,
    label_count: int,
    label_distribution: dict[str, int],
    metrics: dict[str, Any],
    benchmark_metrics: dict[str, Any] | None = None,
    drift_warnings: list[str] | None = None,
    response_automation_allowed: bool = False,
) -> dict[str, Any]:
    """Conservative benchmark/model readiness gate.

    The gate can make a candidate eligible for analyst review or benchmark validation,
    but it never marks the model as production-promoted.
    """
    benchmark = benchmark_metrics or metrics
    drift_warnings = drift_warnings or []
    threat_f1 = _metric(benchmark, "threat_positive_f1", default=_metric(benchmark, "f1"))
    threat_recall = _metric(benchmark, "threat_positive_recall", default=_metric(benchmark, "recall"))
    macro_f1 = _metric(metrics, "macro_f1")
    weighted_f1 = _metric(metrics, "weighted_f1")
    fp_rate = _metric(benchmark, "benign_false_positive_rate")
    labels_with_support = {label for label, count in label_distribution.items() if count > 0}
    important_coverage = bool(labels_with_support & {"threat", "suspicious", "malicious", "threat_positive"})
    checks = [
        {
            "name": "benchmark_or_review_label_count",
            "passed": label_count >= 100,
            "detail": f"{label_count} benchmark/review labels available.",
            "target": ">= 100 for benchmark validation; more is better.",
        },
        {
            "name": "class_coverage",
            "passed": len(labels_with_support) >= 2 and important_coverage,
            "detail": f"Classes with support: {sorted(labels_with_support)}.",
            "target": "Benign-like and threat-positive coverage.",
        },
        {
            "name": "threat_positive_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"Threat-positive F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "threat_positive_recall",
            "passed": threat_recall >= 0.8,
            "detail": f"Threat-positive recall={round(threat_recall, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "macro_or_weighted_f1",
            "passed": macro_f1 >= 0.7 or weighted_f1 >= 0.8,
            "detail": f"Macro F1={round(macro_f1, 4)}, weighted F1={round(weighted_f1, 4)}.",
            "target": "Macro F1 >= 0.70 or weighted F1 >= 0.80.",
        },
        {
            "name": "benign_false_positive_rate",
            "passed": fp_rate <= 0.2,
            "detail": f"Benign-like false-positive rate={round(fp_rate, 4)}.",
            "target": "<= 0.20",
        },
        {
            "name": "drift_clear",
            "passed": not drift_warnings,
            "detail": "No drift warnings." if not drift_warnings else "; ".join(drift_warnings[:3]),
            "target": "No unresolved drift warnings.",
        },
        {
            "name": "response_automation_disabled",
            "passed": not response_automation_allowed,
            "detail": f"response_automation_allowed={response_automation_allowed}.",
            "target": "False unless explicitly approved in a future phase.",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    if passed == len(checks):
        decision = "benchmark_validated_candidate"
        analyst_review_eligible = True
    elif threat_f1 >= 0.75 and threat_recall >= 0.7 and not response_automation_allowed:
        decision = "analyst_review_eligible"
        analyst_review_eligible = True
    else:
        decision = "candidate_only"
        analyst_review_eligible = False
    return {
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "response_automation_allowed": False,
        "analyst_review_eligible": analyst_review_eligible,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "message": (
            "Benchmark readiness is a decision-support gate only. Production promotion remains disabled until a future "
            "real-source/security approval phase."
        ),
    }
