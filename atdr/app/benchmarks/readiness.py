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


def readiness_gate_v3(
    *,
    reviewed_label_count: int,
    reviewed_label_distribution: dict[str, int],
    temporal_class_coverage: dict[str, Any],
    metrics: dict[str, Any],
    benchmark_label_count: int = 0,
    calibration_buckets: list[dict[str, Any]] | None = None,
    drift_warnings: list[str] | None = None,
    response_automation_allowed: bool = False,
) -> dict[str, Any]:
    """Conservative readiness gate for larger reviewed-label experiments.

    This gate can strengthen candidate wording, but it never production-promotes
    a model or permits automated response.
    """
    drift_warnings = drift_warnings or []
    calibration_buckets = calibration_buckets or []
    threat = metrics.get("threat_positive") or {}
    per_class = metrics.get("per_class") or {}
    threat_f1 = _metric(threat, "f1", default=_metric(metrics, "threat_positive_f1"))
    threat_recall = _metric(threat, "recall", default=_metric(metrics, "threat_positive_recall"))
    suspicious_recall = _metric(per_class, "suspicious", "recall")
    malicious_recall = _metric(per_class, "malicious", "recall")
    benign_fp_rate = _metric(metrics, "false_positive_rate", default=_metric(metrics, "benign_false_positive_rate"))
    false_negatives = int((metrics.get("cost_sensitive") or {}).get("threat_false_negatives") or metrics.get("false_negatives") or 0)
    threat_support = sum(
        int((per_class.get(label) or {}).get("support") or 0)
        for label in ("suspicious", "malicious")
    )
    false_negative_rate = round(false_negatives / threat_support, 4) if threat_support else 1.0
    class_coverage = temporal_class_coverage.get("class_coverage") or temporal_class_coverage
    important_temporal_coverage = all(
        int((class_coverage.get(label) or {}).get("train_count") or 0) > 0
        and int((class_coverage.get(label) or {}).get("test_count") or 0) > 0
        for label in ("suspicious", "malicious")
    )
    required_reviewed_classes = {
        "benign": 300,
        "benign_unusual": 300,
        "suspicious": 300,
        "malicious": 150,
        "needs_context": 50,
    }
    minimum_class_coverage = all(
        int(reviewed_label_distribution.get(label) or 0) >= target
        for label, target in required_reviewed_classes.items()
    )
    calibrated = bool(calibration_buckets) and all(
        item.get("accuracy") is None
        or abs(float(item.get("accuracy") or 0) - float(item.get("average_confidence") or item.get("accuracy") or 0)) <= 0.2
        for item in calibration_buckets
    )
    checks = [
        {
            "name": "reviewed_label_count",
            "passed": reviewed_label_count >= 1100,
            "detail": f"{reviewed_label_count} reviewed labels available.",
            "target": ">= 1100 across the minimum class plan.",
        },
        {
            "name": "reviewed_class_coverage",
            "passed": minimum_class_coverage,
            "detail": f"Reviewed distribution: {reviewed_label_distribution}.",
            "target": str(required_reviewed_classes),
        },
        {
            "name": "temporal_class_coverage",
            "passed": important_temporal_coverage,
            "detail": "Suspicious and malicious must exist in both training and test windows.",
            "target": "train_count > 0 and test_count > 0 for both threat classes.",
        },
        {
            "name": "benchmark_label_count",
            "passed": benchmark_label_count >= 100,
            "detail": f"{benchmark_label_count} prepared benchmark labels available.",
            "target": ">= 100 for benchmark-validated candidate wording.",
        },
        {
            "name": "threat_positive_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"Threat-positive F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "threat_positive_recall",
            "passed": threat_recall >= 0.85,
            "detail": f"Threat-positive recall={round(threat_recall, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "suspicious_recall",
            "passed": suspicious_recall >= 0.8,
            "detail": f"Suspicious recall={round(suspicious_recall, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "malicious_recall",
            "passed": malicious_recall >= 0.5,
            "detail": f"Malicious recall={round(malicious_recall, 4)}.",
            "target": ">= 0.50",
        },
        {
            "name": "benign_like_false_positive_rate",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"Benign-like false-positive rate={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "threat_false_negative_rate",
            "passed": false_negative_rate <= 0.2,
            "detail": f"Threat false-negative rate={false_negative_rate}.",
            "target": "<= 0.20",
        },
        {
            "name": "confidence_calibration",
            "passed": calibrated,
            "detail": "Calibration buckets available and within tolerance." if calibrated else "Calibration evidence is missing or outside tolerance.",
            "target": "Confidence buckets available with <= 0.20 confidence/accuracy gap.",
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
            "target": "False.",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    benchmark_ready = benchmark_label_count >= 100 and threat_f1 >= 0.85 and threat_recall >= 0.85
    analyst_ready = (
        reviewed_label_count >= 300
        and threat_f1 >= 0.75
        and threat_recall >= 0.75
        and malicious_recall > 0
        and not response_automation_allowed
    )
    if benchmark_ready and minimum_class_coverage and important_temporal_coverage and passed >= len(checks) - 1:
        decision = "benchmark_validated_candidate"
    elif analyst_ready:
        decision = "analyst_review_eligible"
    else:
        decision = "candidate_only"
    return {
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "response_automation_allowed": False,
        "analyst_review_eligible": analyst_ready,
        "benchmark_validated": decision == "benchmark_validated_candidate",
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "message": "Readiness v3 is a supervised decision-support gate. It cannot activate a model or authorize response automation.",
    }


def readiness_gate_v4(
    *,
    benchmark_label_count: int,
    benchmark_label_distribution: dict[str, int],
    benchmark_metrics: dict[str, Any],
    calibration_status: str,
    controlled_validations_passed: bool,
    response_automation_allowed: bool = False,
) -> dict[str, Any]:
    """Final benchmark-aware decision-support readiness gate.

    v4 may classify a candidate as benchmark validated, but it deliberately
    cannot activate a model, production-promote it, or authorize response.
    """
    threat_f1 = _metric(
        benchmark_metrics,
        "threat_positive_f1",
        default=_metric(benchmark_metrics, "f1"),
    )
    threat_recall = _metric(
        benchmark_metrics,
        "threat_positive_recall",
        default=_metric(benchmark_metrics, "recall"),
    )
    benign_fp_rate = _metric(
        benchmark_metrics,
        "benign_false_positive_rate",
        default=_metric(benchmark_metrics, "benign_like_false_positive_rate"),
    )
    suspicious_recall = _metric(
        benchmark_metrics,
        "per_class",
        "suspicious",
        "recall",
        default=_metric(benchmark_metrics, "suspicious_recall"),
    )
    malicious_recall = _metric(
        benchmark_metrics,
        "per_class",
        "malicious",
        "recall",
        default=_metric(benchmark_metrics, "malicious_recall"),
    )
    normalized_distribution = {
        str(label).lower(): int(count)
        for label, count in benchmark_label_distribution.items()
    }
    benign_support = sum(
        normalized_distribution.get(label, 0)
        for label in ("benign", "benign_like", "benign_unusual")
    )
    suspicious_support = normalized_distribution.get("suspicious", 0)
    malicious_support = normalized_distribution.get("malicious", 0)
    calibration_passed = calibration_status.strip().lower() in {
        "passed",
        "pass",
        "calibrated",
    }
    checks = [
        {
            "name": "benchmark_label_count",
            "passed": benchmark_label_count >= 100,
            "detail": f"{benchmark_label_count} benchmark labels available.",
            "target": ">= 100",
        },
        {
            "name": "benchmark_class_coverage",
            "passed": benign_support > 0
            and suspicious_support > 0
            and malicious_support > 0,
            "detail": f"Benchmark distribution: {benchmark_label_distribution}.",
            "target": "Benign-like, suspicious, and malicious support.",
        },
        {
            "name": "benchmark_threat_positive_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"Threat-positive F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "benchmark_threat_positive_recall",
            "passed": threat_recall >= 0.85,
            "detail": f"Threat-positive recall={round(threat_recall, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "benchmark_benign_like_false_positive_rate",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"Benign-like false-positive rate={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "confidence_calibration",
            "passed": calibration_passed,
            "detail": f"Calibration status={calibration_status or 'missing'}.",
            "target": "passed",
        },
        {
            "name": "controlled_validations",
            "passed": controlled_validations_passed,
            "detail": (
                "Latest controlled validations passed."
                if controlled_validations_passed
                else "One or more controlled validations are missing or failed."
            ),
            "target": "passed",
        },
        {
            "name": "response_automation_disabled",
            "passed": not response_automation_allowed,
            "detail": f"response_automation_allowed={response_automation_allowed}.",
            "target": "False",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    all_required_passed = passed == len(checks)
    analyst_review_eligible = (
        benchmark_label_count >= 100
        and threat_f1 >= 0.75
        and threat_recall >= 0.75
        and not response_automation_allowed
    )
    if all_required_passed:
        decision = "benchmark_validated_candidate"
    elif analyst_review_eligible:
        decision = "analyst_review_eligible"
    else:
        decision = "candidate_only"
    return {
        "version": "v4",
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "analyst_review_eligible": analyst_review_eligible,
        "benchmark_validated": decision == "benchmark_validated_candidate",
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "advisory_metrics": {
            "suspicious_recall": suspicious_recall,
            "malicious_recall": malicious_recall,
            "malicious_recall_ideal_target": 0.7,
            "malicious_recall_is_blocking": False,
        },
        "message": (
            "Benchmark validation strengthens analyst-review evidence only. "
            "Production promotion, model activation, and response automation remain disabled."
        ),
    }
