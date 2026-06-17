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


def readiness_gate_v5(
    *,
    external_label_count: int,
    external_metrics: dict[str, Any],
    calibration_status: str,
    controlled_validations_passed: bool,
    internal_benchmark_validated: bool,
    response_automation_allowed: bool = False,
) -> dict[str, Any]:
    """External/holdout benchmark gate that remains decision-support only."""
    threat_f1 = _metric(
        external_metrics,
        "threat_positive_f1",
        default=_metric(external_metrics, "f1"),
    )
    threat_recall = _metric(
        external_metrics,
        "threat_positive_recall",
        default=_metric(external_metrics, "recall"),
    )
    benign_fp_rate = _metric(
        external_metrics,
        "benign_false_positive_rate",
        default=_metric(external_metrics, "benign_like_false_positive_rate"),
    )
    calibration_normalized = calibration_status.strip().lower()
    calibration_acceptable = calibration_normalized in {
        "passed",
        "pass",
        "not_available",
        "not available",
    }
    checks = [
        {
            "name": "external_benchmark_minimum_rows",
            "passed": external_label_count >= 100,
            "detail": f"{external_label_count} external/holdout labels available.",
            "target": ">= 100; >= 300 preferred",
        },
        {
            "name": "external_benchmark_preferred_rows",
            "passed": external_label_count >= 300,
            "detail": f"{external_label_count} external/holdout labels available.",
            "target": ">= 300 preferred",
            "advisory": True,
        },
        {
            "name": "external_threat_positive_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"External threat-positive F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "external_threat_positive_recall",
            "passed": threat_recall >= 0.85,
            "detail": f"External threat-positive recall={round(threat_recall, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "external_benign_like_false_positive_rate",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"External benign-like false-positive rate={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "confidence_calibration",
            "passed": calibration_acceptable,
            "detail": f"Calibration status={calibration_status or 'missing'}.",
            "target": "passed or not_available",
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
    required_checks = [item for item in checks if not item.get("advisory")]
    passed_required = sum(1 for item in required_checks if item["passed"])
    passed_total = sum(1 for item in checks if item["passed"])
    external_validated = all(item["passed"] for item in required_checks)
    analyst_review_eligible = (
        external_label_count >= 100
        and threat_f1 >= 0.75
        and threat_recall >= 0.75
        and not response_automation_allowed
    )
    if external_validated:
        decision = "external_benchmark_validated_candidate"
    elif internal_benchmark_validated:
        decision = "internal_benchmark_validated_candidate"
    elif analyst_review_eligible:
        decision = "analyst_review_eligible"
    else:
        decision = "candidate_only"
    return {
        "version": "v5",
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "analyst_review_eligible": analyst_review_eligible,
        "internal_benchmark_validated": internal_benchmark_validated,
        "external_benchmark_validated": external_validated,
        "passed": passed_total,
        "total": len(checks),
        "required_passed": passed_required,
        "required_total": len(required_checks),
        "checks": checks,
        "message": (
            "External/holdout validation strengthens SOC triage evidence only. "
            "Production promotion, automatic model activation, and response automation remain disabled."
        ),
    }


def readiness_gate_v6_external_generalization(
    *,
    external_label_count: int,
    external_metrics: dict[str, Any],
    calibration_status: str,
    controlled_validations_passed: bool,
    internal_benchmark_validated: bool,
    overfitting_status: str,
    response_automation_allowed: bool = False,
) -> dict[str, Any]:
    """v1.7 external generalization gate with explicit boundary/overfit checks.

    This remains a decision-support gate. It cannot activate a model, production
    promote a model, or allow response automation.
    """
    result = readiness_gate_v5(
        external_label_count=external_label_count,
        external_metrics=external_metrics,
        calibration_status=calibration_status,
        controlled_validations_passed=controlled_validations_passed,
        internal_benchmark_validated=internal_benchmark_validated,
        response_automation_allowed=response_automation_allowed,
    )
    suspicious_recall = _metric(
        external_metrics,
        "per_class",
        "suspicious",
        "recall",
        default=_metric(external_metrics, "suspicious_recall"),
    )
    malicious_recall = _metric(
        external_metrics,
        "per_class",
        "malicious",
        "recall",
        default=_metric(external_metrics, "malicious_recall"),
    )
    benign_fp_rate = _metric(
        external_metrics,
        "benign_false_positive_rate",
        default=_metric(external_metrics, "benign_like_false_positive_rate"),
    )
    overfitting_limited = overfitting_status.strip().lower() == "limited_generalization_gap"
    extra_checks = [
        {
            "name": "external_suspicious_recall",
            "passed": suspicious_recall >= 0.8,
            "detail": f"External suspicious recall={round(suspicious_recall, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "external_malicious_recall",
            "passed": malicious_recall >= 0.65,
            "detail": f"External malicious recall={round(malicious_recall, 4)}.",
            "target": ">= 0.65",
        },
        {
            "name": "external_low_noise",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"External benign-like false-positive rate={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "overfitting_gap_limited",
            "passed": overfitting_limited,
            "detail": f"Overfitting status={overfitting_status or 'missing'}.",
            "target": "limited_generalization_gap",
        },
    ]
    checks = [*result["checks"], *extra_checks]
    passed = sum(1 for item in checks if item["passed"])
    required_checks = [item for item in checks if not item.get("advisory")]
    required_passed = sum(1 for item in required_checks if item["passed"])
    external_validated = all(item["passed"] for item in required_checks)
    if external_validated:
        decision = "external_benchmark_validated_candidate"
    elif internal_benchmark_validated:
        decision = "internal_benchmark_validated_candidate"
    elif result["analyst_review_eligible"]:
        decision = "analyst_review_eligible"
    else:
        decision = "candidate_only"
    return {
        **result,
        "version": "v6",
        "decision": decision,
        "external_benchmark_validated": external_validated,
        "passed": passed,
        "total": len(checks),
        "required_passed": required_passed,
        "required_total": len(required_checks),
        "checks": checks,
        "advisory_metrics": {
            "suspicious_recall": suspicious_recall,
            "malicious_recall": malicious_recall,
            "benign_false_positive_rate": benign_fp_rate,
            "overfitting_status": overfitting_status,
        },
        "message": (
            "v1.7 external generalization strengthens analyst-review evidence only. "
            "Production promotion, automatic model activation, and response automation remain disabled."
        ),
    }


def readiness_gate_v6_external_finalization(
    *,
    external_label_count: int,
    external_metrics: dict[str, Any],
    calibration_status: str,
    controlled_validations_passed: bool,
    internal_benchmark_validated: bool,
    overfitting_status: str,
    profile_rejected: bool = False,
    response_automation_allowed: bool = False,
) -> dict[str, Any]:
    """Final external benchmark candidate gate for v1.8.

    Calibration may be explicitly limited when its measured error remains within
    the documented tolerance. This gate never activates or production-promotes a
    model and never authorizes response automation.
    """
    threat_precision = _metric(external_metrics, "threat_positive_precision")
    threat_f1 = _metric(external_metrics, "threat_positive_f1")
    threat_recall = _metric(external_metrics, "threat_positive_recall")
    benign_fp_rate = _metric(
        external_metrics,
        "benign_false_positive_rate",
        default=_metric(external_metrics, "benign_like_false_positive_rate"),
    )
    suspicious_recall = _metric(
        external_metrics,
        "per_class",
        "suspicious",
        "recall",
        default=_metric(external_metrics, "suspicious_recall"),
    )
    malicious_recall = _metric(
        external_metrics,
        "per_class",
        "malicious",
        "recall",
        default=_metric(external_metrics, "malicious_recall"),
    )
    calibration_normalized = calibration_status.strip().lower()
    calibration_acceptable = calibration_normalized in {
        "passed",
        "pass",
        "calibrated",
        "limited",
    }
    overfitting_acceptable = overfitting_status.strip().lower() in {
        "limited_generalization_gap",
        "moderate_generalization_gap",
    }
    checks = [
        {
            "name": "external_benchmark_rows",
            "passed": external_label_count >= 300,
            "detail": f"{external_label_count} reviewed external benchmark rows available.",
            "target": ">= 300",
        },
        {
            "name": "external_threat_positive_precision",
            "passed": threat_precision >= 0.8,
            "detail": f"External threat-positive precision={round(threat_precision, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "external_threat_positive_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"External threat-positive F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "external_threat_positive_recall",
            "passed": threat_recall >= 0.85,
            "detail": f"External threat-positive recall={round(threat_recall, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "external_benign_like_false_positive_rate",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"External benign-like false-positive rate={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "external_suspicious_recall",
            "passed": suspicious_recall >= 0.8,
            "detail": f"External suspicious recall={round(suspicious_recall, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "external_malicious_recall",
            "passed": malicious_recall >= 0.6,
            "detail": f"External malicious recall={round(malicious_recall, 4)}.",
            "target": ">= 0.60",
        },
        {
            "name": "confidence_calibration",
            "passed": calibration_acceptable,
            "detail": f"Calibration status={calibration_status or 'missing'}.",
            "target": "passed, calibrated, or explicitly limited",
        },
        {
            "name": "generalization_gap",
            "passed": overfitting_acceptable,
            "detail": f"Generalization status={overfitting_status or 'missing'}.",
            "target": "limited or moderate generalization gap",
        },
        {
            "name": "profile_safety_filter",
            "passed": not profile_rejected,
            "detail": f"profile_rejected={profile_rejected}.",
            "target": "False",
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
    external_validated = all(item["passed"] for item in checks)
    analyst_review_eligible = (
        external_label_count >= 100
        and threat_precision >= 0.75
        and threat_f1 >= 0.75
        and threat_recall >= 0.75
        and not response_automation_allowed
    )
    if external_validated:
        decision = "external_benchmark_validated_candidate"
    elif internal_benchmark_validated:
        decision = "internal_benchmark_validated_candidate"
    elif analyst_review_eligible:
        decision = "analyst_review_eligible"
    else:
        decision = "candidate_only"
    return {
        "version": "v6",
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "analyst_review_eligible": analyst_review_eligible,
        "internal_benchmark_validated": internal_benchmark_validated,
        "external_benchmark_validated": external_validated,
        "passed": passed,
        "total": len(checks),
        "required_passed": passed,
        "required_total": len(checks),
        "checks": checks,
        "calibration_limited": calibration_normalized == "limited",
        "message": (
            "v1.8 external benchmark validation strengthens SOC triage evidence only. "
            "Production promotion, model activation, real enforcement, and response automation remain disabled."
        ),
    }


def readiness_gate_v7_independent_validation(
    *,
    independent_label_count: int,
    independent_metrics: dict[str, Any],
    calibration_status: str,
    external_benchmark_passed: bool,
    independent_overlap_passed: bool,
    controlled_real_source_passed: bool,
    controlled_validations_passed: bool,
    performance_smoke_healthy: bool,
    production_promoted: bool = False,
    model_activated: bool = False,
    response_automation_allowed: bool = False,
    real_firewall_blocking_enabled: bool = False,
) -> dict[str, Any]:
    """Conservative v1.9 gate for independent and controlled-source evidence.

    The strongest result is still a decision-support candidate. This gate cannot
    activate a model, production-promote it, or authorize automated enforcement.
    """
    threat_precision = _metric(independent_metrics, "threat_positive_precision")
    threat_recall = _metric(independent_metrics, "threat_positive_recall")
    threat_f1 = _metric(independent_metrics, "threat_positive_f1")
    benign_fp_rate = _metric(
        independent_metrics,
        "benign_false_positive_rate",
        default=_metric(independent_metrics, "benign_like_false_positive_rate"),
    )
    suspicious_recall = _metric(
        independent_metrics,
        "per_class",
        "suspicious",
        "recall",
        default=_metric(independent_metrics, "suspicious_recall"),
    )
    malicious_recall = _metric(
        independent_metrics,
        "per_class",
        "malicious",
        "recall",
        default=_metric(independent_metrics, "malicious_recall"),
    )
    calibration_acceptable = calibration_status.strip().lower() in {
        "passed",
        "calibrated",
        "limited",
    }
    checks = [
        {
            "name": "v18_external_benchmark_passed",
            "passed": external_benchmark_passed,
            "detail": f"external_benchmark_passed={external_benchmark_passed}.",
            "target": "True",
        },
        {
            "name": "independent_holdout_rows",
            "passed": independent_label_count >= 300,
            "detail": f"{independent_label_count} independent rows available.",
            "target": ">= 300; 500 preferred",
        },
        {
            "name": "independent_overlap_check",
            "passed": independent_overlap_passed,
            "detail": f"independent_overlap_passed={independent_overlap_passed}.",
            "target": "No exact overlap with previous prepared holdouts",
        },
        {
            "name": "independent_threat_precision",
            "passed": threat_precision >= 0.8,
            "detail": f"Threat precision={round(threat_precision, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "independent_threat_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"Threat F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "independent_threat_recall",
            "passed": threat_recall >= 0.85,
            "detail": f"Threat recall={round(threat_recall, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "independent_benign_false_positive_rate",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"Benign-like false-positive rate={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "independent_suspicious_recall",
            "passed": suspicious_recall >= 0.8,
            "detail": f"Suspicious recall={round(suspicious_recall, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "independent_malicious_recall",
            "passed": malicious_recall >= 0.6,
            "detail": f"Malicious recall={round(malicious_recall, 4)}.",
            "target": ">= 0.60",
        },
        {
            "name": "independent_calibration",
            "passed": calibration_acceptable,
            "detail": f"Calibration status={calibration_status or 'missing'}.",
            "target": "passed, calibrated, or explicitly limited",
        },
        {
            "name": "controlled_real_source_validation",
            "passed": controlled_real_source_passed,
            "detail": (
                "Controlled replay/source validation passed."
                if controlled_real_source_passed
                else "Controlled replay/source validation is missing or failed."
            ),
            "target": "passed",
        },
        {
            "name": "controlled_validation_regression",
            "passed": controlled_validations_passed,
            "detail": (
                "Existing controlled validations passed."
                if controlled_validations_passed
                else "Existing controlled validations are missing or failed."
            ),
            "target": "passed",
        },
        {
            "name": "performance_smoke_healthy",
            "passed": performance_smoke_healthy,
            "detail": f"performance_smoke_healthy={performance_smoke_healthy}.",
            "target": "True",
        },
        {
            "name": "production_promotion_disabled",
            "passed": not production_promoted,
            "detail": f"production_promoted={production_promoted}.",
            "target": "False",
        },
        {
            "name": "model_activation_disabled",
            "passed": not model_activated,
            "detail": f"model_activated={model_activated}.",
            "target": "False",
        },
        {
            "name": "response_automation_disabled",
            "passed": not response_automation_allowed,
            "detail": f"response_automation_allowed={response_automation_allowed}.",
            "target": "False",
        },
        {
            "name": "real_firewall_blocking_disabled",
            "passed": not real_firewall_blocking_enabled,
            "detail": (
                "real_firewall_blocking_enabled="
                f"{real_firewall_blocking_enabled}."
            ),
            "target": "False",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    independent_passed = all(item["passed"] for item in checks[1:10])
    if (
        external_benchmark_passed
        and independent_passed
        and controlled_real_source_passed
        and controlled_validations_passed
        and performance_smoke_healthy
        and passed == len(checks)
    ):
        decision = "controlled_real_source_validated_candidate"
    elif external_benchmark_passed and independent_passed:
        decision = "independently_revalidated_candidate"
    elif external_benchmark_passed:
        decision = "external_benchmark_validated_candidate"
    elif threat_f1 >= 0.85 and threat_recall >= 0.85:
        decision = "internal_benchmark_validated_candidate"
    else:
        decision = "analyst_review_eligible"
    return {
        "version": "v7",
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "analyst_review_eligible": True,
        "external_benchmark_validated": external_benchmark_passed,
        "independent_holdout_validated": independent_passed,
        "controlled_real_source_validated": controlled_real_source_passed,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "message": (
            "v1.9 adds independent synthetic and controlled source evidence for "
            "SOC triage decision support. It is not production deployment approval."
        ),
    }


def readiness_gate_v7b_fpr_stabilization(
    *,
    independent_label_count: int,
    independent_metrics: dict[str, Any],
    calibration_status: str,
    external_benchmark_passed: bool,
    independent_overlap_passed: bool,
    controlled_real_source_passed: bool,
    controlled_validations_passed: bool,
    performance_smoke_healthy: bool,
    uses_source_or_scenario_identity: bool,
    preserves_behavior_evidence: bool,
    ambiguous_rows_routed_to_review: bool,
    production_promoted: bool = False,
    model_activated: bool = False,
    response_automation_allowed: bool = False,
    real_firewall_blocking_enabled: bool = False,
) -> dict[str, Any]:
    """Extend v7 with explicit anti-overfitting checks for v1.9b."""
    base = readiness_gate_v7_independent_validation(
        independent_label_count=independent_label_count,
        independent_metrics=independent_metrics,
        calibration_status=calibration_status,
        external_benchmark_passed=external_benchmark_passed,
        independent_overlap_passed=independent_overlap_passed,
        controlled_real_source_passed=controlled_real_source_passed,
        controlled_validations_passed=controlled_validations_passed,
        performance_smoke_healthy=performance_smoke_healthy,
        production_promoted=production_promoted,
        model_activated=model_activated,
        response_automation_allowed=response_automation_allowed,
        real_firewall_blocking_enabled=real_firewall_blocking_enabled,
    )
    stabilization_checks = [
        {
            "name": "identity_independent_boundary",
            "passed": not uses_source_or_scenario_identity,
            "detail": (
                "Boundary logic does not use source or scenario identity."
                if not uses_source_or_scenario_identity
                else "Boundary logic depends on source or scenario identity."
            ),
            "target": "No source/scenario identity inputs",
        },
        {
            "name": "behavior_evidence_preserved",
            "passed": preserves_behavior_evidence,
            "detail": (
                "Behavior-window threat evidence remains authoritative."
                if preserves_behavior_evidence
                else "Useful behavior-window evidence can be suppressed."
            ),
            "target": "True",
        },
        {
            "name": "ambiguous_boundary_review_routing",
            "passed": ambiguous_rows_routed_to_review,
            "detail": (
                "Ambiguous unresolved rows are routed to analyst review."
                if ambiguous_rows_routed_to_review
                else "Ambiguous boundary rows are not explicitly routed to review."
            ),
            "target": "True",
        },
    ]
    checks = [*base["checks"], *stabilization_checks]
    passed = sum(1 for item in checks if item["passed"])
    independent_validated = bool(base["independent_holdout_validated"]) and all(
        item["passed"] for item in stabilization_checks
    )
    controlled_validated = bool(base["controlled_real_source_validated"])
    if (
        independent_validated
        and controlled_validated
        and passed == len(checks)
    ):
        decision = "controlled_real_source_validated_candidate"
    elif independent_validated:
        decision = "independently_revalidated_candidate"
    else:
        decision = str(base["decision"])
    return {
        **base,
        "version": "v7b",
        "decision": decision,
        "independent_holdout_validated": independent_validated,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "message": (
            "v1.9b stabilizes an identity-independent analyst-review boundary. "
            "Production promotion, model activation, automated response, and "
            "real firewall enforcement remain disabled."
        ),
    }


def readiness_gate_v8_fresh_blind_validation(
    *,
    candidate_lock_valid: bool,
    fresh_blind_label_count: int,
    fresh_blind_source_count: int,
    fresh_blind_scenario_count: int,
    fresh_blind_metrics: dict[str, Any],
    calibration_status: str,
    exact_overlap_passed: bool,
    threshold_tuning_performed: bool,
    uses_source_or_scenario_identity: bool,
    controlled_real_source_passed: bool,
    final_controlled_acceptance_passed: bool,
    controlled_validations_passed: bool,
    performance_smoke_healthy: bool,
    external_benchmark_passed: bool = True,
    production_promoted: bool = False,
    model_activated: bool = False,
    response_automation_allowed: bool = False,
    real_firewall_blocking_enabled: bool = False,
) -> dict[str, Any]:
    """Conservative v2.0 gate for a frozen candidate on a fresh holdout."""
    threat_recall = _metric(
        fresh_blind_metrics,
        "threat_positive_recall",
    )
    threat_f1 = _metric(fresh_blind_metrics, "threat_positive_f1")
    benign_fp_rate = _metric(
        fresh_blind_metrics,
        "benign_false_positive_rate",
        default=_metric(
            fresh_blind_metrics,
            "benign_like_false_positive_rate",
        ),
    )
    suspicious_recall = _metric(
        fresh_blind_metrics,
        "per_class",
        "suspicious",
        "recall",
        default=_metric(fresh_blind_metrics, "suspicious_recall"),
    )
    malicious_recall = _metric(
        fresh_blind_metrics,
        "per_class",
        "malicious",
        "recall",
        default=_metric(fresh_blind_metrics, "malicious_recall"),
    )
    calibration_acceptable = calibration_status.strip().lower() in {
        "passed",
        "calibrated",
        "limited",
    }
    checks = [
        {
            "name": "candidate_lock_valid",
            "passed": candidate_lock_valid,
            "detail": f"candidate_lock_valid={candidate_lock_valid}.",
            "target": "True",
        },
        {
            "name": "external_benchmark_passed",
            "passed": external_benchmark_passed,
            "detail": f"external_benchmark_passed={external_benchmark_passed}.",
            "target": "True",
        },
        {
            "name": "fresh_blind_rows",
            "passed": fresh_blind_label_count >= 500,
            "detail": f"{fresh_blind_label_count} blind rows evaluated.",
            "target": ">= 500",
        },
        {
            "name": "fresh_blind_source_diversity",
            "passed": fresh_blind_source_count >= 6,
            "detail": f"{fresh_blind_source_count} sources represented.",
            "target": ">= 6",
        },
        {
            "name": "fresh_blind_scenario_diversity",
            "passed": fresh_blind_scenario_count >= 16,
            "detail": f"{fresh_blind_scenario_count} scenarios represented.",
            "target": ">= 16",
        },
        {
            "name": "fresh_blind_exact_overlap",
            "passed": exact_overlap_passed,
            "detail": f"exact_overlap_passed={exact_overlap_passed}.",
            "target": "No exact overlap with earlier holdouts",
        },
        {
            "name": "no_blind_holdout_tuning",
            "passed": not threshold_tuning_performed,
            "detail": (
                f"threshold_tuning_performed={threshold_tuning_performed}."
            ),
            "target": "False",
        },
        {
            "name": "identity_independent_validation",
            "passed": not uses_source_or_scenario_identity,
            "detail": (
                "Candidate does not use source/scenario identity."
                if not uses_source_or_scenario_identity
                else "Candidate uses prohibited source/scenario identity."
            ),
            "target": "No source/scenario identity",
        },
        {
            "name": "fresh_blind_threat_f1",
            "passed": threat_f1 >= 0.85,
            "detail": f"Threat F1={round(threat_f1, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "fresh_blind_threat_recall",
            "passed": threat_recall >= 0.85,
            "detail": f"Threat recall={round(threat_recall, 4)}.",
            "target": ">= 0.85",
        },
        {
            "name": "fresh_blind_benign_false_positive_rate",
            "passed": benign_fp_rate <= 0.15,
            "detail": f"Benign-like FPR={round(benign_fp_rate, 4)}.",
            "target": "<= 0.15",
        },
        {
            "name": "fresh_blind_suspicious_recall",
            "passed": suspicious_recall >= 0.8,
            "detail": f"Suspicious recall={round(suspicious_recall, 4)}.",
            "target": ">= 0.80",
        },
        {
            "name": "fresh_blind_malicious_recall",
            "passed": malicious_recall >= 0.6,
            "detail": f"Malicious recall={round(malicious_recall, 4)}.",
            "target": ">= 0.60",
        },
        {
            "name": "fresh_blind_calibration",
            "passed": calibration_acceptable,
            "detail": f"Calibration status={calibration_status or 'missing'}.",
            "target": "passed, calibrated, or explicitly limited",
        },
        {
            "name": "controlled_real_source_validation",
            "passed": controlled_real_source_passed,
            "detail": (
                "Controlled source validation passed."
                if controlled_real_source_passed
                else "Controlled source validation failed or is missing."
            ),
            "target": "passed",
        },
        {
            "name": "final_controlled_acceptance",
            "passed": final_controlled_acceptance_passed,
            "detail": (
                "Final controlled acceptance passed."
                if final_controlled_acceptance_passed
                else "Final controlled acceptance failed or is pending."
            ),
            "target": "passed",
        },
        {
            "name": "controlled_validation_regression",
            "passed": controlled_validations_passed,
            "detail": (
                "Existing controlled validations passed."
                if controlled_validations_passed
                else "Existing controlled validations failed or are missing."
            ),
            "target": "passed",
        },
        {
            "name": "performance_smoke_healthy",
            "passed": performance_smoke_healthy,
            "detail": f"performance_smoke_healthy={performance_smoke_healthy}.",
            "target": "True",
        },
        {
            "name": "production_promotion_disabled",
            "passed": not production_promoted,
            "detail": f"production_promoted={production_promoted}.",
            "target": "False",
        },
        {
            "name": "model_activation_disabled",
            "passed": not model_activated,
            "detail": f"model_activated={model_activated}.",
            "target": "False",
        },
        {
            "name": "response_automation_disabled",
            "passed": not response_automation_allowed,
            "detail": (
                f"response_automation_allowed={response_automation_allowed}."
            ),
            "target": "False",
        },
        {
            "name": "real_firewall_blocking_disabled",
            "passed": not real_firewall_blocking_enabled,
            "detail": (
                "real_firewall_blocking_enabled="
                f"{real_firewall_blocking_enabled}."
            ),
            "target": "False",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    fresh_blind_passed = checks[0]["passed"] and all(
        item["passed"] for item in checks[2:14]
    )
    if (
        fresh_blind_passed
        and controlled_real_source_passed
        and final_controlled_acceptance_passed
        and controlled_validations_passed
        and performance_smoke_healthy
        and passed == len(checks)
    ):
        decision = "final_controlled_validation_candidate"
    elif fresh_blind_passed:
        decision = "fresh_blind_revalidated_candidate"
    elif controlled_real_source_passed:
        decision = "controlled_real_source_validated_candidate"
    elif external_benchmark_passed:
        decision = "external_benchmark_validated_candidate"
    else:
        decision = "analyst_review_eligible"
    return {
        "version": "v8",
        "decision": decision,
        "production_status": "not_production_promoted",
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "analyst_review_eligible": True,
        "external_benchmark_validated": external_benchmark_passed,
        "fresh_blind_revalidated": fresh_blind_passed,
        "controlled_real_source_validated": controlled_real_source_passed,
        "final_controlled_validation_passed": (
            final_controlled_acceptance_passed
        ),
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "message": (
            "v2.0 evaluates a frozen decision-support candidate on a fresh "
            "blind holdout and controlled source workflow. It is not "
            "production deployment approval."
        ),
    }


def readiness_gate_v9_production_readiness_track(
    *,
    final_controlled_validation_passed: bool,
    real_source_pilot_validated: bool,
    postgres_lab_validated: bool,
    no_hardware_source_pilot_validated: bool = False,
    real_device_forwarding_validated: bool = False,
    backup_restore_validated: bool = False,
    production_doctor_blockers: list[str] | None = None,
    production_doctor_warnings: list[str] | None = None,
    observability_plan_exists: bool = False,
    ml_monitoring_plan_exists: bool = False,
    runbook_updated: bool = False,
    production_promoted: bool = False,
    model_activated: bool = False,
    response_automation_allowed: bool = False,
    real_firewall_blocking_enabled: bool = False,
) -> dict[str, Any]:
    """v3.0 gate for production-readiness track planning.

    This gate deliberately never returns ``production_ready``. It separates
    academic controlled validation from future real-device and deployment
    hardening milestones.
    """
    blockers = production_doctor_blockers or []
    warnings = production_doctor_warnings or []
    checks = [
        {
            "name": "final_controlled_validation",
            "passed": final_controlled_validation_passed,
            "detail": (
                "Final controlled validation evidence is available."
                if final_controlled_validation_passed
                else "Final controlled validation evidence is missing or failed."
            ),
            "target": "passed",
        },
        {
            "name": "no_hardware_source_pilot_validation",
            "passed": no_hardware_source_pilot_validated,
            "detail": (
                "No-hardware simulated source pilot has been validated."
                if no_hardware_source_pilot_validated
                else "No-hardware simulated source pilot is pending."
            ),
            "target": "validated as a bridge before real-device testing",
        },
        {
            "name": "real_device_forwarding_validation",
            "passed": real_device_forwarding_validated,
            "detail": (
                "A controlled real device has forwarded logs successfully."
                if real_device_forwarding_validated
                else "Real-device forwarding validation is pending."
            ),
            "target": "validated before deployment claims",
        },
        {
            "name": "postgres_lab_validation",
            "passed": postgres_lab_validated,
            "detail": (
                "PostgreSQL lab deployment validation has passed."
                if postgres_lab_validated
                else "PostgreSQL lab deployment validation is pending or blocked by environment."
            ),
            "target": "validated before shared lab deployment",
        },
        {
            "name": "production_doctor_blockers_clear",
            "passed": not blockers,
            "detail": (
                "No production-readiness doctor blockers."
                if not blockers
                else "; ".join(blockers[:5])
            ),
            "target": "zero blockers",
        },
        {
            "name": "backup_restore_validation",
            "passed": backup_restore_validated,
            "detail": (
                "Backup and restore drill has been validated."
                if backup_restore_validated
                else "Backup and restore drill is planned or pending."
            ),
            "target": "validated before shared lab handoff",
        },
        {
            "name": "observability_plan",
            "passed": observability_plan_exists,
            "detail": "Observability and operations plan exists." if observability_plan_exists else "Observability plan pending.",
            "target": "documented",
        },
        {
            "name": "real_source_ml_monitoring_plan",
            "passed": ml_monitoring_plan_exists,
            "detail": "Real-source ML monitoring plan exists." if ml_monitoring_plan_exists else "Real-source ML monitoring plan pending.",
            "target": "documented",
        },
        {
            "name": "runbook_updated",
            "passed": runbook_updated,
            "detail": "Lab/deployment docs reference the v3.0 track." if runbook_updated else "Runbook update pending.",
            "target": "documented",
        },
        {
            "name": "production_promotion_disabled",
            "passed": not production_promoted,
            "detail": f"production_promoted={production_promoted}.",
            "target": "False",
        },
        {
            "name": "model_activation_disabled",
            "passed": not model_activated,
            "detail": f"model_activated={model_activated}.",
            "target": "False",
        },
        {
            "name": "response_automation_disabled",
            "passed": not response_automation_allowed,
            "detail": f"response_automation_allowed={response_automation_allowed}.",
            "target": "False",
        },
        {
            "name": "real_firewall_blocking_disabled",
            "passed": not real_firewall_blocking_enabled,
            "detail": f"real_firewall_blocking_enabled={real_firewall_blocking_enabled}.",
            "target": "False",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    safety_clear = all(item["passed"] for item in checks[-4:])
    planning_clear = all(item["passed"] for item in checks[6:9])
    if not safety_clear or blockers:
        decision = "not_production_ready"
    elif (
        final_controlled_validation_passed
        and no_hardware_source_pilot_validated
        and real_device_forwarding_validated
        and postgres_lab_validated
        and backup_restore_validated
        and planning_clear
    ):
        decision = "shared_lab_readiness_candidate"
    elif final_controlled_validation_passed and no_hardware_source_pilot_validated and not real_device_forwarding_validated:
        decision = "postgres_lab_blocked_by_environment"
    elif final_controlled_validation_passed and no_hardware_source_pilot_validated:
        decision = "no_hardware_source_pilot_validated"
    elif final_controlled_validation_passed and postgres_lab_validated:
        decision = "postgres_lab_validated"
    elif final_controlled_validation_passed:
        decision = "real_source_pilot_ready"
    else:
        decision = "final_controlled_validation_candidate"
    return {
        "version": "v9",
        "decision": decision,
        "production_status": "not_production_ready",
        "production_ready": False,
        "production_readiness_claim": False,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "final_controlled_validation_passed": final_controlled_validation_passed,
        "real_source_pilot_validated": real_source_pilot_validated,
        "no_hardware_source_pilot_validated": no_hardware_source_pilot_validated,
        "real_device_forwarding_validated": real_device_forwarding_validated,
        "postgres_lab_validated": postgres_lab_validated,
        "backup_restore_validated": backup_restore_validated,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "message": (
            "v3.0 is a production-readiness track gate. It can document pilot "
            "readiness, no-hardware source validation, real-device validation, "
            "or PostgreSQL lab validation, but it does not certify production deployment."
        ),
    }
