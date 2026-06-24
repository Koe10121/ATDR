import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import training_dataset_diagnostics
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS, _max_numeric
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v349_repaired_queue_severity_model import SEVERITY_DECISION_MODES, SEVERITY_MODEL_TYPES
from atdr.app.detection.v352_repaired_interface_severity_model import (
    _aggregate_by_strategy,
    _fit_strategy,
    _readiness,
    _select_best,
    _strategy_rows,
    interface_severity_targets,
)


V353_LATEST = "v3_53_severity_feature_repair_latest.json"
FEATURE_SETS = ["v337_current_features", "v353_severity_features"]
V353_NUMERIC_FEATURES = [
    "v353_scan_pressure_score",
    "v353_malicious_signal_score",
    "v353_suspicious_signal_score",
    "v353_low_risk_review_score",
    "v353_evidence_margin_score",
]
V353_CATEGORICAL_FEATURES = ["v353_severity_evidence_tier", "v353_service_family"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _event_count(row: Any) -> float:
    return _max_numeric(
        row,
        [
            "src_ip_5min_log_count",
            "src_ip_5min_event_count",
            "src_ip_15min_event_count",
            "src_ip_60min_event_count",
        ],
    )


def _unique_dst_ips(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ips", "src_ip_15min_unique_dst_ips", "src_ip_60min_unique_dst_ips"],
    )


def _unique_dst_ports(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ports", "src_ip_15min_unique_dst_ports", "src_ip_60min_unique_dst_ports"],
    )


def _deny_count(row: Any) -> float:
    return _max_numeric(
        row,
        [
            "src_ip_5min_deny_count",
            "src_ip_5min_deny_drop_reset_count",
            "src_ip_15min_deny_drop_reset_count",
            "src_ip_60min_deny_drop_reset_count",
        ],
    )


def _unknown_count(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_unknown_app_count", "src_ip_15min_unknown_app_count", "src_ip_60min_unknown_app_count"],
    )


def _high_risk_count(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_high_risk_app_count", "src_ip_15min_high_risk_app_count", "src_ip_60min_high_risk_app_count"],
    )


def _service_family(log: Any) -> str:
    app = _lower(getattr(log, "app", None))
    port = getattr(log, "dst_port", None)
    if app in {"ssl", "quic-base", "web-browsing", "gquic"} or port in {80, 443}:
        return "web"
    if app in {"ping", "icmp", "dns-base", "ntp-base", "stun"} or port in {53, 123, 3478}:
        return "utility"
    if app == "incomplete":
        return "incomplete"
    if app.startswith("unknown"):
        return "unknown"
    if "bittorrent" in app:
        return "peer_to_peer"
    return "other"


def _tier(*, evidence_strength: float, scan_pressure: float, malicious_signal: float, low_risk: float, rule_backed: bool, anomaly: bool) -> str:
    if rule_backed and evidence_strength >= 4.0:
        return "rule_strong"
    if malicious_signal >= 6.0:
        return "malicious_strong"
    if anomaly and evidence_strength >= 3.0:
        return "anomaly_strong"
    if scan_pressure >= 4.0:
        return "scan_pressure"
    if low_risk >= 2.0 and evidence_strength < 2.0:
        return "low_signal_review"
    return "mixed_or_low_context"


def _feature_values(row: Any, log: Any) -> dict[str, Any]:
    unique_ips = _unique_dst_ips(row)
    unique_ports = _unique_dst_ports(row)
    events = _event_count(row)
    deny = _deny_count(row)
    unknown = _unknown_count(row)
    high_risk = _high_risk_count(row)
    evidence_strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    benign_web = _safe_float(row.get("v337_benign_web_likelihood_score"))
    rule_backed = bool(row.get("v337_rule_backed_allow_flag"))
    anomaly = bool(row.get("v337_anomaly_signal_flag"))
    non_allow = _lower(getattr(log, "action", None)) != "allow"
    scan_pressure = (
        min(unique_ips / 3, 3.0)
        + min(unique_ports / 2, 3.0)
        + min(events / 8, 2.0)
        + min(unknown / 2, 2.0)
        + min(deny, 2.0)
    )
    malicious_signal = (
        evidence_strength
        + (1.5 if rule_backed else 0.0)
        + (1.5 if anomaly else 0.0)
        + (1.0 if non_allow else 0.0)
        + min(deny, 3.0)
        + min(high_risk, 3.0)
    )
    suspicious_signal = evidence_strength + min(scan_pressure, 5.0) + min(unknown, 3.0)
    low_risk = benign_web + (1.0 if bool(row.get("v337_low_signal_allow_flag")) else 0.0)
    margin = malicious_signal + suspicious_signal - low_risk
    return {
        "v353_scan_pressure_score": round(scan_pressure, 4),
        "v353_malicious_signal_score": round(malicious_signal, 4),
        "v353_suspicious_signal_score": round(suspicious_signal, 4),
        "v353_low_risk_review_score": round(low_risk, 4),
        "v353_evidence_margin_score": round(margin, 4),
        "v353_severity_evidence_tier": _tier(
            evidence_strength=evidence_strength,
            scan_pressure=scan_pressure,
            malicious_signal=malicious_signal,
            low_risk=low_risk,
            rule_backed=rule_backed,
            anomaly=anomaly,
        ),
        "v353_service_family": _service_family(log),
    }


def enrich_v353_severity_features(prepared: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    frame, meta = enrich_v337_features(prepared)
    rows = [_feature_values(frame.iloc[index], log) for index, log in enumerate(prepared["logs"])]
    for feature in V353_NUMERIC_FEATURES:
        frame[feature] = [row[feature] for row in rows]
    for feature in V353_CATEGORICAL_FEATURES:
        frame[feature] = [row[feature] for row in rows]
    return frame, {
        **meta,
        "numeric_features": [*meta["numeric_features"], *V353_NUMERIC_FEATURES],
        "categorical_features": [*meta["categorical_features"], *V353_CATEGORICAL_FEATURES],
        "experimental_features": [*meta["experimental_features"], *V353_NUMERIC_FEATURES, *V353_CATEGORICAL_FEATURES],
    }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    return math.sqrt(sum((value - avg) ** 2 for value in values) / (len(values) - 1))


def _numeric_separability(frame: Any, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    targets = sorted({row["target"] for row in rows})
    results = []
    for feature in V353_NUMERIC_FEATURES:
        values_by_target: dict[str, list[float]] = defaultdict(list)
        for row in rows:
            value = _safe_float(frame.iloc[row["index"]].get(feature), default=float("nan"))
            if value == value:
                values_by_target[row["target"]].append(value)
        class_stats = {
            target: {
                "rows": len(values),
                "mean": round(_mean(values), 4),
                "std": round(_std(values), 4),
            }
            for target, values in values_by_target.items()
            if values
        }
        if len(class_stats) < 2:
            continue
        pairwise = []
        for left_index, left in enumerate(targets):
            for right in targets[left_index + 1 :]:
                left_values = values_by_target.get(left) or []
                right_values = values_by_target.get(right) or []
                if len(left_values) < 3 or len(right_values) < 3:
                    continue
                pooled = math.sqrt((_std(left_values) ** 2 + _std(right_values) ** 2) / 2)
                effect = abs(_mean(left_values) - _mean(right_values)) / pooled if pooled else 0.0
                pairwise.append({"pair": f"{left} vs {right}", "effect_size": round(effect, 4)})
        if pairwise:
            results.append(
                {
                    "feature": feature,
                    "class_stats": class_stats,
                    "minimum_pairwise_effect_size": round(min(item["effect_size"] for item in pairwise), 4),
                    "maximum_pairwise_effect_size": round(max(item["effect_size"] for item in pairwise), 4),
                    "pairwise": pairwise,
                }
            )
    return sorted(results, key=lambda item: item["minimum_pairwise_effect_size"], reverse=True)


def _categorical_ambiguity(frame: Any, rows: list[dict[str, Any]], feature: str) -> list[dict[str, Any]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        grouped[str(frame.iloc[row["index"]].get(feature) or "unknown")][row["target"]] += 1
    ambiguous = []
    for value, counts in grouped.items():
        total = sum(counts.values())
        if total < 4 or len(counts) < 2:
            continue
        majority, majority_count = counts.most_common(1)[0]
        ambiguous.append(
            {
                "feature": feature,
                "value": value,
                "total": total,
                "target_counts": dict(counts),
                "majority": majority,
                "purity": round(majority_count / total, 4),
                "conflict_ratio": round(1 - majority_count / total, 4),
            }
        )
    return sorted(ambiguous, key=lambda item: (item["conflict_ratio"], item["total"]), reverse=True)


def _feature_support(prepared: dict[str, Any], frame: Any) -> dict[str, Any]:
    targets, _meta = interface_severity_targets(prepared, frame, variant="map_non_threat_to_unusual")
    rows = [
        {"index": index, "target": target}
        for index, target in enumerate(targets)
        if target in {"unusual_needs_review", "evidence_backed_suspicious", "malicious_high_confidence"}
    ]
    categorical = []
    for feature in V353_CATEGORICAL_FEATURES:
        categorical.extend(_categorical_ambiguity(frame, rows, feature)[:8])
    return {
        "rows": len(rows),
        "target_distribution": dict(Counter(row["target"] for row in rows)),
        "numeric_separability": _numeric_separability(frame, rows),
        "categorical_ambiguity": categorical,
    }


def _fit_feature_set_strategies(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    feature_set: str,
) -> list[dict[str, Any]]:
    strategies = []
    for model_type in SEVERITY_MODEL_TYPES:
        for decision_mode in SEVERITY_DECISION_MODES:
            strategy = _fit_strategy(
                prepared,
                augmented,
                interface_variant="map_non_threat_to_unusual",
                severity_model_type=model_type,
                decision_mode=decision_mode,
            )
            if strategy.get("name"):
                strategy["name"] = f"{feature_set}_{strategy['name']}"
            strategy["feature_set"] = feature_set
            strategies.append(strategy)
    return strategies


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {name} | {passed} | {tf1} | {fpr} | {srec} | {mrec} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                tf1=(ranges.get("threat_positive_f1") or {}).get("min"),
                fpr=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                srec=(ranges.get("suspicious_recall") or {}).get("min"),
                mrec=(ranges.get("malicious_recall") or {}).get("min"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.53 Severity Target Separability And Evidence Feature Repair

Generated: {result.get("generated_at")}

This report is diagnostic only. It compares current v337 evidence features with v353 severity-specific feature candidates inside the repaired v3.51 queue/severity interface. No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Passing Splits | Threat F1 Min | FPR Max | Suspicious Recall Min | Malicious Recall Min | Calibration |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(rows)}

## Feature Support

```json
{json.dumps(result.get("feature_support"), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v353_severity_feature_repair(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base

    started = time.perf_counter()
    split_results = []
    feature_support: dict[str, Any] = {}
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        v337_frame, v337_meta = enrich_v337_features(prepared)
        v353_frame, v353_meta = enrich_v353_severity_features(prepared)
        if not feature_support:
            feature_support = _feature_support(prepared, v353_frame)
        strategy_rows = []
        for feature_set, frame, meta in [
            ("v337_current_features", v337_frame, v337_meta),
            ("v353_severity_features", v353_frame, v353_meta),
        ]:
            augmented = {"frame": frame, **meta}
            strategies = _fit_feature_set_strategies(prepared, augmented, feature_set=feature_set)
            strategy_rows.extend(_strategy_rows(prepared, augmented, strategies))
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared.get("split_warnings") or [],
                "strategies": strategy_rows,
            }
        )

    comparison = _aggregate_by_strategy(split_results)
    best_strategy = _select_best(comparison)
    readiness = _readiness(comparison[best_strategy]) if best_strategy else {
        "decision": "candidate_only",
        "passed": 0,
        "total": 0,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": ["no evaluated v3.53 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_53_severity_feature_repair_{stamp}.md"
    latest_path = output_path / V353_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.53",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "feature_sets": FEATURE_SETS,
        "feature_support": feature_support,
        "split_results": split_results,
        "strategy_comparison": comparison,
        "best_strategy": best_strategy,
        "readiness": readiness,
        "training_dataset": training_dataset_diagnostics(db),
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "labels_written": False,
            "ml_labels_before": before_labels,
            "ml_labels_after": after_labels,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
        "report_path": str(report_path),
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
