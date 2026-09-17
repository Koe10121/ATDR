from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.detection.ml_detector import (
    CATEGORICAL_FEATURES,
    FEATURE_COLUMNS,
    NUMERIC_FEATURES,
)
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services.v561_anomaly_bootstrap_service import (
    MAXIMUM_DUPLICATE_RATE,
    MINIMUM_PARSE_RATE,
    MINIMUM_SCHEMA_RATE,
    RELIABILITY_PROTOCOL_VERSION,
    UNRESOLVED_APPS,
    anomaly_bootstrap_status,
    anomaly_manifest_is_valid,
    anomaly_manifest_path,
    install_anomaly_artifact_atomically,
)


VERSION = RELIABILITY_PROTOCOL_VERSION
INSTALL_CONFIRMATION = "INSTALL_GOVERNED_ADVISORY_ANOMALY_CANDIDATE"
DEFAULT_LIMIT = 50_000
MAXIMUM_LIMIT = 50_000
MINIMUM_FIT_ROWS = 5_000
MAXIMUM_FIT_ROWS = 20_000
CONTROLLED_BENIGN_RATE_MAX = 0.15
CONTROLLED_SUSPICIOUS_SCENARIO_RECALL_MIN = 0.60
CONTROLLED_MALICIOUS_SCENARIO_RECALL_MIN = 0.75
PRIVATE_HOLDOUT_QUEUE_RATE_MIN = 0.005
PRIVATE_HOLDOUT_QUEUE_RATE_MAX = 0.05

BENIGN_SCENARIOS = (
    "normal_allowed_traffic",
    "normal_web_dns_quic_traffic",
    "normal_high_volume_but_allowed_traffic",
    "normal_repeated_same_service_traffic",
    "benign_dns_web_traffic",
    "benign_high_volume_single_service",
    "benign_incomplete_allow_noise",
    "benign_repeated_internal_service",
)
SUSPICIOUS_SCENARIOS = (
    "port_scan_like_traffic",
    "suspicious_horizontal_scan",
    "brute_force_like_traffic",
    "suspicious_denied_ssh_burst",
    "suspicious_rare_port_probe",
    "policy_violation_suspicious_app",
    "ddos_or_connection_flood_like",
)
MALICIOUS_SCENARIOS = (
    "malware_c2_like_beaconing",
    "malicious_like_c2_beacon",
    "data_exfiltration_suspicion",
    "malicious_like_exfiltration_burst",
)
SCENARIO_CATEGORIES = {
    **{name: "benign" for name in BENIGN_SCENARIOS},
    **{name: "suspicious" for name in SUSPICIOUS_SCENARIOS},
    **{name: "malicious" for name in MALICIOUS_SCENARIOS},
}
ROBUST_NUMERIC_FEATURES = [
    "log_src_port",
    "log_dst_port",
    "log_bytes",
    "log_bytes_sent",
    "log_bytes_received",
    "log_packets",
    "log_elapsed_time",
    "app_risk",
    "bytes_per_packet",
    "outbound_byte_ratio",
]
ROBUST_CATEGORICAL_FEATURES = [
    *CATEGORICAL_FEATURES,
    "zone_path",
    "app_port_context",
]


class AnomalyReliabilityError(RuntimeError):
    """Expected privacy-safe evaluation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PrivateEvidence:
    records: tuple[dict[str, Any], ...]
    eligible_indexes: tuple[int, ...]
    public: dict[str, Any]


@dataclass(frozen=True)
class ControlledEvidence:
    records: tuple[dict[str, Any], ...]
    scenarios: tuple[str, ...]
    categories: tuple[str, ...]
    public: dict[str, Any]


@dataclass
class Candidate:
    name: str
    pipeline: Any
    queue_target: float
    public: dict[str, Any]


def _optional_ml_imports() -> tuple[Any, ...] | None:
    try:
        import joblib
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import IsolationForest
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import FunctionTransformer, OneHotEncoder
    except ImportError:
        return None
    return (
        joblib,
        pd,
        ColumnTransformer,
        IsolationForest,
        SimpleImputer,
        Pipeline,
        FunctionTransformer,
        OneHotEncoder,
    )


def engineer_robust_anomaly_features(frame: Any) -> Any:
    """Create skew-resistant features while retaining the raw input contract."""

    import numpy as np
    import pandas as pd

    output = frame.copy()
    for feature in NUMERIC_FEATURES:
        numeric = pd.to_numeric(output.get(feature), errors="coerce")
        output[f"log_{feature}"] = np.log1p(numeric.clip(lower=0))
    total_bytes = pd.to_numeric(output.get("bytes"), errors="coerce").fillna(0)
    sent_bytes = pd.to_numeric(output.get("bytes_sent"), errors="coerce").fillna(0)
    packets = pd.to_numeric(output.get("packets"), errors="coerce").fillna(0)
    output["bytes_per_packet"] = np.log1p(total_bytes / packets.clip(lower=1))
    output["outbound_byte_ratio"] = sent_bytes / total_bytes.clip(lower=1)
    output["zone_path"] = (
        output.get("src_zone").fillna("unknown").astype(str)
        + "->"
        + output.get("dst_zone").fillna("unknown").astype(str)
    )
    port = pd.to_numeric(output.get("dst_port"), errors="coerce").fillna(-1).astype(int)
    port_band = pd.cut(
        port,
        bins=[-2, 0, 1023, 49151, 65535],
        labels=["missing", "system", "registered", "dynamic"],
        include_lowest=True,
    ).astype(str)
    output["app_port_context"] = (
        output.get("app").fillna("unknown").astype(str).str.lower()
        + "|"
        + port_band
    )
    return output


def _record_from_normalized(normalized: dict[str, Any], *, ordinal: int) -> dict[str, Any]:
    record = {feature: normalized.get(feature) for feature in FEATURE_COLUMNS}
    record["_ordinal"] = ordinal
    record["_timestamp"] = normalized.get("generated_time") or normalized.get("receive_time")
    record["_log_type"] = str(normalized.get("log_type") or "unknown").lower()
    app = str(normalized.get("app") or "").strip().lower()
    record["_schema"] = "limited" if app in UNRESOLVED_APPS else "structured"
    return record


def _schema_complete(normalized: dict[str, Any]) -> bool:
    return bool(
        normalized.get("log_type") == "TRAFFIC"
        and normalized.get("action")
        and normalized.get("app")
        and normalized.get("protocol")
        and normalized.get("src_port") is not None
        and normalized.get("dst_port") is not None
    )


def _eligible_baseline(normalized: dict[str, Any], *, parser_error: str | None) -> tuple[bool, str | None]:
    if parser_error is not None:
        return False, "parser_failure"
    if normalized.get("log_type") != "TRAFFIC":
        return False, "non_traffic_record"
    if not _schema_complete(normalized):
        return False, "incomplete_feature_schema"
    if str(normalized.get("action") or "").strip().lower() != "allow":
        return False, "non_allow_action"
    app = str(normalized.get("app") or "").strip().lower()
    if app in UNRESOLVED_APPS:
        return False, "unresolved_application"
    app_risk = normalized.get("app_risk")
    if app_risk is not None and int(app_risk) > 3:
        return False, "high_risk_application"
    return True, None


def inspect_private_evidence(
    sample_path: Path,
    *,
    limit: int = DEFAULT_LIMIT,
    minimum_fit_rows: int = MINIMUM_FIT_ROWS,
) -> PrivateEvidence:
    if limit < minimum_fit_rows or limit > MAXIMUM_LIMIT:
        raise AnomalyReliabilityError(
            "invalid_evidence_limit",
            f"Evidence limit must be between {minimum_fit_rows} and {MAXIMUM_LIMIT}.",
        )
    source = sample_path.expanduser().resolve()
    if not source.is_file():
        raise AnomalyReliabilityError(
            "private_evidence_unavailable",
            "The private evidence source is unavailable.",
        )

    records: list[dict[str, Any]] = []
    eligible_indexes: list[int] = []
    seen: set[bytes] = set()
    duplicate_rows = 0
    parsed_rows = 0
    schema_complete_rows = 0
    exclusion_reasons: Counter[str] = Counter()

    with source.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for raw_line in stream:
            if not raw_line.strip():
                continue
            if len(records) + duplicate_rows >= limit:
                break
            digest = hashlib.sha256(raw_line.encode("utf-8", errors="replace")).digest()
            if digest in seen:
                duplicate_rows += 1
                continue
            seen.add(digest)
            parsed = parse_log_line(raw_line.rstrip("\r\n"))
            index = len(records)
            records.append(_record_from_normalized(parsed.normalized, ordinal=index))
            if parsed.error is None:
                parsed_rows += 1
            if parsed.error is None and _schema_complete(parsed.normalized):
                schema_complete_rows += 1
            eligible, reason = _eligible_baseline(
                parsed.normalized,
                parser_error=parsed.error,
            )
            if eligible:
                eligible_indexes.append(index)
            elif reason:
                exclusion_reasons[reason] += 1

    unique_rows = len(records)
    observed_rows = unique_rows + duplicate_rows
    parse_rate = parsed_rows / unique_rows if unique_rows else 0.0
    schema_rate = schema_complete_rows / unique_rows if unique_rows else 0.0
    duplicate_rate = duplicate_rows / observed_rows if observed_rows else 0.0
    gates = {
        "minimum_fit_rows": len(eligible_indexes) >= minimum_fit_rows,
        "parser_quality": parse_rate >= MINIMUM_PARSE_RATE,
        "schema_completeness": schema_rate >= MINIMUM_SCHEMA_RATE,
        "duplicate_containment": duplicate_rate <= MAXIMUM_DUPLICATE_RATE,
    }
    public = {
        "source_role": "operator_supplied_private_development_only",
        "observed_rows": observed_rows,
        "unique_rows": unique_rows,
        "duplicate_rows": duplicate_rows,
        "duplicate_rate": round(duplicate_rate, 4),
        "parsed_rows": parsed_rows,
        "parse_rate": round(parse_rate, 4),
        "schema_complete_rows": schema_complete_rows,
        "schema_complete_rate": round(schema_rate, 4),
        "eligible_baseline_rows": len(eligible_indexes),
        "excluded_rows": unique_rows - len(eligible_indexes),
        "exclusion_reasons": dict(sorted(exclusion_reasons.items())),
        "limit": limit,
        "limit_reached": observed_rows >= limit,
        "gates": gates,
        "passed": all(gates.values()),
        "source_paths_exposed": False,
        "raw_logs_exposed": False,
        "network_addresses_exposed": False,
        "identities_exposed": False,
        "fingerprints_exposed": False,
    }
    return PrivateEvidence(
        records=tuple(records),
        eligible_indexes=tuple(eligible_indexes),
        public=public,
    )


def load_controlled_evidence(*, project_root: Path = PROJECT_ROOT) -> ControlledEvidence:
    scenario_root = project_root / "data" / "samples" / "scenarios"
    records: list[dict[str, Any]] = []
    scenarios: list[str] = []
    categories: list[str] = []
    scenario_counts: Counter[str] = Counter()
    parse_failures = 0
    for scenario, category in SCENARIO_CATEGORIES.items():
        source = scenario_root / f"{scenario}.txt"
        if not source.is_file():
            raise AnomalyReliabilityError(
                "controlled_scenario_missing",
                "A required controlled scenario is unavailable.",
            )
        with source.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for raw_line in stream:
                if not raw_line.strip():
                    continue
                parsed = parse_log_line(raw_line.rstrip("\r\n"))
                if parsed.error is not None:
                    parse_failures += 1
                    continue
                records.append(
                    _record_from_normalized(parsed.normalized, ordinal=len(records))
                )
                scenarios.append(scenario)
                categories.append(category)
                scenario_counts[scenario] += 1
    return ControlledEvidence(
        records=tuple(records),
        scenarios=tuple(scenarios),
        categories=tuple(categories),
        public={
            "scenario_count": len(SCENARIO_CATEGORIES),
            "row_count": len(records),
            "parse_failures": parse_failures,
            "category_scenarios": {
                "benign": len(BENIGN_SCENARIOS),
                "suspicious": len(SUSPICIOUS_SCENARIOS),
                "malicious": len(MALICIOUS_SCENARIOS),
            },
            "scenario_rows": dict(sorted(scenario_counts.items())),
            "synthetic_development_evidence": True,
            "human_reviewed_labels": False,
            "independent_accuracy_evidence": False,
        },
    )


def _frame(imports: tuple[Any, ...], records: Iterable[dict[str, Any]]) -> Any:
    pd = imports[1]
    return pd.DataFrame(
        [{feature: record.get(feature) for feature in FEATURE_COLUMNS} for record in records],
        columns=FEATURE_COLUMNS,
    )


def _percentile(values: Iterable[float], quantile: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise AnomalyReliabilityError(
            "calibration_scores_unavailable",
            "Candidate calibration produced no scores.",
        )
    position = max(0.0, min(1.0, quantile)) * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _score_distribution(scores: list[float]) -> dict[str, float | None]:
    if not scores:
        return {
            "minimum": None,
            "p05": None,
            "median": None,
            "p95": None,
            "maximum": None,
            "mean": None,
        }
    return {
        "minimum": round(min(scores), 6),
        "p05": round(_percentile(scores, 0.05), 6),
        "median": round(median(scores), 6),
        "p95": round(_percentile(scores, 0.95), 6),
        "maximum": round(max(scores), 6),
        "mean": round(mean(scores), 6),
    }


def _predict(model: Any, imports: tuple[Any, ...], records: Iterable[dict[str, Any]]) -> tuple[list[bool], list[float]]:
    frame = _frame(imports, records)
    predictions = model.predict(frame)
    scores = [float(value) for value in model.decision_function(frame)]
    return [int(value) == -1 for value in predictions], scores


def _scenario_recall(
    flags: list[bool],
    scenarios: tuple[str, ...],
    categories: tuple[str, ...],
    category: str,
) -> tuple[float, int, int]:
    captured: dict[str, bool] = {}
    for flag, scenario, row_category in zip(flags, scenarios, categories, strict=True):
        if row_category == category:
            captured[scenario] = captured.get(scenario, False) or flag
    total = len(captured)
    caught = sum(captured.values())
    return (caught / total if total else 0.0), caught, total


def evaluate_controlled_model(
    model: Any,
    imports: tuple[Any, ...],
    controlled: ControlledEvidence,
) -> dict[str, Any]:
    flags, scores = _predict(model, imports, controlled.records)
    category_positions: dict[str, list[int]] = defaultdict(list)
    for index, category in enumerate(controlled.categories):
        category_positions[category].append(index)

    def flag_rate(category: str) -> float:
        positions = category_positions.get(category, [])
        return (
            sum(flags[index] for index in positions) / len(positions)
            if positions
            else 0.0
        )

    suspicious_recall, suspicious_caught, suspicious_total = _scenario_recall(
        flags,
        controlled.scenarios,
        controlled.categories,
        "suspicious",
    )
    malicious_recall, malicious_caught, malicious_total = _scenario_recall(
        flags,
        controlled.scenarios,
        controlled.categories,
        "malicious",
    )
    benign_positions = category_positions.get("benign", [])
    benign_scenarios_flagged = len(
        {
            controlled.scenarios[index]
            for index in benign_positions
            if flags[index]
        }
    )
    return {
        "rows_scored": len(flags),
        "anomaly_count": sum(flags),
        "anomaly_rate": round(sum(flags) / len(flags), 4) if flags else 0.0,
        "controlled_benign_anomaly_rate": round(flag_rate("benign"), 4),
        "controlled_suspicious_row_recall": round(flag_rate("suspicious"), 4),
        "controlled_malicious_row_recall": round(flag_rate("malicious"), 4),
        "controlled_suspicious_scenario_recall": round(suspicious_recall, 4),
        "controlled_malicious_scenario_recall": round(malicious_recall, 4),
        "suspicious_scenarios_captured": suspicious_caught,
        "suspicious_scenarios_total": suspicious_total,
        "malicious_scenarios_captured": malicious_caught,
        "malicious_scenarios_total": malicious_total,
        "benign_scenarios_flagged": benign_scenarios_flagged,
        "benign_scenarios_total": len(BENIGN_SCENARIOS),
        "score_distribution": _score_distribution(scores),
        "synthetic_development_evidence": True,
        "independent_accuracy_claimed": False,
    }


def _ordinal_windows(records: list[dict[str, Any]]) -> list[str]:
    total = max(1, len(records))
    return [f"window_{min(4, (index * 4 // total) + 1)}" for index in range(len(records))]


def _aggregate_queue_groups(
    records: list[dict[str, Any]],
    flags: list[bool],
    scores: list[float],
    *,
    field: str,
    values: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        if values is not None:
            value = values[index]
        else:
            value = str(record.get(field) or "unknown").strip().lower()
        groups[value].append(index)
    output = []
    for value, indexes in groups.items():
        queue_count = sum(flags[index] for index in indexes)
        output.append(
            {
                "value": value,
                "rows": len(indexes),
                "queue_count": queue_count,
                "queue_rate": round(queue_count / len(indexes), 4),
                "score_median": round(median(scores[index] for index in indexes), 6),
            }
        )
    return sorted(
        output,
        key=lambda item: (item["queue_rate"], item["rows"]),
        reverse=True,
    )[:limit]


def evaluate_private_model(
    model: Any,
    imports: tuple[Any, ...],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    flags, scores = _predict(model, imports, records)
    windows = _ordinal_windows(records)
    by_window = _aggregate_queue_groups(
        records,
        flags,
        scores,
        field="_ordinal",
        values=windows,
        limit=4,
    )
    window_rates = [float(item["queue_rate"]) for item in by_window]
    window_range = max(window_rates) - min(window_rates) if window_rates else 0.0
    return {
        "rows_scored": len(flags),
        "queue_count": sum(flags),
        "queue_rate": round(sum(flags) / len(flags), 4) if flags else 0.0,
        "score_distribution": _score_distribution(scores),
        "queue_by_application": _aggregate_queue_groups(
            records,
            flags,
            scores,
            field="app",
        ),
        "queue_by_schema": _aggregate_queue_groups(
            records,
            flags,
            scores,
            field="_schema",
        ),
        "queue_by_time_window": by_window,
        "time_window_queue_rate_range": round(window_range, 4),
        "drift_status": "drift_warning" if window_range > 0.05 else "stable",
        "unlabeled_private_development_evidence": True,
        "false_positive_rate_claimed": False,
        "raw_logs_exposed": False,
        "network_addresses_exposed": False,
    }


def _candidate_pipeline(imports: tuple[Any, ...], *, robust: bool) -> Any:
    (
        _,
        _,
        ColumnTransformer,
        IsolationForest,
        SimpleImputer,
        Pipeline,
        FunctionTransformer,
        OneHotEncoder,
    ) = imports
    numeric = ROBUST_NUMERIC_FEATURES if robust else NUMERIC_FEATURES
    categorical = ROBUST_CATEGORICAL_FEATURES if robust else CATEGORICAL_FEATURES
    steps: list[tuple[str, Any]] = []
    if robust:
        steps.append(
            (
                "feature_engineering",
                FunctionTransformer(
                    engineer_robust_anomaly_features,
                    validate=False,
                ),
            )
        )
    steps.extend(
        [
            (
                "preprocess",
                ColumnTransformer(
                    [
                        ("numeric", SimpleImputer(strategy="median"), numeric),
                        (
                            "categorical",
                            Pipeline(
                                [
                                    (
                                        "imputer",
                                        SimpleImputer(strategy="most_frequent"),
                                    ),
                                    (
                                        "onehot",
                                        OneHotEncoder(handle_unknown="ignore"),
                                    ),
                                ]
                            ),
                            categorical,
                        ),
                    ]
                ),
            ),
            (
                "model",
                IsolationForest(
                    n_estimators=150,
                    contamination="auto",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    return Pipeline(steps)


def _fit_calibrated_candidate(
    imports: tuple[Any, ...],
    *,
    fit_records: list[dict[str, Any]],
    calibration_records: list[dict[str, Any]],
    robust: bool,
    queue_target: float,
) -> Any:
    pipeline = _candidate_pipeline(imports, robust=robust)
    pipeline.fit(_frame(imports, fit_records))
    calibration_frame = _frame(imports, calibration_records)
    score_samples = [float(value) for value in pipeline.score_samples(calibration_frame)]
    pipeline.named_steps["model"].offset_ = _percentile(score_samples, queue_target)
    return pipeline


def _candidate_gates(
    controlled: dict[str, Any],
    private_holdout: dict[str, Any],
    *,
    fit_rows: int,
    minimum_fit_rows: int,
) -> dict[str, bool]:
    return {
        "minimum_fit_rows": fit_rows >= minimum_fit_rows,
        "controlled_benign_noise": float(
            controlled["controlled_benign_anomaly_rate"]
        )
        <= CONTROLLED_BENIGN_RATE_MAX,
        "controlled_suspicious_scenario_capture": float(
            controlled["controlled_suspicious_scenario_recall"]
        )
        >= CONTROLLED_SUSPICIOUS_SCENARIO_RECALL_MIN,
        "controlled_malicious_scenario_capture": float(
            controlled["controlled_malicious_scenario_recall"]
        )
        >= CONTROLLED_MALICIOUS_SCENARIO_RECALL_MIN,
        "private_holdout_queue_floor": float(private_holdout["queue_rate"])
        >= PRIVATE_HOLDOUT_QUEUE_RATE_MIN,
        "private_holdout_queue_ceiling": float(private_holdout["queue_rate"])
        <= PRIVATE_HOLDOUT_QUEUE_RATE_MAX,
        "private_time_window_stability": float(
            private_holdout["time_window_queue_rate_range"]
        )
        <= 0.05,
    }


def _candidate_rank(item: Candidate) -> tuple[float, ...]:
    controlled = item.public["controlled"]
    private = item.public["private_holdout"]
    return (
        float(controlled["controlled_malicious_scenario_recall"]),
        float(controlled["controlled_suspicious_scenario_recall"]),
        -float(controlled["controlled_benign_anomaly_rate"]),
        -abs(float(private["queue_rate"]) - item.queue_target),
        1.0 if item.public["feature_strategy"] == "robust_log_context" else 0.0,
    )


def _clearly_improves(candidate: Candidate, current: dict[str, Any]) -> tuple[bool, list[str]]:
    if current.get("status") != "evaluated":
        return True, ["current_artifact_not_comparable"]
    current_controlled = current["controlled"]
    candidate_controlled = candidate.public["controlled"]
    no_regression = bool(
        float(candidate_controlled["controlled_benign_anomaly_rate"])
        <= max(
            CONTROLLED_BENIGN_RATE_MAX,
            float(current_controlled["controlled_benign_anomaly_rate"]),
        )
        and float(candidate_controlled["controlled_suspicious_scenario_recall"])
        >= float(current_controlled["controlled_suspicious_scenario_recall"])
        and float(candidate_controlled["controlled_malicious_scenario_recall"])
        >= float(current_controlled["controlled_malicious_scenario_recall"])
    )
    strict_improvement = bool(
        float(candidate_controlled["controlled_benign_anomaly_rate"])
        + 0.02
        < float(current_controlled["controlled_benign_anomaly_rate"])
        or float(candidate_controlled["controlled_suspicious_scenario_recall"])
        > float(current_controlled["controlled_suspicious_scenario_recall"])
        or float(candidate_controlled["controlled_malicious_scenario_recall"])
        > float(current_controlled["controlled_malicious_scenario_recall"])
    )
    provenance_improvement = current.get("governed_manifest_valid") is not True
    reasons = []
    if strict_improvement:
        reasons.append("controlled_reliability_improved")
    if provenance_improvement:
        reasons.append("governed_provenance_added")
    return no_regression and (strict_improvement or provenance_improvement), reasons


def _split_private_evidence(
    evidence: PrivateEvidence,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    eligible = [evidence.records[index] for index in evidence.eligible_indexes]
    eligible.sort(
        key=lambda record: (
            record.get("_timestamp") is None,
            record.get("_timestamp") or record["_ordinal"],
            record["_ordinal"],
        )
    )
    fit_end = max(1, int(len(eligible) * 0.70))
    calibration_end = max(fit_end + 1, int(len(eligible) * 0.85))
    fit = eligible[:fit_end]
    if len(fit) > MAXIMUM_FIT_ROWS:
        step = len(fit) / MAXIMUM_FIT_ROWS
        fit = [fit[min(len(fit) - 1, int(index * step))] for index in range(MAXIMUM_FIT_ROWS)]
    return fit, eligible[fit_end:calibration_end], eligible[calibration_end:]


def _evaluate_current(
    imports: tuple[Any, ...],
    *,
    artifact_path: Path,
    controlled: ControlledEvidence,
    private_holdout: list[dict[str, Any]],
) -> dict[str, Any]:
    status = anomaly_bootstrap_status(artifact_path=artifact_path)
    if not artifact_path.is_file():
        return {
            "status": "artifact_unavailable",
            "capability_state": status["state"],
            "governed_manifest_valid": status["governed_manifest_valid"],
        }
    try:
        model = imports[0].load(artifact_path)
        controlled_report = evaluate_controlled_model(model, imports, controlled)
        private_report = evaluate_private_model(model, imports, private_holdout)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "status": "artifact_incompatible",
            "error_type": exc.__class__.__name__,
            "capability_state": status["state"],
            "governed_manifest_valid": status["governed_manifest_valid"],
        }
    return {
        "status": "evaluated",
        "capability_state": status["state"],
        "governed_manifest_valid": status["governed_manifest_valid"],
        "controlled": controlled_report,
        "private_holdout": private_report,
        "artifact_modified": False,
    }


def _build_manifest(
    *,
    evidence: PrivateEvidence,
    candidate: Candidate,
    rows_scored: int,
) -> dict[str, Any]:
    controlled = candidate.public["controlled"]
    private = candidate.public["private_holdout"]
    return {
        "protocol_version": VERSION,
        "model_family": "IsolationForest",
        "capability_role": "advisory_anomaly_scoring",
        "evidence": {
            "source_role": evidence.public["source_role"],
            "observed_rows": evidence.public["observed_rows"],
            "unique_rows": evidence.public["unique_rows"],
            "eligible_baseline_rows": evidence.public["eligible_baseline_rows"],
            "excluded_rows": evidence.public["excluded_rows"],
            "parse_rate": evidence.public["parse_rate"],
            "schema_complete_rate": evidence.public["schema_complete_rate"],
            "duplicate_rate": evidence.public["duplicate_rate"],
        },
        "training": {
            "random_state": 42,
            "n_estimators": 150,
            "contamination": candidate.queue_target,
            "feature_columns": list(FEATURE_COLUMNS),
            "feature_strategy": candidate.public["feature_strategy"],
            "chronological_roles": True,
        },
        "validation": {
            "evidence_gates_passed": evidence.public["passed"],
            "training_completed": True,
            "advisory_scoring_passed": True,
            "rows_scored": rows_scored,
            "model_driven_alerts": 0,
            "model_driven_suppressions": 0,
            "labels_created": 0,
            "model_runs_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
            "rules_alert_authoritative": True,
            "supervised_state": "unqualified",
            "response_state": "simulation_only",
        },
        "reliability": {
            "fixed_gates_passed": all(candidate.public["gates"].values()),
            "development_only": True,
            "independent_accuracy_validated": False,
            "controlled_benign_anomaly_rate": controlled[
                "controlled_benign_anomaly_rate"
            ],
            "controlled_suspicious_scenario_recall": controlled[
                "controlled_suspicious_scenario_recall"
            ],
            "controlled_malicious_scenario_recall": controlled[
                "controlled_malicious_scenario_recall"
            ],
            "private_holdout_queue_rate": private["queue_rate"],
        },
        "governance": {
            "decision_support_only": True,
            "rules_alert_authoritative": True,
            "threat_accuracy_validated": False,
            "supervised_model_activated": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_allowed": False,
        },
        "privacy": {
            "source_paths_recorded": False,
            "raw_logs_recorded": False,
            "network_addresses_recorded": False,
            "row_fingerprints_recorded": False,
            "secrets_recorded": False,
        },
    }


def _install_candidate(
    candidate: Candidate,
    evidence: PrivateEvidence,
    *,
    artifact_path: Path,
) -> dict[str, Any]:
    imports = _optional_ml_imports()
    if imports is None:
        raise AnomalyReliabilityError(
            "ml_dependencies_unavailable",
            "ML dependencies are unavailable.",
        )
    manifest_path = anomaly_manifest_path(artifact_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    pending_artifact = artifact_path.with_name(f".pending-{artifact_path.name}")
    pending_manifest = manifest_path.with_name(f".pending-{manifest_path.name}")
    pending_artifact.unlink(missing_ok=True)
    pending_manifest.unlink(missing_ok=True)
    try:
        imports[0].dump(candidate.pipeline, pending_artifact)
        manifest = _build_manifest(
            evidence=evidence,
            candidate=candidate,
            rows_scored=int(candidate.public["controlled"]["rows_scored"])
            + int(candidate.public["private_holdout"]["rows_scored"]),
        )
        pending_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not anomaly_manifest_is_valid(manifest):
            raise AnomalyReliabilityError(
                "candidate_manifest_invalid",
                "The sanitized candidate manifest did not validate.",
            )
        install_anomaly_artifact_atomically(
            pending_artifact=pending_artifact,
            artifact_path=artifact_path,
            pending_manifest=pending_manifest,
            manifest_path=manifest_path,
            replace_existing=True,
        )
    finally:
        pending_artifact.unlink(missing_ok=True)
        pending_manifest.unlink(missing_ok=True)
    status = anomaly_bootstrap_status(artifact_path=artifact_path)
    return {
        "installed": status["state"] == "governed_advisory_ready",
        "capability_state": status["state"],
        "governed_manifest_valid": status["governed_manifest_valid"],
        "rollback_protection_used": True,
        "artifact_location_exposed": False,
        "manifest_location_exposed": False,
    }


def run_anomaly_reliability_evaluation(
    *,
    sample_path: Path,
    limit: int = DEFAULT_LIMIT,
    install_candidate: bool = False,
    confirmation: str = "",
    artifact_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    minimum_fit_rows: int = MINIMUM_FIT_ROWS,
) -> dict[str, Any]:
    imports = _optional_ml_imports()
    if imports is None:
        raise AnomalyReliabilityError(
            "ml_dependencies_unavailable",
            "ML dependencies are unavailable.",
        )
    configured_artifact = (artifact_path or get_settings().resolved_model_path).resolve()
    evidence = inspect_private_evidence(
        sample_path,
        limit=limit,
        minimum_fit_rows=minimum_fit_rows,
    )
    controlled = load_controlled_evidence(project_root=project_root)
    fit_records, calibration_records, holdout_records = _split_private_evidence(evidence)
    if not evidence.public["passed"] or len(calibration_records) < 20 or len(holdout_records) < 20:
        return {
            "version": VERSION,
            "ok": False,
            "status": "evidence_preflight_failed",
            "evidence": evidence.public,
            "controlled_evidence": controlled.public,
            "executed": False,
            "candidate_installed": False,
            "privacy": _privacy_contract(),
            "safety": _safety_contract(),
        }

    current = _evaluate_current(
        imports,
        artifact_path=configured_artifact,
        controlled=controlled,
        private_holdout=holdout_records,
    )
    candidates: list[Candidate] = []
    for robust in (False, True):
        for queue_target in (0.01, 0.02, 0.03, 0.05):
            model = _fit_calibrated_candidate(
                imports,
                fit_records=fit_records,
                calibration_records=calibration_records,
                robust=robust,
                queue_target=queue_target,
            )
            controlled_report = evaluate_controlled_model(model, imports, controlled)
            private_report = evaluate_private_model(model, imports, holdout_records)
            gates = _candidate_gates(
                controlled_report,
                private_report,
                fit_rows=len(fit_records),
                minimum_fit_rows=minimum_fit_rows,
            )
            strategy = "robust_log_context" if robust else "current_raw_features"
            candidates.append(
                Candidate(
                    name=f"{strategy}_q{int(queue_target * 100):02d}",
                    pipeline=model,
                    queue_target=queue_target,
                    public={
                        "name": f"{strategy}_q{int(queue_target * 100):02d}",
                        "feature_strategy": strategy,
                        "queue_target": queue_target,
                        "fit_rows": len(fit_records),
                        "calibration_rows": len(calibration_records),
                        "private_holdout": private_report,
                        "controlled": controlled_report,
                        "gates": gates,
                        "all_fixed_gates_passed": all(gates.values()),
                        "development_only": True,
                        "active_artifact_written": False,
                    },
                )
            )

    passing = [item for item in candidates if item.public["all_fixed_gates_passed"]]
    leader = max(passing, key=_candidate_rank) if passing else None
    improved = False
    improvement_reasons: list[str] = []
    if leader is not None:
        improved, improvement_reasons = _clearly_improves(leader, current)
    selected = leader if leader is not None and improved else None
    selection = {
        "candidate_selected": selected is not None,
        "candidate_name": selected.name if selected else None,
        "all_fixed_gates_passed": bool(
            selected and selected.public["all_fixed_gates_passed"]
        ),
        "clearly_improves_current": improved,
        "improvement_reasons": improvement_reasons,
        "eligible_for_advisory_install": selected is not None,
        "eligible_for_supervised_activation": False,
        "threat_accuracy_validated": False,
    }

    installation = {
        "requested": install_candidate,
        "installed": False,
        "required_confirmation": INSTALL_CONFIRMATION,
    }
    status = "diagnostic_evaluation_complete"
    if install_candidate:
        if confirmation != INSTALL_CONFIRMATION:
            status = "installation_confirmation_required"
        elif selected is None:
            status = "candidate_installation_refused"
        else:
            installation = {
                **installation,
                **_install_candidate(
                    selected,
                    evidence,
                    artifact_path=configured_artifact,
                ),
            }
            status = "governed_advisory_candidate_installed"

    return {
        "version": VERSION,
        "ok": status
        in {
            "diagnostic_evaluation_complete",
            "governed_advisory_candidate_installed",
        },
        "status": status,
        "executed": True,
        "evidence": evidence.public,
        "chronological_roles": {
            "fit_rows": len(fit_records),
            "calibration_rows": len(calibration_records),
            "private_holdout_rows": len(holdout_records),
            "private_holdout_labels_used": False,
            "sealed_supervised_evidence_accessed": False,
        },
        "controlled_evidence": controlled.public,
        "current_artifact": current,
        "candidate_comparison": [candidate.public for candidate in candidates],
        "selection": selection,
        "installation": installation,
        "reproducible_command": (
            "python -m atdr.scripts.run_v5631_anomaly_reliability "
            "--sample-path <private-log-file> --pretty"
        ),
        "privacy": _privacy_contract(),
        "safety": _safety_contract(),
    }


def _privacy_contract() -> dict[str, bool]:
    return {
        "source_paths_exposed": False,
        "raw_logs_exposed": False,
        "network_addresses_exposed": False,
        "identities_exposed": False,
        "fingerprints_exposed": False,
        "secrets_exposed": False,
    }


def _safety_contract() -> dict[str, Any]:
    return {
        "rules_alert_authoritative": True,
        "isolation_forest_advisory_only": True,
        "supervised_state": "unqualified",
        "supervised_model_activated": False,
        "model_driven_alerts": 0,
        "model_driven_suppressions": 0,
        "labels_created": 0,
        "detection_runs_created": 0,
        "response_actions_created": 0,
        "response_state": "simulation_only",
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }


def safe_anomaly_reliability_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, AnomalyReliabilityError):
        code = exc.code
        message = str(exc)
    else:
        code = "anomaly_reliability_failed_safely"
        message = "Anomaly reliability evaluation failed safely. No private evidence details were exposed."
    return {
        "version": VERSION,
        "ok": False,
        "status": code,
        "message": message,
        "executed": False,
        "candidate_installed": False,
        "privacy": _privacy_contract(),
        "safety": _safety_contract(),
    }
