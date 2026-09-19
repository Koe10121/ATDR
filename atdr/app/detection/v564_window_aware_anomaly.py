from __future__ import annotations

import bisect
import hashlib
import json
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Any, Iterable, Sequence

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.models import NormalizedLog
from atdr.app.detection.ml_detector import (
    CATEGORICAL_FEATURES as LEGACY_CATEGORICAL_FEATURES,
)
from atdr.app.detection.ml_detector import FEATURE_COLUMNS as LEGACY_FEATURE_COLUMNS
from atdr.app.detection.ml_detector import NUMERIC_FEATURES as LEGACY_NUMERIC_FEATURES
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.v5631_advisor_demo_reliability import (
    BENIGN_SCENARIOS,
    CONTROLLED_BENIGN_RATE_MAX,
    CONTROLLED_MALICIOUS_SCENARIO_RECALL_MIN,
    CONTROLLED_SUSPICIOUS_SCENARIO_RECALL_MIN,
    MALICIOUS_SCENARIOS,
    MAXIMUM_FIT_ROWS,
    MAXIMUM_LIMIT,
    MINIMUM_FIT_ROWS,
    PRIVATE_HOLDOUT_QUEUE_RATE_MAX,
    PRIVATE_HOLDOUT_QUEUE_RATE_MIN,
    SCENARIO_CATEGORIES,
    SUSPICIOUS_SCENARIOS,
    _evaluate_current,
    _optional_ml_imports as _legacy_ml_imports,
    _percentile,
    _privacy_contract,
    _score_distribution,
)
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services.v561_anomaly_bootstrap_service import (
    MAXIMUM_DUPLICATE_RATE,
    MINIMUM_PARSE_RATE,
    MINIMUM_SCHEMA_RATE,
    UNRESOLVED_APPS,
)


VERSION = "v5.64-window-aware-advisory-anomaly-v1"
DEFAULT_LIMIT = 50_000
RANDOM_STATE = 564
N_ESTIMATORS = 180
QUEUE_TARGETS = (0.01, 0.02, 0.03, 0.05)
ROLE_FRACTIONS = {
    "fit": 0.55,
    "calibration": 0.15,
    "validation": 0.15,
    "untouched_holdout": 0.15,
}
STRATEGY_NAMES = (
    "current_global_isolation_forest",
    "robust_scaled_global_isolation_forest",
    "chronological_window_baseline",
    "application_context_cohort_normalization",
    "empirical_percentile_calibration",
    "context_enriched_isolation_forest",
    "ood_aware_context_abstention",
    "global_cohort_score_ensemble",
)
# "empirical_percentile_calibration" is built in _fit_strategies from the
# same model and calibration_global as "robust_scaled_global_isolation_forest"
# and computes identical scores (see _strategy_scores). It is not a
# methodologically distinct candidate; report code must disclose this rather
# than presenting eight independent strategies. Seven strategies are
# independently distinct.
STRATEGY_KNOWN_DUPLICATES = {
    "empirical_percentile_calibration": "robust_scaled_global_isolation_forest",
}
DISTINCT_STRATEGY_COUNT = len(STRATEGY_NAMES) - len(STRATEGY_KNOWN_DUPLICATES)

CONTEXT_NUMERIC_FEATURES = [
    "log_src_port",
    "log_dst_port",
    "log_bytes",
    "log_bytes_sent",
    "log_bytes_received",
    "log_packets",
    "log_elapsed_time",
    "log_app_risk",
    "bytes_per_packet",
    "outbound_byte_ratio",
    "src_events_5m",
    "src_events_15m",
    "src_unique_destinations_5m",
    "src_unique_ports_5m",
    "src_deny_ratio_5m",
    "same_tuple_events_15m",
    "same_app_events_15m",
    "destination_events_5m",
    "source_interarrival_log_seconds",
    "source_cadence_jitter",
    "source_events_per_minute_5m",
    "repeat_count_effective",
    "missing_feature_count",
]
CONTEXT_CATEGORICAL_FEATURES = [
    "protocol",
    "application_family",
    "action_group",
    "direction",
    "schema_profile",
    "port_band",
]


class WindowAwareAnomalyError(RuntimeError):
    """Expected, privacy-safe v5.64 evaluation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EvidenceBundle:
    records: tuple[dict[str, Any], ...]
    trainable_indexes: tuple[int, ...]
    public: dict[str, Any]


@dataclass(frozen=True)
class ControlledBundle:
    records: tuple[dict[str, Any], ...]
    scenarios: tuple[str, ...]
    categories: tuple[str, ...]
    public: dict[str, Any]


@dataclass(frozen=True)
class ProtocolRoles:
    fit: tuple[dict[str, Any], ...]
    calibration: tuple[dict[str, Any], ...]
    validation: tuple[dict[str, Any], ...]
    untouched_holdout: tuple[dict[str, Any], ...]
    public: dict[str, Any]


@dataclass
class Strategy:
    name: str
    mode: str
    models: tuple[Any, ...]
    feature_kind: str
    calibration_global: tuple[float, ...]
    calibration_by_family: dict[str, tuple[float, ...]]
    calibration_by_cohort: dict[tuple[str, str], tuple[float, ...]]
    secondary_model: Any | None = None
    secondary_calibration: tuple[float, ...] = ()
    ood_profile: dict[str, Any] | None = None


def _optional_ml_imports() -> tuple[Any, ...] | None:
    try:
        import numpy as np
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import IsolationForest
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder, RobustScaler
    except ImportError:
        return None
    return (
        np,
        pd,
        ColumnTransformer,
        IsolationForest,
        SimpleImputer,
        Pipeline,
        OneHotEncoder,
        RobustScaler,
    )


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _application_family(app: Any) -> str:
    value = _lower(app)
    if value in UNRESOLVED_APPS or value in {"unknown", "not-applicable"}:
        return "unresolved"
    if any(token in value for token in ("quic", "ssl", "web-browsing", "http")):
        return "encrypted_web"
    if "dns" in value:
        return "dns"
    if any(token in value for token in ("ping", "icmp", "traceroute")):
        return "network_control"
    if any(token in value for token in ("ssh", "rdp", "telnet", "vnc")):
        return "remote_access"
    if any(token in value for token in ("ftp", "smb", "nfs", "file")):
        return "file_transfer"
    if any(token in value for token in ("smtp", "imap", "pop3", "mail")):
        return "mail"
    if any(token in value for token in ("facebook", "line", "twitter", "tiktok")):
        return "social_messaging"
    if any(token in value for token in ("ipsec", "stun", "rtp", "vpn")):
        return "tunnel_realtime"
    return "other"


def _direction(src_zone: Any, dst_zone: Any) -> str:
    source = _lower(src_zone)
    destination = _lower(dst_zone)
    internal_tokens = ("inside", "trust", "lan", "wlan", "corp")
    external_tokens = ("outside", "untrust", "internet", "wan")
    source_internal = any(token in source for token in internal_tokens)
    destination_internal = any(token in destination for token in internal_tokens)
    source_external = any(token in source for token in external_tokens)
    destination_external = any(token in destination for token in external_tokens)
    if source_internal and destination_external:
        return "internal_to_external"
    if source_external and destination_internal:
        return "external_to_internal"
    if source_internal and destination_internal:
        return "internal_to_internal"
    if source_external and destination_external:
        return "external_to_external"
    return "unresolved"


def _action_group(action: Any) -> str:
    value = _lower(action)
    if "deny" in value or "drop" in value or value.startswith("reset"):
        return "deny_drop_reset"
    if value == "allow":
        return "allow"
    return "other"


def _port_band(port: Any) -> str:
    if port is None:
        return "missing"
    value = int(port)
    if value <= 1023:
        return "system"
    if value <= 49151:
        return "registered"
    return "dynamic"


def _event_time(normalized: dict[str, Any], ordinal: int) -> tuple[float, bool]:
    value = (
        normalized.get("generated_time")
        or normalized.get("receive_time")
        or normalized.get("start_time")
    )
    if isinstance(value, datetime):
        return value.timestamp(), False
    return float(ordinal), True


def _schema_complete(normalized: dict[str, Any]) -> bool:
    return bool(
        normalized.get("log_type") == "TRAFFIC"
        and normalized.get("action")
        and normalized.get("app")
        and normalized.get("protocol")
        and normalized.get("src_port") is not None
        and normalized.get("dst_port") is not None
        and normalized.get("src_ip")
        and normalized.get("dst_ip")
    )


def _rule_log(
    normalized: dict[str, Any],
    parsed_json: dict[str, Any],
    ordinal: int,
) -> NormalizedLog:
    return NormalizedLog(
        id=ordinal + 1,
        parsed_json=parsed_json,
        is_anomaly=False,
        anomaly_score=None,
        **normalized,
    )


def _base_record(
    normalized: dict[str, Any],
    parsed_json: dict[str, Any],
    *,
    ordinal: int,
    scenario: str | None = None,
) -> dict[str, Any]:
    timestamp, synthetic_time = _event_time(normalized, ordinal)
    app = _lower(normalized.get("app"))
    missing = sum(
        normalized.get(field) in {None, ""}
        for field in ("src_ip", "dst_ip", "dst_port", "protocol", "action", "app")
    )
    record = {feature: normalized.get(feature) for feature in LEGACY_FEATURE_COLUMNS}
    record.update(
        {
            "_ordinal": ordinal,
            "_event_time": timestamp,
            "_synthetic_time": synthetic_time,
            "_src_key": normalized.get("src_ip") or f"missing-source-{ordinal}",
            "_dst_key": normalized.get("dst_ip") or f"missing-destination-{ordinal}",
            "_scenario": scenario,
            "_log_type": _lower(normalized.get("log_type")) or "unknown",
            "schema_profile": "limited" if app in UNRESOLVED_APPS else "structured",
            # Legacy v5.63.1 diagnostic aggregation (evaluate_private_model in
            # v5631_advisor_demo_reliability.py) groups by "_schema", not the
            # "schema_profile" key v5.64 uses internally. Set both so the
            # cross-module current_artifact.private_holdout.queue_by_schema
            # breakdown in run_window_aware_anomaly_redesign's output is
            # correct instead of silently bucketing every row as "unknown".
            "_schema": "limited" if app in UNRESOLVED_APPS else "structured",
            "application_family": _application_family(app),
            "action_group": _action_group(normalized.get("action")),
            "direction": _direction(
                normalized.get("src_zone"), normalized.get("dst_zone")
            ),
            "port_band": _port_band(normalized.get("dst_port")),
            "repeat_count_effective": min(
                max(int(normalized.get("repeat_count") or 1), 1), 10_000
            ),
            "missing_feature_count": missing,
            "_rule_log": _rule_log(normalized, parsed_json, ordinal),
        }
    )
    minute_bucket = int(timestamp // 300)
    record["_duplicate_family"] = (
        record["_src_key"],
        record["_dst_key"],
        normalized.get("src_port"),
        normalized.get("dst_port"),
        _lower(normalized.get("protocol")),
        _lower(normalized.get("action")),
        app,
        normalized.get("bytes"),
        normalized.get("packets"),
        normalized.get("elapsed_time"),
        minute_bucket,
    )
    return record


def _prune(events: deque[dict[str, Any]], cutoff: float) -> None:
    while events and float(events[0]["time"]) < cutoff:
        events.popleft()


def _contextualize(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        records,
        key=lambda item: (float(item["_event_time"]), int(item["_ordinal"])),
    )
    source_events_5m: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    source_events_15m: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    destination_events_5m: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    last_source_time: dict[str, float] = {}
    source_intervals: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=8))

    for record in ordered:
        now = float(record["_event_time"])
        source = str(record["_src_key"])
        destination = str(record["_dst_key"])
        source_5m = source_events_5m[source]
        source_15m = source_events_15m[source]
        destination_5m = destination_events_5m[destination]
        _prune(source_5m, now - 300)
        _prune(source_15m, now - 900)
        _prune(destination_5m, now - 300)

        previous = last_source_time.get(source)
        interarrival = max(0.0, now - previous) if previous is not None else 900.0
        if previous is not None:
            source_intervals[source].append(interarrival)
        intervals = list(source_intervals[source])
        interval_mean = mean(intervals) if intervals else 0.0
        jitter = (
            pstdev(intervals) / interval_mean
            if len(intervals) >= 2 and interval_mean > 0
            else 0.0
        )

        event = {
            "time": now,
            "destination": destination,
            "port": record.get("dst_port"),
            "deny": record["action_group"] == "deny_drop_reset",
            "family": record["application_family"],
            "tuple": (
                destination,
                record.get("dst_port"),
                _lower(record.get("protocol")),
                record["application_family"],
            ),
        }
        source_5m.append(event)
        source_15m.append(event)
        destination_5m.append(event)
        last_source_time[source] = now

        total_bytes = max(float(record.get("bytes") or 0), 0.0)
        sent_bytes = max(float(record.get("bytes_sent") or 0), 0.0)
        packets = max(float(record.get("packets") or 0), 0.0)
        deny_count = sum(bool(item["deny"]) for item in source_5m)
        current_tuple = event["tuple"]
        record.update(
            {
                "log_src_port": math.log1p(max(float(record.get("src_port") or 0), 0.0)),
                "log_dst_port": math.log1p(max(float(record.get("dst_port") or 0), 0.0)),
                "log_bytes": math.log1p(total_bytes),
                "log_bytes_sent": math.log1p(sent_bytes),
                "log_bytes_received": math.log1p(
                    max(float(record.get("bytes_received") or 0), 0.0)
                ),
                "log_packets": math.log1p(packets),
                "log_elapsed_time": math.log1p(
                    max(float(record.get("elapsed_time") or 0), 0.0)
                ),
                "log_app_risk": math.log1p(
                    max(float(record.get("app_risk") or 0), 0.0)
                ),
                "bytes_per_packet": math.log1p(total_bytes / max(packets, 1.0)),
                "outbound_byte_ratio": sent_bytes / max(total_bytes, 1.0),
                "src_events_5m": len(source_5m),
                "src_events_15m": len(source_15m),
                "src_unique_destinations_5m": len(
                    {item["destination"] for item in source_5m}
                ),
                "src_unique_ports_5m": len(
                    {item["port"] for item in source_5m if item["port"] is not None}
                ),
                "src_deny_ratio_5m": deny_count / len(source_5m),
                "same_tuple_events_15m": sum(
                    item["tuple"] == current_tuple for item in source_15m
                ),
                "same_app_events_15m": sum(
                    item["family"] == record["application_family"]
                    for item in source_15m
                ),
                "destination_events_5m": len(destination_5m),
                "source_interarrival_log_seconds": math.log1p(interarrival),
                "source_cadence_jitter": min(float(jitter), 10.0),
                "source_events_per_minute_5m": len(source_5m) / 5.0,
            }
        )
    return ordered


def _annotate_rule_signals(
    records: Sequence[dict[str, Any]],
    *,
    group_field: str | None = None,
) -> None:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if group_field:
        for record in records:
            groups[str(record.get(group_field) or "ungrouped")].append(record)
    else:
        groups["all"] = list(records)
    for group in groups.values():
        logs = [record["_rule_log"] for record in group]
        context = build_detection_context(logs)
        for record in group:
            matches = [
                match
                for match in evaluate_rules(record["_rule_log"], context)
                if match.code != "ml_anomaly_detected"
            ]
            record["_rule_signal"] = bool(matches)
            record["_rule_count"] = len(matches)


def inspect_private_evidence(
    sample_path: Path,
    *,
    limit: int = DEFAULT_LIMIT,
    minimum_fit_rows: int = MINIMUM_FIT_ROWS,
) -> EvidenceBundle:
    if limit < minimum_fit_rows or limit > MAXIMUM_LIMIT:
        raise WindowAwareAnomalyError(
            "invalid_evidence_limit",
            f"Evidence limit must be between {minimum_fit_rows} and {MAXIMUM_LIMIT}.",
        )
    source = sample_path.expanduser().resolve()
    if not source.is_file():
        raise WindowAwareAnomalyError(
            "private_evidence_unavailable",
            "The private evidence source is unavailable.",
        )

    records: list[dict[str, Any]] = []
    trainable_indexes: list[int] = []
    seen: set[bytes] = set()
    duplicates = 0
    parsed_rows = 0
    schema_rows = 0
    synthetic_time_rows = 0
    exclusions: Counter[str] = Counter()

    with source.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for raw_line in stream:
            if not raw_line.strip():
                continue
            if len(records) + duplicates >= limit:
                break
            digest = hashlib.sha256(raw_line.encode("utf-8", errors="replace")).digest()
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            parsed = parse_log_line(raw_line.rstrip("\r\n"))
            ordinal = len(records)
            if parsed.error is None:
                parsed_rows += 1
            record = _base_record(
                parsed.normalized,
                parsed.parsed_json,
                ordinal=ordinal,
            )
            records.append(record)
            synthetic_time_rows += int(bool(record["_synthetic_time"]))
            if parsed.error is not None:
                exclusions["parser_failure"] += 1
            elif parsed.normalized.get("log_type") != "TRAFFIC":
                exclusions["non_traffic_record"] += 1
            elif not _schema_complete(parsed.normalized):
                exclusions["incomplete_feature_schema"] += 1
            else:
                schema_rows += 1
                trainable_indexes.append(ordinal)

    contextualized = _contextualize(records)
    _annotate_rule_signals(contextualized)
    by_ordinal = {int(record["_ordinal"]): record for record in contextualized}
    ordered_records = [by_ordinal[index] for index in range(len(by_ordinal))]
    observed = len(ordered_records) + duplicates
    parse_rate = parsed_rows / len(ordered_records) if ordered_records else 0.0
    schema_rate = schema_rows / len(ordered_records) if ordered_records else 0.0
    duplicate_rate = duplicates / observed if observed else 0.0
    gates = {
        "minimum_fit_rows": len(trainable_indexes) >= minimum_fit_rows,
        "parser_quality": parse_rate >= MINIMUM_PARSE_RATE,
        "schema_completeness": schema_rate >= MINIMUM_SCHEMA_RATE,
        "duplicate_containment": duplicate_rate <= MAXIMUM_DUPLICATE_RATE,
        "chronology_available": synthetic_time_rows == 0,
    }
    return EvidenceBundle(
        records=tuple(ordered_records),
        trainable_indexes=tuple(trainable_indexes),
        public={
            "source_role": "operator_supplied_private_development_only",
            "observed_rows": observed,
            "unique_rows": len(ordered_records),
            "duplicate_rows": duplicates,
            "duplicate_rate": round(duplicate_rate, 4),
            "parsed_rows": parsed_rows,
            "parse_rate": round(parse_rate, 4),
            "schema_complete_rows": schema_rows,
            "schema_complete_rate": round(schema_rate, 4),
            "trainable_rows": len(trainable_indexes),
            "excluded_rows": len(ordered_records) - len(trainable_indexes),
            "exclusion_reasons": dict(sorted(exclusions.items())),
            "synthetic_time_rows": synthetic_time_rows,
            "limit": limit,
            "limit_reached": observed >= limit,
            "gates": gates,
            "passed": all(gates.values()),
            **_privacy_contract(),
        },
    )


def load_controlled_evidence(*, project_root: Path = PROJECT_ROOT) -> ControlledBundle:
    scenario_root = project_root / "data" / "samples" / "scenarios"
    records: list[dict[str, Any]] = []
    scenarios: list[str] = []
    categories: list[str] = []
    counts: Counter[str] = Counter()
    parse_failures = 0
    ordinal = 0
    for scenario, category in SCENARIO_CATEGORIES.items():
        source = scenario_root / f"{scenario}.txt"
        if not source.is_file():
            raise WindowAwareAnomalyError(
                "controlled_scenario_missing",
                "A required controlled scenario is unavailable.",
            )
        scenario_records: list[dict[str, Any]] = []
        with source.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for raw_line in stream:
                if not raw_line.strip():
                    continue
                parsed = parse_log_line(raw_line.rstrip("\r\n"))
                if parsed.error is not None:
                    parse_failures += 1
                    continue
                record = _base_record(
                    parsed.normalized,
                    parsed.parsed_json,
                    ordinal=ordinal,
                    scenario=scenario,
                )
                scenario_records.append(record)
                ordinal += 1
        scenario_records = _contextualize(scenario_records)
        records.extend(scenario_records)
        scenarios.extend([scenario] * len(scenario_records))
        categories.extend([category] * len(scenario_records))
        counts[scenario] += len(scenario_records)
    _annotate_rule_signals(records, group_field="_scenario")
    return ControlledBundle(
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
            "scenario_rows": dict(sorted(counts.items())),
            "synthetic_development_evidence": True,
            "human_reviewed_labels": False,
            "independent_accuracy_evidence": False,
        },
    )


def _partition_roles(
    evidence: EvidenceBundle,
    *,
    minimum_fit_rows: int,
) -> ProtocolRoles:
    eligible = [evidence.records[index] for index in evidence.trainable_indexes]
    eligible.sort(key=lambda item: (item["_event_time"], item["_ordinal"]))
    total = len(eligible)
    fit_end = int(total * ROLE_FRACTIONS["fit"])
    calibration_end = fit_end + int(total * ROLE_FRACTIONS["calibration"])
    validation_end = calibration_end + int(total * ROLE_FRACTIONS["validation"])
    raw_roles = {
        "fit": eligible[:fit_end],
        "calibration": eligible[fit_end:calibration_end],
        "validation": eligible[calibration_end:validation_end],
        "untouched_holdout": eligible[validation_end:],
    }
    isolated: dict[str, list[dict[str, Any]]] = {}
    seen_families: set[tuple[Any, ...]] = set()
    quarantined: Counter[str] = Counter()
    for name in ("fit", "calibration", "validation", "untouched_holdout"):
        role_records: list[dict[str, Any]] = []
        current_families: set[tuple[Any, ...]] = set()
        for record in raw_roles[name]:
            family = record["_duplicate_family"]
            if family in seen_families:
                quarantined[name] += 1
                continue
            role_records.append(record)
            current_families.add(family)
        seen_families.update(current_families)
        isolated[name] = role_records

    fit_window_rows = len(isolated["fit"])
    if fit_window_rows > MAXIMUM_FIT_ROWS:
        step = fit_window_rows / MAXIMUM_FIT_ROWS
        isolated["fit"] = [
            isolated["fit"][min(fit_window_rows - 1, int(index * step))]
            for index in range(MAXIMUM_FIT_ROWS)
        ]
    counts = {name: len(rows) for name, rows in isolated.items()}
    gates = {
        "minimum_fit_rows": counts["fit"] >= minimum_fit_rows,
        "minimum_calibration_rows": counts["calibration"] >= 100,
        "minimum_validation_rows": counts["validation"] >= 100,
        "minimum_untouched_holdout_rows": counts["untouched_holdout"] >= 100,
        "chronological_order": True,
        "duplicate_family_isolation": True,
    }
    return ProtocolRoles(
        fit=tuple(isolated["fit"]),
        calibration=tuple(isolated["calibration"]),
        validation=tuple(isolated["validation"]),
        untouched_holdout=tuple(isolated["untouched_holdout"]),
        public={
            "protocol_locked": True,
            "role_order": [
                "fit",
                "calibration",
                "validation",
                "untouched_holdout",
            ],
            "role_fractions": ROLE_FRACTIONS,
            "fit_window_rows_before_cap": fit_window_rows,
            "role_rows": counts,
            "duplicate_family_quarantined_rows": sum(quarantined.values()),
            "duplicate_family_quarantine_by_role": dict(sorted(quarantined.items())),
            "sealed_supervised_evidence_accessed": False,
            "private_labels_used": False,
            "untouched_holdout_used_for_selection": False,
            "gates": gates,
            "passed": all(gates.values()),
        },
    )


def _frame(imports: tuple[Any, ...], records: Iterable[dict[str, Any]], kind: str) -> Any:
    pd = imports[1]
    columns = (
        [*CONTEXT_NUMERIC_FEATURES, *CONTEXT_CATEGORICAL_FEATURES]
        if kind == "context"
        else list(LEGACY_FEATURE_COLUMNS)
    )
    return pd.DataFrame(
        [{column: record.get(column) for column in columns} for record in records],
        columns=columns,
    )


def _pipeline(imports: tuple[Any, ...], *, kind: str, robust: bool, seed: int) -> Any:
    (
        _,
        _,
        ColumnTransformer,
        IsolationForest,
        SimpleImputer,
        Pipeline,
        OneHotEncoder,
        RobustScaler,
    ) = imports
    numeric = CONTEXT_NUMERIC_FEATURES if kind == "context" else LEGACY_NUMERIC_FEATURES
    categorical = (
        CONTEXT_CATEGORICAL_FEATURES if kind == "context" else LEGACY_CATEGORICAL_FEATURES
    )
    numeric_steps: list[tuple[str, Any]] = [("imputer", SimpleImputer(strategy="median"))]
    if robust:
        numeric_steps.append(
            (
                "scale",
                RobustScaler(quantile_range=(5.0, 95.0)),
            )
        )
    return Pipeline(
        [
            (
                "preprocess",
                ColumnTransformer(
                    [
                        ("numeric", Pipeline(numeric_steps), numeric),
                        (
                            "categorical",
                            Pipeline(
                                [
                                    ("imputer", SimpleImputer(strategy="most_frequent")),
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
                    n_estimators=N_ESTIMATORS,
                    contamination="auto",
                    max_samples=4096,
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def _fit_model(
    imports: tuple[Any, ...],
    records: Sequence[dict[str, Any]],
    *,
    kind: str,
    robust: bool,
    seed: int,
) -> Any:
    model = _pipeline(imports, kind=kind, robust=robust, seed=seed)
    model.named_steps["model"].set_params(max_samples=min(4096, len(records)))
    model.fit(_frame(imports, records, kind))
    return model


def _outlier_scores(
    model: Any,
    imports: tuple[Any, ...],
    records: Sequence[dict[str, Any]],
    kind: str,
) -> list[float]:
    if not records:
        return []
    return [
        -float(value)
        for value in model.score_samples(_frame(imports, records, kind))
    ]


def _percentile_rank(values: Sequence[float], value: float) -> float:
    if not values:
        return 0.0
    return bisect.bisect_right(values, float(value)) / len(values)


def _cohort_calibrations(
    records: Sequence[dict[str, Any]],
    scores: Sequence[float],
) -> tuple[dict[str, tuple[float, ...]], dict[tuple[str, str], tuple[float, ...]]]:
    by_family: dict[str, list[float]] = defaultdict(list)
    by_cohort: dict[tuple[str, str], list[float]] = defaultdict(list)
    for record, score in zip(records, scores, strict=True):
        family = str(record["application_family"])
        direction = str(record["direction"])
        by_family[family].append(float(score))
        by_cohort[(family, direction)].append(float(score))
    return (
        {key: tuple(sorted(values)) for key, values in by_family.items() if len(values) >= 50},
        {key: tuple(sorted(values)) for key, values in by_cohort.items() if len(values) >= 50},
    )


def _ood_profile(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    categories = {
        feature: {str(record.get(feature) or "unknown") for record in records}
        for feature in CONTEXT_CATEGORICAL_FEATURES
    }
    bounds: dict[str, tuple[float, float]] = {}
    for feature in CONTEXT_NUMERIC_FEATURES:
        values = sorted(float(record.get(feature) or 0.0) for record in records)
        low = _percentile(values, 0.005)
        high = _percentile(values, 0.995)
        span = max(high - low, 1.0)
        bounds[feature] = (low - span, high + span)
    return {"categories": categories, "bounds": bounds}


def _ood_reason(record: dict[str, Any], profile: dict[str, Any] | None) -> str | None:
    if profile is None:
        return None
    if int(record.get("missing_feature_count") or 0) >= 3:
        return "missing_features"
    unseen = sum(
        str(record.get(feature) or "unknown") not in values
        for feature, values in profile["categories"].items()
    )
    extremes = sum(
        float(record.get(feature) or 0.0) < bounds[0]
        or float(record.get(feature) or 0.0) > bounds[1]
        for feature, bounds in profile["bounds"].items()
    )
    if unseen >= 3:
        return "categorical_ood"
    if extremes >= 4:
        return "numeric_ood"
    return None


def _strategy_scores(
    strategy: Strategy,
    imports: tuple[Any, ...],
    records: Sequence[dict[str, Any]],
) -> tuple[list[float], list[float], list[str | None]]:
    model_scores = [
        _outlier_scores(model, imports, records, strategy.feature_kind)
        for model in strategy.models
    ]
    raw_scores = [
        median(values)
        for values in zip(*model_scores, strict=True)
    ] if model_scores else []
    global_percentiles = [
        _percentile_rank(strategy.calibration_global, score) for score in raw_scores
    ]
    cohort_percentiles: list[float] = []
    for record, score, fallback in zip(
        records,
        raw_scores,
        global_percentiles,
        strict=True,
    ):
        cohort = (str(record["application_family"]), str(record["direction"]))
        family = str(record["application_family"])
        distribution = strategy.calibration_by_cohort.get(cohort)
        if distribution is None:
            distribution = strategy.calibration_by_family.get(family)
        cohort_percentiles.append(
            _percentile_rank(distribution, score) if distribution else fallback
        )

    if strategy.mode == "cohort":
        percentiles = cohort_percentiles
    elif strategy.mode == "empirical":
        # "empirical_percentile_calibration" is declared with the same model
        # and calibration_global as "robust_scaled_global_isolation_forest"
        # (see _fit_strategies), so this intentionally computes the same
        # global percentile-rank as the "global" branch below. It is kept as
        # an explicit branch, not folded into `else`, so this equivalence is
        # visible in code rather than accidental. See STRATEGY_KNOWN_DUPLICATES.
        percentiles = global_percentiles
    elif strategy.mode == "ensemble":
        assert strategy.secondary_model is not None
        secondary_scores = _outlier_scores(
            strategy.secondary_model,
            imports,
            records,
            "base",
        )
        secondary_percentiles = [
            _percentile_rank(strategy.secondary_calibration, value)
            for value in secondary_scores
        ]
        percentiles = [
            (primary + secondary) / 2.0
            for primary, secondary in zip(
                cohort_percentiles,
                secondary_percentiles,
                strict=True,
            )
        ]
    else:
        percentiles = global_percentiles
    reasons = [
        _ood_reason(record, strategy.ood_profile)
        if strategy.mode == "ood_abstention"
        else None
        for record in records
    ]
    return raw_scores, percentiles, reasons


def _fit_strategies(
    imports: tuple[Any, ...],
    roles: ProtocolRoles,
) -> list[Strategy]:
    fit = list(roles.fit)
    calibration = list(roles.calibration)
    raw_model = _fit_model(
        imports,
        fit,
        kind="base",
        robust=False,
        seed=RANDOM_STATE,
    )
    robust_model = _fit_model(
        imports,
        fit,
        kind="base",
        robust=True,
        seed=RANDOM_STATE + 1,
    )
    context_model = _fit_model(
        imports,
        fit,
        kind="context",
        robust=True,
        seed=RANDOM_STATE + 2,
    )
    fit_windows = [
        fit[index * len(fit) // 3 : (index + 1) * len(fit) // 3]
        for index in range(3)
    ]
    window_models = tuple(
        _fit_model(
            imports,
            window,
            kind="context",
            robust=True,
            seed=RANDOM_STATE + 10 + index,
        )
        for index, window in enumerate(fit_windows)
    )

    raw_calibration = tuple(
        sorted(_outlier_scores(raw_model, imports, calibration, "base"))
    )
    robust_calibration = tuple(
        sorted(_outlier_scores(robust_model, imports, calibration, "base"))
    )
    context_scores = _outlier_scores(context_model, imports, calibration, "context")
    context_calibration = tuple(sorted(context_scores))
    family_calibration, cohort_calibration = _cohort_calibrations(
        calibration,
        context_scores,
    )
    window_score_sets = [
        _outlier_scores(model, imports, calibration, "context")
        for model in window_models
    ]
    window_calibration = tuple(
        sorted(median(values) for values in zip(*window_score_sets, strict=True))
    )
    profile = _ood_profile(fit)

    def strategy(
        name: str,
        mode: str,
        models: tuple[Any, ...],
        feature_kind: str,
        calibration_global: tuple[float, ...],
        *,
        secondary_model: Any | None = None,
        secondary_calibration: tuple[float, ...] = (),
        ood: bool = False,
    ) -> Strategy:
        return Strategy(
            name=name,
            mode=mode,
            models=models,
            feature_kind=feature_kind,
            calibration_global=calibration_global,
            calibration_by_family=family_calibration if feature_kind == "context" else {},
            calibration_by_cohort=cohort_calibration if feature_kind == "context" else {},
            secondary_model=secondary_model,
            secondary_calibration=secondary_calibration,
            ood_profile=profile if ood else None,
        )

    return [
        strategy(
            STRATEGY_NAMES[0],
            "global",
            (raw_model,),
            "base",
            raw_calibration,
        ),
        strategy(
            STRATEGY_NAMES[1],
            "global",
            (robust_model,),
            "base",
            robust_calibration,
        ),
        strategy(
            STRATEGY_NAMES[2],
            "global",
            window_models,
            "context",
            window_calibration,
        ),
        strategy(
            STRATEGY_NAMES[3],
            "cohort",
            (context_model,),
            "context",
            context_calibration,
        ),
        strategy(
            STRATEGY_NAMES[4],
            "empirical",
            (robust_model,),
            "base",
            robust_calibration,
        ),
        strategy(
            STRATEGY_NAMES[5],
            "global",
            (context_model,),
            "context",
            context_calibration,
        ),
        strategy(
            STRATEGY_NAMES[6],
            "ood_abstention",
            (context_model,),
            "context",
            context_calibration,
            ood=True,
        ),
        strategy(
            STRATEGY_NAMES[7],
            "ensemble",
            (context_model,),
            "context",
            context_calibration,
            secondary_model=robust_model,
            secondary_calibration=robust_calibration,
        ),
    ]


def _window_names(records: Sequence[dict[str, Any]]) -> list[str]:
    total = max(len(records), 1)
    return [f"window_{min(4, (index * 4 // total) + 1)}" for index in range(len(records))]


def _aggregate_groups(
    records: Sequence[dict[str, Any]],
    flags: Sequence[bool],
    scores: Sequence[float],
    *,
    field: str,
    values: Sequence[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        value = values[index] if values is not None else str(record.get(field) or "unknown")
        groups[value].append(index)
    output = []
    for value, indexes in groups.items():
        queued = sum(flags[index] for index in indexes)
        output.append(
            {
                "value": value,
                "rows": len(indexes),
                "queue_count": queued,
                "queue_rate": round(queued / len(indexes), 4),
                "score_median": round(median(scores[index] for index in indexes), 6),
            }
        )
    return sorted(output, key=lambda item: (item["queue_rate"], item["rows"]), reverse=True)[:limit]


def _score_buckets(
    scores: Sequence[float],
    flags: Sequence[bool],
    abstentions: Sequence[str | None],
) -> list[dict[str, Any]]:
    boundaries = ((0.0, 0.5), (0.5, 0.8), (0.8, 0.95), (0.95, 0.99), (0.99, 1.000001))
    buckets = []
    for low, high in boundaries:
        indexes = [index for index, value in enumerate(scores) if low <= value < high]
        buckets.append(
            {
                "range": f"{low:.2f}-{min(high, 1.0):.2f}",
                "rows": len(indexes),
                "queue_count": sum(flags[index] for index in indexes),
                "abstained_count": sum(abstentions[index] is not None for index in indexes),
            }
        )
    return buckets


def _rule_contribution(
    records: Sequence[dict[str, Any]],
    flags: Sequence[bool],
) -> dict[str, Any]:
    queued = [index for index, flag in enumerate(flags) if flag]
    overlap = sum(bool(records[index].get("_rule_signal")) for index in queued)
    novel = len(queued) - overlap
    return {
        "queued_rows": len(queued),
        "rule_overlap_rows": overlap,
        "novel_advisory_rows": novel,
        "rule_overlap_rate": round(overlap / len(queued), 4) if queued else 0.0,
        "novel_advisory_rate": round(novel / len(queued), 4) if queued else 0.0,
        "authoritative_behavior_changed": False,
    }


def _behavior_concentration(
    records: Sequence[dict[str, Any]],
    flags: Sequence[bool],
) -> dict[str, Any]:
    features = (
        "src_events_5m",
        "src_unique_destinations_5m",
        "src_unique_ports_5m",
        "src_deny_ratio_5m",
        "same_tuple_events_15m",
        "same_app_events_15m",
        "destination_events_5m",
        "source_interarrival_log_seconds",
        "source_cadence_jitter",
        "log_bytes",
        "log_elapsed_time",
        "repeat_count_effective",
    )
    queued_indexes = [index for index, flag in enumerate(flags) if flag]
    output: dict[str, Any] = {}
    for feature in features:
        all_values = [float(record.get(feature) or 0.0) for record in records]
        queued_values = [
            float(records[index].get(feature) or 0.0) for index in queued_indexes
        ]
        output[feature] = {
            "all_median": round(median(all_values), 4) if all_values else None,
            "queued_median": round(median(queued_values), 4) if queued_values else None,
        }
    unresolved_rows = sum(
        record.get("application_family") == "unresolved" for record in records
    )
    unresolved_queued = sum(
        flag and record.get("application_family") == "unresolved"
        for record, flag in zip(records, flags, strict=True)
    )
    missing_rows = sum(int(record.get("missing_feature_count") or 0) > 0 for record in records)
    missing_queued = sum(
        flag and int(record.get("missing_feature_count") or 0) > 0
        for record, flag in zip(records, flags, strict=True)
    )
    return {
        "numeric_medians": output,
        "unresolved_application": {
            "rows": unresolved_rows,
            "queue_count": unresolved_queued,
            "queue_rate": round(unresolved_queued / unresolved_rows, 4)
            if unresolved_rows
            else 0.0,
        },
        "missing_context": {
            "rows": missing_rows,
            "queue_count": missing_queued,
            "queue_rate": round(missing_queued / missing_rows, 4)
            if missing_rows
            else 0.0,
        },
    }


def _evaluate_private(
    strategy: Strategy,
    imports: tuple[Any, ...],
    records: Sequence[dict[str, Any]],
    queue_target: float,
) -> dict[str, Any]:
    raw_scores, percentiles, abstentions = _strategy_scores(strategy, imports, records)
    flags = [
        percentile >= 1.0 - queue_target and reason is None
        for percentile, reason in zip(percentiles, abstentions, strict=True)
    ]
    windows = _window_names(records)
    by_window = _aggregate_groups(
        records,
        flags,
        percentiles,
        field="_ordinal",
        values=windows,
        limit=4,
    )
    window_rates = [float(item["queue_rate"]) for item in by_window]
    window_range = max(window_rates) - min(window_rates) if window_rates else 0.0
    reason_counts = Counter(reason for reason in abstentions if reason)
    scored = len(records) - sum(reason_counts.values())
    return {
        "rows": len(records),
        "rows_scored": scored,
        "abstained_rows": len(records) - scored,
        "abstention_rate": round((len(records) - scored) / len(records), 4) if records else 0.0,
        "abstention_reasons": dict(sorted(reason_counts.items())),
        "queue_count": sum(flags),
        "queue_rate": round(sum(flags) / len(records), 4) if records else 0.0,
        "raw_score_distribution": _score_distribution(raw_scores),
        "calibrated_score_distribution": _score_distribution(percentiles),
        "confidence_buckets": _score_buckets(percentiles, flags, abstentions),
        "queue_by_application_family": _aggregate_groups(
            records, flags, percentiles, field="application_family"
        ),
        "queue_by_action": _aggregate_groups(
            records, flags, percentiles, field="action_group"
        ),
        "queue_by_direction": _aggregate_groups(
            records, flags, percentiles, field="direction"
        ),
        "queue_by_schema": _aggregate_groups(
            records, flags, percentiles, field="schema_profile"
        ),
        "queue_by_time_window": by_window,
        "time_window_queue_rate_range": round(window_range, 4),
        "drift_status": "drift_warning" if window_range > 0.05 else "stable",
        "behavior_concentration": _behavior_concentration(records, flags),
        "rule_contribution": _rule_contribution(records, flags),
        "unlabeled_private_development_evidence": True,
        "false_positive_rate_claimed": False,
        "private_details_exposed": False,
    }


def _scenario_recall(
    flags: Sequence[bool],
    scenarios: Sequence[str],
    categories: Sequence[str],
    category: str,
) -> tuple[float, int, int]:
    captured: dict[str, bool] = {}
    for flag, scenario, row_category in zip(flags, scenarios, categories, strict=True):
        if row_category == category:
            captured[scenario] = captured.get(scenario, False) or bool(flag)
    total = len(captured)
    caught = sum(captured.values())
    return (caught / total if total else 0.0), caught, total


def _evaluate_controlled(
    strategy: Strategy,
    imports: tuple[Any, ...],
    controlled: ControlledBundle,
    queue_target: float,
) -> dict[str, Any]:
    records = list(controlled.records)
    _, percentiles, abstentions = _strategy_scores(strategy, imports, records)
    flags = [
        percentile >= 1.0 - queue_target and reason is None
        for percentile, reason in zip(percentiles, abstentions, strict=True)
    ]
    positions: dict[str, list[int]] = defaultdict(list)
    for index, category in enumerate(controlled.categories):
        positions[category].append(index)

    def rate(category: str) -> float:
        indexes = positions.get(category, [])
        return sum(flags[index] for index in indexes) / len(indexes) if indexes else 0.0

    suspicious = _scenario_recall(flags, controlled.scenarios, controlled.categories, "suspicious")
    malicious = _scenario_recall(flags, controlled.scenarios, controlled.categories, "malicious")
    anomaly_scenarios = {
        controlled.scenarios[index] for index, flag in enumerate(flags) if flag
    }
    rule_scenarios = {
        controlled.scenarios[index]
        for index, record in enumerate(records)
        if record.get("_rule_signal")
    }
    benign_indexes = positions.get("benign", [])
    scenario_results = []
    for scenario in SCENARIO_CATEGORIES:
        indexes = [
            index
            for index, row_scenario in enumerate(controlled.scenarios)
            if row_scenario == scenario
        ]
        scenario_results.append(
            {
                "scenario": scenario,
                "category": SCENARIO_CATEGORIES[scenario],
                "rows": len(indexes),
                "queued_rows": sum(flags[index] for index in indexes),
                "captured": any(flags[index] for index in indexes),
                "maximum_calibrated_score": round(
                    max((percentiles[index] for index in indexes), default=0.0),
                    6,
                ),
                "rule_signal_present": any(
                    records[index].get("_rule_signal") for index in indexes
                ),
                "abstained_rows": sum(
                    abstentions[index] is not None for index in indexes
                ),
            }
        )
    return {
        "rows_scored": len(records) - sum(reason is not None for reason in abstentions),
        "abstained_rows": sum(reason is not None for reason in abstentions),
        "anomaly_count": sum(flags),
        "anomaly_rate": round(sum(flags) / len(flags), 4) if flags else 0.0,
        "controlled_benign_anomaly_rate": round(rate("benign"), 4),
        "controlled_suspicious_row_recall": round(rate("suspicious"), 4),
        "controlled_malicious_row_recall": round(rate("malicious"), 4),
        "controlled_suspicious_scenario_recall": round(suspicious[0], 4),
        "controlled_malicious_scenario_recall": round(malicious[0], 4),
        "suspicious_scenarios_captured": suspicious[1],
        "suspicious_scenarios_total": suspicious[2],
        "malicious_scenarios_captured": malicious[1],
        "malicious_scenarios_total": malicious[2],
        "benign_scenarios_flagged": len(
            {controlled.scenarios[index] for index in benign_indexes if flags[index]}
        ),
        "benign_scenarios_total": len(BENIGN_SCENARIOS),
        "calibrated_score_distribution": _score_distribution(percentiles),
        "scenario_results": scenario_results,
        "abstention_reasons": dict(
            sorted(Counter(reason for reason in abstentions if reason).items())
        ),
        "rule_contribution": {
            **_rule_contribution(records, flags),
            "anomaly_captured_scenarios": len(anomaly_scenarios),
            "rule_captured_scenarios": len(rule_scenarios),
            "overlap_scenarios": len(anomaly_scenarios & rule_scenarios),
            "novel_anomaly_only_scenarios": len(anomaly_scenarios - rule_scenarios),
        },
        "synthetic_development_evidence": True,
        "independent_accuracy_claimed": False,
    }


def _candidate_gates(
    controlled: dict[str, Any],
    private: dict[str, Any],
    *,
    fit_rows: int,
    minimum_fit_rows: int,
) -> dict[str, bool]:
    return {
        "minimum_fit_rows": fit_rows >= minimum_fit_rows,
        "controlled_benign_noise": float(controlled["controlled_benign_anomaly_rate"])
        <= CONTROLLED_BENIGN_RATE_MAX,
        "controlled_suspicious_scenario_capture": float(
            controlled["controlled_suspicious_scenario_recall"]
        )
        >= CONTROLLED_SUSPICIOUS_SCENARIO_RECALL_MIN,
        "controlled_malicious_scenario_capture": float(
            controlled["controlled_malicious_scenario_recall"]
        )
        >= CONTROLLED_MALICIOUS_SCENARIO_RECALL_MIN,
        "private_holdout_queue_floor": float(private["queue_rate"])
        >= PRIVATE_HOLDOUT_QUEUE_RATE_MIN,
        "private_holdout_queue_ceiling": float(private["queue_rate"])
        <= PRIVATE_HOLDOUT_QUEUE_RATE_MAX,
        "private_time_window_stability": float(private["time_window_queue_rate_range"])
        <= 0.05,
    }


def _rank(report: dict[str, Any]) -> tuple[float, ...]:
    controlled = report["controlled"]
    private = report["private_validation"]
    return (
        float(controlled["controlled_malicious_scenario_recall"]),
        float(controlled["controlled_suspicious_scenario_recall"]),
        -float(controlled["controlled_benign_anomaly_rate"]),
        -float(private["time_window_queue_rate_range"]),
        -abs(float(private["queue_rate"]) - float(report["queue_target"])),
    )


def _improves_current(report: dict[str, Any], current: dict[str, Any]) -> bool:
    if current.get("status") != "evaluated":
        return True
    candidate = report["controlled"]
    baseline = current["controlled"]
    no_regression = bool(
        float(candidate["controlled_benign_anomaly_rate"])
        <= max(
            CONTROLLED_BENIGN_RATE_MAX,
            float(baseline["controlled_benign_anomaly_rate"]),
        )
        and float(candidate["controlled_suspicious_scenario_recall"])
        >= float(baseline["controlled_suspicious_scenario_recall"])
        and float(candidate["controlled_malicious_scenario_recall"])
        >= float(baseline["controlled_malicious_scenario_recall"])
    )
    strict = bool(
        float(candidate["controlled_benign_anomaly_rate"]) + 0.02
        < float(baseline["controlled_benign_anomaly_rate"])
        or float(candidate["controlled_suspicious_scenario_recall"])
        > float(baseline["controlled_suspicious_scenario_recall"])
        or float(candidate["controlled_malicious_scenario_recall"])
        > float(baseline["controlled_malicious_scenario_recall"])
    )
    return no_regression and strict


def _categorical_jsd(
    left: Sequence[dict[str, Any]],
    right: Sequence[dict[str, Any]],
    field: str,
) -> float:
    left_counts = Counter(str(record.get(field) or "unknown") for record in left)
    right_counts = Counter(str(record.get(field) or "unknown") for record in right)
    keys = set(left_counts) | set(right_counts)
    if not left or not right:
        return 0.0

    def kl(counts: Counter[str], total: int, mixture: dict[str, float]) -> float:
        value = 0.0
        for key in keys:
            probability = counts[key] / total
            if probability > 0 and mixture[key] > 0:
                value += probability * math.log2(probability / mixture[key])
        return value

    mixture = {
        key: 0.5 * (left_counts[key] / len(left) + right_counts[key] / len(right))
        for key in keys
    }
    return round(0.5 * kl(left_counts, len(left), mixture) + 0.5 * kl(right_counts, len(right), mixture), 4)


def _drift_report(roles: ProtocolRoles) -> dict[str, Any]:
    fit = list(roles.fit)
    output: dict[str, Any] = {}
    for name, records in (
        ("calibration", roles.calibration),
        ("validation", roles.validation),
        ("untouched_holdout", roles.untouched_holdout),
    ):
        categorical = {
            field: _categorical_jsd(fit, records, field)
            for field in (
                "application_family",
                "action_group",
                "direction",
                "schema_profile",
            )
        }
        numeric_shifts: dict[str, float] = {}
        for field in (
            "src_events_5m",
            "src_unique_destinations_5m",
            "src_unique_ports_5m",
            "same_tuple_events_15m",
            "log_bytes",
            "log_elapsed_time",
        ):
            fit_values = [float(record.get(field) or 0.0) for record in fit]
            role_values = [float(record.get(field) or 0.0) for record in records]
            scale = max(_percentile(fit_values, 0.75) - _percentile(fit_values, 0.25), 1.0)
            numeric_shifts[field] = round(
                abs(median(role_values) - median(fit_values)) / scale,
                4,
            )
        maximum = max([*categorical.values(), *numeric_shifts.values()], default=0.0)
        output[name] = {
            "categorical_js_divergence": categorical,
            "numeric_robust_median_shift": numeric_shifts,
            "maximum_shift": round(maximum, 4),
            "status": "drift_warning" if maximum > 0.25 else "stable",
        }
    return {
        "roles": output,
        "distribution_drift_measured": True,
        "concept_drift_status": "not_measurable_without_private_labels",
        "private_labels_used": False,
    }


def _legacy_diagnosis(
    imports: tuple[Any, ...],
    artifact_path: Path,
    controlled: ControlledBundle,
    holdout: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    if not artifact_path.is_file():
        return {"status": "artifact_unavailable"}
    try:
        model = imports[0].load(artifact_path)
        controlled_frame = _frame(imports, controlled.records, "base")
        holdout_frame = _frame(imports, holdout, "base")
        controlled_flags = [int(value) == -1 for value in model.predict(controlled_frame)]
        holdout_flags = [int(value) == -1 for value in model.predict(holdout_frame)]
        holdout_scores = [
            -float(value) for value in model.decision_function(holdout_frame)
        ]
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {"status": "artifact_incompatible", "error_type": exc.__class__.__name__}

    windows = _window_names(holdout)
    by_window = _aggregate_groups(
        holdout,
        holdout_flags,
        holdout_scores,
        field="_ordinal",
        values=windows,
        limit=4,
    )
    window_rates = [float(item["queue_rate"]) for item in by_window]
    return {
        "status": "evaluated",
        "private_validation": {
            "rows_scored": len(holdout),
            "queue_count": sum(holdout_flags),
            "queue_rate": round(sum(holdout_flags) / len(holdout), 4) if holdout else 0.0,
            "queue_by_application_family": _aggregate_groups(
                holdout, holdout_flags, holdout_scores, field="application_family"
            ),
            "queue_by_action": _aggregate_groups(
                holdout, holdout_flags, holdout_scores, field="action_group"
            ),
            "queue_by_direction": _aggregate_groups(
                holdout, holdout_flags, holdout_scores, field="direction"
            ),
            "queue_by_schema": _aggregate_groups(
                holdout, holdout_flags, holdout_scores, field="schema_profile"
            ),
            "queue_by_time_window": by_window,
            "time_window_queue_rate_range": round(
                max(window_rates) - min(window_rates) if window_rates else 0.0,
                4,
            ),
            "behavior_concentration": _behavior_concentration(
                holdout,
                holdout_flags,
            ),
            "rule_contribution": _rule_contribution(holdout, holdout_flags),
        },
        "controlled_rule_contribution": _rule_contribution(
            controlled.records,
            controlled_flags,
        ),
        "artifact_modified": False,
    }


def _artifact_state(path: Path) -> tuple[bool, int, str | None]:
    if not path.is_file():
        return False, 0, None
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return True, path.stat().st_size, digest


def _safety_contract(*, artifact_unchanged: bool) -> dict[str, Any]:
    return {
        "rules_alert_authoritative": True,
        "isolation_forest_advisory_only": True,
        "hybrid_output_advisory_only": True,
        "supervised_state": "unqualified",
        "supervised_model_activated": False,
        "candidate_installed": False,
        "current_artifact_unchanged": artifact_unchanged,
        "model_driven_alerts": 0,
        "model_driven_suppressions": 0,
        "labels_created": 0,
        "model_runs_created": 0,
        "detection_runs_created": 0,
        "response_actions_created": 0,
        "response_state": "simulation_only",
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }


def _protocol() -> dict[str, Any]:
    return {
        "version": VERSION,
        "locked_before_candidate_comparison": True,
        "roles": ROLE_FRACTIONS,
        "duplicate_family_isolation": True,
        "grouping": ["application_family", "schema", "time_window"],
        "queue_targets": list(QUEUE_TARGETS),
        "strategies": list(STRATEGY_NAMES),
        "distinct_strategy_count": DISTINCT_STRATEGY_COUNT,
        "known_duplicate_strategies": dict(STRATEGY_KNOWN_DUPLICATES),
        "acceptance_gates": {
            "controlled_benign_anomaly_rate_max": CONTROLLED_BENIGN_RATE_MAX,
            "controlled_suspicious_scenario_recall_min": CONTROLLED_SUSPICIOUS_SCENARIO_RECALL_MIN,
            "controlled_malicious_scenario_recall_min": CONTROLLED_MALICIOUS_SCENARIO_RECALL_MIN,
            "private_queue_rate_min": PRIVATE_HOLDOUT_QUEUE_RATE_MIN,
            "private_queue_rate_max": PRIVATE_HOLDOUT_QUEUE_RATE_MAX,
            "private_window_queue_range_max": 0.05,
        },
        "selection_uses_untouched_holdout": False,
        "sealed_supervised_evidence_allowed": False,
        "candidate_installation_available": False,
    }


def run_window_aware_anomaly_redesign(
    *,
    sample_path: Path,
    limit: int = DEFAULT_LIMIT,
    preflight_only: bool = False,
    artifact_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    minimum_fit_rows: int = MINIMUM_FIT_ROWS,
) -> dict[str, Any]:
    imports = _optional_ml_imports()
    legacy_imports = _legacy_ml_imports()
    if imports is None or legacy_imports is None:
        raise WindowAwareAnomalyError(
            "ml_dependencies_unavailable",
            "ML dependencies are unavailable.",
        )
    configured_artifact = (artifact_path or get_settings().resolved_model_path).resolve()
    artifact_before = _artifact_state(configured_artifact)
    evidence = inspect_private_evidence(
        sample_path,
        limit=limit,
        minimum_fit_rows=minimum_fit_rows,
    )
    controlled = load_controlled_evidence(project_root=project_root)
    roles = _partition_roles(evidence, minimum_fit_rows=minimum_fit_rows)
    preflight_passed = bool(evidence.public["passed"] and roles.public["passed"])
    if preflight_only or not preflight_passed:
        artifact_after = _artifact_state(configured_artifact)
        unchanged = artifact_before == artifact_after
        return {
            "version": VERSION,
            "ok": preflight_passed,
            "status": "preflight_passed" if preflight_passed else "evidence_preflight_failed",
            "executed": False,
            "protocol": _protocol(),
            "evidence": evidence.public,
            "chronological_roles": roles.public,
            "controlled_evidence": controlled.public,
            "privacy": _privacy_contract(),
            "safety": _safety_contract(artifact_unchanged=unchanged),
        }

    current = _evaluate_current(
        legacy_imports,
        artifact_path=configured_artifact,
        controlled=controlled,  # type: ignore[arg-type]
        private_holdout=list(roles.validation),
    )
    current["private_comparison_role"] = "development_validation"
    legacy_diagnosis = _legacy_diagnosis(
        legacy_imports,
        configured_artifact,
        controlled,
        roles.validation,
    )
    strategies = _fit_strategies(imports, roles)
    reports: list[dict[str, Any]] = []
    strategy_by_name = {strategy.name: strategy for strategy in strategies}
    for strategy in strategies:
        for target in QUEUE_TARGETS:
            controlled_report = _evaluate_controlled(
                strategy,
                imports,
                controlled,
                target,
            )
            validation_report = _evaluate_private(
                strategy,
                imports,
                roles.validation,
                target,
            )
            gates = _candidate_gates(
                controlled_report,
                validation_report,
                fit_rows=len(roles.fit),
                minimum_fit_rows=minimum_fit_rows,
            )
            reports.append(
                {
                    "name": f"{strategy.name}_q{int(target * 100):02d}",
                    "strategy": strategy.name,
                    "feature_strategy": strategy.feature_kind,
                    "calibration_strategy": strategy.mode,
                    "queue_target": target,
                    "fit_rows": len(roles.fit),
                    "calibration_rows": len(roles.calibration),
                    "controlled": controlled_report,
                    "private_validation": validation_report,
                    "gates": gates,
                    "all_fixed_gates_passed": all(gates.values()),
                    "development_only": True,
                    "active_artifact_written": False,
                    "duplicate_of_strategy": STRATEGY_KNOWN_DUPLICATES.get(strategy.name),
                }
            )

    passing = [report for report in reports if report["all_fixed_gates_passed"]]
    validation_leader = max(passing, key=_rank) if passing else None
    improved = bool(validation_leader and _improves_current(validation_leader, current))
    frozen = validation_leader if improved else None
    holdout_report = None
    holdout_gates = None
    qualified = False
    if frozen is not None:
        strategy = strategy_by_name[str(frozen["strategy"])]
        holdout_report = _evaluate_private(
            strategy,
            imports,
            roles.untouched_holdout,
            float(frozen["queue_target"]),
        )
        holdout_gates = _candidate_gates(
            frozen["controlled"],
            holdout_report,
            fit_rows=len(roles.fit),
            minimum_fit_rows=minimum_fit_rows,
        )
        qualified = all(holdout_gates.values())

    best_diagnostic = max(reports, key=_rank) if reports else None
    artifact_after = _artifact_state(configured_artifact)
    artifact_unchanged = artifact_before == artifact_after
    selection = {
        "validation_candidates_passing": len(passing),
        "frozen_diagnostic_candidate": frozen["name"] if frozen else None,
        "untouched_holdout_evaluated": holdout_report is not None,
        "candidate_qualified": qualified,
        "candidate_selected": qualified,
        "candidate_name": frozen["name"] if qualified and frozen else None,
        "best_nonqualified_diagnostic": (
            best_diagnostic["name"] if best_diagnostic and not qualified else None
        ),
        "clearly_improves_current": improved,
        "eligible_for_install": False,
        "installed": False,
        "threat_accuracy_validated": False,
    }
    return {
        "version": VERSION,
        "ok": artifact_unchanged,
        "status": "diagnostic_candidate_qualified_not_installed" if qualified else "no_candidate_qualified",
        "executed": True,
        "protocol": _protocol(),
        "evidence": evidence.public,
        "chronological_roles": roles.public,
        "controlled_evidence": controlled.public,
        "drift": _drift_report(roles),
        "current_artifact": current,
        "legacy_instability_diagnosis": legacy_diagnosis,
        "candidate_comparison": reports,
        "selection": selection,
        "frozen_holdout_result": holdout_report,
        "frozen_holdout_gates": holdout_gates,
        "installation": {
            "available": False,
            "requested": False,
            "installed": False,
            "reason": "v5.64_is_diagnostic_only",
        },
        "reproducible_command": (
            "python -m atdr.scripts.run_v564_window_aware_anomaly_redesign "
            "--sample-path <private-log-file> --pretty"
        ),
        "privacy": _privacy_contract(),
        "safety": _safety_contract(artifact_unchanged=artifact_unchanged),
    }


def safe_window_aware_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, WindowAwareAnomalyError):
        code = exc.code
        message = str(exc)
    else:
        code = "window_aware_anomaly_failed_safely"
        message = (
            "Window-aware anomaly evaluation failed safely. No private evidence "
            "details were exposed."
        )
    return {
        "version": VERSION,
        "ok": False,
        "status": code,
        "message": message,
        "executed": False,
        "candidate_installed": False,
        "privacy": _privacy_contract(),
        "safety": _safety_contract(artifact_unchanged=True),
    }
