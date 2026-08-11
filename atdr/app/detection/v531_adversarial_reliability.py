from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import NormalizedLog, RawLog
from atdr.app.detection.rule_catalog import RULE_CATALOG, RULE_CATALOG_VERSION
from atdr.app.detection.rules import (
    build_detection_context,
    correlation_window_for_log,
    evaluate_rules,
)
from atdr.app.services.detection_service import (
    DetectionCandidate,
    _alert_authoritative_matches,
    _primary_rule,
    _result_from_matches,
    _should_create_group_alert,
    group_detection_candidates,
)


CORPUS_PATH = PROJECT_ROOT / "data" / "samples" / "scenarios" / "adversarial" / "v5_31_detection_corpus.json"
MIN_ALERT_SCORE = 30
BASE_TIME = datetime(2026, 8, 1, 10, 0, tzinfo=UTC)


def load_v531_corpus(path: Path = CORPUS_PATH) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != "v5.31.0" or not isinstance(payload.get("cases"), list):
        raise ValueError("Invalid v5.31 adversarial corpus contract.")
    return payload


def _offsets(params: dict[str, Any], count: int, *, interval_seconds: int = 10) -> list[int]:
    configured = params.get("offsets")
    if configured is not None:
        values = [int(value) for value in configured]
        if len(values) != count:
            raise ValueError("Adversarial case offsets must match event count.")
        return values
    return [index * interval_seconds for index in range(count)]


def _log(
    case_id: str,
    index: int,
    *,
    source_id: int,
    offset_seconds: int,
    src_ip: str = "203.0.113.10",
    dst_ip: str = "10.0.0.10",
    src_zone: str = "SG-Outside",
    dst_zone: str = "LAN-Inside",
    app: str | None = "unknown-tcp",
    app_category: str | None = "unknown",
    app_risk: int | None = 1,
    app_characteristic: str | None = None,
    dst_port: int | None = 445,
    action: str | None = "allow",
    protocol: str | None = "tcp",
    log_type: str | None = "TRAFFIC",
    subtype: str | None = "end",
    repeat_count: int = 1,
    bytes_value: int | None = 500,
    bytes_sent: int | None = 300,
    bytes_received: int | None = 200,
    packets: int | None = 5,
    parsed_json: dict[str, Any] | None = None,
) -> NormalizedLog:
    raw = RawLog(source_id=source_id, raw_line=f"synthetic-v531:{case_id}:{index}")
    return NormalizedLog(
        id=index + 1,
        raw_log=raw,
        generated_time=BASE_TIME + timedelta(seconds=offset_seconds),
        log_type=log_type,
        subtype=subtype,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_zone=src_zone,
        dst_zone=dst_zone,
        app=app,
        app_category=app_category,
        app_risk=app_risk,
        app_characteristic=app_characteristic,
        dst_port=dst_port,
        action=action,
        protocol=protocol,
        repeat_count=repeat_count,
        bytes=bytes_value,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        packets=packets,
        parsed_json=parsed_json or {},
    )


def build_case_logs(case: dict[str, Any]) -> list[NormalizedLog]:
    case_id = str(case["id"])
    pattern = str(case["pattern"])
    params = dict(case.get("params") or {})
    source_id = int(params.get("source_id", 1))

    if pattern == "vertical_scan":
        count = int(params["count"])
        offsets = _offsets(params, count)
        return [
            _log(case_id, index, source_id=source_id, offset_seconds=offsets[index], dst_port=10_000 + index)
            for index in range(count)
        ]
    if pattern == "missing_time_vertical_scan":
        count = int(params["count"])
        logs = [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=index * 10,
                dst_port=10_000 + index,
            )
            for index in range(count)
        ]
        for log in logs:
            log.generated_time = None
        return logs
    if pattern == "separate_vertical_scan_windows":
        count_per_window = int(params.get("count_per_window", 10))
        separation_seconds = int(params.get("separation_seconds", 3_600))
        logs: list[NormalizedLog] = []
        for window_index in range(2):
            for index in range(count_per_window):
                global_index = (window_index * count_per_window) + index
                logs.append(
                    _log(
                        case_id,
                        global_index,
                        source_id=source_id,
                        offset_seconds=(window_index * separation_seconds) + (index * 10),
                        dst_port=10_000 + global_index,
                    )
                )
        return logs
    if pattern == "horizontal_scan":
        count = int(params["count"])
        offsets = _offsets(params, count)
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=offsets[index],
                dst_ip=f"10.0.1.{index + 1}",
                dst_port=int(params.get("port", 445)),
                action=str(params.get("action", "deny")),
                protocol=str(params.get("protocol", "tcp")),
            )
            for index in range(count)
        ]
    if pattern == "web_fanout":
        count = int(params["count"])
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=index * 10,
                src_ip="10.0.0.20",
                dst_ip=f"198.51.100.{index + 1}",
                src_zone="LAN-Inside",
                dst_zone="SG-Outside",
                app="ssl",
                app_category="general-internet",
                app_risk=2,
                dst_port=443,
            )
            for index in range(count)
        ]
    if pattern == "auth_denies":
        count = int(params["count"])
        vary_targets = bool(params.get("vary_targets"))
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=index * 10,
                dst_ip=f"10.0.2.{index + 1}" if vary_targets else "10.0.2.10",
                app="ssh",
                app_category="remote-access",
                dst_port=22,
                action="deny",
            )
            for index in range(count)
        ]
    if pattern == "beacon":
        offsets = [int(value) for value in params["offsets"]]
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=offset,
                src_ip="10.0.0.30",
                dst_ip="198.51.100.30",
                src_zone="LAN-Inside",
                dst_zone="SG-Outside",
                app="unknown-tcp",
                app_category="unknown",
                app_risk=5,
                app_characteristic="used-by-malware",
                dst_port=4444,
            )
            for index, offset in enumerate(offsets)
        ]
    if pattern == "flood":
        count = int(params["count"])
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=index,
                dst_ip="10.0.3.10",
                app="ssl",
                app_category="general-internet",
                app_risk=2,
                dst_port=443,
                action=str(params.get("action", "allow")),
                repeat_count=int(params.get("repeat_count", 1)),
            )
            for index in range(count)
        ]
    if pattern == "normal_repeated":
        count = int(params["count"])
        port = int(params["port"])
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=index * 5,
                src_ip="10.0.0.40",
                dst_ip="198.51.100.40",
                src_zone="LAN-Inside",
                dst_zone="SG-Outside",
                app=str(params["app"]),
                app_category="general-internet",
                app_risk=2,
                dst_port=port,
                protocol="icmp" if port == 0 else "udp",
            )
            for index in range(count)
        ]
    if pattern == "threat":
        severity = str(params["severity"])
        return [
            _log(
                case_id,
                0,
                source_id=source_id,
                offset_seconds=0,
                src_ip="10.0.0.50",
                dst_ip="198.51.100.50",
                src_zone="LAN-Inside",
                dst_zone="SG-Outside",
                app="ssl",
                app_category="general-internet",
                app_risk=2,
                dst_port=443,
                log_type="THREAT",
                subtype="vulnerability",
                parsed_json={
                    "parsed_threat_severity": severity,
                    "parsed_threat_name": str(params["threat_name"]),
                },
            )
        ]
    if pattern == "source_isolation":
        count = int(params["count_per_source"])
        logs: list[NormalizedLog] = []
        for source_offset, registered_source_id in enumerate((1, 2)):
            for index in range(count):
                global_index = (source_offset * count) + index
                logs.append(
                    _log(
                        case_id,
                        global_index,
                        source_id=registered_source_id,
                        offset_seconds=index * 10,
                        dst_port=10_000 + global_index,
                    )
                )
        return logs
    if pattern == "duplicate_port":
        count = int(params["count"])
        return [
            _log(
                case_id,
                index,
                source_id=source_id,
                offset_seconds=index * 10,
                dst_ip="10.0.4.10",
                dst_port=445,
                action="allow",
            )
            for index in range(count)
        ]
    if pattern == "context_singleton":
        return [_log(case_id, 0, source_id=source_id, offset_seconds=0, dst_port=4040)]
    if pattern == "exfil_volume":
        return [
            _log(
                case_id,
                0,
                source_id=source_id,
                offset_seconds=0,
                src_ip="10.0.0.60",
                dst_ip="198.51.100.60",
                src_zone="LAN-Inside",
                dst_zone="SG-Outside",
                app="ssl",
                app_category="general-internet",
                app_risk=2,
                dst_port=443,
                bytes_sent=int(params["bytes_sent"]),
                bytes_received=int(params["bytes"]) - int(params["bytes_sent"]),
                bytes_value=int(params["bytes"]),
            )
        ]
    if pattern == "inbound_volume":
        return [
            _log(
                case_id,
                0,
                source_id=source_id,
                offset_seconds=0,
                src_ip="198.51.100.70",
                dst_ip="10.0.0.70",
                src_zone="SG-Outside",
                dst_zone="LAN-Inside",
                app="ssl",
                app_category="general-internet",
                app_risk=2,
                dst_port=443,
                bytes_sent=int(params["bytes_sent"]),
                bytes_received=int(params["bytes"]),
                bytes_value=int(params["bytes"]),
            )
        ]
    if pattern == "degraded":
        return [
            _log(
                case_id,
                0,
                source_id=source_id,
                offset_seconds=0,
                src_ip="",
                dst_ip="",
                src_zone="",
                dst_zone="",
                app=None,
                app_category="unknown",
                app_risk=None,
                dst_port=None,
                action=None,
                protocol=None,
                bytes_value=None,
                bytes_sent=None,
                bytes_received=None,
                packets=None,
                parsed_json={"parser_warnings": ["synthetic missing-field validation"]},
            )
        ]
    raise ValueError(f"Unknown v5.31 adversarial pattern: {pattern}")


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    logs = build_case_logs(case)
    context = build_detection_context(logs)
    observed_codes: set[str] = set()
    candidates: list[DetectionCandidate] = []
    for log in logs:
        matches = evaluate_rules(log, context)
        observed_codes.update(match.code for match in matches)
        authoritative = _alert_authoritative_matches(matches)
        if not authoritative:
            continue
        result = _result_from_matches(matches, scoring_matches=authoritative)
        if result.threat_score >= MIN_ALERT_SCORE:
            candidates.append(
                DetectionCandidate(
                    log=log,
                    result=result,
                    primary_rule=_primary_rule(authoritative),
                    correlation_window=correlation_window_for_log(log, context),
                )
            )
    groups = group_detection_candidates(candidates)
    alert_groups = [group for group in groups.values() if _should_create_group_alert(group)]
    expected_present = set(case.get("expected_present") or [])
    expected_absent = set(case.get("expected_absent") or [])
    missing_rules = sorted(expected_present - observed_codes)
    unexpected_rules = sorted(expected_absent & observed_codes)
    expected_alert_count = case.get("expected_alert_count")
    alert_count_matches = expected_alert_count is None or len(alert_groups) == int(expected_alert_count)
    passed = not missing_rules and not unexpected_rules and alert_count_matches
    return {
        "id": str(case["id"]),
        "category": str(case["category"]),
        "event_count": len(logs),
        "expected_present": sorted(expected_present),
        "expected_absent": sorted(expected_absent),
        "observed_rules": sorted(observed_codes),
        "missing_expected_rules": missing_rules,
        "unexpected_rules": unexpected_rules,
        "expected_alert_count": expected_alert_count,
        "actual_alert_count": len(alert_groups),
        "alert_count_matches": alert_count_matches,
        "passed": passed,
    }


def run_v531_adversarial_reliability(path: Path = CORPUS_PATH) -> dict[str, Any]:
    corpus = load_v531_corpus(path)
    cases = [evaluate_case(case) for case in corpus["cases"]]
    categories = Counter(item["category"] for item in cases)
    false_negatives = [
        item["id"]
        for item in cases
        if item["missing_expected_rules"]
        or (
            item["expected_alert_count"] is not None
            and int(item["expected_alert_count"]) > 0
            and item["actual_alert_count"] == 0
        )
    ]
    false_positives = [
        item["id"]
        for item in cases
        if item["unexpected_rules"]
        or (
            item["expected_alert_count"] == 0
            and item["actual_alert_count"] > 0
        )
    ]
    false_negative_rules = Counter(
        rule
        for item in cases
        for rule in item["missing_expected_rules"]
    )
    false_positive_rules = Counter(
        rule
        for item in cases
        for rule in item["unexpected_rules"]
    )
    near_miss_negative_cases = [
        item
        for item in cases
        if item["category"] in {"near_miss", "negative"}
    ]
    boundary_cases = [item for item in cases if item["category"] == "boundary"]
    source_isolation_cases = [
        item
        for item in cases
        if item["category"] == "multi_source"
    ]
    duplicate_cases = [item for item in cases if item["category"] == "duplicate"]
    observed_rule_codes = sorted({code for item in cases for code in item["observed_rules"]})
    return {
        "ok": all(item["passed"] for item in cases),
        "version": corpus["version"],
        "rule_catalog_version": RULE_CATALOG_VERSION,
        "uses_configured_database": False,
        "synthetic_only": True,
        "minimum_alert_score": MIN_ALERT_SCORE,
        "case_count": len(cases),
        "passed_count": sum(1 for item in cases if item["passed"]),
        "category_counts": dict(sorted(categories.items())),
        "false_positive_case_count": len(false_positives),
        "false_positive_cases": false_positives,
        "false_positives_by_rule": dict(sorted(false_positive_rules.items())),
        "false_negative_case_count": len(false_negatives),
        "false_negative_cases": false_negatives,
        "false_negatives_by_rule": dict(sorted(false_negative_rules.items())),
        "near_miss_negative_accuracy": round(
            sum(1 for item in near_miss_negative_cases if item["passed"])
            / max(len(near_miss_negative_cases), 1),
            4,
        ),
        "timing_boundary_correct": bool(boundary_cases)
        and all(item["passed"] for item in boundary_cases),
        "source_isolation_correct": bool(source_isolation_cases)
        and all(item["passed"] for item in source_isolation_cases),
        "duplicate_handling_correct": bool(duplicate_cases)
        and all(item["passed"] for item in duplicate_cases),
        "observed_rule_count": len(observed_rule_codes),
        "catalog_rule_count": len(RULE_CATALOG),
        "observed_rule_codes": observed_rule_codes,
        "cases": cases,
        "safety": {
            "labels_written": 0,
            "models_trained_or_activated": 0,
            "response_actions_created": 0,
            "real_firewall_actions": 0,
            "automatic_response_enabled": False,
            "rule_detection_authoritative": True,
            "isolation_forest_advisory_only": True,
            "supervised_ml_advisory_only": True,
        },
    }
