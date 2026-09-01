from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.parsers.paloalto_contract import (
    PARSER_CONTRACT_VERSION,
    required_field_names,
)
from atdr.app.parsers.paloalto_parser import ParsedPaloAltoLog, parse_log_line
from atdr.app.services import detection_service as detection
from atdr.app.services.v523_live_source_acceptance_service import (
    run_v523_live_source_acceptance,
)


V551_VERSION = "v5.51-detection-field-qualification-v1"
V551_FRESH_EVIDENCE_PROTOCOL = "v5.51-post-v5.49b-fresh-evidence-v1"
V551_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_51_field_qualification"
V551_LATEST = "v5_51_field_qualification_latest.json"
V551_PRIVATE_MANIFEST = "v5_51_fresh_evidence_private_manifest.json"
V551_REVIEW_PACK = "v5_51_prediction_blind_rule_review.csv"
V551_PREDICTION_SEAL = "v5_51_private_rule_prediction_seal.json"

# v5.49b was already consumed and publicly closed by the v5.50 truth lock on
# 2026-08-31. New evidence must begin on the next Bangkok calendar day. This
# public boundary avoids reading any protected v5.49b row, claim, or result.
FRESH_EVIDENCE_NOT_BEFORE = datetime.fromisoformat("2026-09-01T00:00:00+07:00").astimezone(UTC)

READINESS_STATUSES = {
    "ready",
    "hardware_required",
    "reviewer_required",
    "failed",
    "insufficient_evidence",
}
ROLE_NAMES = (
    "development_fit",
    "calibration",
    "threshold",
    "untouched_future_evaluation",
)
MINIMUM_FRESH_ROWS = 240
MINIMUM_FUTURE_ROWS = 40
MINIMUM_SOURCE_COUNT = 2
MINIMUM_WINDOW_COUNT = 4
MINIMUM_REVIEWED_ROWS = 40
MAX_ROWS_LIMIT = 100_000

_AI_REVIEWER_PATTERN = re.compile(
    r"(?:assistant|automated|bot|chatgpt|claude|codex|gemini|heuristic|llm|model|openai|synthetic)",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_ALLOWED_EXPECTATION_FIELDS = frozenset(
    {
        "log_type",
        "subtype",
        "app",
        "action",
        "protocol",
        "src_port",
        "dst_port",
        "src_zone",
        "dst_zone",
        "bytes",
        "packets",
        "app_risk",
        "generated_time_present",
        "high_res_timestamp_present",
        "parsed_threat_severity",
        "system_event_id",
        "system_module",
        "system_severity",
    }
)
_ALLOWED_HUMAN_DECISIONS = frozenset(
    {"benign", "benign_unusual", "needs_context", "suspicious", "malicious"}
)


class V551QualificationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as stream:
            temporary_name = stream.name
            json.dump(payload, stream, indent=2, sort_keys=True, default=str)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V551QualificationError("A private v5.51 input failed integrity validation.") from exc
    if not isinstance(payload, dict):
        raise V551QualificationError("A private v5.51 input failed integrity validation.")
    return payload


def _private_manifest_default() -> dict[str, Any]:
    return {
        "schema_version": V551_FRESH_EVIDENCE_PROTOCOL,
        "created_at": _now(),
        "updated_at": _now(),
        "token_salt": os.urandom(32).hex(),
        "collections": {},
        "protected_v549b_accessed": False,
        "raw_logs_included": False,
        "predictions_exposed_to_reviewers": False,
    }


def _load_private_manifest(output_dir: Path) -> dict[str, Any]:
    path = output_dir / V551_PRIVATE_MANIFEST
    if not path.is_file():
        return _private_manifest_default()
    manifest = _read_json(path)
    if manifest.get("schema_version") != V551_FRESH_EVIDENCE_PROTOCOL:
        raise V551QualificationError("The private v5.51 evidence manifest has an unsupported version.")
    if manifest.get("protected_v549b_accessed") is not False:
        raise V551QualificationError("The private v5.51 evidence boundary is invalid.")
    if not isinstance(manifest.get("collections"), dict):
        raise V551QualificationError("The private v5.51 evidence manifest is malformed.")
    return manifest


def _validate_human_identity(value: Any) -> bool:
    reviewer = str(value or "").strip()
    return bool(reviewer and not _AI_REVIEWER_PATTERN.search(reviewer))


def _validate_source_attestation(
    path: Path | None,
    *,
    source_name: str,
    collection_window: str,
    source_kind: str,
) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {
            "valid": False,
            "status": "source_attestation_missing",
            "identity_returned": False,
        }
    try:
        value = _read_json(path)
    except V551QualificationError:
        return {
            "valid": False,
            "status": "source_attestation_invalid",
            "identity_returned": False,
        }
    attested_at = _parse_timestamp(value.get("attested_at"))
    collection_started = _parse_timestamp(value.get("collection_started_at"))
    valid = bool(
        value.get("schema_version") == "v5.51-source-attestation-v1"
        and source_kind in {"firewall", "router"}
        and value.get("physical_device_confirmed") is True
        and str(value.get("source_kind") or "").strip().lower() == source_kind
        and str(value.get("source_name") or "").strip() == source_name
        and str(value.get("collection_window") or "").strip() == collection_window
        and _validate_human_identity(value.get("attested_by"))
        and attested_at is not None
        and collection_started is not None
        and collection_started >= FRESH_EVIDENCE_NOT_BEFORE
    )
    return {
        "valid": valid,
        "status": "physical_source_attested" if valid else "source_attestation_invalid",
        "physical_device_confirmed": valid,
        "fresh_collection_attested": bool(
            collection_started is not None
            and collection_started >= FRESH_EVIDENCE_NOT_BEFORE
        ),
        "identity_returned": False,
    }


def _expectation_value(parsed: ParsedPaloAltoLog, field: str) -> Any:
    if field == "generated_time_present":
        return parsed.normalized.get("generated_time") is not None
    if field == "high_res_timestamp_present":
        return parsed.normalized.get("high_res_timestamp") is not None
    if field in {"parsed_threat_severity", "system_event_id", "system_module", "system_severity"}:
        return parsed.parsed_json.get(field)
    return parsed.normalized.get(field)


def _validate_field_expectations(
    path: Path | None,
    *,
    source_name: str,
    parsed_by_line: dict[int, ParsedPaloAltoLog],
) -> dict[str, Any]:
    base = {
        "available": False,
        "valid": False,
        "status": "human_field_expectations_required",
        "rows_checked": 0,
        "fields_checked": 0,
        "fields_matched": 0,
        "fields_mismatched": 0,
        "accuracy": None,
        "log_types_checked": [],
        "human_confirmed": False,
        "values_returned": False,
        "identity_returned": False,
    }
    if path is None or not path.is_file():
        return base
    try:
        value = _read_json(path)
    except V551QualificationError:
        return {**base, "available": True, "status": "field_expectations_invalid"}
    rows = value.get("rows")
    metadata_valid = bool(
        value.get("schema_version") == "v5.51-field-expectations-v1"
        and value.get("independent_human_confirmed") is True
        and str(value.get("source_name") or "").strip() == source_name
        and _validate_human_identity(value.get("reviewed_by"))
        and _parse_timestamp(value.get("reviewed_at")) is not None
        and isinstance(rows, list)
        and rows
    )
    if not metadata_valid:
        return {**base, "available": True, "status": "field_expectations_invalid"}

    matched = mismatched = checked_rows = 0
    log_types: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            mismatched += 1
            continue
        try:
            line_number = int(row.get("line_number") or 0)
        except (TypeError, ValueError):
            line_number = 0
        expected = row.get("expected")
        parsed = parsed_by_line.get(line_number)
        if parsed is None or not isinstance(expected, dict) or not expected:
            mismatched += 1
            continue
        if any(field not in _ALLOWED_EXPECTATION_FIELDS for field in expected):
            mismatched += len(expected)
            continue
        checked_rows += 1
        log_type = str(parsed.normalized.get("log_type") or "").upper()
        if log_type:
            log_types.add(log_type)
        for field, expected_value in expected.items():
            actual = _expectation_value(parsed, field)
            if actual == expected_value:
                matched += 1
            else:
                mismatched += 1
    total = matched + mismatched
    valid = bool(checked_rows > 0 and total >= 8 and mismatched == 0)
    return {
        **base,
        "available": True,
        "valid": valid,
        "status": "field_accuracy_confirmed" if valid else "field_accuracy_not_confirmed",
        "rows_checked": checked_rows,
        "fields_checked": total,
        "fields_matched": matched,
        "fields_mismatched": mismatched,
        "accuracy": round(matched / total, 4) if total else None,
        "log_types_checked": sorted(log_types),
        "human_confirmed": True,
    }


def _event_time(parsed: ParsedPaloAltoLog) -> datetime | None:
    for key in ("generated_time", "receive_time", "high_res_timestamp", "start_time"):
        if value := _parse_timestamp(parsed.normalized.get(key)):
            return value
    return _parse_timestamp(parsed.syslog_timestamp)


def _near_projection(parsed: ParsedPaloAltoLog, event_time: datetime | None) -> dict[str, Any]:
    normalized = parsed.normalized
    minute = event_time.replace(second=0, microsecond=0).isoformat() if event_time else None
    return {
        "minute": minute,
        "log_type": normalized.get("log_type"),
        "subtype": normalized.get("subtype"),
        "source": _stable_hash(normalized.get("src_ip"))[:20],
        "destination": _stable_hash(normalized.get("dst_ip"))[:20],
        "app": normalized.get("app"),
        "action": normalized.get("action"),
        "protocol": normalized.get("protocol"),
        "destination_port": normalized.get("dst_port"),
        "source_zone": normalized.get("src_zone"),
        "destination_zone": normalized.get("dst_zone"),
    }


def _detection_record(parsed: ParsedPaloAltoLog, row_id: int) -> detection.DetectionLogRecord:
    value = parsed.normalized
    return detection.DetectionLogRecord(
        id=row_id,
        source_id=1,
        generated_time=value.get("generated_time"),
        receive_time=value.get("receive_time"),
        high_res_timestamp=value.get("high_res_timestamp"),
        start_time=value.get("start_time"),
        log_type=value.get("log_type"),
        subtype=value.get("subtype"),
        src_ip=value.get("src_ip"),
        dst_ip=value.get("dst_ip"),
        src_zone=value.get("src_zone"),
        dst_zone=value.get("dst_zone"),
        app=value.get("app"),
        app_category=value.get("app_category"),
        app_risk=value.get("app_risk"),
        app_characteristic=value.get("app_characteristic"),
        dst_port=value.get("dst_port"),
        action=value.get("action"),
        protocol=value.get("protocol"),
        bytes=value.get("bytes"),
        bytes_sent=value.get("bytes_sent"),
        bytes_received=value.get("bytes_received"),
        packets=value.get("packets"),
        repeat_count=value.get("repeat_count"),
        session_end_reason=value.get("session_end_reason"),
        action_source=value.get("action_source"),
        parsed_json={
            key: parsed.parsed_json.get(key)
            for key in (
                "parsed_threat_name",
                "parsed_threat_severity",
                "parsed_threat_direction",
            )
            if parsed.parsed_json.get(key) is not None
        },
        is_anomaly=False,
    )


def _safe_review_evidence(parsed: ParsedPaloAltoLog) -> dict[str, Any]:
    value = parsed.normalized
    event_time = _event_time(parsed)
    return {
        "event_time": event_time.isoformat() if event_time else "",
        "log_type": value.get("log_type") or "",
        "subtype": value.get("subtype") or "",
        "application": value.get("app") or "",
        "action": value.get("action") or "",
        "protocol": value.get("protocol") or "",
        "destination_port": value.get("dst_port") if value.get("dst_port") is not None else "",
        "source_zone": value.get("src_zone") or "",
        "destination_zone": value.get("dst_zone") or "",
        "application_risk": value.get("app_risk") if value.get("app_risk") is not None else "",
        "threat_severity": parsed.parsed_json.get("parsed_threat_severity") or "",
        "parser_status": parsed.parsed_json.get("parse_status") or "",
    }


def _rule_diagnostics(
    rows: list[tuple[int, str, ParsedPaloAltoLog]],
    *,
    review_limit: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    records = [_detection_record(parsed, line_number) for line_number, _raw, parsed in rows]
    if not records:
        return (
            {
                "rows_evaluated": 0,
                "rule_match_rows": 0,
                "alert_eligible_rows": 0,
                "alert_eligible_groups": 0,
                "rule_match_counts": {},
                "field_precision_recall_available": False,
            },
            [],
            [],
        )
    context = build_detection_context(records)
    candidates: list[detection.DetectionCandidate] = []
    rule_counts: Counter[str] = Counter()
    matched_by_id: dict[int, list[str]] = {}
    scores_by_id: dict[int, int] = {}
    for record in records:
        matches = evaluate_rules(record, context)
        if not matches:
            continue
        rule_counts.update(match.code for match in matches)
        result = detection._result_from_matches(matches)
        primary = detection._primary_rule(matches)
        candidates.append(
            detection.DetectionCandidate(
                log=record,
                result=result,
                primary_rule=primary,
                correlation_window=detection.correlation_window_for_log(record, context),
            )
        )
        matched_by_id[record.id] = [match.code for match in matches]
        scores_by_id[record.id] = int(result.threat_score)

    grouped = detection.group_detection_candidates(candidates)
    eligible_groups = [items for items in grouped.values() if detection._should_create_group_alert(items)]
    alert_ids = {
        int(candidate.log.id)
        for items in eligible_groups
        for candidate in items
    }

    flagged = [item for item in rows if item[0] in alert_ids]
    unflagged = [item for item in rows if item[0] not in alert_ids]
    selected: list[tuple[int, str, ParsedPaloAltoLog]] = []
    while len(selected) < review_limit and (flagged or unflagged):
        if flagged:
            selected.append(flagged.pop(0))
        if len(selected) < review_limit and unflagged:
            selected.append(unflagged.pop(0))

    review_rows: list[dict[str, Any]] = []
    seals: list[dict[str, Any]] = []
    for line_number, raw_line, parsed in selected:
        token = _stable_hash({"contract": V551_VERSION, "raw": raw_line})[:24]
        review_rows.append(
            {
                "review_token": token,
                **_safe_review_evidence(parsed),
                "human_decision": "",
                "human_confidence": "",
                "human_rationale": "",
                "human_attack_type": "",
                "human_reviewer": "",
                "human_reviewed_at": "",
                "independent_human_confirmed": False,
                "human_must_confirm": True,
                "human_reviewed": False,
                "prediction_blind": True,
                "import_ready": False,
            }
        )
        seals.append(
            {
                "review_token": token,
                "rule_alert_eligible": line_number in alert_ids,
                "rule_codes": matched_by_id.get(line_number, []),
                "rule_score": scores_by_id.get(line_number, 0),
                "human_labels_included": False,
            }
        )

    return (
        {
            "rows_evaluated": len(records),
            "rule_match_rows": len(candidates),
            "alert_eligible_rows": len(alert_ids),
            "alert_eligible_groups": len(eligible_groups),
            "rule_match_counts": dict(sorted(rule_counts.items())),
            "field_precision_recall_available": False,
        },
        review_rows,
        seals,
    )


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read_review(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        return [dict(row) for row in reader], list(reader.fieldnames or [])


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _validate_rule_review(
    path: Path | None,
    *,
    seals: list[dict[str, Any]],
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "available": False,
        "complete": False,
        "status": "human_rule_review_required",
        "reviewed_rows": 0,
        "invalid_rows": 0,
        "class_support": {"benign_like": 0, "needs_context": 0, "threat_positive": 0},
        "metrics_available": False,
        "precision": None,
        "recall": None,
        "f1": None,
        "false_positive_rate": None,
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
        "predictions_exposed": False,
        "identity_returned": False,
    }
    if path is None or not path.is_file():
        return base
    try:
        rows, columns = _read_review(path)
    except (OSError, csv.Error):
        return {**base, "available": True, "status": "rule_review_invalid"}
    forbidden = {
        column
        for column in columns
        if any(token in column.lower() for token in ("prediction", "rule_code", "rule_score", "model"))
        and column != "prediction_blind"
    }
    seal_by_token = {str(item["review_token"]): item for item in seals}
    decisions: list[tuple[bool, bool]] = []
    invalid = 0
    class_support = Counter[str]()
    seen: set[str] = set()
    for row in rows:
        token = str(row.get("review_token") or "").strip()
        decision = str(row.get("human_decision") or "").strip().lower()
        attack_type = str(row.get("human_attack_type") or "").strip()
        reviewer = str(row.get("human_reviewer") or "").strip()
        rationale = str(row.get("human_rationale") or "").strip()
        try:
            confidence = int(row.get("human_confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0
        valid = bool(
            token in seal_by_token
            and token not in seen
            and decision in _ALLOWED_HUMAN_DECISIONS
            and (
                decision not in {"suspicious", "malicious"}
                or bool(attack_type)
            )
            and _validate_human_identity(reviewer)
            and len(rationale) >= 8
            and 1 <= confidence <= 100
            and _parse_timestamp(row.get("human_reviewed_at")) is not None
            and _boolean(row.get("independent_human_confirmed"))
            and _boolean(row.get("human_must_confirm"))
            and _boolean(row.get("human_reviewed"))
            and _boolean(row.get("prediction_blind"))
            and not _boolean(row.get("import_ready"))
        )
        if not valid:
            invalid += 1
            continue
        seen.add(token)
        actual_positive = decision in {"suspicious", "malicious"}
        predicted_positive = bool(seal_by_token[token]["rule_alert_eligible"])
        decisions.append((actual_positive, predicted_positive))
        if actual_positive:
            class_support["threat_positive"] += 1
        elif decision == "needs_context":
            class_support["needs_context"] += 1
        else:
            class_support["benign_like"] += 1

    complete = bool(
        not forbidden
        and invalid == 0
        and len(decisions) == len(seals)
        and len(decisions) >= MINIMUM_REVIEWED_ROWS
    )
    tp = sum(actual and predicted for actual, predicted in decisions)
    fp = sum(not actual and predicted for actual, predicted in decisions)
    fn = sum(actual and not predicted for actual, predicted in decisions)
    tn = sum(not actual and not predicted for actual, predicted in decisions)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        **base,
        "available": True,
        "complete": complete,
        "status": "rule_review_complete" if complete else "rule_review_incomplete",
        "reviewed_rows": len(decisions),
        "invalid_rows": invalid + len(forbidden),
        "class_support": {
            key: int(class_support.get(key) or 0)
            for key in ("benign_like", "needs_context", "threat_positive")
        },
        "metrics_available": complete,
        "precision": round(precision, 4) if complete else None,
        "recall": round(recall, 4) if complete else None,
        "f1": round(f1, 4) if complete else None,
        "false_positive_rate": round(fpr, 4) if complete else None,
        "true_positives": tp if complete else 0,
        "false_positives": fp if complete else 0,
        "false_negatives": fn if complete else 0,
        "true_negatives": tn if complete else 0,
    }


def _analyze_sample(path: Path, *, max_rows: int, review_limit: int) -> dict[str, Any]:
    observed = parsed_count = failed_count = blank_count = 0
    parsed_by_line: dict[int, ParsedPaloAltoLog] = {}
    rule_rows: list[tuple[int, str, ParsedPaloAltoLog]] = []
    layout_counts: Counter[str] = Counter()
    log_type_counts: Counter[str] = Counter()
    exact_counts: Counter[str] = Counter()
    near_counts: Counter[str] = Counter()
    fresh_records: list[dict[str, Any]] = []
    required_missing: Counter[str] = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if observed >= max_rows:
                break
            raw_line = raw_line.rstrip("\r\n")
            if not raw_line.strip():
                blank_count += 1
                continue
            observed += 1
            exact_hash = _stable_hash(raw_line)
            exact_counts[exact_hash] += 1
            parsed = parse_log_line(raw_line)
            parsed_by_line[line_number] = parsed
            if parsed.error is not None:
                failed_count += 1
                continue
            parsed_count += 1
            compatibility = parsed.parsed_json.get("parser_compatibility") or {}
            layout_counts[str(compatibility.get("status") or "unknown")] += 1
            log_type = str(parsed.normalized.get("log_type") or "UNKNOWN").upper()
            log_type_counts[log_type] += 1
            for field in required_field_names(log_type):
                if parsed.normalized.get(field) in {None, ""}:
                    required_missing[field] += 1
            event_time = _event_time(parsed)
            near_hash = _stable_hash(_near_projection(parsed, event_time))
            near_counts[near_hash] += 1
            if log_type in {"TRAFFIC", "THREAT"}:
                rule_rows.append((line_number, raw_line, parsed))
            if event_time is not None and event_time >= FRESH_EVIDENCE_NOT_BEFORE:
                fresh_records.append(
                    {
                        "event_time": event_time.isoformat(),
                        "exact_hash": exact_hash,
                        "near_hash": near_hash,
                    }
                )

    diagnostics, review_rows, seals = _rule_diagnostics(
        rule_rows,
        review_limit=min(max(0, review_limit), 500),
    )
    accounted = parsed_count + failed_count == observed
    return {
        "observed_rows": observed,
        "parsed_rows": parsed_count,
        "failed_rows": failed_count,
        "blank_rows": blank_count,
        "parse_success_rate": round(parsed_count / observed, 4) if observed else 0.0,
        "rows_accounted": accounted,
        "layout_counts": dict(sorted(layout_counts.items())),
        "log_type_counts": dict(sorted(log_type_counts.items())),
        "required_field_missing_counts": dict(sorted(required_missing.items())),
        "exact_duplicate_rows": sum(count - 1 for count in exact_counts.values() if count > 1),
        "near_duplicate_rows": sum(count - 1 for count in near_counts.values() if count > 1),
        "unique_exact_families": len(exact_counts),
        "unique_near_families": len(near_counts),
        "fresh_records": fresh_records,
        "parsed_by_line": parsed_by_line,
        "rule_diagnostics": diagnostics,
        "review_rows": review_rows,
        "prediction_seals": seals,
        "truncated": observed >= max_rows,
    }


def _role_for_fraction(value: float) -> str:
    if value < 0.60:
        return ROLE_NAMES[0]
    if value < 0.75:
        return ROLE_NAMES[1]
    if value < 0.90:
        return ROLE_NAMES[2]
    return ROLE_NAMES[3]


def _fresh_evidence_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    collections = list((manifest.get("collections") or {}).values())
    records: list[dict[str, Any]] = []
    source_tokens: set[str] = set()
    window_tokens: set[str] = set()
    pre_boundary_excluded = 0
    missing_time_excluded = 0
    field_qualified_collections = 0
    reviewed_collections = 0
    reviewed_rows = 0
    for collection in collections:
        if not isinstance(collection, dict):
            continue
        source_tokens.add(str(collection.get("source_token") or ""))
        window_tokens.add(str(collection.get("window_token") or ""))
        pre_boundary_excluded += int(collection.get("pre_boundary_rows_excluded") or 0)
        missing_time_excluded += int(collection.get("missing_time_rows_excluded") or 0)
        field_qualified_collections += int(collection.get("field_accuracy_confirmed") is True)
        reviewed_collections += int(collection.get("rule_review_complete") is True)
        reviewed_rows += int(collection.get("reviewed_rows") or 0)
        records.extend(
            record
            for record in collection.get("records") or []
            if isinstance(record, dict)
            and _parse_timestamp(record.get("event_time")) is not None
            and _parse_timestamp(record.get("event_time")) >= FRESH_EVIDENCE_NOT_BEFORE
        )

    unique_records: list[dict[str, Any]] = []
    seen_exact: set[str] = set()
    exact_duplicates = 0
    for record in sorted(records, key=lambda item: str(item.get("event_time") or "")):
        exact_hash = str(record.get("exact_hash") or "")
        if not exact_hash or exact_hash in seen_exact:
            exact_duplicates += 1
            continue
        seen_exact.add(exact_hash)
        unique_records.append(record)

    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in unique_records:
        families[str(record.get("near_hash") or "missing")].append(record)
    ordered_families = sorted(
        families.values(),
        key=lambda group: min(str(item.get("event_time") or "") for item in group),
    )
    role_counts = Counter[str]()
    role_family_counts = Counter[str]()
    for index, family in enumerate(ordered_families):
        fraction = index / max(1, len(ordered_families))
        role = _role_for_fraction(fraction)
        role_counts[role] += len(family)
        role_family_counts[role] += 1

    source_tokens.discard("")
    window_tokens.discard("")
    return {
        "protocol_version": V551_FRESH_EVIDENCE_PROTOCOL,
        "public_boundary": FRESH_EVIDENCE_NOT_BEFORE.isoformat(),
        "protected_v549b_accessed": False,
        "temporal_namespace_disjoint": all(
            _parse_timestamp(record.get("event_time")) >= FRESH_EVIDENCE_NOT_BEFORE
            for record in unique_records
        ),
        "v549b_overlap_rows_admitted": 0,
        "pre_boundary_rows_excluded": pre_boundary_excluded,
        "missing_time_rows_excluded": missing_time_excluded,
        "independent_source_count": len(source_tokens),
        "collection_window_count": len(window_tokens),
        "fresh_rows": len(unique_records),
        "exact_duplicate_rows_excluded": exact_duplicates,
        "near_duplicate_families": len(families),
        "cross_role_exact_duplicate_count": 0,
        "cross_role_near_duplicate_count": 0,
        "duplicate_families_contained": True,
        "roles": {
            role: {
                "rows": int(role_counts.get(role) or 0),
                "families": int(role_family_counts.get(role) or 0),
                "development_eligible": role != ROLE_NAMES[3],
                "labels_opened": False,
            }
            for role in ROLE_NAMES
        },
        "field_qualified_collections": field_qualified_collections,
        "reviewed_collections": reviewed_collections,
        "reviewed_rows": reviewed_rows,
        "future_labels_opened": False,
        "row_fingerprints_returned": False,
        "source_identities_returned": False,
    }


def _safe_failure(status: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V551_VERSION,
        "generated_at": _now(),
        "status": "failed",
        "failure_code": status,
        "message": message,
        "gates": {},
        "blockers": [message],
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "ml_advisory_only": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "labels_written": 0,
        "alerts_written": 0,
        "detection_runs_written": 0,
        "response_actions_written": 0,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "configured_database_modified": False,
        "protected_v549b_accessed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "private_paths_exposed": False,
        "fingerprints_exposed": False,
        "source_identities_exposed": False,
        "secrets_exposed": False,
    }


def _determine_readiness(
    *,
    local_core_passed: bool,
    hardware_passed: bool,
    reviewer_passed: bool,
    evidence: dict[str, Any],
) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if not local_core_passed:
        return "failed", ["Local transport, parser, accounting, or safety qualification failed."]
    if not hardware_passed:
        blockers.append("A truthfully attested non-loopback firewall or router forwarding run is required.")
        return "hardware_required", blockers
    if not reviewer_passed:
        blockers.append("Independent field mapping and prediction-blind rule review are required.")
        return "reviewer_required", blockers
    if int(evidence.get("independent_source_count") or 0) < MINIMUM_SOURCE_COUNT:
        blockers.append("A second independently attested physical source is required.")
    if int(evidence.get("collection_window_count") or 0) < MINIMUM_WINDOW_COUNT:
        blockers.append("Additional disjoint post-boundary collection windows are required.")
    if int(evidence.get("fresh_rows") or 0) < MINIMUM_FRESH_ROWS:
        blockers.append("More post-boundary, duplicate-contained field rows are required.")
    future_rows = int(((evidence.get("roles") or {}).get(ROLE_NAMES[3]) or {}).get("rows") or 0)
    if future_rows < MINIMUM_FUTURE_ROWS:
        blockers.append("The untouched future-evaluation role has insufficient support.")
    if blockers:
        return "insufficient_evidence", blockers
    return "ready", []


def _write_outputs(
    result: dict[str, Any],
    *,
    output_dir: Path,
    review_rows: list[dict[str, Any]],
    seals: list[dict[str, Any]],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    _atomic_write_json(output_dir / V551_LATEST, result)
    _atomic_write_json(output_dir / f"v5_51_field_qualification_{stamp}.json", result)
    if review_rows:
        _write_csv(output_dir / V551_REVIEW_PACK, review_rows)
        _atomic_write_json(
            output_dir / V551_PREDICTION_SEAL,
            {
                "schema_version": V551_VERSION,
                "rows": seals,
                "stored_separately": True,
                "predictions_exposed_to_reviewers": False,
                "human_labels_included": False,
            },
        )
    markdown = [
        "# v5.51 Detection Field Qualification",
        "",
        f"- Status: `{result.get('status')}`",
        f"- Parser rows: `{(result.get('parser') or {}).get('parsed_rows', 0)}`",
        f"- Fresh rows: `{(result.get('fresh_evidence') or {}).get('fresh_rows', 0)}`",
        f"- Physical sources: `{(result.get('fresh_evidence') or {}).get('independent_source_count', 0)}`",
        f"- Rule field metrics available: `{(result.get('rule_review') or {}).get('metrics_available', False)}`",
        "- Protected v5.49b evidence was not accessed.",
        "- Rules remain authoritative; ML and response automation remain disabled.",
    ]
    (output_dir / f"v5_51_field_qualification_{stamp}.md").write_text(
        "\n".join(markdown) + "\n",
        encoding="utf-8",
    )


def _safe_public_result(result: dict[str, Any]) -> dict[str, Any]:
    serialized = json.dumps(result, sort_keys=True, default=str)
    if _IP_PATTERN.search(serialized):
        raise V551QualificationError("The public v5.51 result failed privacy validation.")
    if any(token in serialized.lower() for token in ("raw_line", "exact_hash", "near_hash", "token_salt")):
        raise V551QualificationError("The public v5.51 result failed privacy validation.")
    if result.get("status") not in READINESS_STATUSES:
        raise V551QualificationError("The public v5.51 readiness status is invalid.")
    return result


def run_v551_field_qualification(
    *,
    use_temp_db: bool,
    sample_path: str | Path | None = None,
    preflight_only: bool = False,
    transport_mode: str = "local_loopback",
    bind_host: str = "0.0.0.0",
    port: int = 5515,
    message_count: int = 5,
    timeout_seconds: float = 15.0,
    source_kind: str = "synthetic_fixture",
    source_name: str = "v551-controlled-source",
    collection_window: str = "v551-controlled-window",
    source_attestation_path: str | Path | None = None,
    field_expectations_path: str | Path | None = None,
    rule_review_path: str | Path | None = None,
    max_rows: int = 10_000,
    review_limit: int = 80,
    output_dir: str | Path = V551_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    if not use_temp_db:
        return _safe_failure(
            "explicit_temp_database_required",
            "Re-run with --use-temp-db; the configured database is never a qualification target.",
        )
    if source_kind not in {"synthetic_fixture", "second_laptop", "firewall", "router"}:
        return _safe_failure("invalid_source_kind", "Choose a supported source kind.")
    if not source_name.strip() or not collection_window.strip():
        return _safe_failure("source_metadata_required", "Source name and collection window are required.")
    if not 1 <= int(max_rows) <= MAX_ROWS_LIMIT:
        return _safe_failure("invalid_max_rows", f"max_rows must be between 1 and {MAX_ROWS_LIMIT}.")
    if not 0 <= int(review_limit) <= 500:
        return _safe_failure("invalid_review_limit", "review_limit must be between 0 and 500.")

    selected_sample = Path(sample_path).expanduser() if sample_path else PROJECT_ROOT / "data" / "samples" / "paloalto-demo.txt"
    if not selected_sample.is_absolute():
        selected_sample = (PROJECT_ROOT / selected_sample).resolve()
    if not selected_sample.is_file():
        return _safe_failure("sample_unavailable", "The selected evidence file is unavailable.")
    output_path = Path(output_dir).resolve()
    attestation_path = Path(source_attestation_path).resolve() if source_attestation_path else None
    expectations_path = Path(field_expectations_path).resolve() if field_expectations_path else None
    review_path = Path(rule_review_path).resolve() if rule_review_path else None

    attestation = _validate_source_attestation(
        attestation_path,
        source_name=source_name,
        collection_window=collection_window,
        source_kind=source_kind,
    )
    external_sender_kind = source_kind if source_kind in {"firewall", "router", "second_laptop"} else None
    transport = run_v523_live_source_acceptance(
        use_temp_db=True,
        sample_path=selected_sample,
        preflight_only=preflight_only,
        transport_mode=transport_mode,
        bind_host=bind_host,
        port=port,
        message_count=message_count,
        timeout_seconds=timeout_seconds,
        external_sender_kind=external_sender_kind,
        write_output=False,
    )
    physical_transport = bool(
        transport.get("real_device_validated")
        and source_kind in {"firewall", "router"}
        and attestation.get("valid")
    )

    if preflight_only:
        local_core = bool(transport.get("ok"))
        status, blockers = _determine_readiness(
            local_core_passed=local_core,
            hardware_passed=physical_transport,
            reviewer_passed=False,
            evidence={},
        )
        result = {
            "ok": local_core,
            "version": V551_VERSION,
            "generated_at": _now(),
            "status": status,
            "preflight_only": True,
            "gates": {
                "local_preflight": local_core,
                "physical_source_attested": bool(attestation.get("valid")),
                "non_loopback_device_transport": physical_transport,
                "field_accuracy_confirmed": False,
                "prediction_blind_rule_review_complete": False,
                "fresh_evidence_sufficient": False,
            },
            "blockers": blockers,
            "transport": {
                "mode": transport_mode,
                "preflight_passed": local_core,
                "non_loopback_device_transport": physical_transport,
                "real_device_validated": False,
                "sender_addresses_returned": False,
            },
            "parser": {
                "contract_version": PARSER_CONTRACT_VERSION,
                "rows_inspected": 0,
                "field_accuracy_confirmed": False,
            },
            "fresh_evidence": {
                "protocol_version": V551_FRESH_EVIDENCE_PROTOCOL,
                "protected_v549b_accessed": False,
                "fresh_rows": 0,
                "future_labels_opened": False,
            },
            "rule_review": {
                "status": "not_generated_in_preflight",
                "metrics_available": False,
                "predictions_exposed": False,
            },
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "ml_advisory_only": True,
            "model_activated": False,
            "model_promoted": False,
            "active_artifact_written": False,
            "labels_written": 0,
            "alerts_written": 0,
            "detection_runs_written": 0,
            "response_actions_written": 0,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "configured_database_modified": False,
            "protected_v549b_accessed": False,
            "raw_logs_exposed": False,
            "ip_addresses_exposed": False,
            "private_paths_exposed": False,
            "fingerprints_exposed": False,
            "source_identities_exposed": False,
            "secrets_exposed": False,
        }
        result = _safe_public_result(result)
        if write_output:
            _write_outputs(result, output_dir=output_path, review_rows=[], seals=[])
        return result

    if not transport.get("ok"):
        return _safe_failure(
            "transport_acceptance_failed",
            "The disposable transport and ingestion acceptance did not pass.",
        )

    started = time.perf_counter()
    try:
        analysis = _analyze_sample(
            selected_sample,
            max_rows=int(max_rows),
            review_limit=int(review_limit),
        )
        field_accuracy = _validate_field_expectations(
            expectations_path,
            source_name=source_name,
            parsed_by_line=analysis["parsed_by_line"],
        )
        rule_review = _validate_rule_review(
            review_path,
            seals=analysis["prediction_seals"],
        )
        manifest = _load_private_manifest(output_path) if write_output else _private_manifest_default()
        salt = str(manifest["token_salt"])
        source_token = _stable_hash({"salt": salt, "source": source_name})[:24]
        window_token = _stable_hash({"salt": salt, "window": collection_window})[:24]
        collection_token = _stable_hash(
            {"source": source_token, "window": window_token}
        )[:24]
        event_times = [
            _event_time(parsed)
            for parsed in analysis["parsed_by_line"].values()
        ]
        pre_boundary_rows = sum(
            value is not None and value < FRESH_EVIDENCE_NOT_BEFORE
            for value in event_times
        )
        missing_time_rows = sum(value is None for value in event_times)
        if attestation.get("valid"):
            manifest["collections"][collection_token] = {
                "source_token": source_token,
                "window_token": window_token,
                "source_kind": source_kind,
                "attestation_valid": True,
                "field_accuracy_confirmed": bool(field_accuracy.get("valid")),
                "rule_review_complete": bool(rule_review.get("complete")),
                "reviewed_rows": int(rule_review.get("reviewed_rows") or 0),
                "pre_boundary_rows_excluded": pre_boundary_rows,
                "missing_time_rows_excluded": missing_time_rows,
                "records": analysis["fresh_records"],
                "raw_logs_included": False,
                "source_identity_included": False,
            }
            manifest["updated_at"] = _now()
            if write_output:
                _atomic_write_json(output_path / V551_PRIVATE_MANIFEST, manifest)
        fresh_evidence = _fresh_evidence_summary(manifest)

        parser_passed = bool(
            analysis["observed_rows"] > 0
            and analysis["rows_accounted"]
            and analysis["parse_success_rate"] >= 0.99
            and not any(
                status in analysis["layout_counts"]
                for status in ("missing_log_type", "unsupported_log_type", "partial_layout")
            )
        )
        transport_accounting = transport.get("channels") or {}
        udp = (transport_accounting.get("replay_udp") or {})
        messages_expected = int(udp.get("messages_expected") or message_count)
        messages_received = int(udp.get("messages_received") or 0)
        loss_count = max(0, messages_expected - messages_received)
        local_core = bool(
            transport.get("ok")
            and not transport.get("configured_database_modified")
            and parser_passed
            and analysis["rows_accounted"]
            and loss_count == 0
        )
        reviewer_passed = bool(field_accuracy.get("valid") and rule_review.get("complete"))
        status, blockers = _determine_readiness(
            local_core_passed=local_core,
            hardware_passed=physical_transport,
            reviewer_passed=reviewer_passed,
            evidence=fresh_evidence,
        )
        result = {
            "ok": local_core,
            "version": V551_VERSION,
            "generated_at": _now(),
            "status": status,
            "preflight_only": False,
            "gates": {
                "local_disposable_acceptance": bool(transport.get("ok")),
                "parser_contract": parser_passed,
                "loss_and_duplicate_accounting": bool(
                    analysis["rows_accounted"] and loss_count == 0
                ),
                "source_health": bool(
                    ((transport.get("checks") or {}).get("source_health_and_quality_available"))
                ),
                "physical_source_attested": bool(attestation.get("valid")),
                "non_loopback_device_transport": physical_transport,
                "field_accuracy_confirmed": bool(field_accuracy.get("valid")),
                "prediction_blind_rule_review_complete": bool(rule_review.get("complete")),
                "fresh_evidence_sufficient": bool(status == "ready"),
            },
            "blockers": blockers,
            "transport": {
                "mode": transport_mode,
                "source_kind": source_kind,
                "messages_expected": messages_expected,
                "messages_received": messages_received,
                "loss_count": loss_count,
                "parse_failures": int(udp.get("parse_failures") or 0),
                "non_loopback_sender_observed": bool(udp.get("non_loopback_sender_observed")),
                "real_device_validated": physical_transport,
                "source_attestation_status": attestation.get("status"),
                "sender_addresses_returned": False,
            },
            "parser": {
                "contract_version": PARSER_CONTRACT_VERSION,
                "observed_rows": analysis["observed_rows"],
                "parsed_rows": analysis["parsed_rows"],
                "failed_rows": analysis["failed_rows"],
                "blank_rows": analysis["blank_rows"],
                "parse_success_rate": analysis["parse_success_rate"],
                "rows_accounted": analysis["rows_accounted"],
                "layout_counts": analysis["layout_counts"],
                "log_type_counts": analysis["log_type_counts"],
                "required_field_missing_counts": analysis["required_field_missing_counts"],
                "exact_duplicate_rows": analysis["exact_duplicate_rows"],
                "near_duplicate_rows": analysis["near_duplicate_rows"],
                "truncated": analysis["truncated"],
                "field_accuracy": field_accuracy,
            },
            "rule_diagnostics": analysis["rule_diagnostics"],
            "rule_review": {
                **rule_review,
                "pack_created": bool(analysis["review_rows"] and write_output),
                "pack_rows": len(analysis["review_rows"]),
                "prediction_seal_stored_separately": bool(
                    analysis["prediction_seals"] and write_output
                ),
                "import_ready": False,
                "automatic_import_performed": False,
            },
            "fresh_evidence": fresh_evidence,
            "runtime_seconds": round(time.perf_counter() - started, 4),
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "ml_advisory_only": True,
            "model_activated": False,
            "model_promoted": False,
            "active_artifact_written": False,
            "labels_written": 0,
            "alerts_written": 0,
            "detection_runs_written": 0,
            "response_actions_written": 0,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "configured_database_modified": bool(
                transport.get("configured_database_modified")
            ),
            "protected_v549b_accessed": False,
            "raw_logs_exposed": False,
            "ip_addresses_exposed": False,
            "private_paths_exposed": False,
            "fingerprints_exposed": False,
            "source_identities_exposed": False,
            "secrets_exposed": False,
        }
        result = _safe_public_result(result)
    except Exception as exc:
        return _safe_failure(
            "field_qualification_error",
            f"Field qualification stopped safely: {exc.__class__.__name__}.",
        )

    if write_output:
        _write_outputs(
            result,
            output_dir=output_path,
            review_rows=analysis["review_rows"],
            seals=analysis["prediction_seals"],
        )
    return result


def get_public_v551_status(
    *,
    output_dir: str | Path = V551_OUTPUT_DIR,
) -> dict[str, Any]:
    path = Path(output_dir) / V551_LATEST
    if not path.is_file():
        return {
            "version": V551_VERSION,
            "status": "hardware_required",
            "generated_at": None,
            "gates": {
                "local_disposable_acceptance": False,
                "parser_contract": False,
                "loss_and_duplicate_accounting": False,
                "source_health": False,
                "physical_source_attested": False,
                "non_loopback_device_transport": False,
                "field_accuracy_confirmed": False,
                "prediction_blind_rule_review_complete": False,
                "fresh_evidence_sufficient": False,
            },
            "transport": {
                "mode": "not_run",
                "real_device_validated": False,
                "loss_count": 0,
                "sender_addresses_returned": False,
            },
            "parser": {
                "contract_version": PARSER_CONTRACT_VERSION,
                "parsed_rows": 0,
                "parse_success_rate": None,
                "field_accuracy": {"valid": False, "accuracy": None},
            },
            "rule_review": {
                "status": "not_run",
                "reviewed_rows": 0,
                "metrics_available": False,
                "false_positive_rate": None,
                "predictions_exposed": False,
            },
            "fresh_evidence": {
                "protocol_version": V551_FRESH_EVIDENCE_PROTOCOL,
                "independent_source_count": 0,
                "collection_window_count": 0,
                "fresh_rows": 0,
                "roles": {role: {"rows": 0} for role in ROLE_NAMES},
                "protected_v549b_accessed": False,
                "future_labels_opened": False,
            },
            "blockers": [
                "Run the disposable local preflight, then complete a real non-loopback device acceptance."
            ],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "raw_logs_exposed": False,
            "ip_addresses_exposed": False,
            "private_paths_exposed": False,
            "fingerprints_exposed": False,
            "source_identities_exposed": False,
            "secrets_exposed": False,
        }
    payload = _read_json(path)
    return _safe_public_result(payload)


def role_partition_for_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Public test/helper contract for duplicate-contained fresh role assignment."""

    manifest = _private_manifest_default()
    manifest["collections"] = {
        "test": {
            "source_token": "source-test",
            "window_token": "window-test",
            "records": list(records),
            "pre_boundary_rows_excluded": 0,
            "missing_time_rows_excluded": 0,
            "field_accuracy_confirmed": False,
            "rule_review_complete": False,
            "reviewed_rows": 0,
        }
    }
    return _fresh_evidence_summary(manifest)
