from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v526_native_blind_qualification as v526


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V527_VERSION = "v5.27.0"
V527_LATEST = "v5_27_blind_review_evaluation_latest.json"
V527_PRIVATE_SEAL = "v5_27_blind_review_intake_seal.json"
MIN_REVIEWED_ROWS = 20
VALID_DECISIONS = frozenset(v526.VALID_DECISIONS)
THREAT_DECISIONS = frozenset({"suspicious", "malicious"})
QUEUE_DECISIONS = frozenset({"needs_context", "suspicious", "malicious"})
AUTOMATED_REVIEWER_MARKERS = (
    "assistant",
    "automated",
    "chatgpt",
    "claude",
    "codex",
    "gemini",
    "heuristic",
    "model",
    "openai",
    "synthetic",
    "weak label",
)
PREDICTION_COLUMN_MARKERS = (
    "prediction",
    "predicted_",
    "supervised_queue",
    "supervised_score",
    "isolation_queue",
    "isolation_score",
    "hybrid_queue",
    "hybrid_score",
)
ASSISTED_FIELDS = (
    "assisted_suggestion",
    "assisted_attack_type",
    "assisted_confidence",
    "assisted_reason",
    "assisted_provenance",
    "rule_codes",
    "rule_score",
)
HUMAN_REVIEW_FIELDS = (
    "human_decision",
    "human_attack_type",
    "human_confidence",
    "human_notes",
    "human_reviewer",
    "human_reviewed_at",
    "human_must_confirm",
    "human_reviewed",
)


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object.")
    return payload


def _read_rows(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        return rows, list(reader.fieldnames or [])


def _valid_review_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    if parsed.tzinfo is None:
        return False
    return parsed.astimezone(UTC) <= datetime.now(UTC) + timedelta(minutes=5)


def _valid_confidence(value: str) -> bool:
    try:
        confidence = int(value.strip())
    except (TypeError, ValueError):
        return False
    return 1 <= confidence <= 100


def _integer(value: object, *, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _prediction_exposure_detected(
    rows: list[dict[str, str]],
    columns: list[str],
) -> bool:
    lowered_columns = [column.strip().lower() for column in columns]
    unexpected_prediction_column = any(
        marker in column
        for column in lowered_columns
        for marker in PREDICTION_COLUMN_MARKERS
    )
    assisted_values_present = any(
        str(row.get(field) or "").strip()
        for row in rows
        for field in ASSISTED_FIELDS
    )
    return unexpected_prediction_column or assisted_values_present


def _review_copy_contract(
    pack_rows: list[dict[str, str]],
    pack_columns: list[str],
    review_rows: list[dict[str, str]],
    review_columns: list[str],
) -> dict[str, bool]:
    protected_columns = [
        column for column in pack_columns if column not in HUMAN_REVIEW_FIELDS
    ]
    pack_tokens = [str(row.get("review_token") or "") for row in pack_rows]
    review_tokens = [str(row.get("review_token") or "") for row in review_rows]
    evidence_matches = bool(len(pack_rows) == len(review_rows))
    if evidence_matches:
        evidence_matches = all(
            all(
                str(pack_row.get(column) or "")
                == str(review_row.get(column) or "")
                for column in protected_columns
            )
            for pack_row, review_row in zip(pack_rows, review_rows, strict=True)
        )
    return {
        "review_columns_match_sealed_pack": pack_columns == review_columns,
        "review_row_count_matches_sealed_pack": len(pack_rows) == len(review_rows),
        "review_token_order_matches_sealed_pack": pack_tokens == review_tokens,
        "review_tokens_unique": bool(review_tokens)
        and all(review_tokens)
        and len(review_tokens) == len(set(review_tokens)),
        "review_protected_evidence_matches_sealed_pack": evidence_matches,
        "review_import_ready_remains_false": all(
            not _boolean(row.get("import_ready")) for row in review_rows
        ),
    }


def _lock_contract(
    pack_rows: list[dict[str, str]],
    prediction_lock: dict[str, Any],
    manifest: dict[str, Any],
    v526_result: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bool], str, str]:
    prediction_rows = prediction_lock.get("prediction_rows")
    if not isinstance(prediction_rows, list):
        prediction_rows = []
    pack_tokens = [str(row.get("review_token") or "") for row in pack_rows]
    prediction_tokens = [str(row.get("review_token") or "") for row in prediction_rows]
    pack_projection = [
        {
            "review_token": str(row.get("review_token") or ""),
            "evidence_role": str(row.get("evidence_role") or ""),
            "pattern": str(row.get("pattern") or ""),
        }
        for row in pack_rows
    ]
    checks = {
        "pack_rows_present": bool(pack_rows),
        "pack_tokens_present": bool(pack_tokens) and all(pack_tokens),
        "pack_tokens_unique": len(pack_tokens) == len(set(pack_tokens)),
        "prediction_rows_present": bool(prediction_rows),
        "prediction_tokens_present": bool(prediction_tokens) and all(prediction_tokens),
        "prediction_tokens_unique": len(prediction_tokens) == len(set(prediction_tokens)),
        "pack_and_prediction_row_counts_match": len(pack_rows) == len(prediction_rows),
        "pack_and_prediction_tokens_match": set(pack_tokens) == set(prediction_tokens),
        "pack_manifest_fingerprint_matches": bool(
            manifest.get("blind_pack_fingerprint")
            and v521._pack_fingerprint(pack_projection)
            == manifest.get("blind_pack_fingerprint")
        ),
        "predictions_precede_label_access": prediction_lock.get(
            "predictions_created_before_label_access"
        )
        is True,
        "prediction_lock_has_no_human_fields": prediction_lock.get(
            "human_label_fields_included"
        )
        is False,
        "prediction_lock_has_no_raw_logs": prediction_lock.get("raw_logs_included")
        is False,
        "prediction_lock_has_no_ip_addresses": prediction_lock.get(
            "ip_addresses_included"
        )
        is False,
        "prediction_lock_has_no_source_path": prediction_lock.get(
            "source_path_included"
        )
        is False,
        "prediction_lock_has_no_secrets": prediction_lock.get(
            "secret_values_included"
        )
        is False,
        "v526_result_confirms_frozen_predictions": v526_result.get(
            "prediction_frozen_before_label_access"
        )
        is True,
        "v526_result_confirms_private_lock": v526_result.get(
            "prediction_lock_persisted_privately"
        )
        is True,
        "v526_result_confirms_no_selection_use": v526_result.get(
            "blind_labels_used_for_candidate_selection"
        )
        is False,
    }
    return (
        prediction_rows,
        checks,
        _sha256_json(prediction_lock),
        _sha256_json(pack_projection),
    )


def _seal_contract(
    seal_path: Path,
    *,
    lock_digest: str,
    pack_digest: str,
    row_count: int,
    allow_create: bool,
) -> dict[str, Any]:
    expected = {
        "schema_version": V527_VERSION,
        "prediction_lock_sha256": lock_digest,
        "blind_pack_structure_sha256": pack_digest,
        "row_count": row_count,
        "private_file": True,
        "commit_allowed": False,
    }
    if seal_path.exists():
        seal = _read_json(seal_path)
        matches = all(seal.get(key) == value for key, value in expected.items())
        return {
            "status": "existing_private_seal_valid" if matches else "existing_private_seal_mismatch",
            "passed": matches,
            "created": False,
        }
    if not allow_create:
        return {
            "status": "private_seal_not_created",
            "passed": True,
            "created": False,
        }
    seal_path.parent.mkdir(parents=True, exist_ok=True)
    seal_path.write_text(
        json.dumps({**expected, "created_at": datetime.now(UTC).isoformat()}, indent=2),
        encoding="utf-8",
    )
    return {
        "status": "private_seal_created",
        "passed": True,
        "created": True,
    }


def _row_review_reasons(
    row: dict[str, str],
    *,
    known_tokens: set[str],
    blindness_compromised: bool,
) -> list[str]:
    decision = str(row.get("human_decision") or "").strip().lower()
    reviewed = _boolean(row.get("human_reviewed"))
    review_values_present = any(
        str(row.get(field) or "").strip()
        for field in (
            "human_decision",
            "human_attack_type",
            "human_confidence",
            "human_notes",
            "human_reviewer",
            "human_reviewed_at",
        )
    )
    if not reviewed and not review_values_present:
        return ["not_reviewed"]

    reasons: list[str] = []
    token = str(row.get("review_token") or "").strip()
    reviewer = str(row.get("human_reviewer") or "").strip()
    reviewer_lowered = reviewer.lower()
    attack_type = str(row.get("human_attack_type") or "").strip().lower()
    notes = " ".join(str(row.get("human_notes") or "").strip().split())

    if not reviewed:
        reasons.append("review_flag_false")
    if blindness_compromised:
        reasons.append("prediction_or_assisted_evidence_exposed")
    if not token or token not in known_tokens:
        reasons.append("review_token_not_in_prediction_lock")
    if str(row.get("evidence_role") or "") != "untouched_future_validation":
        reasons.append("wrong_evidence_role")
    if not _boolean(row.get("evidence_role_is_blind")):
        reasons.append("blind_role_flag_false")
    if decision not in VALID_DECISIONS:
        reasons.append("invalid_or_missing_decision")
    if not reviewer:
        reasons.append("reviewer_missing")
    elif any(marker in reviewer_lowered for marker in AUTOMATED_REVIEWER_MARKERS):
        reasons.append("automated_or_assisted_reviewer_identity")
    if not _valid_review_timestamp(str(row.get("human_reviewed_at") or "")):
        reasons.append("invalid_or_missing_review_timestamp")
    if not _valid_confidence(str(row.get("human_confidence") or "")):
        reasons.append("invalid_or_missing_human_confidence")
    if len(notes) < 8:
        reasons.append("human_review_note_too_short")
    if decision in THREAT_DECISIONS and attack_type in {"", "none", "benign", "unknown"}:
        reasons.append("threat_attack_type_missing")
    if _boolean(row.get("human_must_confirm")):
        reasons.append("human_confirmation_still_required")
    if _boolean(row.get("import_ready")):
        reasons.append("blind_review_must_not_be_import_ready")
    if any(str(row.get(field) or "").strip() for field in ASSISTED_FIELDS):
        reasons.append("assisted_or_rule_evidence_present")
    if _boolean(row.get("suggestion_is_weak")):
        reasons.append("weak_suggestion_present")
    if not _boolean(row.get("blind_suggestion_suppressed")):
        reasons.append("blind_suggestion_not_suppressed")
    if _boolean(row.get("raw_log_included")):
        reasons.append("raw_log_exposed")
    if _boolean(row.get("source_ip_included")) or _boolean(
        row.get("destination_ip_included")
    ):
        reasons.append("ip_address_exposed")
    return sorted(set(reasons))


def validate_blind_review_intake(
    *,
    pack_path: Path,
    prediction_lock_path: Path,
    manifest_path: Path,
    v526_result_path: Path,
    seal_path: Path,
    review_path: Path | None = None,
    write_private_seal: bool = True,
) -> tuple[
    dict[str, str],
    dict[str, dict[str, str]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    pack_rows, pack_columns = _read_rows(pack_path)
    review_rows, review_columns = (
        _read_rows(review_path)
        if review_path is not None
        else (pack_rows, pack_columns)
    )
    prediction_lock = _read_json(prediction_lock_path)
    manifest = _read_json(manifest_path)
    v526_result = _read_json(v526_result_path)
    prediction_rows, lock_checks, lock_digest, pack_digest = _lock_contract(
        pack_rows,
        prediction_lock,
        manifest,
        v526_result,
    )
    lock_passed = all(lock_checks.values())
    seal = _seal_contract(
        seal_path,
        lock_digest=lock_digest,
        pack_digest=pack_digest,
        row_count=len(pack_rows),
        allow_create=write_private_seal and lock_passed,
    )
    review_copy_checks = _review_copy_contract(
        pack_rows,
        pack_columns,
        review_rows,
        review_columns,
    )
    review_copy_passed = all(review_copy_checks.values())
    blindness_compromised = _prediction_exposure_detected(
        review_rows,
        review_columns,
    )
    token_counts = Counter(
        str(row.get("review_token") or "") for row in review_rows
    )
    duplicate_tokens = {token for token, count in token_counts.items() if token and count > 1}
    known_tokens = {
        str(row.get("review_token") or "") for row in prediction_rows if row.get("review_token")
    }
    labels: dict[str, str] = {}
    contexts: dict[str, dict[str, str]] = {}
    excluded_reasons: Counter[str] = Counter()
    decision_distribution: Counter[str] = Counter()
    pack_contexts = {
        str(row.get("review_token") or "").strip(): row for row in pack_rows
    }

    for row in review_rows:
        token = str(row.get("review_token") or "").strip()
        reasons = _row_review_reasons(
            row,
            known_tokens=known_tokens,
            blindness_compromised=blindness_compromised,
        )
        if token in duplicate_tokens:
            reasons = sorted({*reasons, "duplicate_review_token"})
        if not lock_passed:
            reasons = sorted({*reasons, "prediction_lock_identity_failed"})
        if not seal.get("passed"):
            reasons = sorted({*reasons, "private_seal_mismatch"})
        if not review_copy_passed:
            reasons = sorted({*reasons, "review_copy_contract_failed"})
        if reasons:
            excluded_reasons.update(reasons)
            continue
        decision = str(row.get("human_decision") or "").strip().lower()
        labels[token] = decision
        contexts[token] = pack_contexts[token]
        decision_distribution[decision] += 1

    queue_classes = {
        "needs_review" if decision in QUEUE_DECISIONS else "non_threat"
        for decision in labels.values()
    }
    enough_for_metrics = (
        len(labels) >= MIN_REVIEWED_ROWS
        and queue_classes == {"needs_review", "non_threat"}
        and lock_passed
        and bool(seal.get("passed"))
        and review_copy_passed
        and not blindness_compromised
    )
    audit = {
        "status": "valid_review_intake" if enough_for_metrics else "review_intake_incomplete",
        "rows_in_pack": len(pack_rows),
        "rows_in_review_copy": len(review_rows),
        "valid_reviewed_rows": len(labels),
        "rejected_or_excluded_rows": len(pack_rows) - len(labels),
        "rejection_reasons": dict(sorted(excluded_reasons.items())),
        "decision_distribution": dict(sorted(decision_distribution.items())),
        "binary_queue_classes_present": len(queue_classes),
        "minimum_reviewed_rows": MIN_REVIEWED_ROWS,
        "enough_for_metrics": enough_for_metrics,
        "blindness_compromised": blindness_compromised,
        "lock_contract_passed": lock_passed,
        "lock_checks": lock_checks,
        "separate_review_copy_used": review_path is not None,
        "review_copy_contract_passed": review_copy_passed,
        "review_copy_checks": review_copy_checks,
        "private_seal": seal,
        "predictions_rerun": False,
        "prediction_values_returned": False,
        "review_tokens_returned": False,
        "reviewer_identities_returned": False,
        "fingerprints_returned": False,
        "assisted_labels_counted_as_human": 0,
        "labels_written": 0,
    }
    return labels, contexts, prediction_rows, audit


def _top(values: list[str], limit: int = 8) -> list[dict[str, Any]]:
    return [
        {"value": value, "rows": count}
        for value, count in Counter(values).most_common(limit)
    ]


def _parser_quality(row: dict[str, str]) -> str:
    if _boolean(row.get("parser_error")):
        return "parser_error"
    if _integer(row.get("required_missing_count")) > 0:
        return "required_fields_missing"
    if _integer(row.get("parser_warning_count")) > 0:
        return "parser_warning"
    return "parsed_cleanly"


def _evidence_strength(row: dict[str, str]) -> str:
    log_type = str(row.get("log_type") or "").upper()
    diversity = max(
        _integer(row.get("source_unique_destinations")),
        _integer(row.get("source_unique_ports")),
    )
    denies = _integer(row.get("source_deny_count"))
    risk = _integer(row.get("application_risk"))
    if log_type == "THREAT" or (diversity >= 8 and denies >= 4):
        return "strong_context"
    if diversity >= 3 or denies >= 2 or risk >= 4:
        return "moderate_context"
    return "limited_context"


def _pattern_flags(row: dict[str, str]) -> list[str]:
    app = str(row.get("application") or "").strip().lower()
    action = str(row.get("action") or "").strip().lower()
    protocol = str(row.get("protocol") or "").strip().lower()
    pattern = str(row.get("pattern") or "").strip().lower()
    port = _integer(row.get("destination_port"))
    flags: list[str] = []
    if app in {"quic", "quic-base"} and port == 443:
        flags.append("quic_443")
    if app == "incomplete" and action == "allow" and port == 80:
        flags.append("incomplete_allow_80")
    if protocol in {"icmp", "icmp6"} or app in {"ping", "icmp"}:
        flags.append("icmp_or_ping")
    if app in {"unknown", "unknown-tcp", "unknown-udp"} or (
        app == "incomplete" and protocol in {"tcp", "udp"}
    ):
        flags.append("unknown_udp_tcp")
    if "scan" in pattern or max(
        _integer(row.get("source_unique_destinations")),
        _integer(row.get("source_unique_ports")),
    ) >= 8:
        flags.append("scan_like")
    if str(row.get("log_type") or "").upper() == "THREAT":
        flags.append("threat_record")
    if _integer(row.get("group_size"), default=1) > 1:
        flags.append("duplicate_or_near_duplicate_group")
    return flags or ["other"]


def _error_pattern_summary(
    errors: list[tuple[dict[str, Any], dict[str, str], str]],
) -> dict[str, Any]:
    return {
        "rows": len(errors),
        "applications": _top([str(context.get("application") or "unknown") for _, context, _ in errors]),
        "actions": _top([str(context.get("action") or "unknown") for _, context, _ in errors]),
        "destination_ports": _top([str(context.get("destination_port") or "unknown") for _, context, _ in errors]),
        "parser_quality": _top([_parser_quality(context) for _, context, _ in errors]),
        "evidence_strength": _top([_evidence_strength(context) for _, context, _ in errors]),
        "log_types": _top([str(context.get("log_type") or "unknown") for _, context, _ in errors]),
        "pattern_flags": _top([flag for _, context, _ in errors for flag in _pattern_flags(context)]),
        "human_decisions": _top([decision for _, _, decision in errors]),
        "private_identifiers_included": False,
    }


def _evaluate_layers(
    labels: dict[str, str],
    contexts: dict[str, dict[str, str]],
    prediction_rows: list[dict[str, Any]],
    *,
    enough_for_metrics: bool,
) -> dict[str, Any]:
    if not enough_for_metrics:
        return {
            "status": "withheld_until_legitimate_blind_support_exists",
            "metrics_calculated": False,
            "reason": (
                "At least 20 legitimate independent human reviews and both queue classes are required."
            ),
            "layers": {},
            "false_positive_or_negative_claims_made": False,
        }
    joined = [row for row in prediction_rows if str(row.get("review_token")) in labels]
    y_true = [
        "needs_review"
        if labels[str(row["review_token"])] in QUEUE_DECISIONS
        else "non_threat"
        for row in joined
    ]
    layers: dict[str, Any] = {}
    for layer in ("rule", "isolation", "supervised", "hybrid"):
        predictions = [str(row[f"{layer}_queue"]) for row in joined]
        scores = [float(row[f"{layer}_score"]) for row in joined]
        metrics = frozen._binary_metrics(y_true, predictions)
        for decision in ("suspicious", "malicious"):
            positions = [
                index
                for index, row in enumerate(joined)
                if labels[str(row["review_token"])] == decision
            ]
            metrics[f"{decision}_recall"] = (
                round(
                    sum(predictions[index] == "needs_review" for index in positions)
                    / len(positions),
                    4,
                )
                if positions
                else None
            )
            metrics[f"{decision}_support"] = len(positions)
        metrics["human_needs_context_rate"] = round(
            sum(decision == "needs_context" for decision in labels.values())
            / max(1, len(labels)),
            4,
        )
        metrics["model_abstention_rate"] = None
        false_positives: list[tuple[dict[str, Any], dict[str, str], str]] = []
        false_negatives: list[tuple[dict[str, Any], dict[str, str], str]] = []
        for index, row in enumerate(joined):
            token = str(row["review_token"])
            if y_true[index] == predictions[index]:
                continue
            item = (row, contexts[token], labels[token])
            (false_positives if y_true[index] == "non_threat" else false_negatives).append(item)
        layers[layer] = {
            "rows": len(joined),
            "metrics": metrics,
            "calibration": {
                **frozen._calibration_report(y_true, scores),
                "interpretation": (
                    "probability_calibration"
                    if layer in {"supervised", "hybrid"}
                    else "diagnostic_score_calibration_only"
                ),
            },
            "error_patterns": {
                "false_positives": _error_pattern_summary(false_positives),
                "false_negatives": _error_pattern_summary(false_negatives),
            },
        }
    return {
        "status": "locked_blind_metrics_calculated_without_prediction_rerun",
        "metrics_calculated": True,
        "rows": len(joined),
        "layers": layers,
        "false_positive_or_negative_claims_made": True,
    }


def _repair_recommendations(evaluation: dict[str, Any]) -> dict[str, Any]:
    if not evaluation.get("metrics_calculated"):
        return {
            "status": "unavailable_until_human_review_complete",
            "recommendations": [
                "Complete independent blind review without access to frozen predictions.",
                "Do not tune or select a model against this blind pack.",
            ],
            "blind_pack_used_for_tuning": False,
        }
    supervised = evaluation["layers"]["supervised"]
    fp_flags = supervised["error_patterns"]["false_positives"]["pattern_flags"]
    fn_flags = supervised["error_patterns"]["false_negatives"]["pattern_flags"]
    top_fp = fp_flags[0]["value"] if fp_flags else "none"
    top_fn = fn_flags[0]["value"] if fn_flags else "none"
    return {
        "status": "development_only_repair_recommendations_available",
        "recommendations": [
            f"Investigate the dominant aggregate false-positive pattern in development evidence: {top_fp}.",
            f"Investigate the dominant aggregate false-negative pattern in development evidence: {top_fn}.",
            "Any repaired candidate requires a new untouched blind pack before another final evaluation.",
        ],
        "blind_pack_used_for_tuning": False,
        "new_blind_pack_required_after_repair": True,
    }


def run_v527_blind_review_evaluation(
    *,
    evidence_dir: Path = DEFAULT_EVIDENCE_DIR,
    output_dir: Path = DEFAULT_EVIDENCE_DIR,
    review_path: Path | None = None,
    write_reports: bool = True,
    write_private_seal: bool = True,
) -> dict[str, Any]:
    pack_path = evidence_dir / v521.V521_BLIND_PACK
    prediction_lock_path = evidence_dir / v526.V526_PREDICTION_LOCK
    manifest_path = evidence_dir / v521.V521_MANIFEST_LATEST
    v526_result_path = evidence_dir / v526.V526_LATEST
    seal_path = evidence_dir / V527_PRIVATE_SEAL
    required = [pack_path, prediction_lock_path, manifest_path, v526_result_path]
    if not all(path.is_file() for path in required):
        return {
            "ok": False,
            "status": "required_private_evidence_missing",
            "required_files_present": False,
            "paths_returned": False,
            "private_identifiers_returned": False,
            "fingerprints_returned": False,
        }

    labels, contexts, prediction_rows, intake = validate_blind_review_intake(
        pack_path=pack_path,
        prediction_lock_path=prediction_lock_path,
        manifest_path=manifest_path,
        v526_result_path=v526_result_path,
        seal_path=seal_path,
        review_path=review_path,
        write_private_seal=write_private_seal,
    )
    evaluation = _evaluate_layers(
        labels,
        contexts,
        prediction_rows,
        enough_for_metrics=bool(intake["enough_for_metrics"]),
    )
    report = {
        "ok": bool(intake["lock_contract_passed"] and intake["private_seal"]["passed"]),
        "status": (
            "v5_27_locked_blind_evaluation_complete"
            if evaluation.get("metrics_calculated")
            else "v5_27_human_review_handoff_required"
        ),
        "schema_version": V527_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "review_intake": intake,
        "locked_evaluation": evaluation,
        "development_repair_plan": _repair_recommendations(evaluation),
        "lifecycle_state": "shadow_observation",
        "safety": {
            "predictions_rerun": False,
            "blind_pack_used_for_tuning": False,
            "labels_created_or_updated": 0,
            "model_artifacts_written": 0,
            "model_activated": False,
            "model_promoted": False,
            "response_actions_created": 0,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "rules_remain_alert_authoritative": True,
        },
        "paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
    }
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(report, indent=2, sort_keys=True, default=str)
        (output_dir / V527_LATEST).write_text(serialized, encoding="utf-8")
        (output_dir / f"v5_27_blind_review_evaluation_{_stamp()}.json").write_text(
            serialized,
            encoding="utf-8",
        )
    return report
