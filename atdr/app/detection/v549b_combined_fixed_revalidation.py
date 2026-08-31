from __future__ import annotations

import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v545_development_model_repair as v545
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548
from atdr.app.detection import (
    v549a_supplemental_threat_anchor_acquisition as v549a,
)


V549B_VERSION = "v5.49b-immutable-combined-fixed-revalidation-v1"
V549B_PROTOCOL_VERSION = "v5.49b-combined-fixed-protocol-v1"
V549B_OUTPUT_DIR = v549a.V549A_OUTPUT_DIR
V549B_PROTOCOL_LOCK = "v5_49b_combined_fixed_revalidation_protocol.json"
V549B_EXECUTION_CLAIM = "v5_49b_combined_fixed_revalidation_execution_claim.json"
V549B_RESULT = "v5_49b_combined_fixed_revalidation_latest.json"
V549B_AGGREGATE_DIAGNOSTICS = (
    "v5_49b_combined_fixed_revalidation_aggregate_diagnostics.json"
)
V549B_REPORT_PREFIX = "v5_49b_combined_fixed_revalidation"
MEASURED_CONFIRMATION = "RUN_V549B_COMBINED_FIXED_REVALIDATION"

EXPECTED_ORIGINAL_ROWS = 120
EXPECTED_SUPPLEMENTAL_ROWS = 60
EXPECTED_COMBINED_ROWS = EXPECTED_ORIGINAL_ROWS + EXPECTED_SUPPLEMENTAL_ROWS


class V549BRevalidationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V549BRevalidationError(
            "The private v5.49b record failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V549BRevalidationError(
            "The private v5.49b record failed integrity validation."
        )
    return payload


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _workspace_paths(
    output_dir: Path,
    original_output_dir: Path,
) -> dict[str, Path]:
    return {
        "original_manifest": original_output_dir / v547.V547_MANIFEST,
        "original_sealed": original_output_dir / v547.V547_SEALED_PACK,
        "original_working": original_output_dir / v547.V547_WORKING_COPY,
        "original_review_state": original_output_dir / v548.V548_REVIEW_STATE,
        "original_protocol": original_output_dir / v548.V548_PROTOCOL_LOCK,
        "old_execution_claim": original_output_dir / v548.V548_EXECUTION_CLAIM,
        "old_result": original_output_dir / v548.V548_RESULT,
        "supplemental_manifest": output_dir / v549a.V549A_MANIFEST,
        "supplemental_sealed": output_dir / v549a.V549A_SEALED_PACK,
        "supplemental_working": output_dir / v549a.V549A_WORKING_COPY,
        "supplemental_review_state": output_dir / v549a.V549A_REVIEW_STATE,
        "proposal": output_dir / v549a.V549B_PROPOSED_PROTOCOL,
        "protocol": output_dir / V549B_PROTOCOL_LOCK,
        "claim": output_dir / V549B_EXECUTION_CLAIM,
        "result": output_dir / V549B_RESULT,
        "aggregate_diagnostics": output_dir / V549B_AGGREGATE_DIAGNOSTICS,
    }


def _require_files(paths: dict[str, Path], names: tuple[str, ...]) -> None:
    if any(not paths[name].is_file() for name in names):
        raise V549BRevalidationError(
            "The closed combined-review workspace is incomplete."
        )


def _validate_proposal(
    proposal: dict[str, Any],
    *,
    original_protocol: dict[str, Any],
    original_manifest: dict[str, Any],
    supplemental_manifest: dict[str, Any],
    combined_support: dict[str, int],
) -> None:
    immutable_false_fields = (
        "evaluation_claim_created",
        "evaluation_labels_accessed",
        "partitions_changed",
        "features_changed",
        "strategies_changed",
        "thresholds_changed",
        "calibration_changed",
        "quality_gates_changed",
        "model_activated",
        "response_automation_allowed",
    )
    valid = bool(
        proposal.get("schema_version") == v549a.V549B_PROPOSED_VERSION
        and proposal.get("status") == "proposal_only_not_locked_or_executed"
        and proposal.get("original_protocol_version")
        == original_protocol.get("schema_version")
        and proposal.get("original_protocol_digest")
        == original_protocol.get("protocol_digest")
        and proposal.get("original_pack_digest")
        == original_manifest.get("sealed_pack_digest")
        and proposal.get("supplemental_pack_digest")
        == supplemental_manifest.get("sealed_pack_digest")
        and proposal.get("combined_class_support") == combined_support
        and proposal.get("minimum_class_support")
        == v549a.COMBINED_MINIMUM_CLASS_SUPPORT
        and proposal.get("original_review_immutable") is True
        and proposal.get("supplemental_review_immutable") is True
        and int(proposal.get("evaluation_execution_count") or 0) == 0
        and all(proposal.get(field) is False for field in immutable_false_fields)
    )
    if not valid:
        raise V549BRevalidationError(
            "The proposed v5.49b protocol failed integrity validation."
        )


def _class_support(rows: list[dict[str, Any]]) -> dict[str, int]:
    support: Counter[str] = Counter()
    for row in rows:
        decision = str(row.get("human_decision") or "").strip().casefold()
        if decision in {"benign", "benign_unusual"}:
            support["benign_like"] += 1
        elif decision == "suspicious":
            support["suspicious"] += 1
        elif decision == "malicious":
            support["malicious"] += 1
    return {
        name: int(support.get(name, 0))
        for name in v549a.COMBINED_MINIMUM_CLASS_SUPPORT
    }


def _private_custody(
    output_dir: Path,
    original_output_dir: Path,
) -> dict[str, Any]:
    paths = _workspace_paths(output_dir, original_output_dir)
    _require_files(
        paths,
        (
            "original_manifest",
            "original_sealed",
            "original_working",
            "original_review_state",
            "original_protocol",
            "supplemental_manifest",
            "supplemental_sealed",
            "supplemental_working",
            "supplemental_review_state",
            "proposal",
        ),
    )
    if paths["old_execution_claim"].exists() or paths["old_result"].exists():
        raise V549BRevalidationError(
            "The superseded v5.48 evaluation is no longer unconsumed."
        )

    try:
        original = v549a.validate_original_review_custody(original_output_dir)
        supplemental = v549a.review_progress(output_dir)
        combined = v549a.combined_support_status(
            output_dir=output_dir,
            original_output_dir=original_output_dir,
        )
        original_protocol = v548.validate_fixed_protocol(original_output_dir)
        original_manifest = v547._read_json(paths["original_manifest"])
        supplemental_manifest = v547._read_json(paths["supplemental_manifest"])
        proposal = v547._read_json(paths["proposal"])
        original_sealed, original_columns = v547._read_csv(
            paths["original_sealed"]
        )
        supplemental_sealed, supplemental_columns = v547._read_csv(
            paths["supplemental_sealed"]
        )
        v547._assert_pack_contract(
            original_sealed,
            original_columns,
            sealed=True,
        )
        v549a._assert_pack_contract(
            supplemental_sealed,
            supplemental_columns,
            sealed=True,
        )
    except (
        OSError,
        ValueError,
        v547.V547AcquisitionError,
        v548.V548RevalidationError,
        v549a.V549ASupplementalAcquisitionError,
    ) as exc:
        raise V549BRevalidationError(
            "The combined closed-review custody check failed."
        ) from exc

    original_review = original.get("review") or {}
    combined_support = {
        key: int((combined.get("class_support") or {}).get(key) or 0)
        for key in v549a.COMBINED_MINIMUM_CLASS_SUPPORT
    }
    if (
        int(original_review.get("total") or 0) != EXPECTED_ORIGINAL_ROWS
        or int(original_review.get("reviewed") or 0) != EXPECTED_ORIGINAL_ROWS
        or int(original_review.get("remaining") or 0) != 0
        or int(original_review.get("invalid") or 0) != 0
        or original_review.get("closed") is not True
        or int(supplemental.get("total") or 0) != EXPECTED_SUPPLEMENTAL_ROWS
        or int(supplemental.get("reviewed") or 0) != EXPECTED_SUPPLEMENTAL_ROWS
        or int(supplemental.get("remaining") or 0) != 0
        or int(supplemental.get("invalid") or 0) != 0
        or supplemental.get("complete") is not True
        or not v549a._review_closed(output_dir)
        or combined.get("passed") is not True
        or combined_support
        != {"benign_like": 95, "suspicious": 39, "malicious": 27}
        or len(original_sealed) != EXPECTED_ORIGINAL_ROWS
        or len(supplemental_sealed) != EXPECTED_SUPPLEMENTAL_ROWS
    ):
        raise V549BRevalidationError(
            "The combined review no longer matches the approved v5.49b evidence state."
        )
    _validate_proposal(
        proposal,
        original_protocol=original_protocol,
        original_manifest=original_manifest,
        supplemental_manifest=supplemental_manifest,
        combined_support=combined_support,
    )

    combined_sealed = [*original_sealed, *supplemental_sealed]
    tokens = [str(row.get("review_token") or "") for row in combined_sealed]
    if not all(tokens) or len(tokens) != len(set(tokens)):
        raise V549BRevalidationError(
            "The combined sealed evidence contains a duplicate review token."
        )
    return {
        "paths": paths,
        "original_status": original,
        "supplemental_status": supplemental,
        "combined_support": combined_support,
        "original_protocol": original_protocol,
        "original_manifest": original_manifest,
        "supplemental_manifest": supplemental_manifest,
        "proposal": proposal,
        "combined_sealed_rows": combined_sealed,
        "file_bindings": {
            "original_manifest": v547._file_sha256(paths["original_manifest"]),
            "original_sealed": v547._file_sha256(paths["original_sealed"]),
            "original_working": v547._file_sha256(paths["original_working"]),
            "original_review_state": v547._file_sha256(
                paths["original_review_state"]
            ),
            "original_protocol": v547._file_sha256(paths["original_protocol"]),
            "supplemental_manifest": v547._file_sha256(
                paths["supplemental_manifest"]
            ),
            "supplemental_sealed": v547._file_sha256(
                paths["supplemental_sealed"]
            ),
            "supplemental_working": v547._file_sha256(
                paths["supplemental_working"]
            ),
            "supplemental_review_state": v547._file_sha256(
                paths["supplemental_review_state"]
            ),
            "proposal": v547._file_sha256(paths["proposal"]),
        },
    }


def _protocol_core(custody: dict[str, Any]) -> dict[str, Any]:
    original_core = custody["original_protocol"].get("protocol") or {}
    expected_contracts = {
        "partition_policy": original_core.get("partition_policy"),
        "feature_schema": list(v548.FIXED_FEATURE_SCHEMA),
        "candidate_strategies": [
            dict(spec) for spec in v548.FIXED_CANDIDATE_STRATEGIES
        ],
        "quality_gates": dict(v548.FIXED_QUALITY_GATES),
        "threshold_grid": list(v545.reliability.THRESHOLD_GRID),
    }
    if (
        original_core.get("feature_schema") != expected_contracts["feature_schema"]
        or original_core.get("candidate_strategies")
        != expected_contracts["candidate_strategies"]
        or original_core.get("quality_gates")
        != expected_contracts["quality_gates"]
        or original_core.get("threshold_grid")
        != expected_contracts["threshold_grid"]
        or v548.FIXED_QUALITY_GATES != v542.FIXED_FREEZE_GATES
    ):
        raise V549BRevalidationError(
            "The inherited fixed evaluation contract changed before v5.49b lock."
        )
    return {
        "protocol_version": V549B_PROTOCOL_VERSION,
        "source_protocol_version": v548.V548_PROTOCOL_VERSION,
        "source_protocol_digest": custody["original_protocol"].get(
            "protocol_digest"
        ),
        "proposal_version": v549a.V549B_PROPOSED_VERSION,
        "evidence_rows": {
            "original": EXPECTED_ORIGINAL_ROWS,
            "supplemental": EXPECTED_SUPPLEMENTAL_ROWS,
            "combined": EXPECTED_COMBINED_ROWS,
        },
        "combined_class_support": custody["combined_support"],
        "minimum_class_support": dict(v549a.COMBINED_MINIMUM_CLASS_SUPPORT),
        "partition_policy": expected_contracts["partition_policy"],
        "partition_commitments": v548._partition_commitment(
            custody["combined_sealed_rows"]
        ),
        "feature_schema": expected_contracts["feature_schema"],
        "candidate_strategies": expected_contracts["candidate_strategies"],
        "quality_gates": expected_contracts["quality_gates"],
        "threshold_grid": expected_contracts["threshold_grid"],
        "calibration_partition_is_dedicated": True,
        "threshold_partition_is_dedicated": True,
        "sealed_review_bindings": custody["file_bindings"],
        "selection_bias": {
            "supplemental_evidence_threat_enriched": True,
            "representative_of_normal_production_prevalence": False,
            "queue_rate_is_field_prevalence_estimate": False,
            "precision_is_field_prevalence_estimate": False,
        },
        "contracts_changed": {
            "partitions": False,
            "features": False,
            "strategies": False,
            "thresholds": False,
            "calibration": False,
            "quality_gates": False,
        },
        "review_sets_immutable": True,
        "evaluation_modeling_labels_accessed_during_lock": False,
        "old_protocol_replaced": False,
    }


def lock_combined_protocol(
    *,
    output_dir: Path = V549B_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    original_output_dir = Path(original_output_dir)
    custody = _private_custody(output_dir, original_output_dir)
    core = _protocol_core(custody)
    lock_path = custody["paths"]["protocol"]
    digest = v548._stable_hash(core)
    if lock_path.is_file():
        lock = _read_json(lock_path)
        if (
            lock.get("schema_version") != V549B_PROTOCOL_VERSION
            or lock.get("protocol") != core
            or lock.get("protocol_digest") != digest
            or lock.get("immutable") is not True
        ):
            raise V549BRevalidationError(
                "The immutable v5.49b protocol or bound evidence changed after lock."
            )
        return lock
    lock = {
        "schema_version": V549B_PROTOCOL_VERSION,
        "created_at": _now(),
        "status": "combined_fixed_protocol_locked",
        "protocol": core,
        "protocol_digest": digest,
        "immutable": True,
        "evaluation_execution_count": 0,
        "evaluation_modeling_labels_accessed": False,
    }
    _atomic_write_json(lock_path, lock)
    return lock


def _validate_bound_files_without_modeling_label_access(
    *,
    output_dir: Path,
    original_output_dir: Path,
) -> dict[str, Any]:
    paths = _workspace_paths(output_dir, original_output_dir)
    _require_files(
        paths,
        (
            "original_manifest",
            "original_sealed",
            "original_working",
            "original_review_state",
            "original_protocol",
            "supplemental_manifest",
            "supplemental_sealed",
            "supplemental_working",
            "supplemental_review_state",
            "proposal",
            "protocol",
        ),
    )
    if paths["old_execution_claim"].exists() or paths["old_result"].exists():
        raise V549BRevalidationError(
            "The superseded v5.48 evaluation was unexpectedly consumed."
        )
    lock = _read_json(paths["protocol"])
    core = lock.get("protocol") or {}
    bindings = core.get("sealed_review_bindings") or {}
    current_bindings = {
        name: v547._file_sha256(paths[name])
        for name in (
            "original_manifest",
            "original_sealed",
            "original_working",
            "original_review_state",
            "original_protocol",
            "supplemental_manifest",
            "supplemental_sealed",
            "supplemental_working",
            "supplemental_review_state",
            "proposal",
        )
    }
    if (
        lock.get("schema_version") != V549B_PROTOCOL_VERSION
        or lock.get("immutable") is not True
        or lock.get("protocol_digest") != v548._stable_hash(core)
        or bindings != current_bindings
        or core.get("feature_schema") != list(v548.FIXED_FEATURE_SCHEMA)
        or core.get("candidate_strategies")
        != [dict(spec) for spec in v548.FIXED_CANDIDATE_STRATEGIES]
        or core.get("quality_gates") != v548.FIXED_QUALITY_GATES
        or core.get("threshold_grid") != list(v545.reliability.THRESHOLD_GRID)
        or core.get("contracts_changed") != {
            "partitions": False,
            "features": False,
            "strategies": False,
            "thresholds": False,
            "calibration": False,
            "quality_gates": False,
        }
    ):
        raise V549BRevalidationError(
            "The immutable v5.49b protocol failed pre-execution validation."
        )
    return lock


def _claim_execution(output_dir: Path, *, protocol_digest: str) -> dict[str, Any]:
    claim_path = Path(output_dir) / V549B_EXECUTION_CLAIM
    claim = {
        "schema_version": V549B_VERSION,
        "status": "combined_fixed_revalidation_execution_claimed",
        "claimed_at": _now(),
        "evaluation_execution_count": 1,
        "protocol_digest": protocol_digest,
        "evaluation_modeling_labels_accessed_before_claim": False,
    }
    try:
        descriptor = os.open(
            claim_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        )
    except FileExistsError as exc:
        raise V549BRevalidationError(
            "The one-time combined revalidation has already been claimed."
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(claim, stream, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        # The claim intentionally remains after an interrupted write.
        raise
    return claim


def _validate_claim(output_dir: Path, *, protocol_digest: str) -> dict[str, Any] | None:
    path = Path(output_dir) / V549B_EXECUTION_CLAIM
    if not path.is_file():
        return None
    claim = _read_json(path)
    if (
        claim.get("schema_version") != V549B_VERSION
        or claim.get("status")
        != "combined_fixed_revalidation_execution_claimed"
        or int(claim.get("evaluation_execution_count") or 0) != 1
        or claim.get("protocol_digest") != protocol_digest
        or claim.get("evaluation_modeling_labels_accessed_before_claim") is not False
    ):
        raise V549BRevalidationError(
            "The v5.49b execution claim failed integrity validation."
        )
    return claim


def _load_combined_review_rows_after_claim(
    *,
    output_dir: Path,
    original_output_dir: Path,
) -> list[dict[str, Any]]:
    paths = _workspace_paths(output_dir, original_output_dir)
    original_rows, original_columns = v547._read_csv(paths["original_working"])
    supplemental_rows, supplemental_columns = v547._read_csv(
        paths["supplemental_working"]
    )
    v547._assert_pack_contract(original_rows, original_columns, sealed=False)
    v549a._assert_pack_contract(
        supplemental_rows,
        supplemental_columns,
        sealed=False,
    )
    rows = [*original_rows, *supplemental_rows]
    support = _class_support(rows)
    if (
        len(original_rows) != EXPECTED_ORIGINAL_ROWS
        or len(supplemental_rows) != EXPECTED_SUPPLEMENTAL_ROWS
        or support != {"benign_like": 95, "suspicious": 39, "malicious": 27}
        or any(not v547._boolean(row.get("human_reviewed")) for row in rows)
    ):
        raise V549BRevalidationError(
            "The claimed combined evaluation labels failed integrity validation."
        )
    return rows


def _metric_projection(strategy: dict[str, Any]) -> dict[str, Any]:
    metrics = strategy.get("metrics") or {}
    calibration = strategy.get("calibration") or {}
    gate = strategy.get("fixed_freeze_gate") or {}
    return {
        "name": strategy.get("name"),
        "status": strategy.get("status"),
        "model_type": strategy.get("model_type"),
        "target_mode": strategy.get("target_mode"),
        "queue_precision": metrics.get("queue_precision"),
        "queue_recall": metrics.get("queue_recall"),
        "queue_f1": metrics.get("queue_f1"),
        "threat_positive_precision": metrics.get("threat_positive_precision"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": metrics.get(
            "benign_like_false_positive_rate"
        ),
        "suspicious_recall": metrics.get("suspicious_recall"),
        "malicious_recall": metrics.get("malicious_recall"),
        "macro_f1": metrics.get("macro_f1"),
        "weighted_f1": metrics.get("weighted_f1"),
        "review_queue_rate": metrics.get("review_queue_rate"),
        "false_positives": metrics.get("false_positive"),
        "false_negatives": metrics.get("false_negative"),
        "suspicious_support": metrics.get("suspicious_support"),
        "malicious_support": metrics.get("malicious_support"),
        "brier_score": calibration.get("brier_score"),
        "expected_calibration_error": calibration.get(
            "expected_calibration_error"
        ),
        "max_confidence_accuracy_gap": calibration.get(
            "max_confidence_accuracy_gap"
        ),
        "applied_calibration_method": strategy.get(
            "applied_calibration_method"
        ),
        "fixed_gate_passed": bool(gate.get("passed")),
        "gate_checks": dict(gate.get("checks") or {}),
        "gate_values": dict(gate.get("gates") or {}),
    }


def write_post_execution_aggregate_diagnostics(
    *,
    output_dir: Path = V549B_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    original_output_dir = Path(original_output_dir)
    paths = _workspace_paths(output_dir, original_output_dir)
    _require_files(paths, ("protocol", "claim", "result"))
    lock = _validate_bound_files_without_modeling_label_access(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    _validate_claim(
        output_dir,
        protocol_digest=str(lock.get("protocol_digest") or ""),
    )
    result = _read_json(paths["result"])
    if (
        result.get("schema_version") != V549B_VERSION
        or int(result.get("evaluation_execution_count") or 0) != 1
        or result.get("protocol_digest") != lock.get("protocol_digest")
    ):
        raise V549BRevalidationError(
            "The fixed result failed aggregate-diagnostics validation."
        )
    rows = _load_combined_review_rows_after_claim(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    evaluation = v548._partition_rows(rows)["evaluation"]
    labels = [str(row.get("human_decision") or "") for row in evaluation]
    strategy_diagnostics: list[dict[str, Any]] = []
    for strategy in result.get("strategies") or []:
        mode = str(strategy.get("target_mode") or "")
        effective_labels = (
            [label for label in labels if label != "needs_context"]
            if mode == "binary_threat_positive"
            else labels
        )
        positives = sum(
            label in {"needs_context", "suspicious", "malicious"}
            for label in effective_labels
        )
        total = len(effective_labels)
        recall = float(strategy.get("queue_recall") or 0.0)
        queue_rate = float(strategy.get("review_queue_rate") or 0.0)
        true_positive = max(0, min(positives, round(recall * positives)))
        queue_size = max(0, min(total, round(queue_rate * total)))
        false_positive = max(0, queue_size - true_positive)
        false_negative = max(0, positives - true_positive)
        true_negative = max(0, total - positives - false_positive)
        strategy_diagnostics.append(
            {
                "name": strategy.get("name"),
                "evaluation_rows": total,
                "suspicious_support": sum(
                    label == "suspicious" for label in effective_labels
                ),
                "malicious_support": sum(
                    label == "malicious" for label in effective_labels
                ),
                "true_positives": true_positive,
                "false_positives": false_positive,
                "false_negatives": false_negative,
                "true_negatives": true_negative,
            }
        )
    payload = {
        "schema_version": V549B_VERSION,
        "generated_at": _now(),
        "status": "post_execution_aggregate_diagnostics_completed",
        "evaluation_execution_count": 1,
        "protocol_digest": lock.get("protocol_digest"),
        "evaluation_partition_class_support": {
            decision: labels.count(decision)
            for decision in (
                "benign",
                "benign_unusual",
                "needs_context",
                "suspicious",
                "malicious",
            )
        },
        "strategies": strategy_diagnostics,
        "model_evaluation_rerun": False,
        "row_predictions_created": False,
        "rows_returned": False,
        "identities_returned": False,
        "fingerprints_returned": False,
        "private_paths_returned": False,
        "secrets_exposed": False,
    }
    existing = (
        _read_json(paths["aggregate_diagnostics"])
        if paths["aggregate_diagnostics"].is_file()
        else None
    )
    if existing is not None:
        comparable_existing = {
            key: value for key, value in existing.items() if key != "generated_at"
        }
        comparable_payload = {
            key: value for key, value in payload.items() if key != "generated_at"
        }
        if comparable_existing != comparable_payload:
            raise V549BRevalidationError(
                "The stored aggregate diagnostics disagree with the fixed result."
            )
        return existing
    _atomic_write_json(paths["aggregate_diagnostics"], payload)
    return payload


def _merge_aggregate_diagnostics(
    strategies: list[dict[str, Any]],
    diagnostics: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    by_name = {
        str(row.get("name") or ""): row
        for row in (diagnostics or {}).get("strategies") or []
    }
    return [
        {**strategy, **by_name.get(str(strategy.get("name") or ""), {})}
        for strategy in strategies
    ]


def _run_comparison(rows: list[dict[str, Any]]) -> dict[str, Any]:
    comparison = v548._run_fixed_comparison(rows)
    strategies = comparison.get("strategies") or []
    if len(strategies) != len(v548.FIXED_CANDIDATE_STRATEGIES):
        raise V549BRevalidationError(
            "The fixed comparison did not report all eight strategies."
        )
    projections = [_metric_projection(strategy) for strategy in strategies]
    passing = [
        strategy
        for strategy in strategies
        if strategy.get("status") == "evaluated"
        and (strategy.get("fixed_freeze_gate") or {}).get("passed") is True
    ]
    selected = max(
        passing,
        key=lambda row: (
            float((row.get("metrics") or {}).get("queue_f1") or 0.0),
            -float(
                (row.get("metrics") or {}).get(
                    "benign_like_false_positive_rate"
                )
                or 1.0
            ),
        ),
        default=None,
    )
    return {
        "partition_rows": comparison.get("partition_rows") or {},
        "strategy_count": len(strategies),
        "evaluated_strategy_count": sum(
            strategy.get("status") == "evaluated" for strategy in strategies
        ),
        "strategies": projections,
        "passing_strategy_count": len(passing),
        "diagnostic_candidate": selected.get("name") if selected else None,
        "diagnostic_candidate_qualified": selected is not None,
    }


def _public_protocol(lock: dict[str, Any] | None) -> dict[str, Any]:
    core = (lock or {}).get("protocol") or {}
    return {
        "version": V549B_PROTOCOL_VERSION,
        "locked": lock is not None,
        "valid": lock is not None,
        "immutable": bool(lock and lock.get("immutable")),
        "strategy_count": len(v548.FIXED_CANDIDATE_STRATEGIES),
        "combined_rows": int(
            (core.get("evidence_rows") or {}).get("combined")
            or EXPECTED_COMBINED_ROWS
        ),
        "contracts_unchanged": bool(
            lock
            and all(
                value is False
                for value in (core.get("contracts_changed") or {}).values()
            )
        ),
        "supplemental_evidence_threat_enriched": True,
        "representative_of_production_prevalence": False,
        "digest_exposed": False,
    }


def get_public_v549b_status(
    *,
    output_dir: Path = V549B_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    original_output_dir = Path(original_output_dir)
    paths = _workspace_paths(output_dir, original_output_dir)
    custody = _private_custody(output_dir, original_output_dir)
    lock = None
    if paths["protocol"].is_file():
        lock = lock_combined_protocol(
            output_dir=output_dir,
            original_output_dir=original_output_dir,
        )
    claim = (
        _validate_claim(
            output_dir,
            protocol_digest=str((lock or {}).get("protocol_digest") or ""),
        )
        if lock is not None and paths["claim"].is_file()
        else None
    )
    result = _read_json(paths["result"]) if paths["result"].is_file() else None
    if result is not None and claim is None:
        raise V549BRevalidationError(
            "The combined result exists without its one-time execution claim."
        )
    if result is not None and (
        result.get("schema_version") != V549B_VERSION
        or int(result.get("evaluation_execution_count") or 0) != 1
        or result.get("protocol_digest") != lock.get("protocol_digest")
    ):
        raise V549BRevalidationError(
            "The combined result failed integrity validation."
        )
    diagnostics = (
        _read_json(paths["aggregate_diagnostics"])
        if result is not None and paths["aggregate_diagnostics"].is_file()
        else None
    )
    if diagnostics is not None and (
        diagnostics.get("schema_version") != V549B_VERSION
        or int(diagnostics.get("evaluation_execution_count") or 0) != 1
        or diagnostics.get("protocol_digest") != lock.get("protocol_digest")
        or diagnostics.get("model_evaluation_rerun") is not False
    ):
        raise V549BRevalidationError(
            "The post-execution aggregate diagnostics failed integrity validation."
        )
    status = (
        "combined_fixed_revalidation_completed"
        if result
        else "combined_fixed_revalidation_failed_closed"
        if claim
        else "ready_for_combined_fixed_revalidation"
        if lock
        else "ready_for_combined_protocol_lock"
    )
    return {
        "version": V549B_VERSION,
        "status": status,
        "custody": {
            "original_reviewed": EXPECTED_ORIGINAL_ROWS,
            "supplemental_reviewed": EXPECTED_SUPPLEMENTAL_ROWS,
            "combined_reviewed": EXPECTED_COMBINED_ROWS,
            "remaining": 0,
            "invalid": 0,
            "reviews_closed": True,
            "reviews_immutable": True,
            "combined_class_support": custody["combined_support"],
            "minimum_class_support": dict(v549a.COMBINED_MINIMUM_CLASS_SUPPORT),
            "combined_support_passed": True,
            "old_evaluation_execution_count": 0,
        },
        "protocol": _public_protocol(lock),
        "evaluation_attempted": claim is not None,
        "evaluation_execution_count": int(claim is not None),
        "metrics_available": result is not None,
        "strategy_count": int((result or {}).get("strategy_count") or 0),
        "evaluated_strategy_count": int(
            (result or {}).get("evaluated_strategy_count") or 0
        ),
        "strategies": _merge_aggregate_diagnostics(
            list((result or {}).get("strategies") or []),
            diagnostics,
        ),
        "diagnostic_candidate": (result or {}).get("diagnostic_candidate"),
        "diagnostic_candidate_qualified": bool(
            (result or {}).get("diagnostic_candidate_qualified")
        ),
        "selection_bias_notice": (
            "Supplemental evidence was threat-enriched; queue rate and precision "
            "are diagnostic and are not field-prevalence estimates."
        ),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "labels_written": 0,
        "model_runs_written": 0,
        "detection_runs_written": 0,
        "alerts_written": 0,
        "response_actions_written": 0,
        "predictions_exposed": False,
        "raw_logs_exposed": False,
        "ip_addresses_exposed": False,
        "source_identities_exposed": False,
        "private_paths_exposed": False,
        "fingerprints_exposed": False,
        "digests_exposed": False,
        "secrets_exposed": False,
    }


def run_v549b_combined_fixed_revalidation(
    *,
    output_dir: Path = V549B_OUTPUT_DIR,
    original_output_dir: Path = v548.V548_OUTPUT_DIR,
    status_only: bool = False,
    preflight_only: bool = False,
    confirmation: str | None = None,
    use_temp_db: bool = False,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    original_output_dir = Path(original_output_dir)
    if status_only:
        return get_public_v549b_status(
            output_dir=output_dir,
            original_output_dir=original_output_dir,
        )

    lock_combined_protocol(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    status = get_public_v549b_status(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    if preflight_only:
        return {
            **status,
            "ok": status["status"] == "ready_for_combined_fixed_revalidation",
            "preflight_only": True,
            "message": "The immutable combined protocol is locked; no evaluation was run.",
        }
    if status["metrics_available"]:
        return {
            **status,
            "ok": True,
            "executed_now": False,
            "message": "The immutable one-time combined revalidation already exists.",
        }
    if status["evaluation_attempted"]:
        return {
            **status,
            "ok": False,
            "executed_now": False,
            "message": (
                "The one-time evaluation was already claimed; automatic retry is prohibited."
            ),
        }
    if confirmation != MEASURED_CONFIRMATION:
        return {
            **status,
            "ok": False,
            "status": "confirmation_required",
            "executed_now": False,
            "message": "Explicit combined fixed-revalidation confirmation is required.",
        }
    if not use_temp_db:
        return {
            **status,
            "ok": False,
            "status": "disposable_execution_required",
            "executed_now": False,
            "message": "Use --use-temp-db for the isolated diagnostic execution.",
        }

    lock = _validate_bound_files_without_modeling_label_access(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    try:
        _claim_execution(
            output_dir,
            protocol_digest=str(lock.get("protocol_digest") or ""),
        )
    except V549BRevalidationError:
        return {
            **get_public_v549b_status(
                output_dir=output_dir,
                original_output_dir=original_output_dir,
            ),
            "ok": False,
            "executed_now": False,
            "message": (
                "The one-time evaluation was already claimed; automatic retry is prohibited."
            ),
        }

    rows = _load_combined_review_rows_after_claim(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    comparison = _run_comparison(rows)
    result = {
        "schema_version": V549B_VERSION,
        "generated_at": _now(),
        "status": "combined_fixed_diagnostic_revalidation_completed",
        "evaluation_execution_count": 1,
        "protocol_digest": lock.get("protocol_digest"),
        "use_temp_db": True,
        **comparison,
        "selection_bias": {
            "supplemental_evidence_threat_enriched": True,
            "representative_of_normal_production_prevalence": False,
            "queue_rate_is_field_prevalence_estimate": False,
            "precision_is_field_prevalence_estimate": False,
        },
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "labels_written": 0,
        "model_runs_written": 0,
        "detection_runs_written": 0,
        "alerts_written": 0,
        "response_actions_written": 0,
        "row_predictions_stored": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    _atomic_write_json(output_dir / V549B_RESULT, result)
    write_post_execution_aggregate_diagnostics(
        output_dir=output_dir,
        original_output_dir=original_output_dir,
    )
    return {
        **get_public_v549b_status(
            output_dir=output_dir,
            original_output_dir=original_output_dir,
        ),
        "ok": True,
        "executed_now": True,
        "message": (
            "Combined diagnostic revalidation completed once without activation."
        ),
    }
