import csv
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import training_dataset_diagnostics
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR, _source_name
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket
from atdr.app.detection.v342_label_policy_reframing import behavior_aware_soc_target
from atdr.app.detection.v344_two_stage_soc_queue import _queue_target
from atdr.app.detection.v346_queue_target_separability import (
    _analysis_rows,
    _categorical_mix,
    _distribution,
    _mixed_row_share,
    _numeric_separability,
    _split_drift,
)


V347_LATEST = "v3_47_queue_target_repair_proposal_latest.json"
LOW_SIGNAL_EVIDENCE = {"web_low_signal", "utility_low_signal", "low_context"}
STRONG_EVIDENCE = {"rule_backed", "anomaly_backed", "web_scan_context", "incomplete_scan_context", "unknown_scan_context"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _target_values(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _queue_values(target_values: list[str]) -> list[str]:
    return [_queue_target(target) for target in target_values]


def _feature_snapshot(row: Any) -> dict[str, Any]:
    evidence = _evidence_bucket(row)
    strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    benign_web = _safe_float(row.get("v337_benign_web_likelihood_score"))
    family = str(row.get("v337_traffic_family") or "unknown")
    return {
        "evidence_bucket": evidence,
        "evidence_strength": strength,
        "benign_web_likelihood": benign_web,
        "traffic_family": family,
        "rule_backed": bool(row.get("v337_rule_backed_allow_flag")),
        "anomaly_signal": bool(row.get("v337_anomaly_signal_flag")),
        "low_signal_allow": bool(row.get("v337_low_signal_allow_flag")),
        "web_low_signal": bool(row.get("v337_web_low_signal_flag")),
        "utility_low_signal": bool(row.get("v337_utility_low_signal_flag")),
        "scan_context": evidence in {"web_scan_context", "incomplete_scan_context", "unknown_scan_context"},
    }


def propose_queue_target(current_queue: str, row: Any) -> tuple[str, str]:
    snapshot = _feature_snapshot(row)
    strong = (
        snapshot["rule_backed"]
        or snapshot["anomaly_signal"]
        or snapshot["scan_context"]
        or snapshot["evidence_strength"] >= 4.0
    )
    low_signal = (
        snapshot["evidence_bucket"] in LOW_SIGNAL_EVIDENCE
        or snapshot["low_signal_allow"]
        or snapshot["web_low_signal"]
        or snapshot["utility_low_signal"]
    )
    if current_queue == "needs_review":
        if strong:
            return current_queue, "preserve_needs_review_strong_evidence"
        if low_signal and snapshot["benign_web_likelihood"] >= 1.0 and snapshot["evidence_strength"] < 2.5:
            return "non_threat", "propose_demote_low_signal_web_or_utility"
        if snapshot["traffic_family"] in {"web_general", "other_allow"} and snapshot["evidence_strength"] < 2.0:
            return "non_threat", "propose_demote_low_context_allowed_service"
        return current_queue, "preserve_needs_review_ambiguous"
    if current_queue == "non_threat":
        if snapshot["evidence_bucket"] in STRONG_EVIDENCE and snapshot["evidence_strength"] >= 3.0:
            return "needs_review", "propose_promote_strong_evidence_non_threat"
        return current_queue, "preserve_non_threat"
    return current_queue, "preserve_unknown_queue_target"


def _proposal_rows(prepared: dict[str, Any], frame: Any, queue_values: list[str]) -> tuple[list[str], list[dict[str, Any]]]:
    proposed_values: list[str] = []
    proposals: list[dict[str, Any]] = []
    for index, current_queue in enumerate(queue_values):
        proposed, reason = propose_queue_target(current_queue, frame.iloc[index])
        proposed_values.append(proposed)
        if proposed == current_queue:
            continue
        label = prepared["labels"][index]
        log = prepared["logs"][index]
        snapshot = _feature_snapshot(frame.iloc[index])
        proposals.append(
            {
                "index": index,
                "label_id": label.id,
                "log_id": getattr(log, "id", None),
                "current_label": label.label,
                "reviewed": bool(label.reviewed),
                "label_source": str(label.label_source or ""),
                "source_name": _source_name(log),
                "pattern": f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}",
                "current_queue_target": current_queue,
                "proposed_queue_target": proposed,
                "proposal_reason": reason,
                **snapshot,
            }
        )
    return proposed_values, proposals


def _ambiguity_snapshot(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pattern_mix = _categorical_mix(rows, "pattern", min_count=4)
    family_mix = _categorical_mix(rows, "traffic_family", min_count=4)
    evidence_mix = _categorical_mix(rows, "evidence_bucket", min_count=4)
    source_mix = _categorical_mix(rows, "source_name", min_count=4)
    return {
        "pattern_share": _mixed_row_share(pattern_mix, len(rows)),
        "traffic_family_share": _mixed_row_share(family_mix, len(rows)),
        "evidence_bucket_share": _mixed_row_share(evidence_mix, len(rows)),
        "source_share": _mixed_row_share(source_mix, len(rows)),
        "top_patterns": pattern_mix[:12],
        "top_traffic_families": family_mix[:12],
        "top_evidence_buckets": evidence_mix[:12],
        "top_sources": source_mix[:12],
    }


def _split_shift(rows: list[dict[str, Any]]) -> dict[str, Any]:
    before = {row["index"]: row["queue_target"] for row in rows}
    after = {row["index"]: row["proposed_queue_target"] for row in rows}
    changed = [row for row in rows if before[row["index"]] != after[row["index"]]]
    return {
        "changed_rows": len(changed),
        "changed_share": round(len(changed) / len(rows), 4) if rows else 0.0,
        "change_reasons": Counter(row.get("proposal_reason") or "unchanged" for row in changed).most_common(12),
    }


def _write_proposals_csv(proposals: list[dict[str, Any]], path: Path) -> dict[str, Any]:
    if not proposals:
        return {"generated": False, "path": "", "rows": 0, "import_ready": False}
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "label_id",
        "log_id",
        "current_label",
        "reviewed",
        "label_source",
        "source_name",
        "pattern",
        "current_queue_target",
        "proposed_queue_target",
        "proposal_reason",
        "evidence_bucket",
        "evidence_strength",
        "benign_web_likelihood",
        "traffic_family",
        "rule_backed",
        "anomaly_signal",
        "scan_context",
        "import_ready",
        "human_must_confirm",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in proposals:
            writer.writerow({**{field: row.get(field, "") for field in fields}, "import_ready": False, "human_must_confirm": True})
    return {"generated": True, "path": str(path), "rows": len(proposals), "import_ready": False}


def _assessment(before: dict[str, Any], after: dict[str, Any], split_drift_before: list[dict[str, Any]], split_drift_after: list[dict[str, Any]]) -> dict[str, Any]:
    max_before_drift = max((row["absolute_rate_shift"] for row in split_drift_before), default=0.0)
    max_after_drift = max((row["absolute_rate_shift"] for row in split_drift_after), default=0.0)
    checks = [
        {
            "name": "pattern ambiguity improved",
            "passed": after["pattern_share"] <= before["pattern_share"],
            "value": {"before": before["pattern_share"], "after": after["pattern_share"]},
            "target": "after <= before",
        },
        {
            "name": "traffic family ambiguity improved",
            "passed": after["traffic_family_share"] <= before["traffic_family_share"],
            "value": {"before": before["traffic_family_share"], "after": after["traffic_family_share"]},
            "target": "after <= before",
        },
        {
            "name": "split drift improved",
            "passed": max_after_drift <= max_before_drift,
            "value": {"before": max_before_drift, "after": max_after_drift},
            "target": "after <= before",
        },
        {"name": "proposal is not import-ready", "passed": True, "value": False, "target": "required"},
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "diagnostic_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "blockers": [row["name"] for row in checks if not row["passed"]],
        "checks": checks,
        "recommendation": "Use this as a target-repair proposal only; do not import as labels or activate a model.",
    }


def _render_report(result: dict[str, Any]) -> str:
    assessment = result.get("assessment") or {}
    return f"""# v3.47 Queue Target Repair Proposal

Generated: {result.get("generated_at")}

This report is diagnostic only. It proposes queue-target repair rules for analysis. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Summary

- Rows audited: {result.get("rows_audited")}
- Current queue distribution: `{result.get("current_queue_target_distribution")}`
- Proposed queue distribution: `{result.get("proposed_queue_target_distribution")}`
- Proposed changed rows: {result.get("proposal_summary", {}).get("changed_rows")}
- Proposal CSV import-ready: `{result.get("proposal_csv", {}).get("import_ready")}`
- Assessment: {assessment.get("decision")}
- Checks passed: {assessment.get("passed")} / {assessment.get("total")}
- Blockers: {assessment.get("blockers")}

## Before / After Ambiguity

```json
{json.dumps(result.get("ambiguity_before_after"), indent=2, default=str)}
```

## Proposal Reasons

```json
{json.dumps(result.get("proposal_summary", {}).get("change_reasons", []), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v347_queue_target_repair_proposal(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    started = time.perf_counter()
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base
    prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
    frame, meta = enrich_v337_features(prepared)
    target_values = _target_values(prepared, frame)
    current_queue = [_queue_target(target) for target in target_values]
    proposed_queue, proposals = _proposal_rows(prepared, frame, current_queue)
    current_rows = _analysis_rows(prepared, frame, target_values, current_queue)
    proposed_rows = [
        {**row, "queue_target": proposed_queue[position], "proposed_queue_target": proposed_queue[position]}
        for position, row in enumerate(current_rows)
    ]
    before_ambiguity = _ambiguity_snapshot(current_rows)
    after_ambiguity = _ambiguity_snapshot(proposed_rows)
    split_drift_before = _split_drift(base, target_values=target_values, queue_values=current_queue, test_size=test_size)
    split_drift_after = _split_drift(base, target_values=target_values, queue_values=proposed_queue, test_size=test_size)
    proposal_summary = _split_shift(
        [
            {
                **row,
                "proposed_queue_target": proposed_queue[position],
                "proposal_reason": next(
                    (proposal["proposal_reason"] for proposal in proposals if proposal["index"] == row["index"]),
                    "unchanged",
                ),
            }
            for position, row in enumerate(current_rows)
        ]
    )
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_47_queue_target_repair_proposal_{stamp}.md"
    latest_path = output_path / V347_LATEST
    csv_path = output_path / f"v3_47_queue_target_repair_proposals_{stamp}.csv"
    proposal_csv = _write_proposals_csv(proposals, csv_path)
    assessment = _assessment(before_ambiguity, after_ambiguity, split_drift_before, split_drift_after)
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.47",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "rows_audited": len(current_rows),
        "target_mode": "queue_target_repair_proposal",
        "current_queue_target_distribution": _distribution(current_queue),
        "proposed_queue_target_distribution": _distribution(proposed_queue),
        "proposal_summary": proposal_summary,
        "proposal_examples": proposals[:25],
        "proposal_csv": proposal_csv,
        "ambiguity_before_after": {"before": before_ambiguity, "after": after_ambiguity},
        "top_numeric_separators_after": _numeric_separability(frame, proposed_rows, meta["numeric_features"])[:25],
        "split_drift_before": split_drift_before,
        "split_drift_after": split_drift_after,
        "assessment": assessment,
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
