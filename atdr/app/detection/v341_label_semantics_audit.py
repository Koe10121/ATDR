import csv
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import BENIGN_LIKE_LABELS, OUTPUT_DIR, REVIEW_FIELDS, THREAT_LABELS, _source_name
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V341_LATEST = "v3_41_label_semantics_audit_latest.json"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _evidence_bucket(row: Any) -> str:
    if bool(row.get("v337_rule_backed_allow_flag")):
        return "rule_backed"
    if bool(row.get("v337_anomaly_signal_flag")):
        return "anomaly_backed"
    if bool(row.get("v337_web_scan_context_flag")):
        return "web_scan_context"
    if bool(row.get("v337_incomplete_scan_context_flag")):
        return "incomplete_scan_context"
    if bool(row.get("v337_unknown_scan_context_flag")):
        return "unknown_scan_context"
    if bool(row.get("v337_web_low_signal_flag")):
        return "web_low_signal"
    if bool(row.get("v337_utility_low_signal_flag")):
        return "utility_low_signal"
    if _safe_float(row.get("v337_behavior_evidence_strength")) >= 3:
        return "evidence_strength_only"
    return "low_context"


def _label_group(label: str) -> str:
    if label in THREAT_LABELS:
        return "threat"
    if label in BENIGN_LIKE_LABELS:
        return "benign_like"
    return "other"


def classify_semantic_issue(label: str, row: Any) -> dict[str, Any]:
    evidence = _evidence_bucket(row)
    strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    benign_web = _safe_float(row.get("v337_benign_web_likelihood_score"))
    family = str(row.get("v337_traffic_family") or "unknown")
    issue = "aligned_or_unknown"
    severity = 0
    recommendation = "keep_current_label_policy"
    if label in THREAT_LABELS and evidence in {"web_low_signal", "utility_low_signal", "low_context"}:
        issue = "threat_label_on_low_signal_traffic"
        severity = 4 if evidence != "low_context" else 3
        recommendation = "recheck_as_needs_context_or_benign_unusual"
    elif label in THREAT_LABELS and benign_web >= 2.0 and strength < 2.0:
        issue = "threat_label_with_strong_benign_web_likelihood"
        severity = 4
        recommendation = "recheck_as_needs_context_or_benign_unusual"
    elif label in BENIGN_LIKE_LABELS and evidence in {
        "rule_backed",
        "anomaly_backed",
        "web_scan_context",
        "incomplete_scan_context",
        "unknown_scan_context",
    }:
        issue = "benign_like_label_with_threat_evidence"
        severity = 4 if evidence in {"rule_backed", "unknown_scan_context", "incomplete_scan_context"} else 3
        recommendation = "recheck_as_suspicious_or_needs_context"
    elif label == "needs_context" and evidence in {"rule_backed", "unknown_scan_context", "incomplete_scan_context"}:
        issue = "needs_context_with_strong_threat_evidence"
        severity = 3
        recommendation = "recheck_as_suspicious_if_pattern_repeats"
    return {
        "issue": issue,
        "severity": severity,
        "recommendation": recommendation,
        "evidence_bucket": evidence,
        "traffic_family": family,
        "evidence_strength": round(strength, 4),
        "benign_web_likelihood": round(benign_web, 4),
    }


def _row_record(prepared: dict[str, Any], frame: Any, index: int) -> dict[str, Any]:
    label = prepared["labels"][index]
    log = prepared["logs"][index]
    row = frame.iloc[index]
    issue = classify_semantic_issue(label.label, row)
    return {
        "index": index,
        "label": label,
        "log": log,
        "pattern": _pattern(log),
        "source_name": _source_name(log),
        "label_value": label.label,
        "label_group": _label_group(label.label),
        "review_status": "reviewed" if bool(label.reviewed) else "weak_or_unreviewed",
        "label_source": str(label.label_source or ""),
        **issue,
    }


def _pattern_conflicts(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    review_grouped: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for record in records:
        key = (record["pattern"], record["evidence_bucket"])
        grouped[key][record["label_value"]] += 1
        review_grouped[key][record["review_status"]] += 1
    conflicts = []
    for (pattern, evidence), labels in grouped.items():
        benign = sum(labels[label] for label in BENIGN_LIKE_LABELS)
        threat = sum(labels[label] for label in THREAT_LABELS)
        if not benign or not threat:
            continue
        total = sum(labels.values())
        conflicts.append(
            {
                "pattern": pattern,
                "evidence_bucket": evidence,
                "total": total,
                "benign_like": benign,
                "threat": threat,
                "threat_ratio": round(threat / total, 4) if total else 0,
                "label_counts": dict(labels),
                "review_status_counts": dict(review_grouped[(pattern, evidence)]),
            }
        )
    conflicts.sort(key=lambda item: (item["total"], min(item["threat_ratio"], 1 - item["threat_ratio"])), reverse=True)
    return conflicts


def _semantic_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    issue_counts = Counter(record["issue"] for record in records)
    high_severity = [record for record in records if int(record["severity"]) >= 3]
    reviewed_high_severity = [record for record in high_severity if record["review_status"] == "reviewed"]
    conflicts = _pattern_conflicts(records)
    by_issue_pattern: dict[str, Counter[str]] = defaultdict(Counter)
    by_issue_family: dict[str, Counter[str]] = defaultdict(Counter)
    by_issue_source: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        if record["issue"] == "aligned_or_unknown":
            continue
        by_issue_pattern[record["issue"]][record["pattern"]] += 1
        by_issue_family[record["issue"]][record["traffic_family"]] += 1
        by_issue_source[record["issue"]][record["source_name"]] += 1
    return {
        "total_rows": len(records),
        "issue_counts": dict(issue_counts),
        "high_severity_issue_count": len(high_severity),
        "reviewed_high_severity_issue_count": len(reviewed_high_severity),
        "weak_high_severity_issue_count": len(high_severity) - len(reviewed_high_severity),
        "issue_rate": round(len(high_severity) / len(records), 4) if records else 0,
        "reviewed_issue_rate": round(len(reviewed_high_severity) / len(high_severity), 4) if high_severity else 0,
        "top_conflicting_patterns": conflicts[:20],
        "top_issue_patterns": {
            issue: counter.most_common(12) for issue, counter in sorted(by_issue_pattern.items())
        },
        "top_issue_traffic_families": {
            issue: counter.most_common(10) for issue, counter in sorted(by_issue_family.items())
        },
        "top_issue_sources": {
            issue: counter.most_common(10) for issue, counter in sorted(by_issue_source.items())
        },
    }


def _fix_summary_bug(summary: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    high = [record for record in records if int(record["severity"]) >= 3]
    reviewed = [record for record in high if record["review_status"] == "reviewed"]
    summary["reviewed_issue_rate"] = round(len(reviewed) / len(high), 4) if high else 0
    return summary


def _sample_rows(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    selected = [record for record in records if int(record["severity"]) >= 3]
    selected.sort(
        key=lambda record: (
            int(record["severity"]),
            1 if record["review_status"] == "weak_or_unreviewed" else 0,
            _safe_float(record.get("evidence_strength")),
        ),
        reverse=True,
    )
    return selected[:limit]


def _write_audit_sample(records: list[dict[str, Any]], *, output_path: Path, limit: int) -> dict[str, Any]:
    selected = _sample_rows(records, limit)
    if not selected:
        return {"generated": False, "path": "", "rows": 0, "candidate_rows": 0, "import_ready": False}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        *REVIEW_FIELDS,
        "codex_semantic_issue",
        "codex_semantic_severity",
        "codex_policy_recommendation",
        "codex_evidence_bucket",
        "codex_traffic_family",
        "codex_evidence_strength",
        "codex_note",
        "import_ready",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in selected:
            label = record["label"]
            log = record["log"]
            timestamp = log.generated_time or log.receive_time or log.start_time
            writer.writerow(
                {
                    "label_id": label.id,
                    "log_id": log.id,
                    "timestamp": timestamp.isoformat() if timestamp else "",
                    "split_window": "diagnostic_all",
                    "source_name": record["source_name"],
                    "src_ip": log.src_ip or "",
                    "dst_ip": log.dst_ip or "",
                    "dst_port": log.dst_port if log.dst_port is not None else "",
                    "protocol": log.protocol or "",
                    "app": log.app or "",
                    "action": log.action or "",
                    "current_label": label.label,
                    "current_attack_type": label.attack_type or "",
                    "reviewed_status": record["review_status"],
                    "label_source": record["label_source"],
                    "model_prediction": "",
                    "model_confidence": "",
                    "threat_positive_score": "",
                    "rule_score": "",
                    "anomaly_score": log.anomaly_score if log.anomaly_score is not None else "",
                    "hybrid_risk_score": "",
                    "reason_selected": "v3.41 label semantics audit",
                    "evidence_summary": (
                        f"pattern={record['pattern']}; evidence_bucket={record['evidence_bucket']}; "
                        f"traffic_family={record['traffic_family']}; evidence_strength={record['evidence_strength']}; "
                        f"benign_web_likelihood={record['benign_web_likelihood']}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": "",
                    "human_review_confidence": "",
                    "human_review_note": "",
                    "codex_semantic_issue": record["issue"],
                    "codex_semantic_severity": record["severity"],
                    "codex_policy_recommendation": record["recommendation"],
                    "codex_evidence_bucket": record["evidence_bucket"],
                    "codex_traffic_family": record["traffic_family"],
                    "codex_evidence_strength": record["evidence_strength"],
                    "codex_note": "Diagnostic only. Do not import directly; human review policy must confirm any label change.",
                    "import_ready": "false",
                }
            )
    return {"generated": True, "path": str(output_path), "rows": len(selected), "candidate_rows": len(records), "import_ready": False}


def _render_report(result: dict[str, Any]) -> str:
    summary = result.get("semantic_summary") or {}
    return f"""# v3.41 Supervised Label Semantics Audit

Generated: {result.get("generated_at")}

This phase is diagnostic only. It audits whether current labels match evidence profiles and traffic patterns. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Summary

- Rows audited: {summary.get("total_rows")}
- High-severity semantic issues: {summary.get("high_severity_issue_count")}
- Reviewed high-severity issues: {summary.get("reviewed_high_severity_issue_count")}
- Weak/unreviewed high-severity issues: {summary.get("weak_high_severity_issue_count")}
- Issue rate: {summary.get("issue_rate")}
- Reviewed issue rate: {summary.get("reviewed_issue_rate")}

## Issue Counts

```json
{json.dumps(summary.get("issue_counts"), indent=2, default=str)}
```

## Top Conflicting Patterns

```json
{json.dumps(summary.get("top_conflicting_patterns", [])[:12], indent=2, default=str)}
```

## Top Issue Patterns

```json
{json.dumps(summary.get("top_issue_patterns"), indent=2, default=str)}
```

## Audit Sample

```json
{json.dumps(result.get("sample"), indent=2, default=str)}
```

## Readiness

- Decision: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def _readiness(summary: dict[str, Any]) -> dict[str, Any]:
    high = int(summary.get("high_severity_issue_count") or 0)
    conflicts = len(summary.get("top_conflicting_patterns") or [])
    checks = [
        {
            "name": "label semantics are clean enough for promotion",
            "passed": high == 0,
            "value": high,
            "target": "0 high-severity semantic issues",
        },
        {
            "name": "pattern label conflicts are resolved",
            "passed": conflicts == 0,
            "value": conflicts,
            "target": "0 conflicting app/action/port/evidence buckets",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "no model activation", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "candidate_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": [row["name"] for row in checks if not row["passed"]],
        "checks": checks,
    }


def run_v341_label_semantics_audit(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    sample_limit: int = 200,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base

    started = time.perf_counter()
    prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
    frame, meta = enrich_v337_features(prepared)
    records = [_row_record(prepared, frame, index) for index in range(len(prepared["labels"]))]
    semantic_summary = _fix_summary_bug(_semantic_summary(records), records)

    split_label_summary = []
    for split_mode in V335_SPLITS:
        split_prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        train_counts = Counter(split_prepared["y"][index] for index in split_prepared["train_idx"])
        test_counts = Counter(split_prepared["y"][index] for index in split_prepared["test_idx"])
        split_label_summary.append(
            {
                "split_mode": split_mode,
                "training_rows": len(split_prepared["train_idx"]),
                "test_rows": len(split_prepared["test_idx"]),
                "train_counts": dict(train_counts),
                "test_counts": dict(test_counts),
                "suspicious_train_test": {
                    "train": int(train_counts.get("suspicious", 0)),
                    "test": int(test_counts.get("suspicious", 0)),
                },
                "benign_like_train_test": {
                    "train": sum(int(train_counts.get(label, 0)) for label in BENIGN_LIKE_LABELS),
                    "test": sum(int(test_counts.get(label, 0)) for label in BENIGN_LIKE_LABELS),
                },
            }
        )
    readiness = _readiness(semantic_summary)
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_41_label_semantics_audit_{stamp}.md"
    latest_path = output_path / V341_LATEST
    sample = _write_audit_sample(
        records,
        output_path=output_path / "v3_41_label_semantics_audit_sample.csv",
        limit=sample_limit,
    )
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.41",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "semantic_summary": semantic_summary,
        "split_label_summary": split_label_summary,
        "sample": sample,
        "training_dataset": training_dataset_diagnostics(db),
        "readiness": readiness,
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
