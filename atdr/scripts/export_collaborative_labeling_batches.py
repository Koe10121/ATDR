import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import and_, desc, or_, select
from sqlalchemy.orm import Session

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import MLLabel, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.supervised_detector import predict_supervised_log
from atdr.app.ml.features import build_log_features
from atdr.app.services.active_learning_service import (
    build_active_learning_review_sample,
    build_suspicious_recall_review_sample,
    build_training_window_threat_review_sample,
)
from atdr.app.services.class_temporal_coverage_service import (
    build_class_temporal_coverage,
    classify_log_time_window,
)


DEFAULT_OUTPUT_DIR = Path("ml_baseline_reviews/collaborative_labeling_batches")

FIELDNAMES = [
    "batch_id",
    "reviewer_assignment",
    "label_id",
    "log_id",
    "timestamp",
    "split_window",
    "src_ip",
    "dst_ip",
    "src_zone",
    "dst_zone",
    "src_port",
    "dst_port",
    "protocol",
    "app",
    "action",
    "app_risk",
    "bytes",
    "packets",
    "current_label",
    "current_attack_type",
    "label_source",
    "reviewed_status",
    "model_prediction",
    "model_confidence",
    "malicious_probability",
    "threat_positive_score",
    "hybrid_risk_score",
    "rule_score",
    "is_anomaly",
    "anomaly_score",
    "behavior_window_summary",
    "reason_selected_for_review",
    "evidence_summary",
    "reviewer_instructions",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]

VALID_LABELS = "benign | benign_unusual | suspicious | malicious | needs_context"
VALID_ATTACK_TYPES = (
    "normal | port_scan | brute_force | dos_ddos | malware_c2 | policy_violation | "
    "data_exfiltration_suspicion | unknown_anomaly"
)


def _latest_labels_by_log(db: Session) -> dict[int, MLLabel]:
    labels = list(db.scalars(select(MLLabel).order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))))
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return latest


def _simple_rule_score(log: NormalizedLog) -> int:
    score = 0
    action = (log.action or "").lower()
    app = (log.app or "").lower()
    if action in {"deny", "drop", "reset-both", "reset-client", "reset-server"}:
        score += 30
    if log.is_anomaly:
        score += 25
    if (log.app_risk or 0) >= 5:
        score += 25
    elif (log.app_risk or 0) >= 4:
        score += 15
    if app in {"unknown", "unknown-tcp", "unknown-udp", "incomplete"}:
        score += 15
    return min(score, 100)


def _candidate_priority(log: NormalizedLog, *, reason: str) -> int:
    score = _simple_rule_score(log)
    if "suspicious recall" in reason:
        score += 35
    if "training-window threat" in reason:
        score += 30
    if "active-learning" in reason:
        score += 25
    if reason == "low-risk baseline":
        score = 15
    return min(score, 140)


def _is_protected(label: MLLabel | None) -> bool:
    if label is None:
        return False
    return bool(label.reviewed)


def _add_candidate(
    candidates: dict[int, dict[str, Any]],
    *,
    log_id: int,
    priority: int,
    reason: str,
    latest_labels: dict[int, MLLabel],
) -> None:
    label = latest_labels.get(log_id)
    if _is_protected(label):
        return
    existing = candidates.get(log_id)
    if existing is None or priority > int(existing["priority"]):
        candidates[log_id] = {"log_id": log_id, "priority": priority, "reason": reason}


def _collect_review_candidates(db: Session, *, total: int) -> list[dict[str, Any]]:
    latest_labels = _latest_labels_by_log(db)
    candidates: dict[int, dict[str, Any]] = {}

    active_rows = build_active_learning_review_sample(
        db,
        limit=max(total // 2, 300),
        focus="malicious,suspicious,needs_context",
        strategy="threat_boundary",
    )
    for row in active_rows:
        _add_candidate(
            candidates,
            log_id=int(row["log_id"]),
            priority=int(row.get("selection_score") or 90),
            reason=f"active-learning: {row.get('reason_selected_for_review') or 'priority review'}",
            latest_labels=latest_labels,
        )

    training_rows = build_training_window_threat_review_sample(db, limit=max(total // 4, 200))
    for row in training_rows:
        _add_candidate(
            candidates,
            log_id=int(row["log_id"]),
            priority=int(row.get("selection_score") or 95),
            reason=f"training-window threat: {row.get('reason_selected_for_review') or 'time-split support'}",
            latest_labels=latest_labels,
        )

    suspicious_rows = build_suspicious_recall_review_sample(db, limit=max(total // 4, 200))
    for row in suspicious_rows:
        _add_candidate(
            candidates,
            log_id=int(row["log_id"]),
            priority=int(row.get("selection_score") or 100),
            reason=f"suspicious recall: {row.get('reason_selected_for_review') or 'class boundary review'}",
            latest_labels=latest_labels,
        )

    high_risk_statement = (
        select(NormalizedLog)
        .where(
            or_(
                NormalizedLog.is_anomaly.is_(True),
                NormalizedLog.app_risk >= 4,
                NormalizedLog.action.in_(["deny", "drop", "reset-both", "reset-client", "reset-server"]),
                NormalizedLog.app.in_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
            )
        )
        .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
        .limit(max(total * 2, 1000))
    )
    for log in db.scalars(high_risk_statement):
        _add_candidate(
            candidates,
            log_id=log.id,
            priority=_candidate_priority(log, reason="high-risk unlabeled or weak-label row"),
            reason="high-risk unlabeled or weak-label row",
            latest_labels=latest_labels,
        )

    low_risk_statement = (
        select(NormalizedLog)
        .where(
            and_(
                NormalizedLog.is_anomaly.is_(False),
                NormalizedLog.action == "allow",
                or_(NormalizedLog.app_risk <= 2, NormalizedLog.app_risk.is_(None)),
                NormalizedLog.src_ip.is_not(None),
                NormalizedLog.dst_ip.is_not(None),
                NormalizedLog.app.notin_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
            )
        )
        .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
        .limit(max(total // 3, 300))
    )
    for log in db.scalars(low_risk_statement):
        _add_candidate(
            candidates,
            log_id=log.id,
            priority=_candidate_priority(log, reason="low-risk baseline"),
            reason="low-risk baseline",
            latest_labels=latest_labels,
        )

    ordered = sorted(candidates.values(), key=lambda row: (int(row["priority"]), int(row["log_id"])), reverse=True)
    high_or_boundary = [row for row in ordered if row["reason"] != "low-risk baseline"]
    low_risk = [row for row in ordered if row["reason"] == "low-risk baseline"]
    low_risk_target = max(1, int(total * 0.2))
    selected = high_or_boundary[: max(0, total - low_risk_target)]
    selected.extend(low_risk[:low_risk_target])
    if len(selected) < total:
        selected_ids = {row["log_id"] for row in selected}
        selected.extend(row for row in ordered if row["log_id"] not in selected_ids)
    return selected[:total]


def _collect_fast_review_candidates(db: Session, *, total: int) -> list[dict[str, Any]]:
    latest_labels = _latest_labels_by_log(db)
    candidates: dict[int, dict[str, Any]] = {}

    unreviewed_statement = (
        select(MLLabel)
        .where(MLLabel.reviewed.is_(False))
        .order_by(desc(MLLabel.created_at), desc(MLLabel.id))
        .limit(max(total, 600))
    )
    for label in db.scalars(unreviewed_statement):
        log = label.log or db.get(NormalizedLog, label.log_id)
        if log is None:
            continue
        priority = _candidate_priority(log, reason="unreviewed assisted label")
        if label.label in {"suspicious", "malicious", "needs_context"}:
            priority += 30
        _add_candidate(
            candidates,
            log_id=label.log_id,
            priority=priority,
            reason=f"unreviewed assisted label current_label={label.label}",
            latest_labels=latest_labels,
        )

    high_risk_statement = (
        select(NormalizedLog)
        .where(
            or_(
                NormalizedLog.is_anomaly.is_(True),
                NormalizedLog.app_risk >= 4,
                NormalizedLog.action.in_(["deny", "drop", "reset-both", "reset-client", "reset-server"]),
                NormalizedLog.app.in_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
            )
        )
        .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
        .limit(max(total * 2, 1000))
    )
    for log in db.scalars(high_risk_statement):
        _add_candidate(
            candidates,
            log_id=log.id,
            priority=_candidate_priority(log, reason="high-risk unlabeled or weak-label row"),
            reason="high-risk unlabeled or weak-label row",
            latest_labels=latest_labels,
        )

    low_risk_statement = (
        select(NormalizedLog)
        .where(
            and_(
                NormalizedLog.is_anomaly.is_(False),
                NormalizedLog.action == "allow",
                or_(NormalizedLog.app_risk <= 2, NormalizedLog.app_risk.is_(None)),
                NormalizedLog.src_ip.is_not(None),
                NormalizedLog.dst_ip.is_not(None),
                NormalizedLog.app.notin_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
            )
        )
        .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
        .limit(max(total // 3, 300))
    )
    for log in db.scalars(low_risk_statement):
        _add_candidate(
            candidates,
            log_id=log.id,
            priority=_candidate_priority(log, reason="low-risk baseline"),
            reason="low-risk baseline",
            latest_labels=latest_labels,
        )

    ordered = sorted(candidates.values(), key=lambda row: (int(row["priority"]), int(row["log_id"])), reverse=True)
    low_risk_target = max(1, int(total * 0.2))
    low_risk = [row for row in ordered if row["reason"] == "low-risk baseline"]
    risk_rows = [row for row in ordered if row["reason"] != "low-risk baseline"]
    selected = risk_rows[: max(0, total - low_risk_target)]
    selected.extend(low_risk[:low_risk_target])
    if len(selected) < total:
        selected_ids = {row["log_id"] for row in selected}
        selected.extend(row for row in ordered if row["log_id"] not in selected_ids)
    return selected[:total]


def _ip_alias(value: str | None, aliases: dict[str, str]) -> str:
    if not value:
        return ""
    if value not in aliases:
        aliases[value] = f"IP_{len(aliases) + 1:04d}"
    return aliases[value]


def _behavior_summary(db: Session, log: NormalizedLog, *, enabled: bool) -> str:
    if not enabled:
        return "behavior summary skipped for fast collaboration export"
    try:
        features = build_log_features(db, log)
    except Exception as exc:  # pragma: no cover - defensive summary only
        return f"feature_summary_unavailable={exc.__class__.__name__}"
    keys = [
        "src_ip_5min_log_count",
        "src_ip_5min_deny_count",
        "src_ip_5min_unique_dst_ports",
        "src_ip_15min_unique_dst_ports",
        "src_ip_15min_deny_ratio",
        "scanning_like_behavior_score",
        "repeated_connection_attempts",
        "external_to_internal_flag",
        "unknown_app_flag",
    ]
    parts = [f"{key}={features.get(key, '')}" for key in keys if features.get(key, "") not in {"", None}]
    return "; ".join(parts[:9])


def _review_instructions() -> str:
    return (
        f"Fill human_review_decision with one of: {VALID_LABELS}. "
        f"Fill human_review_attack_type with one of: {VALID_ATTACK_TYPES}. "
        "Use needs_context when evidence is ambiguous. Do not edit log_id or label_id."
    )


def _build_export_rows(
    db: Session,
    *,
    total: int,
    anonymize: bool,
    deep_active_learning: bool,
    include_model_predictions: bool,
    include_behavior_summary: bool,
) -> list[dict[str, Any]]:
    latest_labels = _latest_labels_by_log(db)
    temporal_coverage = build_class_temporal_coverage(db)
    aliases: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    candidates = (
        _collect_review_candidates(db, total=total)
        if deep_active_learning
        else _collect_fast_review_candidates(db, total=total)
    )
    for candidate in candidates:
        log = db.get(NormalizedLog, int(candidate["log_id"]))
        if log is None:
            continue
        label = latest_labels.get(log.id)
        rule_score = _simple_rule_score(log)
        prediction = predict_supervised_log(db, log.id, rule_score=rule_score) if include_model_predictions else {}
        probabilities = prediction.get("class_probabilities") or {}
        malicious_probability = float(probabilities.get("malicious") or prediction.get("malicious_probability") or 0)
        suspicious_probability = float(probabilities.get("suspicious") or 0)
        hybrid = prediction.get("hybrid_risk") or hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=log.is_anomaly,
            supervised_malicious_probability=malicious_probability,
        )
        timestamp = log.generated_time or log.receive_time
        rows.append(
            {
                "batch_id": "",
                "reviewer_assignment": "",
                "label_id": label.id if label else "",
                "log_id": log.id,
                "timestamp": timestamp.isoformat() if timestamp else "",
                "split_window": classify_log_time_window(log, temporal_coverage),
                "src_ip": _ip_alias(log.src_ip, aliases) if anonymize else log.src_ip or "",
                "dst_ip": _ip_alias(log.dst_ip, aliases) if anonymize else log.dst_ip or "",
                "src_zone": log.src_zone or "",
                "dst_zone": log.dst_zone or "",
                "src_port": log.src_port or "",
                "dst_port": log.dst_port or "",
                "protocol": log.protocol or "",
                "app": log.app or "",
                "action": log.action or "",
                "app_risk": log.app_risk or "",
                "bytes": log.bytes or "",
                "packets": log.packets or "",
                "current_label": label.label if label else "",
                "current_attack_type": label.attack_type if label else "unknown_anomaly",
                "label_source": label.label_source if label else "",
                "reviewed_status": label.reviewed if label else False,
                "model_prediction": prediction.get("predicted_label") or "",
                "model_confidence": round(float(prediction.get("confidence") or 0), 4),
                "malicious_probability": round(malicious_probability, 4),
                "threat_positive_score": round(malicious_probability + suspicious_probability, 4),
                "hybrid_risk_score": int((hybrid or {}).get("final_risk_score", 0)),
                "rule_score": rule_score,
                "is_anomaly": bool(log.is_anomaly),
                "anomaly_score": log.anomaly_score if log.anomaly_score is not None else "",
                "behavior_window_summary": _behavior_summary(db, log, enabled=include_behavior_summary),
                "reason_selected_for_review": candidate["reason"],
                "evidence_summary": (
                    f"action={log.action}; app={log.app}; risk={log.app_risk}; dst_port={log.dst_port}; "
                    f"rule_score={rule_score}; anomaly={bool(log.is_anomaly)}; "
                    f"model={prediction.get('predicted_label') or 'unknown'}"
                ),
                "reviewer_instructions": _review_instructions(),
                "human_review_decision": "",
                "human_review_attack_type": label.attack_type if label else "unknown_anomaly",
                "human_review_confidence": label.confidence if label else 3,
                "human_review_note": "",
            }
        )
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def _write_instructions(path: Path, *, anonymized: bool, total_rows: int, batches: int) -> None:
    privacy = (
        "The exported IP address columns are pseudonymized aliases, so the file can be reviewed without exposing exact IPs."
        if anonymized
        else "This export includes real IP addresses from the local database. Share only with trusted project reviewers."
    )
    path.write_text(
        "\n".join(
            [
                "# ATDR Collaborative Labeling Instructions",
                "",
                f"Rows exported: {total_rows}",
                f"Batch files: {batches}",
                "",
                privacy,
                "",
                "Reviewers should only edit these columns:",
                "- human_review_decision",
                "- human_review_attack_type",
                "- human_review_confidence",
                "- human_review_note",
                "",
                f"Allowed labels: {VALID_LABELS}",
                f"Allowed attack types: {VALID_ATTACK_TYPES}",
                "",
                "Guidance:",
                "- Use `benign` for clearly normal traffic.",
                "- Use `benign_unusual` for allowed but unusual traffic that should not alert immediately.",
                "- Use `suspicious` for risky behavior that needs analyst attention.",
                "- Use `malicious` only when evidence is strong.",
                "- Use `needs_context` when the row cannot be judged safely from the evidence.",
                "- Do not edit `log_id` or `label_id`; the import workflow needs them.",
                "",
                "Import path:",
                "1. Collect the reviewed CSVs from your reviewers.",
                "2. Open React dashboard > AI Governance.",
                "3. Import each reviewed CSV.",
                "4. Keep default protection on unless you intentionally need correction mode.",
                "5. Retrain the supervised model after import.",
                "",
                "Demo wording:",
                "These are human review batches generated from active-learning and rule/ML disagreement cases. "
                "They improve supervised learning, but model metrics must still be described as decision-support metrics, "
                "not certified production accuracy.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def export_batches(
    db: Session,
    *,
    total: int,
    batches: int,
    output_dir: Path,
    include_real_ips: bool,
    deep_active_learning: bool,
    include_model_predictions: bool,
    include_behavior_summary: bool,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = _build_export_rows(
        db,
        total=total,
        anonymize=not include_real_ips,
        deep_active_learning=deep_active_learning,
        include_model_predictions=include_model_predictions,
        include_behavior_summary=include_behavior_summary,
    )
    if not rows:
        return {"status": "empty", "rows": 0, "paths": []}
    for index, row in enumerate(rows):
        batch_number = (index % batches) + 1
        row["batch_id"] = f"batch_{batch_number:02d}"
        row["reviewer_assignment"] = f"reviewer_{batch_number:02d}"

    master_path = output_dir / "atdr_labeling_master.csv"
    _write_csv(master_path, rows)
    paths = [str(master_path)]
    for batch_number in range(1, batches + 1):
        batch_rows = [row for row in rows if row["batch_id"] == f"batch_{batch_number:02d}"]
        batch_path = output_dir / f"atdr_labeling_batch_{batch_number:02d}.csv"
        _write_csv(batch_path, batch_rows)
        paths.append(str(batch_path))
    instructions_path = output_dir / "LABELING_INSTRUCTIONS.md"
    _write_instructions(instructions_path, anonymized=not include_real_ips, total_rows=len(rows), batches=batches)
    paths.append(str(instructions_path))

    return {
        "status": "exported",
        "rows": len(rows),
        "batches": batches,
        "rows_per_batch": dict(Counter(row["batch_id"] for row in rows)),
        "anonymized": not include_real_ips,
        "deep_active_learning": deep_active_learning,
        "model_predictions_included": include_model_predictions,
        "behavior_summary_included": include_behavior_summary,
        "paths": paths,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export collaborative ATDR labeling batches for human reviewers.")
    parser.add_argument("--total", type=int, default=1200, help="Total rows to export across all batches.")
    parser.add_argument("--batches", type=int, default=4, help="Number of reviewer batch CSV files to create.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--include-real-ips", action="store_true", help="Include exact IP addresses instead of aliases.")
    parser.add_argument("--deep-active-learning", action="store_true", help="Use slower model-disagreement selection.")
    parser.add_argument("--include-model-predictions", action="store_true", help="Add per-row supervised predictions.")
    parser.add_argument("--include-behavior-summary", action="store_true", help="Add per-row behavior-window feature summaries.")
    args = parser.parse_args()

    if args.total < 1:
        raise SystemExit("--total must be at least 1")
    if args.batches < 1:
        raise SystemExit("--batches must be at least 1")

    init_db()
    with SessionLocal() as db:
        result = export_batches(
            db,
            total=args.total,
            batches=args.batches,
            output_dir=Path(args.output_dir),
            include_real_ips=args.include_real_ips,
            deep_active_learning=args.deep_active_learning,
            include_model_predictions=args.include_model_predictions,
            include_behavior_summary=args.include_behavior_summary,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
