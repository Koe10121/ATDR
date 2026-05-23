import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import AuditLog, NormalizedLog
from atdr.app.services.ml_service import UNKNOWN_APPS, dataset_profile, evaluation_report, model_status


REVIEW_VERSION = "ml-baseline-review-v1"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _baseline_filters(max_app_risk: int) -> list:
    return [
        func.lower(NormalizedLog.action) == "allow",
        or_(NormalizedLog.app_risk.is_(None), NormalizedLog.app_risk <= max_app_risk),
        or_(NormalizedLog.app.is_(None), func.lower(NormalizedLog.app).not_in(UNKNOWN_APPS)),
        NormalizedLog.is_anomaly.is_(False),
    ]


def _logs_to_review_rows(logs: list[NormalizedLog], *, include_review_columns: bool) -> list[dict]:
    rows: list[dict] = []
    for log in logs:
        raw_line = log.raw_log.raw_line if log.raw_log else ""
        row = {
            "normalized_log_id": log.id,
            "generated_time": log.generated_time,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "src_zone": log.src_zone,
            "dst_zone": log.dst_zone,
            "app": log.app,
            "action": log.action,
            "protocol": log.protocol,
            "src_port": log.src_port,
            "dst_port": log.dst_port,
            "bytes": log.bytes,
            "packets": log.packets,
            "app_risk": log.app_risk,
            "is_anomaly": log.is_anomaly,
            "anomaly_score": None if log.anomaly_score is None else round(float(log.anomaly_score), 6),
            "raw_evidence_excerpt": raw_line[:500],
        }
        if include_review_columns:
            row["review_label"] = ""
            row["analyst_notes"] = ""
        rows.append(row)
    return rows


def _sample_anomaly_rows(db: Session, limit: int) -> list[dict]:
    logs = list(
        db.scalars(
            select(NormalizedLog)
            .options(joinedload(NormalizedLog.raw_log))
            .where(NormalizedLog.is_anomaly.is_(True))
            .order_by(NormalizedLog.anomaly_score.asc(), desc(NormalizedLog.id))
            .limit(limit)
        )
    )
    return _logs_to_review_rows(logs, include_review_columns=True)


def _sample_baseline_rows(db: Session, *, limit: int, max_app_risk: int) -> list[dict]:
    statement = select(NormalizedLog).options(joinedload(NormalizedLog.raw_log)).order_by(desc(NormalizedLog.id)).limit(limit)
    for filter_clause in _baseline_filters(max_app_risk):
        statement = statement.where(filter_clause)
    rows = _logs_to_review_rows(list(db.scalars(statement)), include_review_columns=True)
    for row in rows:
        row["accepted_for_baseline"] = ""
    return rows


def _top_anomaly_examples(anomaly_rows: list[dict], limit: int = 10) -> list[dict]:
    return [
        {
            "normalized_log_id": row["normalized_log_id"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "app": row["app"],
            "action": row["action"],
            "dst_port": row["dst_port"],
            "app_risk": row["app_risk"],
            "anomaly_score": row["anomaly_score"],
        }
        for row in anomaly_rows[:limit]
    ]


def _readiness(profile: dict) -> dict:
    candidate_count = int(profile.get("baseline_candidate_count") or 0)
    total_logs = int(profile.get("total_logs") or 0)
    if candidate_count >= 1000:
        level = "ready_for_lab_review"
        message = "Baseline candidate volume is strong enough for a lab-pilot review cycle."
    elif candidate_count >= 100:
        level = "limited_but_usable"
        message = "Baseline candidate volume is usable for prototype review, but collect more reviewed traffic before production use."
    elif candidate_count >= 20:
        level = "minimum_viable"
        message = "Baseline candidate volume meets the minimum technical training threshold but is too small for production confidence."
    else:
        level = "not_ready"
        message = "Collect more allowed, low-risk, reviewed traffic before training or trusting anomaly scoring."
    return {
        "level": level,
        "message": message,
        "baseline_candidate_count": candidate_count,
        "total_logs": total_logs,
        "baseline_candidate_rate": profile.get("baseline_candidate_rate", 0),
    }


def _threshold_guidance(report: dict, readiness: dict) -> dict:
    status = report.get("model_status", {})
    anomaly_rate = float(report.get("anomaly_rate") or 0)
    expected_rate = float(status.get("contamination") or 0) * 100
    guidance: list[str] = [
        "Treat IsolationForest as assistive evidence only; do not automate containment from ML alone.",
        "Review anomaly_review.csv and label rows as true_positive, benign_unusual, or false_positive.",
        "Retrain with baseline-only traffic after removing reviewed noisy/benign outliers.",
    ]
    if expected_rate and anomaly_rate > expected_rate * 3:
        guidance.append("Current anomaly rate is much higher than configured contamination; review baseline quality and noisy features.")
    elif expected_rate and anomaly_rate < expected_rate * 0.25:
        guidance.append("Current anomaly rate is much lower than configured contamination; verify that scoring covered the intended logs.")
    if readiness["level"] in {"not_ready", "minimum_viable"}:
        guidance.append("Do not use this model for lab response decisions until the baseline window is reviewed and expanded.")
    return {
        "configured_contamination_percent": round(expected_rate, 2),
        "current_anomaly_rate_percent": anomaly_rate,
        "review_sample_recommendation": "Review at least the top 100 anomalies or all anomalies if fewer than 100.",
        "guidance": guidance,
    }


def build_ml_baseline_review(
    db: Session,
    *,
    anomaly_limit: int = 200,
    baseline_limit: int = 200,
    baseline_max_app_risk: int = 3,
) -> dict:
    profile = dataset_profile(db, baseline_max_app_risk=baseline_max_app_risk)
    report = evaluation_report(db)
    anomalies = _sample_anomaly_rows(db, anomaly_limit)
    baseline_sample = _sample_baseline_rows(db, limit=baseline_limit, max_app_risk=baseline_max_app_risk)
    readiness = _readiness(profile)
    threshold_guidance = _threshold_guidance(report, readiness)
    return {
        "review_version": REVIEW_VERSION,
        "generated_at": datetime.now(timezone.utc),
        "ml_assistive_only": True,
        "baseline_filter": {
            "action": "allow",
            "max_app_risk": baseline_max_app_risk,
            "exclude_unknown_apps": True,
            "exclude_existing_anomalies": True,
        },
        "model_status": model_status(db),
        "dataset_profile": profile,
        "baseline_readiness": readiness,
        "evaluation_summary": {
            "scored_log_count": report.get("scored_log_count", 0),
            "anomaly_count": report.get("anomaly_count", 0),
            "anomaly_rate": report.get("anomaly_rate", 0),
            "score_stats_all": report.get("score_stats_all", {}),
            "score_stats_anomalies": report.get("score_stats_anomalies", {}),
            "run_comparison": report.get("run_comparison", {}),
            "drift_signals": report.get("drift_signals", []),
            "top_anomalous_src_ips": report.get("top_anomalous_src_ips", []),
            "top_anomalous_apps": report.get("top_anomalous_apps", []),
            "top_anomalous_dst_ports": report.get("top_anomalous_dst_ports", []),
            "recommendations": report.get("recommendations", []),
        },
        "threshold_guidance": threshold_guidance,
        "anomaly_review_rows": anomalies,
        "baseline_candidate_rows": baseline_sample,
        "top_anomaly_examples": _top_anomaly_examples(anomalies),
        "next_actions": [
            "Have an analyst review anomaly_review.csv and label each row.",
            "Review baseline_candidate_sample.csv and mark rows that are safe normal traffic.",
            "Adjust suppressions or rule thresholds for confirmed noisy benign patterns.",
            "Retrain with baseline-only mode and rerun scoring after the review window is approved.",
            "Keep response actions simulated until firewall integration is formally approved.",
        ],
        "limitations": [
            "IsolationForest is unsupervised and does not prove malicious intent.",
            "Accuracy cannot be claimed without labeled analyst review.",
            "Campus/lab traffic patterns can drift; review anomaly rate and top entities after each scoring run.",
        ],
    }


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _safe_text(value) for key, value in row.items()})


def _markdown_summary(review: dict, manifest: dict) -> str:
    readiness = review["baseline_readiness"]
    summary = review["evaluation_summary"]
    guidance = review["threshold_guidance"]
    lines = [
        "# MFU ATDR ML Baseline Review",
        "",
        f"- Generated at: {_safe_text(review['generated_at'])}",
        f"- Review version: {review['review_version']}",
        "- AI posture: ML is assistive only; rules and analyst review remain primary.",
        f"- Baseline readiness: {readiness['level']} - {readiness['message']}",
        f"- Total logs: {readiness['total_logs']}",
        f"- Baseline candidates: {readiness['baseline_candidate_count']} ({readiness['baseline_candidate_rate']}%)",
        f"- Scored logs: {summary['scored_log_count']}",
        f"- Current anomalies: {summary['anomaly_count']} ({summary['anomaly_rate']}%)",
        f"- Expected contamination: {guidance['configured_contamination_percent']}%",
        "",
        "## Files",
    ]
    lines.extend(f"- `{name}`: {path}" for name, path in manifest["files"].items())
    lines.extend(["", "## Review Instructions"])
    lines.extend(f"- {item}" for item in guidance["guidance"])
    lines.extend(["", "## Next Actions"])
    lines.extend(f"- {item}" for item in review["next_actions"])
    lines.extend(["", "## Limitations"])
    lines.extend(f"- {item}" for item in review["limitations"])
    lines.append("")
    return "\n".join(lines)


def export_ml_baseline_review(
    db: Session,
    *,
    output_dir: str | Path | None = None,
    anomaly_limit: int = 200,
    baseline_limit: int = 200,
    baseline_max_app_risk: int = 3,
    actor: str = "cli",
    audit: bool = True,
) -> dict:
    review = build_ml_baseline_review(
        db,
        anomaly_limit=anomaly_limit,
        baseline_limit=baseline_limit,
        baseline_max_app_risk=baseline_max_app_risk,
    )
    base_dir = Path(output_dir) if output_dir is not None else Path(PROJECT_ROOT) / "ml_baseline_reviews"
    if not base_dir.is_absolute():
        base_dir = Path(PROJECT_ROOT) / base_dir
    target_dir = base_dir / f"ml-baseline-{_utc_timestamp()}"
    target_dir.mkdir(parents=True, exist_ok=True)

    summary_payload = {key: value for key, value in review.items() if key not in {"anomaly_review_rows", "baseline_candidate_rows"}}
    files = {
        "summary_json": target_dir / "ml_baseline_summary.json",
        "anomaly_review_csv": target_dir / "anomaly_review.csv",
        "baseline_candidate_csv": target_dir / "baseline_candidate_sample.csv",
        "markdown_summary": target_dir / "ML_BASELINE_REVIEW.md",
    }
    _write_json(files["summary_json"], summary_payload)
    _write_csv(files["anomaly_review_csv"], review["anomaly_review_rows"])
    _write_csv(files["baseline_candidate_csv"], review["baseline_candidate_rows"])

    manifest = {
        "ok": True,
        "output_dir": str(target_dir),
        "generated_at": review["generated_at"],
        "review_version": review["review_version"],
        "baseline_readiness": review["baseline_readiness"],
        "anomaly_rows": len(review["anomaly_review_rows"]),
        "baseline_candidate_rows": len(review["baseline_candidate_rows"]),
        "files": {name: str(path) for name, path in files.items()},
    }
    files["markdown_summary"].write_text(_markdown_summary(review, manifest), encoding="utf-8")

    if audit:
        db.add(
            AuditLog(
                actor=actor,
                action="export_ml_baseline_review",
                target_type="ml_baseline_review",
                target_value=str(target_dir),
                details={
                    "anomaly_rows": manifest["anomaly_rows"],
                    "baseline_candidate_rows": manifest["baseline_candidate_rows"],
                    "baseline_readiness": manifest["baseline_readiness"]["level"],
                    "output_dir": str(target_dir),
                },
            )
        )
        db.commit()
    return manifest
