from collections import defaultdict
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from atdr.app.core.config import get_settings
from atdr.app.db.models import Alert, AlertEvidence, MLModelRun, NormalizedLog, SuppressionRule, WatchlistItem
from atdr.app.services.ml_service import dataset_profile, model_status


CLOSED_STATUSES = {"resolved", "false_positive"}
HIGH_SEVERITIES = {"High", "Critical"}


def _rate(part: int | float, total: int | float) -> float:
    return round((float(part) / float(total)) * 100, 2) if total else 0.0


def _count(db: Session, model, *filters) -> int:
    statement = select(func.count(model.id))
    for filter_clause in filters:
        statement = statement.where(filter_clause)
    return int(db.scalar(statement) or 0)


def _group_counts(db: Session, column, *, limit: int = 10) -> list[dict[str, Any]]:
    rows = db.execute(select(column, func.count()).group_by(column).order_by(desc(func.count())).limit(limit)).all()
    return [{"name": str(name or "unknown"), "count": int(count)} for name, count in rows]


def _alert_type_pressure(db: Session, total_alerts: int) -> list[dict[str, Any]]:
    rows = db.execute(select(Alert.alert_type, Alert.severity, func.count()).group_by(Alert.alert_type, Alert.severity)).all()
    by_type: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "severity_counts": defaultdict(int)})
    for alert_type, severity, count in rows:
        key = str(alert_type or "unknown")
        by_type[key]["count"] += int(count)
        by_type[key]["severity_counts"][str(severity or "unknown")] += int(count)

    items: list[dict[str, Any]] = []
    for alert_type, data in by_type.items():
        severity_counts = dict(data["severity_counts"])
        high_count = sum(severity_counts.get(severity, 0) for severity in HIGH_SEVERITIES)
        count = int(data["count"])
        share = _rate(count, total_alerts)
        if share >= 35:
            tuning_priority = "critical"
        elif share >= 20 or count >= 500:
            tuning_priority = "high"
        elif share >= 10 or count >= 100:
            tuning_priority = "medium"
        else:
            tuning_priority = "low"
        items.append(
            {
                "alert_type": alert_type,
                "count": count,
                "share_pct": share,
                "high_or_critical_count": high_count,
                "high_or_critical_rate": _rate(high_count, count),
                "severity_counts": severity_counts,
                "tuning_priority": tuning_priority,
            }
        )
    return sorted(items, key=lambda item: (item["count"], item["high_or_critical_count"]), reverse=True)


def _suppression_candidates(alert_pressure: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in alert_pressure:
        if item["count"] < 25:
            continue
        if item["high_or_critical_rate"] > 15:
            continue
        candidates.append(
            {
                "alert_type": item["alert_type"],
                "count": item["count"],
                "share_pct": item["share_pct"],
                "reason": "High-volume, mostly Low/Medium alert type. Review representative evidence before suppressing or lowering priority.",
                "recommended_action": "Create a reviewed suppression only for a known-benign source/app/rule combination, not for the whole alert type.",
            }
        )
    return candidates[:8]


def _matched_rule_codes(alert: Alert) -> list[str]:
    codes: list[str] = []
    for item in alert.matched_rules_json or []:
        code = item.get("code") if isinstance(item, dict) else None
        if code and code != "group_metadata":
            codes.append(str(code))
    return codes


def _first_evidence_app(alert: Alert) -> str | None:
    for evidence in alert.evidence:
        log = evidence.normalized_log
        if log and log.app:
            return log.app
    return None


def _false_positive_learning(db: Session) -> dict[str, Any]:
    alerts = list(
        db.scalars(
            select(Alert)
            .options(selectinload(Alert.evidence).selectinload(AlertEvidence.normalized_log))
            .where(Alert.status == "false_positive")
            .order_by(desc(Alert.updated_at), desc(Alert.id))
            .limit(250)
        )
    )
    by_type: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "alert_ids": [], "rule_codes": defaultdict(int)})
    pattern_counts: dict[tuple[str, str | None, str | None], dict[str, Any]] = {}

    for alert in alerts:
        alert_type = alert.alert_type or "unknown"
        by_type[alert_type]["count"] += 1
        by_type[alert_type]["alert_ids"].append(alert.id)
        for code in _matched_rule_codes(alert):
            by_type[alert_type]["rule_codes"][code] += 1

        app = _first_evidence_app(alert)
        key = (alert_type, alert.src_ip, app)
        if key not in pattern_counts:
            pattern_counts[key] = {
                "alert_type": alert_type,
                "src_ip": alert.src_ip,
                "app": app,
                "count": 0,
                "sample_alert_ids": [],
            }
        pattern_counts[key]["count"] += 1
        pattern_counts[key]["sample_alert_ids"].append(alert.id)

    top_false_positive_types = [
        {
            "alert_type": alert_type,
            "count": data["count"],
            "sample_alert_ids": data["alert_ids"][:8],
            "top_rule_codes": [
                {"code": code, "count": count}
                for code, count in sorted(data["rule_codes"].items(), key=lambda item: item[1], reverse=True)[:5]
            ],
        }
        for alert_type, data in sorted(by_type.items(), key=lambda item: item[1]["count"], reverse=True)
    ]

    suppression_recommendations: list[dict[str, Any]] = []
    for pattern in sorted(pattern_counts.values(), key=lambda item: item["count"], reverse=True):
        if not pattern["src_ip"] and not pattern["app"]:
            continue
        count = int(pattern["count"])
        confidence = "high" if count >= 3 else "medium" if count == 2 else "low"
        suppression_recommendations.append(
            {
                "confidence": confidence,
                "alert_type": pattern["alert_type"],
                "src_ip": pattern["src_ip"],
                "app": pattern["app"],
                "false_positive_count": count,
                "sample_alert_ids": pattern["sample_alert_ids"][:8],
                "suggested_suppression": {
                    "alert_type": pattern["alert_type"],
                    "src_ip": pattern["src_ip"],
                    "app": pattern["app"],
                    "reason": (
                        "False-positive learning candidate. Review raw evidence and business context before creating "
                        "an active suppression."
                    ),
                },
                "recommended_action": (
                    "Review the sample alerts, confirm this is known-benign behavior, then create a narrow suppression "
                    "for this exact source/app/type combination."
                ),
            }
        )

    return {
        "false_positive_count": len(alerts),
        "top_false_positive_types": top_false_positive_types[:10],
        "suppression_recommendations": suppression_recommendations[:10],
        "learning_state": "active" if alerts else "needs_feedback",
        "message": (
            "False-positive decisions are available for tuning recommendations."
            if alerts
            else "Mark reviewed alerts as false positives to unlock data-driven suppression recommendations."
        ),
    }


def _readiness_item(name: str, status: str, detail: str, *, recommendation: str | None = None) -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "recommendation": recommendation}


def build_detection_tuning_report(db: Session) -> dict[str, Any]:
    settings = get_settings()
    total_logs = _count(db, NormalizedLog)
    total_alerts = _count(db, Alert)
    active_alerts = _count(db, Alert, Alert.status.not_in(CLOSED_STATUSES))
    unassigned_active = _count(db, Alert, Alert.status.not_in(CLOSED_STATUSES), Alert.assigned_to.is_(None))
    high_critical_open = _count(db, Alert, Alert.status.not_in(CLOSED_STATUSES), Alert.severity.in_(HIGH_SEVERITIES))
    high_critical_unassigned = _count(
        db,
        Alert,
        Alert.status.not_in(CLOSED_STATUSES),
        Alert.severity.in_(HIGH_SEVERITIES),
        Alert.assigned_to.is_(None),
    )
    false_positive_alerts = _count(db, Alert, Alert.status == "false_positive")
    active_suppressions = _count(db, SuppressionRule, SuppressionRule.active.is_(True))
    active_watchlists = _count(db, WatchlistItem, WatchlistItem.active.is_(True))

    ml_status = model_status(db)
    profile = dataset_profile(db)
    latest_training = ml_status.get("latest_training") or {}
    latest_scoring = ml_status.get("latest_scoring") or {}
    anomaly_rate = float(ml_status.get("current_anomaly_rate") or 0)
    expected_rate = round(float(ml_status.get("contamination") or settings.ml_contamination) * 100, 2)
    alert_pressure = _alert_type_pressure(db, total_alerts)
    alerts_per_1000_logs = round((total_alerts / total_logs) * 1000, 2) if total_logs else 0.0

    readiness: list[dict[str, Any]] = [
        _readiness_item(
            "Data Volume",
            "ready" if total_logs >= 10000 else "needs_data",
            f"{total_logs} normalized logs available.",
            recommendation=None if total_logs >= 10000 else "Collect at least 10,000 representative logs before baseline decisions.",
        ),
        _readiness_item(
            "ML Baseline",
            "ready" if ml_status.get("artifact_exists") and (latest_training.get("training_log_count") or 0) >= 1000 else "needs_training",
            f"Latest training used {latest_training.get('training_log_count') or 0} logs.",
            recommendation="Use baseline-only training on reviewed normal traffic." if not ml_status.get("artifact_exists") else None,
        ),
        _readiness_item(
            "Anomaly Rate",
            "ready" if 0.5 <= anomaly_rate <= max(5.0, expected_rate * 2) else "review",
            f"{anomaly_rate}% current anomaly rate versus {expected_rate}% configured contamination.",
            recommendation="Review contamination, baseline filters, and top anomalous entities before trusting ML priority." if anomaly_rate else None,
        ),
        _readiness_item(
            "Alert Noise",
            "review" if alerts_per_1000_logs > 30 else "ready",
            f"{alerts_per_1000_logs} alerts per 1,000 logs.",
            recommendation="Tune noisy rules and reviewed suppressions before a live SOC pilot." if alerts_per_1000_logs > 30 else None,
        ),
        _readiness_item(
            "Ownership",
            "review" if high_critical_unassigned else "ready",
            f"{high_critical_unassigned} unassigned active High/Critical alerts.",
            recommendation="Assign High/Critical alerts before supervisor or lab-pilot handoff." if high_critical_unassigned else None,
        ),
        _readiness_item(
            "Live Ingestion",
            "available" if settings.syslog_host == "127.0.0.1" else "review",
            f"UDP receiver command available on {settings.syslog_host}:{settings.syslog_port}.",
            recommendation="Run as a supervised service and bind only to approved lab interfaces for pilot use.",
        ),
        _readiness_item(
            "Response Safety",
            "ready" if settings.response_simulation else "review",
            "Response actions are simulated."
            if settings.response_simulation
            else f"Simulation is disabled, but provider '{settings.response_provider}' still requires approved connector validation.",
            recommendation=None
            if settings.response_simulation
            else "Re-enable simulation until a connector, allowlist, rollback, and change process are tested.",
        ),
    ]

    recommendations: list[str] = []
    false_positive_learning = _false_positive_learning(db)
    if high_critical_unassigned:
        recommendations.append("Assign owners to active High/Critical alerts before treating the queue as operationally controlled.")
    if alerts_per_1000_logs > 30:
        recommendations.append("Start tuning with the highest-volume alert types and review whether they need thresholds, grouping, or suppressions.")
    if active_suppressions == 0 and total_alerts >= 500:
        recommendations.append("Create reviewed suppressions for known-benign noisy combinations after evidence review.")
    if anomaly_rate > max(5.0, expected_rate * 2):
        recommendations.append("Current anomaly rate is high; tune baseline training and contamination before using ML to prioritize response.")
    if false_positive_alerts == 0 and total_alerts >= 100:
        recommendations.append("Mark reviewed false positives so tuning reports can learn which alert types are noisy.")
    if false_positive_learning["suppression_recommendations"]:
        recommendations.append("Review false-positive learning recommendations and create narrow suppressions for confirmed benign patterns.")
    recommendations.extend(profile.get("recommendations", [])[:2])

    latest_runs = [
        {
            "id": run.id,
            "operation": run.operation,
            "status": run.status,
            "actor": run.actor,
            "training_log_count": run.training_log_count,
            "scored_log_count": run.scored_log_count,
            "anomaly_rate": run.anomaly_rate,
            "created_at": run.created_at,
        }
        for run in db.scalars(select(MLModelRun).order_by(desc(MLModelRun.created_at), desc(MLModelRun.id)).limit(5))
    ]

    return {
        "summary": {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "alerts_per_1000_logs": alerts_per_1000_logs,
            "high_critical_open": high_critical_open,
            "high_critical_unassigned": high_critical_unassigned,
            "unassigned_active": unassigned_active,
            "false_positive_alerts": false_positive_alerts,
            "active_suppressions": active_suppressions,
            "active_watchlists": active_watchlists,
        },
        "alert_type_pressure": alert_pressure[:12],
        "suppression_candidates": _suppression_candidates(alert_pressure),
        "false_positive_learning": false_positive_learning,
        "severity_distribution": _group_counts(db, Alert.severity),
        "status_distribution": _group_counts(db, Alert.status),
        "ml": {
            "artifact_exists": ml_status.get("artifact_exists"),
            "latest_training_log_count": latest_training.get("training_log_count"),
            "latest_scored_log_count": latest_scoring.get("scored_log_count"),
            "current_anomaly_rate": anomaly_rate,
            "expected_contamination_rate": expected_rate,
            "baseline_candidate_count": profile.get("baseline_candidate_count"),
            "high_risk_rate": profile.get("high_risk_rate"),
            "unknown_app_rate": profile.get("unknown_app_rate"),
            "latest_runs": latest_runs,
        },
        "production_readiness": readiness,
        "recommendations": list(dict.fromkeys(recommendations)),
    }
