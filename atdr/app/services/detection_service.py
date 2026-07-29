from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.core.config import get_settings
from atdr.app.db.models import Alert, AuditLog, NormalizedLog, RawLog
from atdr.app.detection.ml_detector import apply_model_to_db
from atdr.app.detection.rules import DetectionResult, RuleMatch, build_detection_context, evaluate_rules
from atdr.app.detection.scoring import clamp_score, severity_from_score
from atdr.app.services.alert_service import (
    ALERT_DEDUP_ACTIVE_STATUSES,
    create_grouped_alert_from_detections,
    existing_evidence_log_ids,
)
from atdr.app.services.operation_run_service import (
    attack_type_counts_for_alerts,
    complete_detection_run,
    fail_detection_run,
    start_detection_run,
)
from atdr.app.services.suppression_service import (
    list_suppressions,
    matching_suppression,
    record_suppression_hit,
)
from atdr.app.services.watchlist_service import list_watchlist_items, matching_watchlist_items, record_watchlist_hits


GROUP_BUCKET_MINUTES = 5
LOW_SEVERITY_GROUP_MIN_EVIDENCE = 5
INTERNET_SWEEP_RULES = {"unusual_destination_port", "unknown_or_incomplete_app", "outside_to_inside"}
APP_RISK_POLICY_RULES = {"app_risk_4", "app_risk_5", "suspicious_app_characteristic"}
REPEATED_DESTINATION_RULES = {"beaconing_like_outbound", "connection_flood_suspicion"}
MULTI_EVENT_PATTERN_RULES = {"beaconing_like_outbound", "connection_flood_suspicion", "possible_port_scan"}
ADVISORY_EVIDENCE_RULES = frozenset({"ml_anomaly_detected"})
PRIMARY_RULE_PRIORITY = {
    "possible_port_scan": 100,
    "connection_flood_suspicion": 98,
    "brute_force_like_attempts": 97,
    "beaconing_like_outbound": 96,
    "multiple_denied_connections": 95,
    "paloalto_threat_log": 90,
    "watchlist_match": 88,
    "deny_drop_action": 80,
    "app_risk_5": 75,
    "app_risk_4": 70,
    "suspicious_app_characteristic": 65,
    "repeated_source_ip": 60,
    "unusual_destination_port": 55,
    "unknown_or_incomplete_app": 50,
    "outside_to_inside": 40,
    "high_outbound_bytes": 38,
    "high_bytes_outlier": 35,
    "high_packets_outlier": 35,
    "ml_anomaly_detected": 5,
}


@dataclass(slots=True)
class DetectionCandidate:
    log: NormalizedLog
    result: DetectionResult
    primary_rule: RuleMatch


def _alert_authoritative_matches(matches: list[RuleMatch]) -> list[RuleMatch]:
    """Return evidence that is permitted to create and classify an alert."""

    return [match for match in matches if match.code not in ADVISORY_EVIDENCE_RULES]


def _result_from_matches(
    matches: list[RuleMatch],
    *,
    scoring_matches: list[RuleMatch] | None = None,
) -> DetectionResult:
    authoritative = matches if scoring_matches is None else scoring_matches
    score = clamp_score(sum(match.score for match in authoritative))
    severity = severity_from_score(score)
    explanation = " ".join(match.explanation for match in matches)
    return DetectionResult(threat_score=score, severity=severity, explanation=explanation, matched_rules=matches)


def _primary_rule(matches: list[RuleMatch]) -> RuleMatch:
    return max(matches, key=lambda item: (PRIMARY_RULE_PRIORITY.get(item.code, 0), item.score))


def _event_time(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.high_res_timestamp or log.start_time


def _time_bucket(log: NormalizedLog, bucket_minutes: int = GROUP_BUCKET_MINUTES) -> str:
    event_time = _event_time(log)
    if event_time is None:
        return "unknown-time"
    minute = (event_time.minute // bucket_minutes) * bucket_minutes
    return event_time.replace(minute=minute, second=0, microsecond=0).isoformat()


def _outside_to_inside(log: NormalizedLog) -> bool:
    src_zone = (log.src_zone or "").lower()
    dst_zone = (log.dst_zone or "").lower()
    src_outside = "outside" in src_zone or "untrust" in src_zone or "internet" in src_zone
    dst_inside = any(token in dst_zone for token in ("inside", "trust", "lan", "wlan", "corp"))
    return src_outside and dst_inside


def _group_key(candidate: DetectionCandidate) -> tuple:
    log = candidate.log
    primary_code = candidate.primary_rule.code
    source_group = log.src_ip or "unknown-source"
    if primary_code in INTERNET_SWEEP_RULES and _outside_to_inside(log):
        source_group = "multiple-internet-sources"
    if primary_code in APP_RISK_POLICY_RULES and not _outside_to_inside(log):
        source_group = "multiple-app-risk-sources"
    destination_group = log.dst_ip if primary_code in REPEATED_DESTINATION_RULES else None
    dst_port = (
        log.dst_port
        if primary_code in {"deny_drop_action", "unusual_destination_port", "brute_force_like_attempts", *REPEATED_DESTINATION_RULES}
        else None
    )
    app = log.app if primary_code in {"paloalto_threat_log", *APP_RISK_POLICY_RULES, "beaconing_like_outbound"} else None
    time_bucket = "repeated-pattern-window" if primary_code in MULTI_EVENT_PATTERN_RULES else _time_bucket(log)
    zone_path = f"{log.src_zone or 'unknown'}->{log.dst_zone or 'unknown'}"
    return (
        primary_code,
        source_group,
        destination_group,
        time_bucket,
        dst_port,
        app,
        zone_path,
    )


def group_detection_candidates(
    candidates: list[DetectionCandidate],
) -> dict[tuple, list[DetectionCandidate]]:
    grouped: dict[tuple, list[DetectionCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(_group_key(candidate), []).append(candidate)
    return grouped


def _should_create_group_alert(candidates: list[DetectionCandidate]) -> bool:
    if any(candidate.primary_rule.code == "watchlist_match" for candidate in candidates):
        return True
    max_score = max(candidate.result.threat_score for candidate in candidates)
    if max_score <= 30:
        return len(candidates) >= LOW_SEVERITY_GROUP_MIN_EVIDENCE
    return True


def run_detection(
    db: Session,
    *,
    limit: int | None = 5000,
    use_ml: bool = True,
    actor: str = "system",
    source_id: int | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
    event_time_start: datetime | None = None,
    event_time_end: datetime | None = None,
    dedup_alert_cache: list[Alert] | None = None,
    dedup_evidence_id_cache: dict[int, set[int]] | None = None,
) -> dict:
    settings = get_settings()
    run = start_detection_run(
        db,
        detection_type="hybrid" if use_ml else "rule",
        details={
            "limit": limit,
            "use_ml": use_ml,
            "actor": actor,
            "source_id": source_id,
            "source_name": source_name,
            "source_type": source_type,
            "event_time_start": event_time_start.isoformat() if event_time_start else None,
            "event_time_end": event_time_end.isoformat() if event_time_end else None,
        },
    )
    statement = (
        select(NormalizedLog)
        .options(joinedload(NormalizedLog.raw_log))
        .order_by(NormalizedLog.id.desc())
    )
    try:
        if source_id is not None:
            statement = statement.join(RawLog, NormalizedLog.raw_log_id == RawLog.id).where(RawLog.source_id == source_id)
        event_time = func.coalesce(
            NormalizedLog.generated_time,
            NormalizedLog.receive_time,
            NormalizedLog.high_res_timestamp,
            NormalizedLog.start_time,
        )
        if event_time_start is not None:
            statement = statement.where(event_time >= event_time_start)
        if event_time_end is not None:
            statement = statement.where(event_time < event_time_end)
        if limit:
            statement = statement.limit(limit)
        logs = list(db.scalars(statement))
        logs.reverse()

        if use_ml:
            apply_model_to_db(db, limit=limit)

        context = build_detection_context(logs)
        already_alerted = existing_evidence_log_ids(db)
        active_watchlist_items = list_watchlist_items(db, active_only=True)
        candidates: list[DetectionCandidate] = []
        evaluated = 0
        watchlist_matches = 0
        advisory_anomaly_signals = 0
        advisory_only_logs = 0

        for log in logs:
            evaluated += 1
            if log.id in already_alerted:
                continue
            matches = evaluate_rules(log, context)
            matched_watchlist_items = matching_watchlist_items(log, active_watchlist_items)
            if matched_watchlist_items:
                watchlist_matches += len(matched_watchlist_items)
                record_watchlist_hits(matched_watchlist_items)
                indicators = ", ".join(
                    f"{item.indicator_type}:{item.indicator_value}" for item in matched_watchlist_items[:5]
                )
                severity_boost = max(item.severity_boost for item in matched_watchlist_items)
                matches.append(
                    RuleMatch(
                        code="watchlist_match",
                        title="Watchlist indicator match",
                        score=severity_boost,
                        explanation=f"Matched active watchlist indicator(s): {indicators}.",
                    )
                )
            if not matches:
                continue
            advisory_anomaly_signals += sum(
                1 for match in matches if match.code in ADVISORY_EVIDENCE_RULES
            )
            authoritative_matches = _alert_authoritative_matches(matches)
            if not authoritative_matches:
                advisory_only_logs += 1
                continue
            result = _result_from_matches(matches, scoring_matches=authoritative_matches)
            if result.threat_score >= settings.min_alert_score:
                candidates.append(
                    DetectionCandidate(
                        log=log,
                        result=result,
                        primary_rule=_primary_rule(authoritative_matches),
                    )
                )

        grouped = group_detection_candidates(candidates)
        candidate_alert_types = {
            grouped_candidates[0].primary_rule.code
            for grouped_candidates in grouped.values()
            if grouped_candidates
        }
        if dedup_alert_cache is None:
            dedup_alerts = (
                list(
                    db.scalars(
                        select(Alert)
                        .options(joinedload(Alert.evidence))
                        .where(
                            Alert.alert_type.in_(candidate_alert_types),
                            Alert.status.in_(ALERT_DEDUP_ACTIVE_STATUSES),
                        )
                        .order_by(Alert.updated_at.asc(), Alert.id.asc())
                    ).unique()
                )
                if candidate_alert_types
                else []
            )
        else:
            dedup_alerts = dedup_alert_cache
        evidence_id_cache = (
            dedup_evidence_id_cache
            if dedup_evidence_id_cache is not None
            else {}
        )
        known_alert_objects = {id(item) for item in dedup_alerts}
        active_suppressions = list_suppressions(db, active_only=True)
        created = 0
        deduplicated_alert_updates = 0
        suppressed_groups = 0
        suppressed_by_rules = 0
        touched_alerts = []
        for grouped_candidates in grouped.values():
            if not _should_create_group_alert(grouped_candidates):
                suppressed_groups += 1
                continue
            group_logs = [candidate.log for candidate in grouped_candidates]
            suppression = matching_suppression(
                db,
                alert_type=grouped_candidates[0].primary_rule.code,
                logs=group_logs,
                rules=active_suppressions,
            )
            if suppression is not None:
                record_suppression_hit(suppression, count=len(grouped_candidates))
                suppressed_by_rules += 1
                continue
            detections = [(candidate.log, candidate.result) for candidate in grouped_candidates]
            alert = create_grouped_alert_from_detections(
                db,
                detections,
                primary_rule_code=grouped_candidates[0].primary_rule.code,
                dedup_alerts=dedup_alerts,
                evidence_id_cache=evidence_id_cache,
            )
            touched_alerts.append(alert)
            if id(alert) in known_alert_objects:
                deduplicated_alert_updates += 1
            else:
                created += 1
                known_alert_objects.add(id(alert))

        run_attack_types = attack_type_counts_for_alerts(touched_alerts)
        run_details = {
            "evaluated": evaluated,
            "candidate_logs": len(candidates),
            "created_alerts": created,
            "deduplicated_alert_updates": deduplicated_alert_updates,
            "suppressed_low_groups": suppressed_groups,
            "suppressed_by_rules": suppressed_by_rules,
            "watchlist_matches": watchlist_matches,
            "advisory_anomaly_signals": advisory_anomaly_signals,
            "advisory_only_logs": advisory_only_logs,
            "rule_detection_authoritative": True,
            "limit": limit,
            "use_ml": use_ml,
            "source_id": source_id,
            "source_name": source_name,
            "source_type": source_type,
            "event_time_start": event_time_start.isoformat() if event_time_start else None,
            "event_time_end": event_time_end.isoformat() if event_time_end else None,
            "group_bucket_minutes": GROUP_BUCKET_MINUTES,
            "low_severity_group_min_evidence": LOW_SEVERITY_GROUP_MIN_EVIDENCE,
            "top_attack_types": run_attack_types,
        }
        complete_detection_run(
            db,
            run,
            logs_evaluated=evaluated,
            alerts_created=created,
            alerts_deduplicated=deduplicated_alert_updates,
            alerts_suppressed=suppressed_groups + suppressed_by_rules,
            top_attack_types=run_attack_types,
            details=run_details,
        )
        db.add(
            AuditLog(
                actor=actor,
                action="run_detection",
                target_type="normalized_logs",
                target_value="latest_batch",
                details={**run_details, "detection_run_id": run.id},
            )
        )
        db.commit()
        return {
            **run_details,
            "use_ml": use_ml,
            "detection_run_id": run.id,
            "group_bucket_minutes": GROUP_BUCKET_MINUTES,
            "low_severity_group_min_evidence": LOW_SEVERITY_GROUP_MIN_EVIDENCE,
        }
    except Exception as exc:
        fail_detection_run(db, run, error=f"{exc.__class__.__name__}: {exc}")
        db.commit()
        raise
