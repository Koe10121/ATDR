from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AlertEvidence, MLLabel, NormalizedLog
from atdr.app.detection.attack_mapping import attack_mapping_for_type, infer_attack_type_from_rules
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.rule_catalog import rule_spec
from atdr.app.detection.supervised_detector import predict_supervised_log
from atdr.app.ml.features import build_log_features
from atdr.app.services.case_service import case_trace_for_alert


BEHAVIOR_EXPLANATION_FEATURES = [
    "src_ip_5min_log_count",
    "src_ip_5min_deny_count",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "deny_rate_5min",
    "src_ip_15min_event_count",
    "src_ip_1h_event_count",
    "src_ip_24h_event_count",
    "dst_ip_5min_event_count",
    "rare_dst_port_flag",
    "rare_app_flag",
    "unknown_app_flag",
    "external_to_internal_flag",
    "internal_to_external_flag",
    "first_seen_src_ip_flag",
    "first_seen_app_flag",
    "repeated_connection_attempts",
    "scanning_like_behavior_score",
]

HUMAN_LABEL_SOURCES = {"manual", "reviewed_import"}

RULE_ANALYST_CHECKS: dict[str, tuple[str, ...]] = {
    "paloalto_threat_log": (
        "Verify the vendor threat subtype, severity, signature or threat name, and firewall action.",
        "Correlate the THREAT row with its traffic session and endpoint or service telemetry.",
    ),
    "possible_port_scan": (
        "Confirm whether the source is an authorized scanner or asset-discovery system.",
        "Review the destination-port spread, deny rate, targets, and five-minute event window.",
    ),
    "possible_horizontal_scan": (
        "Confirm whether same-service probing across destinations is authorized asset discovery.",
        "Review destination ownership, service port, deny rate, and source-scoped five-minute window.",
    ),
    "brute_force_like_attempts": (
        "Confirm repeated failures target the same destination and authentication service.",
        "Check authentication or identity-provider logs before concluding password guessing.",
    ),
    "beaconing_like_outbound": (
        "Inspect interval regularity, destination ownership, application identity, and endpoint process context.",
        "Compare with approved telemetry, keepalive, monitoring, and software-update schedules.",
    ),
    "connection_flood_suspicion": (
        "Verify connection volume, target service health, packet or bandwidth impact, and approved load tests.",
        "Do not claim denial of service without independent availability telemetry.",
    ),
    "high_outbound_bytes": (
        "Validate the outbound byte direction, destination, data owner, protocol, and approved transfer schedule.",
        "Do not claim exfiltration without content, authorization, or endpoint evidence.",
    ),
    "multiple_denied_connections": (
        "Check whether denies are expected policy enforcement, internet background noise, or a misconfigured client.",
    ),
    "deny_drop_action": (
        "Verify the matched firewall policy and whether the denied session is expected.",
    ),
    "app_risk_4": (
        "Confirm the application is approved and compare its destination and user context with local policy.",
    ),
    "app_risk_5": (
        "Confirm the application is approved and compare its destination and user context with local policy.",
    ),
    "suspicious_app_characteristic": (
        "Validate the broad vendor application characteristic against local business use and stronger evidence.",
    ),
    "unknown_or_incomplete_app": (
        "Check parser/source quality and later session records before treating an unresolved app as malicious.",
    ),
    "unusual_destination_port": (
        "Verify ownership and authorization for the non-standard service port.",
    ),
    "high_bytes_outlier": (
        "Check direction, application, destination, and normal transfer baselines.",
    ),
    "high_packets_outlier": (
        "Check traffic direction, service role, packet baseline, and availability telemetry.",
    ),
    "repeated_source_ip": (
        "Check whether NAT, monitoring, or a busy approved client explains the repeated source activity.",
    ),
}


def _rule_codes(rules: list[dict[str, Any]]) -> list[str]:
    return [
        str(rule.get("code") or "")
        for rule in rules
        if str(rule.get("code") or "") and rule.get("code") != "group_metadata"
    ]


def _rule_false_positive_considerations(rules: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for code in _rule_codes(rules):
        spec = rule_spec(code)
        if spec:
            values.extend(spec.false_positives)
    return list(dict.fromkeys(values))[:10]


def _rule_evidence_limitations(rules: list[dict[str, Any]], missing_context: list[str]) -> list[str]:
    values: list[str] = []
    for code in _rule_codes(rules):
        spec = rule_spec(code)
        if spec and spec.claim_boundary:
            values.append(spec.claim_boundary)
    values.extend(f"Missing context: {item}." for item in missing_context)
    return list(dict.fromkeys(values))[:10]


def _rule_specific_analyst_checks(rules: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for code in _rule_codes(rules):
        values.extend(RULE_ANALYST_CHECKS.get(code, ()))
    values.extend(
        [
            "Confirm the source and destination pattern is expected for this environment.",
            "Review linked logs and source health before approving any simulated response.",
            "Keep response actions simulated, justified, and analyst-approved.",
        ]
    )
    return list(dict.fromkeys(values))[:8]


def compact_behavior_features(db: Session, log: NormalizedLog) -> dict[str, Any]:
    try:
        features = build_log_features(db, log)
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    return {"available": True, **{key: features.get(key) for key in BEHAVIOR_EXPLANATION_FEATURES}}


def explain_log_triage(log: NormalizedLog) -> dict[str, Any]:
    """Return a deterministic, read-only explanation for a single normalized log.

    This is intentionally not a second detector. It explains the current
    evidence state for analysts: whether the log is already linked to an alert,
    which normalized fields look relevant, and why a row may not have become an
    alert yet.
    """

    alert_ids = sorted({item.alert_id for item in getattr(log, "alert_evidence", []) if item.alert_id is not None})
    parser_warnings = []
    if isinstance(log.parsed_json, dict):
        raw_warnings = log.parsed_json.get("parser_warnings")
        if isinstance(raw_warnings, list):
            parser_warnings = [str(item) for item in raw_warnings[:8]]
        parser_error = log.parsed_json.get("parser_error")
        if parser_error:
            parser_warnings.append(str(parser_error))

    normalized_signals: list[str] = []
    action = (log.action or "").lower()
    session_end = (log.session_end_reason or "").lower()
    app = (log.app or "").lower()
    src_zone = (log.src_zone or "").lower()
    dst_zone = (log.dst_zone or "").lower()

    if any(token in action or token in session_end for token in ("deny", "drop", "reset")):
        normalized_signals.append("deny/drop/reset behavior")
    if app in {"", "unknown", "incomplete", "not-applicable", "unknown-tcp"}:
        normalized_signals.append("unknown or incomplete application")
    if log.app_risk is not None and log.app_risk >= 4:
        normalized_signals.append(f"high application risk {log.app_risk}")
    if log.dst_port is not None:
        normalized_signals.append(f"destination port {log.dst_port}")
    if ("outside" in src_zone or "untrust" in src_zone or "internet" in src_zone) and any(
        token in dst_zone for token in ("inside", "trust", "lan", "wlan", "corp")
    ):
        normalized_signals.append("external-to-internal direction")
    if log.is_anomaly:
        normalized_signals.append(f"IsolationForest anomaly score {log.anomaly_score}")

    normalized_fields_used = {
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "src_port": log.src_port,
        "dst_port": log.dst_port,
        "app": log.app,
        "action": log.action,
        "protocol": log.protocol,
        "src_zone": log.src_zone,
        "dst_zone": log.dst_zone,
        "bytes": log.bytes,
        "packets": log.packets,
        "app_risk": log.app_risk,
        "session_end_reason": log.session_end_reason,
    }

    if alert_ids:
        status = "flagged"
        summary = f"This log is linked to alert(s): {', '.join(str(item) for item in alert_ids)}."
        reasons = ["The log is already part of alert evidence."]
    else:
        status = "not_flagged"
        summary = "No active alert evidence currently links to this log."
        reasons = [
            "No alert evidence row currently references this normalized log.",
            "It may be benign, below alert threshold, already covered by another grouped alert, suppressed by policy, or detection may not have run after ingestion.",
        ]
        if normalized_signals:
            reasons.append("Analyst-relevant fields exist, but they did not produce an alert link on their own.")
        else:
            reasons.append("No obvious rule-level signal is visible in the normalized fields returned for this row.")

    evidence_strength = (
        "moderate"
        if alert_ids and normalized_signals and not parser_warnings
        else "limited"
    )
    missing_context = []
    if parser_warnings:
        missing_context.append("clean parser evidence")
    if app in {"", "unknown", "incomplete", "not-applicable", "unknown-tcp"}:
        missing_context.append("confirmed application identity")
    if not alert_ids:
        missing_context.append("authoritative alert linkage")
    missing_context.append("asset ownership and expected traffic baseline")

    analyst_next_steps = [
        "Check nearby logs from the same source IP and time window.",
        "Review parser warnings before trusting missing fields.",
        "If evidence looks suspicious, add or update a human-reviewed label.",
    ]
    if alert_ids:
        analyst_next_steps.insert(0, "Open the related alert and review the Why flagged panel.")
    else:
        analyst_next_steps.insert(0, "Run detection after ingestion if this log was imported recently.")

    return {
        "status": status,
        "summary": summary,
        "reasons": reasons,
        "why_flagged": summary if alert_ids else None,
        "why_not_flagged": summary if not alert_ids else None,
        "normalized_fields_used": normalized_fields_used,
        "normalized_signals": normalized_signals[:10],
        "rule_evidence": normalized_signals[:10],
        "anomaly_evidence": {
            "is_anomaly": bool(log.is_anomaly),
            "anomaly_score": log.anomaly_score,
        },
        "ml_evidence": {
            "supervised_prediction_available": False,
            "decision_support_only": True,
        },
        "risk_score": None,
        "severity": None,
        "attack_mapping": None,
        "evidence_strength": evidence_strength,
        "missing_context": list(dict.fromkeys(missing_context)),
        "parser_warnings": parser_warnings[:8],
        "alert_ids": alert_ids,
        "decision_support_only": True,
        "response_automation_allowed": False,
        "safety_note": "Decision support only. Response automation remains disabled.",
        "analyst_next_steps": analyst_next_steps,
    }


def alert_explanation_completeness(alert: Alert, summary: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = summary or {}
    group_metadata = next(
        (rule for rule in (alert.matched_rules_json or []) if isinstance(rule, dict) and rule.get("code") == "group_metadata"),
        {},
    )
    has_source_or_destination = bool(
        alert.src_ip
        or alert.dst_ip
        or group_metadata.get("sample_src_ips")
        or group_metadata.get("sample_dst_ips")
    )
    exact_signals = summary.get("exact_evidence_signals") or []
    has_exact_signal = any(
        isinstance(signal, dict)
        and bool(signal.get("code"))
        and signal.get("score_contribution") is not None
        and bool(signal.get("observed"))
        for signal in exact_signals
    )
    evidence_limitations = summary.get("evidence_limitations") or []
    false_positive_considerations = summary.get("false_positive_considerations") or []
    traceability = summary.get("traceability") or {}
    case_trace = traceability.get("case") or {}
    checks = {
        "alert_title": bool(alert.title),
        "alert_type": bool(alert.alert_type),
        "severity": bool(alert.severity),
        "risk_score": alert.threat_score is not None,
        "source_or_destination": has_source_or_destination,
        "matched_rule_or_ml_reason": bool(
            (summary.get("matched_rule_names") or [])
            or (summary.get("supervised") or {}).get("predicted_label")
            or (alert.matched_rules_json or [])
        ),
        "evidence_count": bool(
            summary.get("evidence_count")
            or getattr(alert, "evidence", None)
        ),
        "why_flagged": bool(summary.get("why_flagged") or alert.explanation),
        "recommended_analyst_action": bool(alert.recommended_response),
        "attack_type_and_mapping": bool(
            summary.get("attack_type")
            and (summary.get("attack_mapping") or {}).get("mapping_origin")
        ),
        "exact_evidence_signals": has_exact_signal,
        "evidence_limitations": bool(evidence_limitations),
        "false_positive_considerations": bool(false_positive_considerations),
        "prioritized_analyst_checks": bool(
            summary.get("prioritized_analyst_checks")
        ),
        "source_traceability_field": isinstance(
            traceability.get("source_ids"),
            list,
        ),
        "related_log_traceability": bool(
            traceability.get("evidence_log_ids")
            and int(traceability.get("related_log_count") or 0) >= 1
        ),
        "case_traceability": bool(case_trace.get("case_id")),
        "decision_support_safety": bool(
            summary.get("decision_support_only") is True
            and summary.get("response_automation_allowed") is False
        ),
    }
    missing = [name for name, passed in checks.items() if not passed]
    score = round(sum(1 for passed in checks.values() if passed) / max(len(checks), 1), 4)
    return {
        "score": score,
        "passed": not missing,
        "checks": checks,
        "missing": missing,
    }


def _latest_label_by_log(db: Session, log_ids: list[int]) -> dict[int, MLLabel]:
    if not log_ids:
        return {}
    rows = db.scalars(
        select(MLLabel)
        .where(MLLabel.log_id.in_(log_ids))
        .order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))
    ).all()
    latest: dict[int, MLLabel] = {}
    for row in rows:
        latest.setdefault(row.log_id, row)
    return latest


def _primary_attack_type(alert: Alert, labels: dict[int, MLLabel]) -> tuple[str, str]:
    rule_attack_type = infer_attack_type_from_rules(alert.matched_rules_json or [])
    if rule_attack_type != "unknown_anomaly":
        return rule_attack_type, "deterministic_rule_mapping"
    for label in labels.values():
        source = str(label.label_source or "manual")
        if (
            label.reviewed
            and source in HUMAN_LABEL_SOURCES
            and label.attack_type
            and label.attack_type != "normal"
        ):
            return label.attack_type, "human_reviewed_disposition"
    return rule_attack_type, "deterministic_rule_mapping"


def build_alert_detection_summary(db: Session, alert: Alert) -> dict[str, Any]:
    evidence_logs = list(
        db.scalars(
            select(NormalizedLog)
            .join(
                AlertEvidence,
                AlertEvidence.normalized_log_id == NormalizedLog.id,
            )
            .where(AlertEvidence.alert_id == alert.id)
            .order_by(AlertEvidence.id.asc())
            .limit(25)
        )
    )
    primary_log = evidence_logs[0] if evidence_logs else None
    evidence_ids = [log.id for log in evidence_logs]
    labels = _latest_label_by_log(db, evidence_ids)
    attack_type, attack_mapping_origin = _primary_attack_type(alert, labels)
    mapping = attack_mapping_for_type(attack_type)
    mapping["mapping_origin"] = attack_mapping_origin
    mapping["mitre_supported"] = str(mapping.get("technique_id") or "").startswith("T")
    rule_matches = [rule for rule in (alert.matched_rules_json or []) if rule.get("code") != "group_metadata"]
    authoritative_rule_matches = [rule for rule in rule_matches if rule.get("code") != "ml_anomaly_detected"]
    advisory_anomaly_matches = [rule for rule in rule_matches if rule.get("code") == "ml_anomaly_detected"]
    anomaly_logs = [log for log in evidence_logs if log.is_anomaly]
    anomaly_scores = [float(log.anomaly_score) for log in evidence_logs if log.anomaly_score is not None]
    supervised: dict[str, Any] = {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0}
    if primary_log is not None:
        try:
            supervised = predict_supervised_log(db, primary_log.id, rule_score=alert.threat_score)
        except Exception:
            supervised = {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0}
    hybrid = supervised.get("hybrid_risk") if supervised.get("hybrid_risk") else hybrid_risk_score(
        rule_score=alert.threat_score,
        isolation_anomaly_score=primary_log.anomaly_score if primary_log else None,
        isolation_is_anomaly=bool(primary_log and primary_log.is_anomaly),
        supervised_malicious_probability=float(supervised.get("malicious_probability") or 0),
    )
    behavior = compact_behavior_features(db, primary_log) if primary_log is not None else {"available": False}
    normalized_fields_used = (
        {
            "src_ip": primary_log.src_ip,
            "dst_ip": primary_log.dst_ip,
            "src_port": primary_log.src_port,
            "dst_port": primary_log.dst_port,
            "app": primary_log.app,
            "action": primary_log.action,
            "protocol": primary_log.protocol,
            "src_zone": primary_log.src_zone,
            "dst_zone": primary_log.dst_zone,
            "bytes": primary_log.bytes,
            "packets": primary_log.packets,
            "app_risk": primary_log.app_risk,
            "session_end_reason": primary_log.session_end_reason,
        }
        if primary_log is not None
        else {}
    )

    detection_sources: list[str] = []
    if authoritative_rule_matches:
        detection_sources.append("rule")
    if anomaly_logs or advisory_anomaly_matches:
        detection_sources.append("anomaly")
    if len(detection_sources) > 1:
        detection_sources.append("hybrid")
    detection_sources = list(dict.fromkeys(detection_sources))

    authoritative_evidence_points: list[str] = []
    for rule in authoritative_rule_matches[:4]:
        title = rule.get("title") or rule.get("code")
        explanation = rule.get("explanation")
        authoritative_evidence_points.append(f"{title}: {explanation}" if explanation else str(title))
    evidence_points = list(authoritative_evidence_points)
    if behavior.get("src_ip_5min_deny_count"):
        evidence_points.append(f"Source had {behavior['src_ip_5min_deny_count']} deny/drop/reset events in 5 minutes.")
    if behavior.get("src_ip_5min_unique_dst_ports"):
        evidence_points.append(f"Source touched {behavior['src_ip_5min_unique_dst_ports']} unique destination ports in 5 minutes.")
    if behavior.get("src_ip_5min_unique_dst_ips"):
        evidence_points.append(f"Source reached {behavior['src_ip_5min_unique_dst_ips']} unique destination IPs in 5 minutes.")
    if behavior.get("repeated_connection_attempts"):
        evidence_points.append(f"Repeated connection attempts observed: {behavior['repeated_connection_attempts']}.")
    if behavior.get("scanning_like_behavior_score"):
        evidence_points.append(f"Scanning-like behavior score is {behavior['scanning_like_behavior_score']}.")
    if behavior.get("rare_dst_port_flag"):
        evidence_points.append("Destination port is rare for the current dataset.")
    if behavior.get("rare_app_flag"):
        evidence_points.append("Application is rare for the current dataset.")
    if behavior.get("unknown_app_flag"):
        evidence_points.append("Application is unknown or incomplete.")
    if behavior.get("external_to_internal_flag"):
        evidence_points.append("Traffic direction is external to internal.")
    elif behavior.get("internal_to_external_flag"):
        evidence_points.append("Traffic direction is internal to external.")
    if anomaly_scores:
        evidence_points.append(
            "Advisory IsolationForest anomaly score range: "
            f"{round(min(anomaly_scores), 6)} to {round(max(anomaly_scores), 6)}."
        )
    diagnostic_points: list[str] = []
    if supervised.get("predicted_label"):
        if supervised.get("queue_probability") is not None:
            diagnostic_points.append(
                "Governed supervised queue suggests "
                f"{supervised.get('queue_decision')} at probability {supervised.get('queue_probability', 0.0)} "
                f"against threshold {supervised.get('threshold', 0.5)}; it was not used to create this alert."
            )
        else:
            diagnostic_points.append(
                "Current supervised diagnostic predicts "
                f"{supervised.get('predicted_label')} with confidence {supervised.get('confidence', 0.0)}; "
                "it was not used to create this alert."
            )
    elif supervised.get("abstained"):
        compatibility = supervised.get("schema_compatibility") or {}
        diagnostic_points.append(
            "Supervised scoring abstained: "
            f"{compatibility.get('message', 'evidence did not satisfy the governed model contract')}"
        )

    observed_evidence = [
        {
            "field": key,
            "value": value,
        }
        for key, value in normalized_fields_used.items()
        if value is not None and str(value).strip() != ""
    ]
    rule_inferences = []
    confidence_rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
    rule_confidences: list[str] = []
    for rule in rule_matches:
        spec = rule_spec(str(rule.get("code") or ""))
        confidence = str(rule.get("confidence") or (spec.confidence if spec else "unknown"))
        rule_confidences.append(confidence)
        rule_inferences.append(
            {
                "rule_id": rule.get("rule_id") or (spec.rule_id if spec else None),
                "code": rule.get("code"),
                "title": rule.get("title"),
                "confidence": confidence,
                "claim_boundary": rule.get("claim_boundary") or (spec.claim_boundary if spec else None),
                "observed_explanation": rule.get("explanation"),
                "alert_authoritative": rule.get("code") != "ml_anomaly_detected",
                "evidence_role": (
                    "rule_alert_authority" if rule.get("code") != "ml_anomaly_detected" else "advisory_anomaly_only"
                ),
            }
        )
    strongest_rule_confidence = max(
        rule_confidences,
        key=lambda value: confidence_rank.get(value, 0),
        default="unknown",
    )
    missing_context = []
    if primary_log is not None:
        if not primary_log.app or str(primary_log.app).lower() in {"unknown", "incomplete", "not-applicable"}:
            missing_context.append("application identity")
        if not primary_log.src_zone or not primary_log.dst_zone:
            missing_context.append("complete zone direction")
        if not labels:
            missing_context.append("analyst-reviewed disposition")
        parsed = primary_log.parsed_json if isinstance(primary_log.parsed_json, dict) else {}
        if parsed.get("parser_warnings"):
            missing_context.append("clean parser evidence")
        if supervised.get("abstained"):
            missing_context.extend(
                f"ML-required field: {field}"
                for field in supervised.get("missing_required_features", [])
            )

    if authoritative_evidence_points:
        why = "Flagged by deterministic rule evidence because " + "; ".join(authoritative_evidence_points[:4])
    else:
        why = "Recorded for analyst review; authoritative rule metadata is unavailable. " + alert.explanation
    if not why.endswith("."):
        why += "."

    group_metadata = next(
        (
            rule
            for rule in alert.matched_rules_json or []
            if isinstance(rule, dict) and rule.get("code") == "group_metadata"
        ),
        {},
    )
    exact_evidence_signals = [
        {
            "rule_id": rule.get("rule_id") or (rule_spec(str(rule.get("code") or "")).rule_id if rule_spec(str(rule.get("code") or "")) else None),
            "code": rule.get("code"),
            "title": rule.get("title") or rule.get("code"),
            "score_contribution": int(rule.get("score") or 0),
            "observed": rule.get("explanation"),
            "alert_authoritative": rule.get("code") != "ml_anomaly_detected",
        }
        for rule in rule_matches
    ]
    raw_score = sum(
        int(rule.get("score") or 0)
        for rule in authoritative_rule_matches
    )
    false_positive_considerations = _rule_false_positive_considerations(rule_matches)
    evidence_limitations = _rule_evidence_limitations(rule_matches, list(dict.fromkeys(missing_context)))
    prioritized_analyst_checks = _rule_specific_analyst_checks(authoritative_rule_matches)
    traceability = {
        "alert_id": int(alert.id) if alert.id is not None else None,
        "source_ids": sorted(
            {
                int(source_id)
                for source_id in group_metadata.get("source_ids") or []
                if source_id is not None
            }
        ),
        "evidence_log_ids": evidence_ids,
        "evidence_log_ids_truncated": int(group_metadata.get("related_log_count") or len(evidence_ids)) > len(evidence_ids),
        "related_log_count": int(group_metadata.get("related_log_count") or len(evidence_ids)),
        "occurrence_count": int(group_metadata.get("occurrence_count") or len(evidence_ids)),
        "case": case_trace_for_alert(alert),
    }

    return {
        "alert_identity": {
            "id": int(alert.id) if alert.id is not None else None,
            "title": alert.title,
            "type": alert.alert_type,
            "severity": alert.severity,
            "risk_score": alert.threat_score,
        },
        "what_happened": alert.explanation,
        "detection_source": detection_sources,
        "attack_type": attack_type,
        "attack_mapping": mapping,
        "normalized_fields_used": normalized_fields_used,
        "rule_evidence": authoritative_evidence_points[:8],
        "risk_score_basis": {
            "reported_score": alert.threat_score,
            "raw_authoritative_rule_score": raw_score,
            "score_clamped_to_100": raw_score > 100,
            "components": [
                {
                    "code": item["code"],
                    "title": item["title"],
                    "score": item["score_contribution"],
                }
                for item in exact_evidence_signals
                if item["alert_authoritative"]
            ],
        },
        "exact_evidence_signals": exact_evidence_signals,
        "alert_authority": {
            "layer": "deterministic_rules",
            "authoritative_rule_count": len(authoritative_rule_matches),
            "authoritative_rule_names": [
                str(rule.get("title") or rule.get("code")) for rule in authoritative_rule_matches
            ],
            "anomaly_advisory_only": True,
            "supervised_decision_support_only": True,
            "hybrid_diagnostic_only": True,
        },
        "anomaly_evidence": {
            "present": bool(anomaly_logs),
            "count": len(anomaly_logs),
            "min_score": round(min(anomaly_scores), 6) if anomaly_scores else None,
            "max_score": round(max(anomaly_scores), 6) if anomaly_scores else None,
            "used_for_alert_creation": False,
            "evidence_role": "advisory_only",
        },
        "ml_evidence": {
            "predicted_label": supervised.get("predicted_label"),
            "queue_decision": supervised.get("queue_decision"),
            "queue_probability": supervised.get("queue_probability"),
            "threshold": supervised.get("threshold"),
            "calibration_method": supervised.get("calibration_method"),
            "model_version": supervised.get("model_version"),
            "feature_set_version": supervised.get("feature_set_version"),
            "lifecycle_state": supervised.get("lifecycle_state", "inactive"),
            "malicious_probability": supervised.get("malicious_probability", 0.0),
            "confidence": supervised.get("confidence", 0.0),
            "observed_signals": supervised.get("observed_signals", []),
            "confidence_limitations": supervised.get("confidence_limitations", []),
            "schema_compatibility": supervised.get("schema_compatibility"),
            "abstained": bool(supervised.get("abstained", False)),
            "abstention_reason_codes": supervised.get("abstention_reason_codes", []),
            "missing_required_features": supervised.get("missing_required_features", []),
            "used_for_alert_creation": False,
            "used_for_severity": False,
            "used_for_suppression": False,
            "evidence_role": "governed_shadow_or_decision_support_only",
            "decision_support_only": True,
        },
        "matched_rule_names": [str(rule.get("title") or rule.get("code")) for rule in rule_matches],
        "anomaly": {
            "present": bool(anomaly_logs),
            "count": len(anomaly_logs),
            "min_score": round(min(anomaly_scores), 6) if anomaly_scores else None,
            "max_score": round(max(anomaly_scores), 6) if anomaly_scores else None,
            "used_for_alert_creation": False,
            "evidence_role": "advisory_only",
        },
        "supervised": {
            "predicted_label": supervised.get("predicted_label"),
            "queue_decision": supervised.get("queue_decision"),
            "queue_probability": supervised.get("queue_probability"),
            "threshold": supervised.get("threshold"),
            "calibration_method": supervised.get("calibration_method"),
            "model_version": supervised.get("model_version"),
            "feature_set_version": supervised.get("feature_set_version"),
            "lifecycle_state": supervised.get("lifecycle_state", "inactive"),
            "malicious_probability": supervised.get("malicious_probability", 0.0),
            "confidence": supervised.get("confidence", 0.0),
            "observed_signals": supervised.get("observed_signals", []),
            "confidence_limitations": supervised.get("confidence_limitations", []),
            "schema_compatibility": supervised.get("schema_compatibility"),
            "abstained": bool(supervised.get("abstained", False)),
            "abstention_reason_codes": supervised.get("abstention_reason_codes", []),
            "missing_required_features": supervised.get("missing_required_features", []),
            "used_for_alert_creation": False,
            "used_for_severity": False,
            "used_for_suppression": False,
            "evidence_role": "governed_shadow_or_decision_support_only",
            "decision_support_only": True,
        },
        "hybrid_risk": {**hybrid, "used_for_alert_creation": False, "evidence_role": "current_diagnostic_only"},
        "observed_evidence": observed_evidence,
        "rule_inferences": rule_inferences,
        "diagnostic_evidence": diagnostic_points,
        "missing_context": list(dict.fromkeys(missing_context)),
        "evidence_limitations": evidence_limitations,
        "false_positive_considerations": false_positive_considerations,
        "evidence_confidence": strongest_rule_confidence,
        "behavior_window": behavior,
        "top_evidence_points": evidence_points[:8],
        "why_flagged": why,
        "why_suspicious": why,
        "prioritized_analyst_checks": prioritized_analyst_checks,
        "analyst_next_steps": prioritized_analyst_checks,
        "traceability": traceability,
        "evidence_count": int(group_metadata.get("related_log_count") or len(evidence_ids)),
        "decision_support_only": True,
        "response_automation_allowed": False,
        "safety_note": "Decision support only. Response automation remains disabled.",
    }
