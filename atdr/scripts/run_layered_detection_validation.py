import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.detection.hybrid_scoring import hybrid_risk_score, isolation_score_to_risk
from atdr.app.detection.ml_detector import apply_model_to_db
from atdr.app.detection.scoring import severity_from_score
from atdr.app.detection.supervised_detector import POSITIVE_LABELS, predict_supervised_log
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.source_service import get_or_create_source, source_to_dict
from atdr.scripts.generate_detection_variants import DEFAULT_OUTPUT_DIR as DEFAULT_VARIANT_DIR
from atdr.scripts.generate_detection_variants import generate_detection_variants
from atdr.scripts.run_detection_validation_suite import (
    SEVERITY_RANK,
    _json_default,
    _load_expectations,
)
from atdr.scripts.run_source_scenario import SCENARIOS, _temp_session_factory


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
LAYERED_EXPECTATIONS_PATH = SCENARIO_DIR / "layered_expectations.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "layered_detection"
MODES = ("rules_only", "anomaly_only", "supervised_only", "hybrid")


def _load_layered_expectations(path: Path = LAYERED_EXPECTATIONS_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_source_name(scenario: str, variant_id: int, mode: str, *, use_temp_db: bool) -> str:
    if use_temp_db:
        return f"layered-{scenario}-v{variant_id}-{mode}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"layered-{scenario}-v{variant_id}-{mode}-{stamp}"


def _logs_for_source(db: Session, source_id: int) -> list[NormalizedLog]:
    statement = (
        select(NormalizedLog)
        .join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
        .where(RawLog.source_id == source_id)
        .order_by(NormalizedLog.id)
    )
    return list(db.scalars(statement))


def _attack_types_from_alerts(alerts: list[dict[str, Any]]) -> set[str]:
    return {str(alert.get("attack_type") or "") for alert in alerts if alert.get("attack_type")}


def _expected_attack_types(expectation: dict[str, Any]) -> set[str]:
    if expectation.get("expected_attack_types"):
        return {str(item) for item in expectation["expected_attack_types"]}
    if expectation.get("expected_attack_type"):
        return {str(expectation["expected_attack_type"])}
    return set()


def _max_severity(alerts: list[dict[str, Any]]) -> str:
    return max(
        (str(alert.get("severity") or "Low") for alert in alerts),
        key=lambda value: SEVERITY_RANK.get(value, 0),
        default="Low",
    )


def _max_risk(alerts: list[dict[str, Any]]) -> int:
    return max((int(float(alert.get("risk_score") or 0)) for alert in alerts), default=0)


def _anomaly_evidence_quality(log: NormalizedLog) -> dict[str, Any]:
    parsed = log.parsed_json or {}
    profile = str(parsed.get("parser_profile") or "palo_alto")
    structured_values = (
        log.src_ip,
        log.dst_ip,
        log.app,
        log.action,
        log.protocol,
        log.dst_port,
        log.src_zone,
        log.dst_zone,
    )
    structured_field_count = sum(value not in {None, ""} for value in structured_values)
    warnings = [str(item) for item in parsed.get("parser_warnings") or []]
    parser_error = parsed.get("parser_error")
    limited = bool(
        profile in {"generic_syslog", "raw_fallback"}
        or parser_error
        or warnings
        or structured_field_count < 4
    )
    return {
        "status": "limited" if limited else "sufficient",
        "parser_profile": profile,
        "structured_field_count": structured_field_count,
        "parser_warning_count": len(warnings),
        "parser_error_present": bool(parser_error),
        "alert_authority": False,
    }


def _is_false_positive(mode: str, expectation: dict[str, Any], alerts: list[dict[str, Any]]) -> bool:
    if expectation.get("expected_alert_present"):
        return False
    severe = SEVERITY_RANK.get(_max_severity(alerts), 0) >= SEVERITY_RANK["High"]
    if mode in {"anomaly_only", "supervised_only"}:
        return bool(severe)
    max_allowed = expectation.get("expected_alert_count_max")
    too_many = max_allowed is not None and len(alerts) > int(max_allowed)
    return bool(severe or too_many)


def _is_false_negative(mode: str, expectation: dict[str, Any], alerts: list[dict[str, Any]]) -> bool:
    if mode not in {"rules_only", "hybrid"}:
        return False
    if not expectation.get("expected_alert_present"):
        return False
    if not alerts:
        return True
    expected = _expected_attack_types(expectation)
    if expected:
        return not expected.issubset(_attack_types_from_alerts(alerts))
    return False


def _alert_rows_from_db(db: Session, source_id: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    alerts = list_alerts(db, source_id=source_id, limit=75)
    summaries = [build_alert_detection_summary(db, alert) for alert in alerts]
    rows = [
        {
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "risk_score": alert.threat_score,
            "title": alert.title,
            "evidence_count": len(alert.evidence),
            "attack_type": summary.get("attack_type"),
            "why_flagged": summary.get("why_flagged"),
            "detection_source": summary.get("detection_source"),
            "top_evidence_points": summary.get("top_evidence_points", []),
            "rule_signals": [
                str(rule.get("code"))
                for rule in alert.matched_rules_json or []
                if rule.get("code") and rule.get("code") != "group_metadata"
            ],
            "anomaly_scores": [
                float(item.normalized_log.anomaly_score)
                for item in alert.evidence
                if item.normalized_log is not None and item.normalized_log.anomaly_score is not None
            ],
            "supervised_probability": float((summary.get("supervised") or {}).get("queue_probability") or 0.0),
            "hybrid_components": (summary.get("hybrid_risk") or {}).get("components") or {},
            "layered_evidence": {
                "rule": _rule_evidence(alert.matched_rules_json or []),
                "anomaly": _anomaly_evidence(summary),
                "ml": _supervised_evidence(summary),
                "hybrid": _hybrid_evidence(summary),
            },
        }
        for alert, summary in zip(alerts, summaries, strict=False)
    ]
    return rows, summaries


def _rule_evidence(rules: list[dict[str, Any]]) -> list[str]:
    return [
        f"{rule.get('title') or rule.get('code')}: {rule.get('explanation') or ''}".strip()
        for rule in rules
        if rule.get("code") not in {"ml_anomaly_detected", "group_metadata"}
    ][:5]


def _anomaly_evidence(summary: dict[str, Any]) -> str:
    anomaly = summary.get("anomaly") or {}
    if not anomaly.get("present"):
        return "No IsolationForest anomaly signal in this alert."
    return f"IsolationForest anomaly signal present on {anomaly.get('count', 0)} evidence row(s)."


def _supervised_evidence(summary: dict[str, Any]) -> str:
    supervised = summary.get("supervised") or {}
    label = supervised.get("predicted_label")
    if not label:
        return "No supervised SOC triage prediction available."
    confidence = supervised.get("confidence", 0.0)
    return f"Supervised SOC triage predicted {label} with confidence {confidence}."


def _hybrid_evidence(summary: dict[str, Any]) -> str:
    hybrid = summary.get("hybrid_risk") or {}
    if not hybrid:
        return "Hybrid risk score not available."
    components = hybrid.get("components") or {}
    return (
        f"Hybrid risk {hybrid.get('final_risk_score')} from rule={components.get('rule_score')}, "
        f"anomaly={components.get('isolation_score')}, supervised={components.get('supervised_score')}."
    )


def _diagnostic_anomaly_alerts(db: Session, source_id: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    result = apply_model_to_db(db, limit=None)
    logs = _logs_for_source(db, source_id)
    rows: list[dict[str, Any]] = []
    for log in logs:
        if not log.is_anomaly:
            continue
        raw_risk = int(round(isolation_score_to_risk(log.anomaly_score, is_anomaly=True)))
        evidence_quality = _anomaly_evidence_quality(log)
        risk = min(raw_risk, 40) if evidence_quality["status"] == "limited" else raw_risk
        rows.append(
            {
                "alert_id": None,
                "alert_type": "diagnostic_anomaly",
                "severity": severity_from_score(risk),
                "risk_score": risk,
                "raw_anomaly_risk_score": raw_risk,
                "anomaly_score": float(log.anomaly_score) if log.anomaly_score is not None else None,
                "evidence_quality": evidence_quality,
                "title": f"Diagnostic anomaly signal for log {log.id}",
                "evidence_count": 1,
                "attack_type": "unknown_anomaly",
                "why_flagged": "IsolationForest marked this event as unusual compared with the model baseline.",
                "detection_source": ["anomaly"],
                "top_evidence_points": [
                    f"Anomaly score={round(float(log.anomaly_score), 6) if log.anomaly_score is not None else 'not_available'}.",
                    (
                        "Limited parser/field evidence caps this advisory signal below High severity."
                        if evidence_quality["status"] == "limited"
                        else "Structured evidence is sufficient for normal advisory severity mapping."
                    ),
                    "Diagnostic anomaly-only mode does not trigger response actions.",
                ],
                "layered_evidence": {
                    "rule": [],
                    "anomaly": "IsolationForest anomaly diagnostic signal.",
                    "ml": "Not evaluated in anomaly-only mode.",
                    "hybrid": "Not evaluated in anomaly-only mode.",
                },
                "rule_signals": [],
                "anomaly_scores": [float(log.anomaly_score)] if log.anomaly_score is not None else [],
                "supervised_probability": 0.0,
                "hybrid_components": {},
            }
        )
    return rows, {
        "scored_logs": len(result),
        "anomaly_count": len(rows),
        "model_available": bool(result),
        "persistent_alerts_created": 0,
    }


def _diagnostic_supervised_alerts(db: Session, source_id: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    logs = _logs_for_source(db, source_id)
    rows: list[dict[str, Any]] = []
    predictions: list[dict[str, Any]] = []
    for log in logs:
        prediction = predict_supervised_log(db, log.id, rule_score=0)
        if prediction.get("predicted_label"):
            predictions.append(prediction)
        predicted_label = prediction.get("predicted_label")
        malicious_probability = float(prediction.get("malicious_probability") or 0.0)
        if predicted_label not in POSITIVE_LABELS and malicious_probability < 0.5:
            continue
        hybrid = prediction.get("hybrid_risk") or hybrid_risk_score(supervised_malicious_probability=malicious_probability)
        risk = int(round(float(hybrid.get("final_risk_score") or malicious_probability * 100)))
        rows.append(
            {
                "alert_id": None,
                "alert_type": "diagnostic_supervised_soc_triage",
                "severity": severity_from_score(risk),
                "risk_score": risk,
                "title": f"Diagnostic supervised SOC triage signal for log {log.id}",
                "evidence_count": 1,
                "attack_type": predicted_label or "unknown_anomaly",
                "why_flagged": (
                    f"Supervised SOC triage predicted {predicted_label or 'unknown'} "
                    f"with confidence {prediction.get('confidence', 0.0)}."
                ),
                "detection_source": ["supervised"],
                "top_evidence_points": [
                    f"Predicted label={predicted_label or 'not_available'}.",
                    f"Threat-positive probability={malicious_probability}.",
                    "Decision support only; no response action is created.",
                ],
                "layered_evidence": {
                    "rule": [],
                    "anomaly": "Not evaluated in supervised-only mode.",
                    "ml": f"SOC triage prediction={predicted_label or 'not_available'}.",
                    "hybrid": "Hybrid score shown only as advisory probability/risk translation.",
                },
                "prediction": prediction,
                "rule_signals": [],
                "anomaly_scores": [],
                "supervised_probability": malicious_probability,
                "hybrid_components": hybrid.get("components") or {},
            }
        )
    return rows, {
        "logs_evaluated": len(logs),
        "predictions_available": len(predictions),
        "diagnostic_threat_signals": len(rows),
        "model_available": bool(predictions),
        "persistent_alerts_created": 0,
        "decision_support_only": True,
    }


def _run_persistent_mode(
    *,
    db: Session,
    mode: str,
    source_id: int,
    source_name: str,
    source_type: str,
    line_count: int,
    repeat_import_detection: bool,
    path: Path,
    parser_profile: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    detection_results = [
        run_detection(
            db,
            limit=max(100, line_count * 3),
            use_ml=mode == "hybrid",
            actor="layered_detection_validation",
            source_id=source_id,
            source_name=source_name,
            source_type=source_type,
        )
    ]
    import_results: list[dict[str, Any]] = []
    if repeat_import_detection:
        import_results.append(
            import_log_file(
                db,
                path,
                actor="layered_detection_validation",
                source_id=source_id,
                parser_profile=parser_profile,
            )
        )
        detection_results.append(
            run_detection(
                db,
                limit=max(100, line_count * 3),
                use_ml=mode == "hybrid",
                actor="layered_detection_validation",
                source_id=source_id,
                source_name=source_name,
                source_type=source_type,
            )
        )
    alerts, summaries = _alert_rows_from_db(db, source_id)
    return alerts, summaries, detection_results + import_results


def _contribution_summary(mode: str, alerts: list[dict[str, Any]], diagnostics: dict[str, Any]) -> dict[str, Any]:
    source_counter: Counter[str] = Counter()
    for alert in alerts:
        for source in alert.get("detection_source") or []:
            source_counter[str(source)] += 1
    anomaly_signals = source_counter.get("anomaly", 0) if mode == "hybrid" else 0
    supervised_signals = source_counter.get("supervised", 0) if mode == "hybrid" else 0
    if mode == "anomaly_only":
        anomaly_signals += int(diagnostics.get("anomaly_count") or 0)
    if mode == "supervised_only":
        supervised_signals += int(diagnostics.get("diagnostic_threat_signals") or 0)
    return {
        "mode": mode,
        "rule_contribution": mode in {"rules_only", "hybrid"} and source_counter.get("rule", 0) > 0,
        "anomaly_contribution": anomaly_signals > 0,
        "supervised_contribution": supervised_signals > 0,
        "hybrid_contribution": mode == "hybrid" and (source_counter.get("hybrid", 0) > 0 or bool(alerts)),
        "rule_alerts": source_counter.get("rule", 0),
        "anomaly_alerts": anomaly_signals,
        "supervised_signals": supervised_signals,
        "hybrid_signals": source_counter.get("hybrid", 0),
    }


def _checks_for_mode(
    *,
    mode: str,
    expectation: dict[str, Any],
    layered_expectation: dict[str, Any],
    source: dict[str, Any],
    alerts: list[dict[str, Any]],
    response_actions_before: int,
    response_actions_after: int,
) -> tuple[list[dict[str, Any]], bool, bool]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    parse_success = int(source.get("parse_success_count") or 0)
    parse_failures = int(source.get("parse_failure_count") or 0)
    add(
        "parser_success_min",
        parse_success >= int(expectation.get("expected_parser_success_min", 0)),
        f"Parser successes: {parse_success}; expected at least {expectation.get('expected_parser_success_min', 0)}.",
    )
    add(
        "parser_failure_min",
        parse_failures >= int(expectation.get("expected_parse_failures_min", 0)),
        f"Parse failures: {parse_failures}; expected at least {expectation.get('expected_parse_failures_min', 0)}.",
    )
    add(
        "no_response_actions",
        response_actions_after == response_actions_before,
        f"Response actions before/after: {response_actions_before}/{response_actions_after}.",
    )

    false_positive = _is_false_positive(mode, expectation, alerts)
    false_negative = _is_false_negative(mode, expectation, alerts)
    required_mode = layered_expectation.get("rules" if mode == "rules_only" else mode.replace("_only", ""))
    if mode in {"rules_only", "hybrid"} and expectation.get("expected_alert_present"):
        add(
            f"{mode}_expected_detection",
            not false_negative,
            f"Expected attack types: {sorted(_expected_attack_types(expectation))}; actual: {sorted(_attack_types_from_alerts(alerts))}.",
        )
    if not expectation.get("expected_alert_present"):
        add(
            f"{mode}_quiet_negative_control",
            not false_positive,
            f"Max severity: {_max_severity(alerts)}; alerts/signals: {len(alerts)}.",
        )
    if mode in {"anomaly_only", "supervised_only"} and required_mode in {"optional", "quiet_or_optional", "advisory_only"}:
        add(
            f"{mode}_advisory_not_required",
            True,
            "This layer is diagnostic/advisory in controlled validation and does not decide promotion or response.",
        )
    return checks, false_positive, false_negative


def _run_variant_mode(
    *,
    scenario: str,
    variant: dict[str, Any],
    mode: str,
    expectation: dict[str, Any],
    layered_expectation: dict[str, Any],
    use_temp_db: bool,
) -> dict[str, Any]:
    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            spec = SCENARIOS[scenario]
            source = get_or_create_source(
                db,
                name=_scenario_source_name(scenario, int(variant["variant_id"]), mode, use_temp_db=use_temp_db),
                source_type=spec.default_source_type,
                parser_profile=spec.default_parser_profile,
            )
            db.commit()
            db.refresh(source)
            response_actions_before = int(db.query(ResponseAction).count())
            path = Path(variant["path"])
            import_results = [
                import_log_file(
                    db,
                    path,
                    actor="layered_detection_validation",
                    source_id=source.id,
                    parser_profile=spec.default_parser_profile,
                )
            ]
            if mode in {"anomaly_only", "supervised_only"} and spec.repeat_import_detection:
                import_results.append(
                    import_log_file(
                        db,
                        path,
                        actor="layered_detection_validation",
                        source_id=source.id,
                        parser_profile=spec.default_parser_profile,
                    )
                )
            import_result = import_results[0]
            diagnostics: dict[str, Any] = {}
            mode_artifacts: list[dict[str, Any]] = []
            if mode in {"rules_only", "hybrid"}:
                alerts, _summaries, mode_artifacts = _run_persistent_mode(
                    db=db,
                    mode=mode,
                    source_id=source.id,
                    source_name=source.name,
                    source_type=source.source_type,
                    line_count=count_nonblank_log_lines(path),
                    repeat_import_detection=spec.repeat_import_detection,
                    path=path,
                    parser_profile=spec.default_parser_profile,
                )
            elif mode == "anomaly_only":
                alerts, diagnostics = _diagnostic_anomaly_alerts(db, source.id)
            elif mode == "supervised_only":
                alerts, diagnostics = _diagnostic_supervised_alerts(db, source.id)
            else:
                raise ValueError(f"Unknown detection mode: {mode}")

            db.refresh(source)
            source_detail = source_to_dict(source, include_quality=True, db=db)
            response_actions_after = int(db.query(ResponseAction).count())
            checks, false_positive, false_negative = _checks_for_mode(
                mode=mode,
                expectation=expectation,
                layered_expectation=layered_expectation,
                source=source_detail,
                alerts=alerts,
                response_actions_before=response_actions_before,
                response_actions_after=response_actions_after,
            )
            contribution = _contribution_summary(mode, alerts, diagnostics)
            passed = all(item["passed"] for item in checks) and not false_positive and not false_negative
            return {
                "scenario": scenario,
                "variant_id": int(variant["variant_id"]),
                "variant_file": Path(variant["path"]).name,
                "mode": mode,
                "passed": passed,
                "false_positive": false_positive,
                "false_negative": false_negative,
                "expected_attack_types": sorted(_expected_attack_types(expectation)),
                "expected_alert_present": bool(expectation.get("expected_alert_present")),
                "actual_attack_types": sorted(_attack_types_from_alerts(alerts)),
                "alerts_created": len(alerts),
                "alerts_deduplicated": sum(int(item.get("deduplicated_alert_updates") or 0) for item in mode_artifacts),
                "max_severity": _max_severity(alerts),
                "max_risk_score": _max_risk(alerts),
                "evidence_count": sum(int(alert.get("evidence_count") or 0) for alert in alerts),
                "evidence_keywords": sorted(
                    {
                        keyword
                        for alert in alerts
                        for text in [alert.get("why_flagged") or "", " ".join(alert.get("top_evidence_points") or [])]
                        for keyword in ["rule", "anomaly", "supervised", "hybrid", "port", "scan", "denied", "repeated", "risk", "outbound"]
                        if keyword in text.lower()
                    }
                ),
                "checks": checks,
                "source": source_detail,
                "import_result": import_result,
                "import_results": import_results,
                "mode_artifacts": mode_artifacts,
                "diagnostics": diagnostics,
                "alerts": alerts[:10],
                "contribution": contribution,
                "layered_expectation": layered_expectation,
                "safety": {
                    "controlled_layered_validation": True,
                    "automatic_response_enabled": False,
                    "real_firewall_blocking_enabled": False,
                    "production_readiness_claim": False,
                    "response_actions_created": response_actions_after - response_actions_before,
                },
            }
    finally:
        if temp_engine is not None:
            temp_engine.dispose()


def _mode_summary(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        grouped[str(item["mode"])].append(item)
    rows = []
    for mode, items in sorted(grouped.items()):
        rows.append(
            {
                "mode": mode,
                "tests": len(items),
                "passed_count": sum(1 for item in items if item["passed"]),
                "failed_count": sum(1 for item in items if not item["passed"]),
                "false_positive_count": sum(1 for item in items if item["false_positive"]),
                "false_negative_count": sum(1 for item in items if item["false_negative"]),
                "rule_contribution_count": sum(1 for item in items if item["contribution"]["rule_contribution"]),
                "anomaly_contribution_count": sum(1 for item in items if item["contribution"]["anomaly_contribution"]),
                "supervised_contribution_count": sum(1 for item in items if item["contribution"]["supervised_contribution"]),
                "hybrid_contribution_count": sum(1 for item in items if item["contribution"]["hybrid_contribution"]),
            }
        )
    return rows


def _scenario_summary(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        grouped[str(item["scenario"])].append(item)
    rows = []
    for scenario, items in sorted(grouped.items()):
        mode_status = {item["mode"]: "PASS" if item["passed"] else "REVIEW" for item in items}
        best_mode = "hybrid" if any(item["mode"] == "hybrid" and item["passed"] for item in items) else "rules_only"
        rows.append(
            {
                "scenario": scenario,
                "tests": len(items),
                "passed_count": sum(1 for item in items if item["passed"]),
                "failed_count": sum(1 for item in items if not item["passed"]),
                "rules": mode_status.get("rules_only", "not_run"),
                "anomaly": mode_status.get("anomaly_only", "not_run"),
                "ml_soc_triage": mode_status.get("supervised_only", "not_run"),
                "hybrid": mode_status.get("hybrid", "not_run"),
                "best_mode": best_mode,
                "notes": (items[0].get("layered_expectation") or {}).get("notes"),
            }
        )
    return rows


def _likely_failure_root_cause(item: dict[str, Any]) -> str:
    scenario = str(item.get("scenario") or "")
    mode = str(item.get("mode") or "")
    if mode == "anomaly_only" and scenario in {
        "generic_syslog_mixed",
        "malformed_raw_fallback",
        "malformed_vendor_mixed_fields",
    }:
        return "field-poor parser fallback was over-scored by a global anomaly baseline"
    if mode == "hybrid" and scenario == "benign_high_volume_single_service":
        return "advisory anomaly evidence was counted toward alert-authoritative score"
    if mode == "hybrid" and scenario == "suspicious_rare_port_probe":
        return "anomaly precedence masked the more specific deny/rare-port rule evidence"
    if scenario == "malicious_like_c2_beacon" and mode in {"rules_only", "hybrid"}:
        return "variant timestamp offsets stretched a cadence-sensitive sequence beyond its five-minute window"
    return "requires targeted evidence review"


def build_failure_matrix(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in results:
        if item.get("passed"):
            continue
        alerts = item.get("alerts") or []
        anomaly_scores = [
            float(score)
            for alert in alerts
            for score in alert.get("anomaly_scores") or []
        ]
        if not anomaly_scores:
            anomaly_scores = [
                float(match.group(1))
                for alert in alerts
                for point in alert.get("top_evidence_points") or []
                if (match := re.search(r"Anomaly score=(-?\d+(?:\.\d+)?)", str(point)))
            ]
        supervised_probabilities = [
            float(alert.get("supervised_probability") or 0.0)
            for alert in alerts
            if alert.get("supervised_probability") is not None
        ]
        rows.append(
            {
                "scenario": item.get("scenario"),
                "variant_id": item.get("variant_id"),
                "detection_layer": item.get("mode"),
                "classification": (
                    "false_positive"
                    if item.get("false_positive")
                    else "false_negative"
                    if item.get("false_negative")
                    else "failed_check"
                ),
                "expected_behavior": {
                    "attack_types": item.get("expected_attack_types") or [],
                    "alert_present": bool(item.get("expected_alert_present")),
                    "quiet": not bool(item.get("expected_alert_present")),
                },
                "actual_behavior": {
                    "attack_types": item.get("actual_attack_types") or [],
                    "alerts_or_signals": item.get("alerts_created"),
                    "max_severity": item.get("max_severity"),
                    "max_risk_score": item.get("max_risk_score"),
                },
                "rule_evidence_signals": sorted(
                    {
                        str(signal)
                        for alert in alerts
                        for signal in (
                            alert.get("rule_signals")
                            or ((alert.get("layered_evidence") or {}).get("rule") or [])
                        )
                    }
                ),
                "supervised_probability": max(supervised_probabilities, default=None),
                "anomaly_score": min(anomaly_scores, default=None),
                "hybrid_contribution": [
                    alert.get("hybrid_components") or {}
                    for alert in alerts
                    if alert.get("hybrid_components")
                ][:3],
                "likely_root_cause": _likely_failure_root_cause(item),
                "response_actions_created": (item.get("safety") or {}).get("response_actions_created", 0),
            }
        )
    return rows


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Layered Detection Validation",
        "",
        f"- Generated at: {report['generated_at']}",
        "- Scope: controlled synthetic/replay layered detection validation",
        f"- Database mode: {'temporary in-memory SQLite' if report['use_temp_db'] else 'current local database'}",
        "- Response mode: simulated and analyst-approved only",
        "- Real firewall blocking: disabled",
        "- Production readiness claim: none",
        "",
        "## Summary",
        "",
        f"- Passed mode runs: {report['passed_count']} / {report['mode_run_count']}",
        f"- False positives: {report['false_positive_count']}",
        f"- False negatives: {report['false_negative_count']}",
        "",
        "## Scenario Mode Matrix",
        "",
        "| Scenario | Rules | Anomaly | ML/SOC Triage | Hybrid | Best Mode | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["scenario_summary"]:
        lines.append(
            "| "
            f"{row['scenario']} | {row['rules']} | {row['anomaly']} | {row['ml_soc_triage']} | "
            f"{row['hybrid']} | {row['best_mode']} | {row.get('notes') or ''} |"
        )
    lines.extend(["", "## Mode Contribution Summary", "", "| Mode | Tests | Passed | FP | FN | Rule | Anomaly | ML | Hybrid |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for row in report["mode_summary"]:
        lines.append(
            "| "
            f"{row['mode']} | {row['tests']} | {row['passed_count']} | "
            f"{row['false_positive_count']} | {row['false_negative_count']} | "
            f"{row['rule_contribution_count']} | {row['anomaly_contribution_count']} | "
            f"{row['supervised_contribution_count']} | {row['hybrid_contribution_count']} |"
        )
    lines.extend(["", "## Layer Interpretation", ""])
    lines.extend(
        [
            "- Rules are the primary source for known controlled patterns such as scans, brute-force-like attempts, beaconing-like traffic, and exfiltration suspicion.",
            "- Anomaly-only mode is diagnostic. It may contribute on unusual rows when an IsolationForest artifact is available, but it is not required to catch every scenario.",
            "- Supervised-only mode is advisory SOC triage. Candidate ML predictions are reported when available and do not trigger response.",
            "- Hybrid mode combines rule score, anomaly score, supervised probability, and context into a decision-support risk score.",
            "",
            "## Limitations",
            "",
            "- This suite uses safe synthetic/replay logs and does not execute attacks.",
            "- The suite does not certify production accuracy.",
            "- Real router/firewall forwarding remains future controlled lab validation.",
            "- Response actions remain simulated and analyst-approved.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"layered_detection_{timestamp}"
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, default=_json_default, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(markdown_path)}


def run_layered_detection_validation(
    *,
    scenarios: list[str] | None = None,
    variants: int = 3,
    use_temp_db: bool = True,
    write_output: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    variant_output_dir: Path = DEFAULT_VARIANT_DIR,
) -> dict[str, Any]:
    base_expectations = _load_expectations()
    layered_expectations = _load_layered_expectations()
    selected = scenarios or list(base_expectations.keys())
    manifest = generate_detection_variants(scenarios=selected, variants=variants, output_dir=variant_output_dir)
    results = []
    for variant in manifest["variants"]:
        scenario = str(variant["scenario"])
        for mode in MODES:
            results.append(
                _run_variant_mode(
                    scenario=scenario,
                    variant=variant,
                    mode=mode,
                    expectation=base_expectations[scenario],
                    layered_expectation=layered_expectations.get(scenario, {}),
                    use_temp_db=use_temp_db,
                )
            )
    report = {
        "ok": all(item["passed"] for item in results),
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled layered detection contribution validation",
        "use_temp_db": use_temp_db,
        "scenario_count": len(selected),
        "variant_count": int(manifest["variant_count"]),
        "mode_count": len(MODES),
        "mode_run_count": len(results),
        "passed_count": sum(1 for item in results if item["passed"]),
        "failed_count": sum(1 for item in results if not item["passed"]),
        "false_positive_count": sum(1 for item in results if item["false_positive"]),
        "false_negative_count": sum(1 for item in results if item["false_negative"]),
        "mode_summary": _mode_summary(results),
        "scenario_summary": _scenario_summary(results),
        "failure_matrix": build_failure_matrix(results),
        "results": results,
        "variant_manifest": {
            "manifest_path": manifest["manifest_path"],
            "output_dir": manifest["output_dir"],
            "variant_count": manifest["variant_count"],
        },
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_mode": "simulated analyst-approved only",
            "production_readiness_claim": False,
            "synthetic_variants_only": True,
        },
        "limitations": [
            "Anomaly-only and supervised-only modes are diagnostic/advisory when artifacts are unavailable or weak.",
            "Controlled synthetic/replay validation does not replace real router/firewall forwarding validation.",
        ],
    }
    if write_output:
        report["paths"] = write_report(report, output_dir=output_dir)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run layered ATDR detection validation across rules, anomaly, ML, and hybrid modes.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="Scenario family to validate. Repeat for multiple.")
    parser.add_argument("--all", action="store_true", help="Validate every known scenario family.")
    parser.add_argument("--variants", type=int, default=3)
    parser.add_argument("--use-temp-db", action="store_true", default=True, help="Use temporary in-memory SQLite; default true.")
    parser.add_argument("--write-to-current-db", action="store_true", help="Opt in to writing generated variants to the current local DB.")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--variant-output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    selected = None if args.all or not args.scenario else args.scenario
    report = run_layered_detection_validation(
        scenarios=selected,
        variants=args.variants,
        use_temp_db=not args.write_to_current_db,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
        variant_output_dir=Path(args.variant_output_dir) if args.variant_output_dir else DEFAULT_VARIANT_DIR,
    )
    print(json.dumps(report, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
