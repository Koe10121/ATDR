from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog
from atdr.app.detection.explanations import alert_explanation_completeness, explain_log_triage


def test_explain_log_triage_reports_not_flagged_with_parser_context():
    log = NormalizedLog(
        id=10,
        raw_log_id=1,
        src_ip="203.0.113.10",
        dst_ip="10.0.0.10",
        dst_port=80,
        app="incomplete",
        action="allow",
        src_zone="outside",
        dst_zone="inside",
        parsed_json={"parser_warnings": ["unknown or incomplete application"]},
    )

    explanation = explain_log_triage(log)

    assert explanation["status"] == "not_flagged"
    assert "No alert evidence" in explanation["reasons"][0]
    assert "unknown or incomplete application" in explanation["normalized_signals"]
    assert explanation["normalized_fields_used"]["dst_port"] == 80
    assert explanation["why_not_flagged"]
    assert explanation["rule_evidence"]
    assert explanation["anomaly_evidence"]["is_anomaly"] is False
    assert explanation["decision_support_only"] is True
    assert explanation["response_automation_allowed"] is False
    assert "Decision support" in explanation["safety_note"]


def test_explain_log_triage_reports_flagged_alert_links():
    log = NormalizedLog(id=11, raw_log_id=2, src_ip="203.0.113.11", dst_ip="10.0.0.11", action="deny")
    log.alert_evidence.append(AlertEvidence(alert_id=42, normalized_log_id=11))

    explanation = explain_log_triage(log)

    assert explanation["status"] == "flagged"
    assert explanation["alert_ids"] == [42]
    assert "deny/drop/reset behavior" in explanation["normalized_signals"]
    assert explanation["why_flagged"]
    assert "Open the related alert" in explanation["analyst_next_steps"][0]


def test_alert_explanation_completeness_identifies_missing_fields():
    alert = Alert(
        title="High: test",
        alert_type="possible_port_scan",
        src_ip="203.0.113.44",
        dst_ip="10.0.0.44",
        threat_score=85,
        severity="High",
        status="open",
        explanation="Rule matched scanning behavior.",
        matched_rules_json=[{"code": "possible_port_scan", "title": "Possible port scan"}],
        recommended_response="Review related logs before containment.",
    )
    alert.evidence.append(AlertEvidence(normalized_log_id=1))
    summary = {
        "why_flagged": "Flagged because source touched many destination ports.",
        "matched_rule_names": ["Possible port scan"],
    }

    completeness = alert_explanation_completeness(alert, summary)

    assert completeness["passed"] is True
    assert completeness["score"] == 1.0
    assert completeness["missing"] == []
