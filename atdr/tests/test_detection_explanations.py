from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog
from atdr.app.detection.explanations import alert_explanation_completeness, explain_log_triage, recommended_response


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


def test_explain_log_triage_does_not_report_false_direction_for_same_zone_untrust():
    # Regression test: a prior substring-matching bug ("trust" in "untrust")
    # made this reuse the same zone-classification defect fixed in
    # atdr/app/detection/rules.py, reporting a false "external-to-internal
    # direction" signal for traffic that never left Palo Alto's default
    # "untrust" zone.
    log = NormalizedLog(
        id=12,
        raw_log_id=3,
        src_ip="203.0.113.12",
        dst_ip="198.51.100.12",
        dst_port=443,
        app="ssl",
        action="allow",
        src_zone="untrust",
        dst_zone="untrust",
        parsed_json={},
    )

    explanation = explain_log_triage(log)

    assert "external-to-internal direction" not in explanation["normalized_signals"]


def test_explain_log_triage_still_reports_genuine_outside_to_inside_direction():
    log = NormalizedLog(
        id=13,
        raw_log_id=4,
        src_ip="203.0.113.13",
        dst_ip="10.0.0.13",
        dst_port=443,
        app="ssl",
        action="allow",
        src_zone="untrust",
        dst_zone="trust",
        parsed_json={},
    )

    explanation = explain_log_triage(log)

    assert "external-to-internal direction" in explanation["normalized_signals"]


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

    assert completeness["passed"] is False
    assert completeness["score"] < 1.0
    assert "exact_evidence_signals" in completeness["missing"]
    assert "evidence_limitations" in completeness["missing"]
    assert "related_log_traceability" in completeness["missing"]
    assert "case_traceability" in completeness["missing"]


def test_alert_explanation_completeness_passes_full_governed_contract():
    alert = Alert(
        id=42,
        title="High: test",
        alert_type="possible_port_scan",
        src_ip="203.0.113.44",
        dst_ip="10.0.0.44",
        threat_score=85,
        severity="High",
        status="open",
        explanation="Rule matched scanning behavior.",
        matched_rules_json=[
            {
                "code": "possible_port_scan",
                "title": "Possible port scan",
                "score": 25,
                "explanation": "Ten distinct destination ports were observed.",
            }
        ],
        recommended_response="Review related logs before containment.",
    )
    alert.evidence.append(AlertEvidence(normalized_log_id=1))
    summary = {
        "why_flagged": "Flagged because the source touched many destination ports.",
        "matched_rule_names": ["Possible port scan"],
        "attack_type": "port_scan",
        "attack_mapping": {"mapping_origin": "deterministic_rule_mapping"},
        "exact_evidence_signals": [
            {
                "code": "possible_port_scan",
                "score_contribution": 25,
                "observed": "Ten distinct destination ports were observed.",
            }
        ],
        "evidence_limitations": ["Intent and authorization require analyst context."],
        "false_positive_considerations": ["Authorized vulnerability scanner"],
        "prioritized_analyst_checks": ["Confirm whether the scanner is authorized."],
        "traceability": {
            "alert_id": 42,
            "source_ids": [],
            "evidence_log_ids": [1],
            "related_log_count": 1,
            "case": {"case_id": "synthetic-case"},
        },
        "decision_support_only": True,
        "response_automation_allowed": False,
    }

    completeness = alert_explanation_completeness(alert, summary)

    assert completeness["passed"] is True
    assert completeness["score"] == 1.0
    assert completeness["missing"] == []


def test_recommended_response_is_rule_specific_not_generic_by_severity():
    # Regression test: recommended_response used to be 3 fixed sentences
    # selected purely by severity bucket -- a credential brute-force, a
    # port scan, and a C2 beacon all produced identical text modulo one
    # substituted IP. Different rule codes at the same severity must now
    # produce genuinely different guidance.
    port_scan = recommended_response(
        "High", {"code": "possible_port_scan", "title": "Possible port scan"}, src_ip="203.0.113.9"
    )
    brute_force = recommended_response(
        "High", {"code": "brute_force_like_attempts", "title": "Brute force"}, src_ip="203.0.113.9"
    )
    beaconing = recommended_response(
        "High", {"code": "beaconing_like_outbound", "title": "Beaconing"}, src_ip="203.0.113.9"
    )
    assert len({port_scan, brute_force, beaconing}) == 3
    assert "authorized scanner or asset-discovery system" in port_scan
    assert "same destination and authentication service" in brute_force
    assert "interval regularity" in beaconing
    # All still carry the source and the severity-appropriate action.
    for text in (port_scan, brute_force, beaconing):
        assert "203.0.113.9" in text
        assert "preserve raw evidence" in text


def test_recommended_response_names_a_source_count_for_multi_source_groups():
    # Regression test: a grouped alert spanning many source IPs used to
    # recommend investigating one single IP (the highest-scoring log's),
    # even though the alert's own explanation text correctly said "Sample
    # sources: A, B, C...". The recommendation must reflect the same
    # multi-source reality instead of pointing at one arbitrary IP.
    single_source = recommended_response(
        "High",
        {"code": "possible_port_scan", "title": "Possible port scan"},
        src_ip="203.0.113.9",
        observations={"unique_src_count": 1},
    )
    multi_source = recommended_response(
        "High",
        {"code": "possible_port_scan", "title": "Possible port scan"},
        src_ip="203.0.113.9",
        observations={"unique_src_count": 5},
    )
    assert "203.0.113.9" in single_source
    assert "203.0.113.9" not in multi_source
    assert "5 sources" in multi_source


def test_recommended_response_falls_back_gracefully_with_no_rule_or_evidence():
    assert recommended_response("Low", None) == (
        "Monitor the event and mark as false positive if expected for this environment."
    )
    # A rule code with no entry in the analyst-checks table (e.g. the
    # dynamically-added watchlist match) must not crash -- falls back to
    # the severity-appropriate action alone.
    assert recommended_response("Medium", {"code": "watchlist_match", "title": "Watchlist"}, src_ip="10.0.0.9") == (
        "Review 10.0.0.9, validate the business context, and monitor for repeated behavior."
    )
