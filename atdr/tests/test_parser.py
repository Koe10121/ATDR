from atdr.app.parsers.paloalto_parser import parse_log_line, parse_log_line_for_profile


TRAFFIC_LINE = (
    '2026-05-20T13:36:16+07:00 lab-fw.example.invalid '
    '1,2026/05/20 13:36:15,000000000001,TRAFFIC,end,2561,2026/05/20 13:36:15,'
    '198.51.100.10,203.0.113.20,0.0.0.0,0.0.0.0,Synthetic-Allow-Test,,,ping,'
    'vsys1,Outside-Lab,Inside-Lab,ethernet1/1,ethernet1/2,Synthetic-Forwarding,'
    '2026/05/20 13:36:15,35845233,1,0,0,0,0,0x100019,icmp,allow,172,86,86,2,'
    '2026/05/20 13:36:02,0,any,,7588383920033660891,0x0,Thailand,Thailand,,1,1,'
    'aged-out,0,0,0,0,vsys1,LAB-FW,from-policy,,,0,,0,,N/A,0,0,0,0,'
    '00000000-0000-4000-8000-000000000001,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,'
    '2026-05-20T13:36:16.534+07:00,,,internet-utility,general-internet,network-protocol,'
    '2,"has-known-vulnerability,tunnel-other-application,pervasive-use",,untunneled,no,no,0'
)


THREAT_LINE = (
    '2026-05-20T13:36:17+07:00 lab-fw.example.invalid '
    '1,2026/05/20 13:36:17,000000000001,THREAT,spyware,2561,2026/05/20 13:36:17,'
    '192.0.2.10,198.51.100.30,203.0.113.40,198.51.100.30,Synthetic-Allow-Internet,,,'
    'json-rpc,vsys1,Inside-Lab,Outside-Lab,ethernet1/2,ethernet1/1,Synthetic-Forwarding,'
    '2026/05/20 13:36:17,916848,1,3547,14444,22007,14444,0x402000,tcp,drop,,'
    'Synthetic Test Signature(99999),any,critical,client-to-server,'
    '7588383908313708726,0x0,private-lab,Germany,,,0,,,0,,,,,,,,0,0,0,0,0,'
    'vsys1,LAB-FW,,,,,0,,0,,N/A,synthetic-category,TestContent-1,0x0,0,4294967295,,,'
    '00000000-0000-4000-8000-000000000002,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,'
    '2026-05-20T13:36:17.674+07:00,,,,ip-protocol,networking,network-protocol,1,'
    'has-known-vulnerability,,json-rpc,no,no,_reportid'
)

SYSTEM_LINE = (
    "2026-05-20T13:36:18+07:00 lab-fw.example.invalid "
    "1,2026/05/20 13:36:18,000000000001,SYSTEM,general,2561,"
    "2026/05/20 13:36:18,vsys1,auth-success,local-admin,,,auth,"
    "informational,Authentication event recorded,12345,0x0,0,0,0,0,"
    "vsys1,LAB-FW,,,2026-05-20T13:36:18.000+07:00"
)


def test_parse_traffic_line_with_quoted_characteristics():
    parsed = parse_log_line(TRAFFIC_LINE)

    assert parsed.error is None
    assert parsed.device_hostname == "lab-fw.example.invalid"
    assert parsed.normalized["log_type"] == "TRAFFIC"
    assert parsed.normalized["src_ip"] == "198.51.100.10"
    assert parsed.normalized["dst_ip"] == "203.0.113.20"
    assert parsed.normalized["app"] == "ping"
    assert parsed.normalized["protocol"] == "icmp"
    assert parsed.normalized["bytes"] == 172
    assert parsed.normalized["app_risk"] == 2
    assert parsed.normalized["app_characteristic"] == "has-known-vulnerability,tunnel-other-application,pervasive-use"
    assert parsed.parsed_json["field_count"] == 115
    assert parsed.parsed_json["parser_contract_version"] == "palo_alto_syslog_v5.12"
    assert parsed.parsed_json["parser_compatibility"]["status"] == "supported_known_layout"
    assert parsed.parsed_json["application_resolution"]["status"] == "identified"


def test_parse_threat_line_safely():
    parsed = parse_log_line(THREAT_LINE)

    assert parsed.error is None
    assert parsed.normalized["log_type"] == "THREAT"
    assert parsed.normalized["subtype"] == "spyware"
    assert parsed.normalized["action"] == "drop"
    assert parsed.normalized["dst_country"] == "Germany"
    assert parsed.normalized["app_risk"] == 1
    assert parsed.parsed_json["parsed_threat_severity"] == "critical"
    assert parsed.parsed_json["parser_compatibility"]["status"] == "supported_known_layout"


def test_parse_system_line_uses_system_contract_without_traffic_warnings():
    parsed = parse_log_line(SYSTEM_LINE)

    assert parsed.error is None
    assert parsed.normalized["log_type"] == "SYSTEM"
    assert parsed.normalized["vsys"] == "vsys1"
    assert parsed.normalized["device_name"] == "LAB-FW"
    assert parsed.normalized["src_ip"] is None
    assert parsed.normalized["app"] is None
    assert parsed.parsed_json["system_event_id"] == "auth-success"
    assert parsed.parsed_json["system_module"] == "auth"
    assert parsed.parsed_json["system_severity"] == "informational"
    assert parsed.parsed_json["system_description_present"] is True
    assert parsed.parsed_json["parser_compatibility"]["status"] == "supported_known_layout"
    assert parsed.parsed_json["application_resolution"]["status"] == "not_applicable"
    assert "missing source IP" not in parsed.parsed_json["parser_warnings"]
    assert "missing action" not in parsed.parsed_json["parser_warnings"]


def test_unresolved_application_is_a_quality_notice_not_parser_failure():
    parsed = parse_log_line(TRAFFIC_LINE.replace(",,,ping,", ",,,incomplete,"))

    assert parsed.error is None
    assert parsed.normalized["app"] == "incomplete"
    assert parsed.parsed_json["application_resolution"] == {
        "status": "unresolved",
        "reason": "session_application_identification_incomplete",
    }
    assert parsed.parsed_json["parser_warnings"] == []
    assert parsed.parsed_json["parser_notices"]


def test_absent_application_is_distinct_from_unresolved_application():
    parsed = parse_log_line(TRAFFIC_LINE.replace(",,,ping,", ",,,,"))

    assert parsed.error is None
    assert parsed.normalized["app"] is None
    assert parsed.parsed_json["application_resolution"] == {
        "status": "absent",
        "reason": "application_field_absent_or_not_applicable",
    }
    assert "missing application field" in parsed.parsed_json[
        "parser_warnings"
    ]


def test_extended_traffic_layout_keeps_anchor_based_app_metadata():
    parsed = parse_log_line(f"{TRAFFIC_LINE},future-field")

    assert parsed.error is None
    assert parsed.parsed_json["field_count"] == 116
    assert parsed.parsed_json["parser_compatibility"]["status"] == "supported_extended_layout"
    assert parsed.parsed_json["app_metadata_mapping"] == "pan_high_res_anchor_traffic"
    assert parsed.normalized["app_risk"] == 2


def test_malformed_line_does_not_raise():
    parsed = parse_log_line("bad line")

    assert parsed.error is not None
    assert "parser_error" in parsed.parsed_json


def test_blank_line_and_missing_fields_are_recorded_safely():
    blank = parse_log_line("   ")
    assert blank.error == "blank line"
    assert blank.parsed_json["parser_error"] == "blank line"

    partial = parse_log_line("2026-05-20T13:36:16+07:00 lab-fw.example.invalid 1,2026/05/20 13:36:15")
    assert partial.error is None
    assert partial.parsed_json["parse_status"] == "partial"
    assert partial.parsed_json["parser_compatibility"]["status"] == "missing_log_type"
    assert "missing source IP" in partial.parsed_json["parser_warnings"]
    assert "missing destination IP" in partial.parsed_json["parser_warnings"]
    assert "missing action" in partial.parsed_json["parser_warnings"]


def test_generic_syslog_profile_preserves_raw_message_without_crashing():
    parsed = parse_log_line_for_profile(
        "2026-05-20T13:36:16+07:00 lab-router interface ge-0/0/1 link changed",
        "generic_syslog",
    )

    assert parsed.error is None
    assert parsed.device_hostname == "lab-router"
    assert parsed.normalized == {}
    assert parsed.parsed_json["parser_profile"] == "generic_syslog"
    assert parsed.parsed_json["parse_status"] == "preserved_unstructured"
    assert "limited normalized fields" in parsed.parsed_json["parser_warnings"][0]


def test_raw_fallback_profile_preserves_evidence_and_counts_failure():
    parsed = parse_log_line_for_profile("not a firewall log", "raw_fallback")

    assert parsed.error == "raw fallback parser profile"
    assert parsed.raw_line == "not a firewall log"
    assert parsed.normalized == {}
    assert parsed.parsed_json["raw_fallback"] is True
    assert parsed.parsed_json["parse_status"] == "fallback"
