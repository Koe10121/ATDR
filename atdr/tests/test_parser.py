from atdr.app.parsers.paloalto_parser import parse_log_line


TRAFFIC_LINE = (
    '2026-05-20T13:36:16+07:00 MFU-FW.mfu.ac.th '
    '1,2026/05/20 13:36:15,013101011043,TRAFFIC,end,2561,2026/05/20 13:36:15,'
    '43.210.171.152,202.28.46.69,0.0.0.0,0.0.0.0,Allow-Outside_to_WLAN,,,ping,'
    'vsys1,SG-Outside,WLAN-Inside,ethernet1/22.240,ethernet1/22.241,Forward-to-FortiSIEM,'
    '2026/05/20 13:36:15,35845233,1,0,0,0,0,0x100019,icmp,allow,172,86,86,2,'
    '2026/05/20 13:36:02,0,any,,7588383920033660891,0x0,Thailand,Thailand,,1,1,'
    'aged-out,0,0,0,0,WLAN,MFU-FW,from-policy,,,0,,0,,N/A,0,0,0,0,'
    'e3702b83-bc00-4ee6-bc8d-a5c7f19568da,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,'
    '2026-05-20T13:36:16.534+07:00,,,internet-utility,general-internet,network-protocol,'
    '2,"has-known-vulnerability,tunnel-other-application,pervasive-use",,untunneled,no,no,0'
)


THREAT_LINE = (
    '2026-05-20T13:36:17+07:00 MFU-FW.mfu.ac.th '
    '1,2026/05/20 13:36:17,013101011043,THREAT,spyware,2561,2026/05/20 13:36:17,'
    '10.1.216.174,57.129.69.132,202.28.45.142,57.129.69.132,Allow_All-Users_Internet_All-Apps,,,'
    'json-rpc,vsys1,WLAN-Inside,SG-Outside,ethernet1/22.241,ethernet1/22.240,Forward-to-FortiSIEM,'
    '2026/05/20 13:36:17,916848,1,3547,14444,22007,14444,0x402000,tcp,drop,,'
    'XMRig Miner Command and Control Traffic Detection(85886),any,critical,client-to-server,'
    '7588383908313708726,0x0,10.0.0.0-10.255.255.255,Germany,,,0,,,0,,,,,,,,0,0,0,0,0,'
    'WLAN,MFU-FW,,,,,0,,0,,N/A,cryptominer,AppThreat-9103-10057,0x0,0,4294967295,,,'
    '18dd2c91-ac6c-4985-85c8-cb9e91676045,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,'
    '2026-05-20T13:36:17.674+07:00,,,,ip-protocol,networking,network-protocol,1,'
    'has-known-vulnerability,,json-rpc,no,no,_reportid'
)


def test_parse_traffic_line_with_quoted_characteristics():
    parsed = parse_log_line(TRAFFIC_LINE)

    assert parsed.error is None
    assert parsed.device_hostname == "MFU-FW.mfu.ac.th"
    assert parsed.normalized["log_type"] == "TRAFFIC"
    assert parsed.normalized["src_ip"] == "43.210.171.152"
    assert parsed.normalized["dst_ip"] == "202.28.46.69"
    assert parsed.normalized["app"] == "ping"
    assert parsed.normalized["protocol"] == "icmp"
    assert parsed.normalized["bytes"] == 172
    assert parsed.normalized["app_risk"] == 2
    assert parsed.normalized["app_characteristic"] == "has-known-vulnerability,tunnel-other-application,pervasive-use"
    assert parsed.parsed_json["field_count"] == 115


def test_parse_threat_line_safely():
    parsed = parse_log_line(THREAT_LINE)

    assert parsed.error is None
    assert parsed.normalized["log_type"] == "THREAT"
    assert parsed.normalized["subtype"] == "spyware"
    assert parsed.normalized["action"] == "drop"
    assert parsed.normalized["dst_country"] == "Germany"
    assert parsed.normalized["app_risk"] == 1
    assert parsed.parsed_json["parsed_threat_severity"] == "critical"


def test_malformed_line_does_not_raise():
    parsed = parse_log_line("bad line")

    assert parsed.error is not None
    assert "parser_error" in parsed.parsed_json


def test_blank_line_and_missing_fields_are_recorded_safely():
    blank = parse_log_line("   ")
    assert blank.error == "blank line"
    assert blank.parsed_json["parser_error"] == "blank line"

    partial = parse_log_line("2026-05-20T13:36:16+07:00 MFU-FW.mfu.ac.th 1,2026/05/20 13:36:15")
    assert partial.error is None
    assert "missing source IP" in partial.parsed_json["parser_warnings"]
    assert "missing destination IP" in partial.parsed_json["parser_warnings"]
    assert "missing action" in partial.parsed_json["parser_warnings"]
