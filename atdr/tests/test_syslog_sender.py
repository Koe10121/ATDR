from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.scripts.send_sample_syslog import SAMPLE_SYSLOG_LINE


def test_sample_syslog_sender_payload_is_parseable():
    parsed = parse_log_line(SAMPLE_SYSLOG_LINE)

    assert parsed.error is None
    assert parsed.device_hostname == "lab-fw.example.invalid"
    assert parsed.normalized["log_type"] == "TRAFFIC"
    assert parsed.normalized["src_ip"] == "198.51.100.10"
