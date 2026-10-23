"""A blocked attack from the internet is rated no higher than the firewall rated it.

On live, points for the block itself and for context (a risky app, inbound direction) made five dropped attacks
Critical, two of them Nmap probes the firewall rated low (#2049, #4199). Malware and C2 keep their rating: the
infected device is inside MFU, blocked or not.
"""

from datetime import datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.detection.rules import blocked_attack_cap
from atdr.app.services.detection_service import run_detection

AT = datetime(2026, 5, 20, 13, 37, 15)
CHARACTERISTICS = "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _threat(*, src="34.78.120.11", dst="202.28.46.16", port=80, severity="low", name="Nmap Aggressive Option Print Detection(94318)",
            subtype="vulnerability", category="any", action="drop", src_zone="SG-Outside", dst_zone="WLAN-Inside", app="ssl",
            session_end_reason="threat") -> NormalizedLog:
    """Shaped like the live alert #4199: a probe from the internet the firewall dropped."""
    return NormalizedLog(
        generated_time=AT, receive_time=AT, log_type="THREAT", subtype=subtype, category=category, src_ip=src, dst_ip=dst,
        src_zone=src_zone, dst_zone=dst_zone, app=app, app_risk=4, app_characteristic=CHARACTERISTICS, dst_port=port,
        src_port=51515, protocol="tcp", action=action, session_end_reason=session_end_reason,
        parsed_json={"parsed_threat_severity": severity, "parsed_threat_name": name},
    )


def _store(db, *logs: NormalizedLog) -> None:
    for log in logs:
        raw = RawLog(raw_line=f"{log.src_ip} {log.dst_ip} {log.dst_port} {log.parsed_json}")
        db.add(raw)
        db.flush()
        log.raw_log_id = raw.id
        db.add(log)
    db.commit()


def test_the_cap_follows_the_firewalls_rating_for_blocked_attacks_from_the_internet_only():
    assert blocked_attack_cap(_threat(severity="informational")) == (30, "informational")
    assert blocked_attack_cap(_threat(severity="low")) == (30, "low")
    assert blocked_attack_cap(_threat(severity="medium")) == (60, "medium")
    assert blocked_attack_cap(_threat(severity="high")) == (80, "high")
    assert blocked_attack_cap(_threat(severity="critical")) == (80, "critical")
    assert blocked_attack_cap(_threat(action="reset-both")) == (30, "low"), "a reset is a block too"
    # Not capped: let through, not a threat record, from a private address, malware or C2, or no rating to follow.
    assert blocked_attack_cap(_threat(action="alert", session_end_reason="aged-out")) is None
    traffic = _threat()
    traffic.log_type = "TRAFFIC"
    assert blocked_attack_cap(traffic) is None
    assert blocked_attack_cap(_threat(src="10.20.30.40")) is None
    assert blocked_attack_cap(_threat(src="10.1.216.174", dst="57.129.69.132", src_zone="WLAN-Inside", dst_zone="SG-Outside")) is None
    assert blocked_attack_cap(_threat(subtype="spyware", severity="critical")) is None
    assert blocked_attack_cap(_threat(category="command-and-control", severity="critical")) is None
    assert blocked_attack_cap(_threat(severity="")) is None


@pytest.mark.parametrize("bounded", [False, True])
def test_blocked_attacks_from_the_internet_are_rated_by_the_firewall_and_malware_stays_critical(bounded):
    db = _session()
    _store(
        db,
        _threat(),  # #4199
        _threat(src="91.230.168.223", dst="202.28.44.17", port=111, app="portmapper", severity="medium",
                name="RPC Portmapper DUMP Request Detected(32796)"),  # #4208
        _threat(src="147.45.50.171", dst="202.28.44.41", app="web-browsing", severity="high",
                name="Apache HTTP Server Path Traversal Vulnerability(91752)"),  # #4218
        *[_threat(src="43.128.109.187", dst="202.28.46.68", app="web-browsing", severity="critical",
                  name="Bash Remote Code Execution Vulnerability(36729)") for _ in range(4)],  # #4188
        _threat(src="10.1.216.174", dst="57.129.69.132", port=14444, src_zone="WLAN-Inside", dst_zone="SG-Outside", app="json-rpc",
                subtype="spyware", severity="critical", name="XMRig Miner Command and Control Traffic Detection(85886)"),  # #4152
    )

    run_detection(db, limit=100, use_ml=False, actor="test", bounded_memory=bounded)

    by_source = {alert.src_ip: alert for alert in db.scalars(select(Alert))}
    assert {source: (alert.severity, alert.threat_score) for source, alert in by_source.items()} == {
        "34.78.120.11": ("Low", 30),
        "91.230.168.223": ("Medium", 60),
        "147.45.50.171": ("High", 80),
        "43.128.109.187": ("High", 80),
        "10.1.216.174": ("Critical", 100),
    }
    assert by_source["34.78.120.11"].explanation.endswith(
        "The firewall blocked this attack from the internet, so it is rated no higher than the firewall rated it (low).")
    assert "rated no higher" not in by_source["10.1.216.174"].explanation


@pytest.mark.parametrize("bounded", [False, True])
def test_the_same_probe_let_through_keeps_its_rating(bounded):
    db = _session()
    _store(db, _threat(action="alert", session_end_reason="aged-out"))

    run_detection(db, limit=100, use_ml=False, actor="test", bounded_memory=bounded)

    (alert,) = db.scalars(select(Alert))
    # The firewall's 20 points for a low rating and 45 for context, without the block's 25.
    assert (alert.severity, alert.threat_score) == ("High", 65)
    assert "rated no higher" not in alert.explanation
