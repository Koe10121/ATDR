from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.services.detection_service import run_detection


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _add_scan_log(db, index: int) -> None:
    raw = RawLog(raw_line=f"scan log {index}")
    db.add(raw)
    db.flush()
    db.add(
        NormalizedLog(
            raw_log_id=raw.id,
            generated_time=datetime(2026, 5, 20, 13, 36, 15),
            log_type="TRAFFIC",
            src_ip="203.0.113.10",
            dst_ip=f"10.0.0.{index}",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="unknown",
            app_category="unknown",
            dst_port=10000 + index,
            action="allow",
            protocol="tcp",
            bytes=100,
            packets=1,
            parsed_json={},
        )
    )


def test_run_detection_groups_related_logs_into_one_alert():
    db = _session()
    for index in range(30):
        _add_scan_log(db, index)
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["candidate_logs"] == 30
    assert result["created_alerts"] == 1
    assert len(alerts) == 1
    assert alerts[0].alert_type == "possible_port_scan"
    assert len(alerts[0].evidence) == 30


def test_run_detection_groups_internet_sweep_by_destination_port():
    db = _session()
    for index in range(20):
        raw = RawLog(raw_line=f"incomplete inbound {index}")
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(2026, 5, 20, 13, 36, 15),
                log_type="TRAFFIC",
                src_ip=f"198.51.100.{index}",
                dst_ip="10.0.0.50",
                src_zone="SG-Outside",
                dst_zone="WLAN-Inside",
                app="incomplete",
                app_category="unknown",
                dst_port=4040,
                action="allow",
                protocol="tcp",
                bytes=60,
                packets=1,
                parsed_json={},
            )
        )
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["candidate_logs"] == 20
    assert result["created_alerts"] == 1
    assert alerts[0].alert_type == "unusual_destination_port"
    assert alerts[0].src_ip is None
    assert len(alerts[0].evidence) == 20


def test_low_severity_singletons_are_suppressed():
    db = _session()
    for index in range(3):
        raw = RawLog(raw_line=f"app risk only {index}")
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(2026, 5, 20, 13, 36, 15),
                log_type="TRAFFIC",
                src_ip=f"172.25.1.{index}",
                dst_ip=f"203.0.113.{index}",
                src_zone="WLAN-Inside",
                dst_zone="SG-Outside",
                app="ssl",
                app_risk=4,
                app_characteristic="able-to-transfer-file",
                dst_port=443,
                action="allow",
                protocol="tcp",
                bytes=1000,
                packets=10,
                parsed_json={},
            )
        )
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["candidate_logs"] == 3
    assert result["created_alerts"] == 0
    assert result["suppressed_low_groups"] == 3
    assert alerts == []
