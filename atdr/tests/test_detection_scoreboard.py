"""The detection scoreboard must score the *current* rules, never write the
source database, and keep one source's traffic on one side of the split."""

import hashlib
import ipaddress
from datetime import datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, MLLabel, NormalizedLog, RawLog
from atdr.app.services.detection_scoreboard_service import (
    ScoreboardError,
    confusion,
    run_detection_scoreboard,
    snapshot_database,
    split_for_source,
)


def _file_hash(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_db(path):
    engine = create_engine(f"sqlite:///{path.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, future=True)()


def _add_log(db, index: int, **fields) -> int:
    raw = RawLog(raw_line=f"scoreboard log {index}")
    db.add(raw)
    db.flush()
    log = NormalizedLog(raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, 36, index % 60), parsed_json={}, **fields)
    db.add(log)
    db.flush()
    return int(log.id)


def _scan_log(db, index: int) -> int:
    return _add_log(
        db,
        index,
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
    )


def _benign_log(db, index: int) -> int:
    return _add_log(
        db,
        100 + index,
        log_type="TRAFFIC",
        src_ip="10.9.9.9",
        dst_ip="93.184.216.34",
        src_zone="WLAN-Inside",
        dst_zone="SG-Outside",
        app="ssl",
        app_category="networking",
        app_risk=1,
        dst_port=443,
        action="allow",
        protocol="tcp",
        bytes=5000,
        packets=12,
    )


def _label(db, log_id: int, label: str, *, source: str = "manual") -> None:
    db.add(MLLabel(log_id=log_id, label=label, attack_type="port_scan" if label == "malicious" else "benign",
                   confidence=4, reviewer="tester", label_source=source, reviewed=True))


def test_confusion_math():
    pairs = [(True, True)] * 8 + [(True, False)] * 2 + [(False, True)] * 1 + [(False, False)] * 9
    m = confusion(pairs)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (8, 2, 1, 9)
    assert m["precision"] == pytest.approx(8 / 9, abs=1e-4)
    assert m["recall"] == 0.8
    assert m["false_alarm_rate"] == 0.1


def test_split_keeps_each_source_on_one_side_and_holds_out_about_thirty_percent():
    assert split_for_source("203.0.113.10") == split_for_source("203.0.113.10")
    ips = [str(ipaddress.IPv4Address(0x0A000000 + i)) for i in range(2000)]
    held_out = sum(1 for ip in ips if split_for_source(ip) == "test")
    assert 0.25 < held_out / len(ips) < 0.35


def test_scoreboard_scores_current_rules_not_stored_alerts_and_never_writes_source(tmp_path):
    source = tmp_path / "source.db"
    engine, db = _source_db(source)
    scan_ids = [_scan_log(db, index) for index in range(30)]
    benign_ids = [_benign_log(db, index) for index in range(5)]
    for log_id in scan_ids[:3]:
        _label(db, log_id, "malicious")
    for log_id in benign_ids:
        _label(db, log_id, "benign")
    _label(db, scan_ids[3], "needs_context")
    # A stale alert from "older rules" wrongly covers a benign log. The
    # scoreboard must ignore it and score only what today's rules produce.
    stale = Alert(title="Stale", alert_type="app_risk_4", src_ip="10.9.9.9", threat_score=40, severity="Medium",
                  status="open", explanation="old", matched_rules_json=[], recommended_response="-")
    db.add(stale)
    db.flush()
    db.add(AlertEvidence(alert_id=stale.id, normalized_log_id=benign_ids[0]))
    db.commit()
    db.close()
    engine.dispose()
    before = _file_hash(source)

    report = run_detection_scoreboard(source=source, work_dir=tmp_path / "work", report_dir=tmp_path / "reports")

    overall = report["overall"]["all"]
    assert (overall["tp"], overall["fn"], overall["fp"], overall["tn"]) == (3, 0, 0, 5)
    assert report["labels"]["excluded"] == {"needs_context": 1}
    assert report["by_alert_type"]["possible_port_scan"]["precision"] == 1.0
    assert "app_risk_4" not in report["alerts"]["by_type"]  # the stale alert is not counted as produced
    assert "possible_port_scan" in report["by_rule"]
    assert report["run"]["logs_checked"] == 35
    assert report["overall"]["dev"]["labeled_logs"] + report["overall"]["test"]["labeled_logs"] == 8
    assert (tmp_path / "reports" / "latest.json").exists()
    assert list((tmp_path / "work").glob("*.db")) == []

    assert _file_hash(source) == before
    check_engine = create_engine(f"sqlite:///{source.as_posix()}", future=True)
    with sessionmaker(bind=check_engine, future=True)() as check:
        assert [alert.title for alert in check.scalars(select(Alert))] == ["Stale"]
        assert check.scalar(select(NormalizedLog.last_detection_run_id).where(NormalizedLog.id == scan_ids[0])) is None
    check_engine.dispose()


def test_snapshot_refuses_to_overwrite_its_source(tmp_path):
    source = tmp_path / "source.db"
    engine, db = _source_db(source)
    db.close()
    engine.dispose()
    with pytest.raises(ScoreboardError):
        snapshot_database(source, source)
