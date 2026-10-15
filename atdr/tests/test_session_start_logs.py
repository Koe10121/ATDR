"""A firewall that logs each session's start and end is counted once per session.

BOTSv2's lab firewall wrote a TRAFFIC "start" and an "end" record for every session (222,202 and 192,758), so
every count ATDR keeps would have seen each connection twice. MFU's firewall logs session ends only.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import LogSource, NormalizedLog, RawLog
from atdr.app.services.detection_scoreboard_service import run_all_detection
from atdr.app.services.detection_service import (
    _context_neighbour_records,
    dataset_outlier_thresholds,
    run_detection,
    without_session_starts,
)

AT = datetime(2017, 8, 23, 20, 30)


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _session(db, source: LogSource, index: int, subtype: str, *, ends_after: timedelta = timedelta(seconds=2),
             size: int = 4000) -> None:
    at = AT + timedelta(seconds=7 * index) + (ends_after if subtype == "end" else timedelta(0))
    raw = RawLog(raw_line=f"{source.name} {index} {subtype}", source_id=source.id)
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(
        raw_log_id=raw.id, generated_time=at, log_type="TRAFFIC", subtype=subtype, src_ip="10.0.2.107",
        dst_ip="45.77.65.211", src_zone="Inside", dst_zone="Outside", app="ssl", dst_port=443, src_port=40000 + index,
        protocol="tcp", action="allow", bytes=0 if subtype == "start" else size, packets=1 if subtype == "start" else 12,
        packets_received=0 if subtype == "start" else 6, session_end_reason=None if subtype == "start" else "tcp-fin",
        parsed_json={},
    ))


def _source(db, name: str) -> LogSource:
    source = LogSource(name=name, source_type="file_upload")
    db.add(source)
    db.flush()
    return source


def test_session_starts_are_left_out_only_where_the_firewall_also_logs_ends():
    db = _db()
    both, starts_only = _source(db, "logs-both"), _source(db, "logs-starts-only")
    for index in range(6):
        _session(db, both, index, "start")
        _session(db, both, index, "end")
        _session(db, starts_only, index, "start")
    # A blocked connection has one record of its own: it is kept.
    _session(db, both, 6, "deny")
    db.commit()

    logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id)))
    kept = without_session_starts(db, logs)
    assert sorted((log.raw_log.source_id, log.subtype) for log in kept) == sorted(
        [(both.id, "end")] * 6 + [(both.id, "deny")] + [(starts_only.id, "start")] * 6
    )
    ends_only = [log for log in logs if log.subtype == "end"]
    assert without_session_starts(db, ends_only) == ends_only


def test_skipped_starts_are_checked_and_a_batch_of_starts_alone_does_not_end_the_run():
    db = _db()
    source = _source(db, "logs-both")
    # Long sessions: the five starts fill one five-minute window and their ends come twenty minutes later, so the
    # first batch (whole windows) holds nothing but starts.
    for index in range(5):
        _session(db, source, index, "start")
        _session(db, source, index, "end", ends_after=timedelta(minutes=20))
    db.commit()

    first = run_detection(db, limit=5, use_ml=False, actor="test", only_unchecked=True, model_alerts=False)
    assert first["session_starts_skipped"] == 5
    assert first["evaluated"] == 5, "a run that checked only skipped starts still checked them"

    totals = run_all_detection(db, batch_size=5)
    assert int(db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.last_detection_run_id.is_(None)))) == 0
    assert totals["logs_checked"] == 5


def test_the_neighbours_counted_around_a_batch_hold_no_redundant_starts():
    db = _db()
    source = _source(db, "logs-both")
    for index in range(6):
        _session(db, source, index, "start")
        _session(db, source, index, "end")
    db.commit()
    logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.generated_time, NormalizedLog.id)))

    neighbours = _context_neighbour_records(db, logs[-1:], source_id=None)

    assert neighbours and {record.subtype for record in neighbours} == {"end"}


def test_session_starts_do_not_lower_the_bar_for_unusually_large_sessions():
    db = _db()
    source = _source(db, "logs-both")
    # Sessions of 1 MB and 60 MB put the bar well above its 10 MB floor.
    for index in range(40):
        _session(db, source, index, "end", size=60_000_000 if index % 2 else 1_000_000)
    db.commit()
    before = dataset_outlier_thresholds(db)
    assert before[0] > 100_000_000

    for index in range(40, 400):
        _session(db, source, index, "start")
    db.commit()

    assert dataset_outlier_thresholds(db) == before
