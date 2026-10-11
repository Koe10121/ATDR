"""New logs are checked by themselves, a five-minute window at a time, once their evidence is complete."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Event

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, DetectionRun, NormalizedLog, OperationJob, RawLog
from atdr.app.services import auto_detection_service, operation_worker
from atdr.app.services.auto_detection_service import (
    AUTO_DETECTION_ACTOR,
    automatic_detection_status,
    due_logs,
    run_automatic_detection,
)
from atdr.app.services.detection_service import run_detection
from atdr.app.services.job_service import record_worker_heartbeat

STORED = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
QUIET = 120.0


def _sessions():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _store(db, entries, stored_at: datetime) -> list[int]:
    ids = []
    for at, fields in entries:
        raw = RawLog(raw_line=f"auto detection {at.isoformat()} {fields['src_ip']} {fields['dst_port']}", imported_at=stored_at)
        db.add(raw)
        db.flush()
        log = NormalizedLog(raw_log_id=raw.id, generated_time=at, log_type="TRAFFIC", protocol="tcp", parsed_json={}, **fields)
        db.add(log)
        db.flush()
        ids.append(int(log.id))
    db.commit()
    return ids


def _benign(at: datetime, host: int = 1):
    return at, {
        "src_ip": f"10.1.1.{host}", "dst_ip": "93.184.216.34", "src_zone": "WLAN-Inside", "dst_zone": "SG-Outside",
        "app": "ssl", "app_risk": 1, "dst_port": 443, "action": "allow", "bytes": 5000, "packets": 12,
    }


def _probe(at: datetime, port: int):
    return at, {
        "src_ip": "203.0.113.10", "dst_ip": "10.20.30.40", "src_zone": "SG-Outside", "dst_zone": "LAN-Inside",
        "app": "incomplete", "dst_port": port, "action": "deny", "bytes": 60, "packets": 1,
    }


def _check_in(at: datetime):
    return at, {
        "src_ip": "10.1.5.5", "dst_ip": "198.51.100.77", "src_zone": "LAN-Inside", "dst_zone": "SG-Outside",
        "app": "unknown-tcp", "dst_port": 4444, "action": "allow", "bytes": 300, "packets": 4,
    }


def _traffic(attack: str = "scan") -> list:
    """Twenty minutes of ordinary traffic with an attack that crosses the 13:40 window edge.

    "scan": 12 denied probes of different ports, five seconds apart from 13:39:30.
    "beacon": six check-ins with one outside server, a minute apart from 13:38:10.
    """

    start = datetime(2026, 5, 20, 13, 36)
    entries = [_benign(start + timedelta(seconds=10 * step), host=1 + step % 3) for step in range(120)]
    if attack == "scan":
        entries += [_probe(datetime(2026, 5, 20, 13, 39, 30) + timedelta(seconds=5 * index), 20000 + index) for index in range(12)]
    else:
        entries += [_check_in(datetime(2026, 5, 20, 13, 38, 10) + timedelta(minutes=index)) for index in range(6)]
    return sorted(entries, key=lambda entry: entry[0])


def _alerts(db) -> list[tuple]:
    evidence: dict[int, list[int]] = {}
    for alert_id, log_id in db.execute(select(AlertEvidence.alert_id, AlertEvidence.normalized_log_id)):
        evidence.setdefault(alert_id, []).append(log_id)
    return sorted(
        (alert.alert_type, alert.severity, alert.threat_score, tuple(sorted(evidence.get(alert.id, []))))
        for alert in db.scalars(select(Alert))
    )


def test_a_window_is_due_once_the_window_after_it_is_complete_or_logs_stop_arriving():
    db = _sessions()()
    just_stored = STORED + timedelta(seconds=1)
    assert due_logs(db, now=just_stored, quiet_seconds=QUIET).due is False

    _store(db, [_benign(datetime(2026, 5, 20, 13, 36)), _benign(datetime(2026, 5, 20, 13, 39, 59))], STORED)
    still_open = due_logs(db, now=just_stored, quiet_seconds=QUIET)
    assert (still_open.waiting, still_open.due, still_open.reason) == (2, False, "newest_window_still_open")

    # A log in the next window closes 13:35-13:40, but that window is still evidence for the beaconing rule.
    _store(db, [_benign(datetime(2026, 5, 20, 13, 44, 59))], STORED)
    assert due_logs(db, now=just_stored, quiet_seconds=QUIET).due is False

    _store(db, [_benign(datetime(2026, 5, 20, 13, 45))], STORED)
    complete = due_logs(db, now=just_stored, quiet_seconds=QUIET)
    assert (complete.due, complete.before, complete.reason) == (True, datetime(2026, 5, 20, 13, 40), "window_complete")

    # Nothing stored for the quiet period: an import has finished or the feed has stopped, so everything is due.
    quiet = due_logs(db, now=STORED + timedelta(seconds=QUIET), quiet_seconds=QUIET)
    assert (quiet.waiting, quiet.due, quiet.before, quiet.reason) == (4, True, None, "logs_stopped_arriving")


@pytest.mark.parametrize(("attack", "alert_type", "attack_logs"), [("scan", "possible_port_scan", 12), ("beacon", "beaconing_like_outbound", 6)])
def test_logs_arriving_live_are_alerted_exactly_as_when_checked_after_they_have_all_arrived(attack, alert_type, attack_logs):
    # Checked as soon as its own window closed, the scan's first half was raised as "multiple denied connections"
    # (High) instead of a port scan (Critical); checked half a window later, the beacon's alert kept four of its six
    # check-ins. Waiting for the whole following window gives what checking the stored traffic gives.
    settings = get_settings().model_copy(update={"auto_detection_quiet_seconds": QUIET})
    traffic = _traffic(attack)

    # The button on a large file: every step is one whole five-minute window, with all the traffic already stored.
    stored_first = _sessions()()
    _store(stored_first, traffic, STORED)
    for _ in range(20):
        step = run_detection(stored_first, limit=1, use_ml=False, actor="test", only_unchecked=True)
        if not step["remaining_unchecked"]:
            break
    expected = _alerts(stored_first)
    found = {log_id for _type, _severity, _score, evidence in expected if _type == alert_type for log_id in evidence}
    assert len(found) == attack_logs, "every log of the attack across the window edge is alerted as that attack"

    # One step for the whole file alerts the same logs as that attack. A scan that crosses a window edge is one alert
    # either way now: window-sized steps used to make one per window, because its halves share no destination port.
    at_once = _sessions()()
    _store(at_once, traffic, STORED)
    whole = run_automatic_detection(at_once, now=STORED + timedelta(seconds=QUIET), settings=settings)
    assert whole["evaluated"] == len(traffic) and whole["reason"] == "logs_stopped_arriving"
    assert {log_id for *_, evidence in _alerts(at_once) for log_id in evidence} == {log_id for *_, evidence in expected for log_id in evidence}
    assert {alert[0] for alert in _alerts(at_once)} == {alert[0] for alert in expected}
    assert len([alert for alert in expected if alert[0] == alert_type]) == 1, "window by window, the attack is still one alert"

    live = _sessions()()
    checked_before_its_time = []
    clock = STORED
    for start in range(0, len(traffic), 4):
        arrived = traffic[start:start + 4]
        clock += timedelta(seconds=1)
        _store(live, arrived, clock)
        result = run_automatic_detection(live, now=clock + timedelta(seconds=1), settings=settings)
        newest = arrived[-1][0]
        if newest < datetime(2026, 5, 20, 13, 45) and result is not None:
            checked_before_its_time.append((newest, result["evaluated"]))
    assert checked_before_its_time == [], "nothing is checked until the window after it is complete"
    # 13:35-13:40 was checked while later windows were still arriving; the rest once the feed went quiet.
    assert live.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.last_detection_run_id.is_not(None))) > 0
    assert live.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.last_detection_run_id.is_(None))) > 0
    run_automatic_detection(live, now=clock + timedelta(seconds=QUIET), settings=settings)

    assert live.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.last_detection_run_id.is_(None))) == 0
    assert _alerts(live) == expected


def test_while_a_check_reads_and_judges_its_logs_other_writers_are_not_held_up(tmp_path, monkeypatch):
    # The run's own record took SQLite's only write lock and kept it until the final commit: on one window of MFU
    # traffic that was 44 seconds, and the syslog receiver's save failed with "database is locked".
    import sqlite3

    from atdr.app.services import detection_service

    path = tmp_path / "detection.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}", connect_args={"timeout": 5}, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()
    _store(db, _traffic("scan"), STORED)
    other_writer: list[str] = []
    judge = detection_service.evaluate_rules

    def judge_while_another_writer_tries(log, context):
        if not other_writer:
            writer = sqlite3.connect(str(path), timeout=0.2, isolation_level=None)
            try:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("ROLLBACK")
                other_writer.append("wrote")
            except sqlite3.OperationalError as exc:
                other_writer.append(str(exc))
            finally:
                writer.close()
        return judge(log, context)

    monkeypatch.setattr(detection_service, "evaluate_rules", judge_while_another_writer_tries)
    result = run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True)

    assert other_writer == ["wrote"]
    assert result["created_alerts"] > 0
    assert db.scalar(select(DetectionRun.status).where(DetectionRun.id == result["detection_run_id"])) == "completed"


def test_logs_that_are_already_alert_evidence_are_not_judged_again():
    # Only the batch's own logs are looked up among the evidence (every evidence row ever stored grows with a
    # live feed), and that must still find them.
    db = _sessions()()
    _store(db, _traffic("scan"), STORED)

    first = run_detection(db, limit=None, use_ml=False, actor="test")
    alerts = _alerts(db)
    again = run_detection(db, limit=None, use_ml=False, actor="test")

    assert first["created_alerts"] > 0
    assert (again["created_alerts"], again["deduplicated_alert_updates"]) == (0, 0)
    assert _alerts(db) == alerts


def test_a_check_left_running_by_an_ended_process_is_closed_by_the_next_one():
    # A run's record is saved when it starts, so stopping ATDR mid-check used to leave it "running" for good.
    db = _sessions()()
    _store(db, _traffic("scan"), STORED)
    now = datetime.now(timezone.utc)
    record = {"detection_type": "rule", "status": "running", "logs_evaluated": 0, "alerts_created": 0,
              "alerts_deduplicated": 0, "alerts_suppressed": 0, "top_attack_types_json": [], "details_json": {}}
    db.add(DetectionRun(**record, started_at=now - timedelta(hours=2)))
    db.add(DetectionRun(**record, started_at=now - timedelta(minutes=1)))
    db.commit()

    run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True)

    runs = list(db.scalars(select(DetectionRun).order_by(DetectionRun.id)))
    assert [run.status for run in runs] == ["failed", "running", "completed"], "a run a minute old may still be working"
    assert "ended before it finished" in runs[0].error_summary


def test_an_automatic_check_is_recorded_like_a_manual_one_and_shown_on_the_page():
    testing_session = _sessions()
    settings = get_settings().model_copy(update={"auto_detection_enabled": True, "auto_detection_quiet_seconds": QUIET})
    with testing_session() as db:
        assert run_automatic_detection(db, now=STORED, settings=settings) is None
        assert db.scalar(select(func.count(OperationJob.id))) == 0 and db.scalar(select(func.count(DetectionRun.id))) == 0
        before = automatic_detection_status(db, settings=settings, now=STORED)
        assert before == {"enabled": True, "worker_running": False, "quiet_seconds": 120, "window_minutes": 5, "last_check": None}

        ids = _store(db, _traffic(), STORED)
        result = run_automatic_detection(db, now=STORED + timedelta(seconds=QUIET), settings=settings)
        record_worker_heartbeat(db, worker_id="worker-one", status="idle")
        status = automatic_detection_status(db, settings=settings)
        job = db.get(OperationJob, result["job_id"])
        recorded = (job.job_type, job.requested_by, job.status, dict(job.details_json), dict(job.result_summary_json), job.related_detection_run_id)
        runs = [(run.id, run.details_json["actor"]) for run in db.scalars(select(DetectionRun).order_by(DetectionRun.id))]
        job_started, job_finished = job.started_at, job.finished_at
        first_step_finished = db.scalar(select(func.min(DetectionRun.finished_at)))

    # The job spans the whole check: it starts before the first step ends, not when the job row was written.
    assert job_started <= first_step_finished <= job_finished
    assert recorded[:3] == ("run_detection", AUTO_DETECTION_ACTOR, "completed")
    assert recorded[3]["automatic"] is True and recorded[3]["reason"] == "logs_stopped_arriving"
    assert recorded[4]["logs_evaluated"] == len(ids) and recorded[4]["alerts_created"] == result["created_alerts"] >= 1
    assert recorded[5] == runs[-1][0] and all(actor == AUTO_DETECTION_ACTOR for _run_id, actor in runs)
    assert status["worker_running"] is True
    assert status["last_check"] == {
        "status": "completed", "finished_at": status["last_check"]["finished_at"], "logs_checked": len(ids),
        "alerts_created": result["created_alerts"], "alerts_updated": result["deduplicated_alert_updates"],
    }
    assert status["last_check"]["finished_at"].endswith("+00:00")


def test_a_busy_database_is_tried_again_later_and_any_other_failure_is_recorded(monkeypatch):
    testing_session = _sessions()
    settings = get_settings().model_copy(update={"auto_detection_quiet_seconds": QUIET})
    quiet = STORED + timedelta(seconds=QUIET)

    def busy(*_args, **_kwargs):
        raise OperationalError("INSERT INTO detection_runs", {}, Exception("database is locked"))

    def broken(*_args, **_kwargs):
        raise RuntimeError("rule crashed")

    with testing_session() as db:
        _store(db, [_benign(datetime(2026, 5, 20, 13, 36))], STORED)
        monkeypatch.setattr(auto_detection_service, "run_detection", busy)
        # An import or a manual check holds SQLite's one write lock: no failed job, the next look tries again.
        assert run_automatic_detection(db, now=quiet, settings=settings) is None
        assert db.scalar(select(func.count(OperationJob.id))) == 0

        monkeypatch.setattr(auto_detection_service, "run_detection", broken)
        with pytest.raises(RuntimeError, match="rule crashed"):
            run_automatic_detection(db, now=quiet, settings=settings)
        failed = db.scalar(select(OperationJob))
        status = automatic_detection_status(db, settings=settings)

    assert (failed.requested_by, failed.status) == (AUTO_DETECTION_ACTOR, "failed")
    assert status["last_check"]["status"] == "failed" and status["last_check"]["logs_checked"] == 0


def test_the_worker_looks_for_logs_to_check_only_when_switched_on_and_never_dies_of_a_failed_check(monkeypatch):
    testing_session = _sessions()
    monkeypatch.setattr(operation_worker, "SessionLocal", testing_session)
    calls = []

    def checked(db, *, settings, between_batches):
        calls.append("check")
        between_batches()
        return outcomes.pop(0)

    def crashed(db, *, settings, between_batches):
        calls.append("crash")
        raise RuntimeError("rule crashed")

    def switched(on: bool):
        configured = get_settings().model_copy(update={"auto_detection_enabled": on, "auto_detection_poll_seconds": 15.0})
        monkeypatch.setattr(operation_worker, "get_settings", lambda: configured)

    monkeypatch.setattr(operation_worker, "run_automatic_detection", checked)
    monkeypatch.setattr(operation_worker.time, "monotonic", lambda: 1000.0)
    outcomes = [None, {"more_due": True}, {"more_due": False}]

    switched(False)
    assert operation_worker._automatic_detection_look("worker-one", 0.0) == 0.0 and calls == []

    switched(True)
    assert operation_worker._automatic_detection_look("worker-one", 1000.5) == 1000.5 and calls == [], "not yet time to look"
    assert operation_worker._automatic_detection_look("worker-one", 0.0) == 1015.0, "nothing due: look again after the poll time"
    assert operation_worker._automatic_detection_look("worker-one", 0.0) == 1000.0, "complete windows still waiting: look again at once"
    assert operation_worker._automatic_detection_look("worker-one", 0.0) == 1015.0
    with testing_session() as db:
        heartbeat = db.get(operation_worker.OperationWorkerHeartbeat, "worker-one")
        assert heartbeat.status == "running" and heartbeat.details_json["automatic_detection"] is True

    monkeypatch.setattr(operation_worker, "run_automatic_detection", crashed)
    assert operation_worker._automatic_detection_look("worker-one", 0.0) == 1015.0
    assert calls == ["check", "check", "check", "crash"]


def test_the_idle_worker_checks_waiting_logs_and_queued_jobs_still_come_first(monkeypatch):
    testing_session = _sessions()
    configured = get_settings().model_copy(update={
        "auto_detection_enabled": True, "auto_detection_quiet_seconds": 0.001, "auto_detection_poll_seconds": 0.01,
        "operation_worker_poll_seconds": 0.01,
    })
    monkeypatch.setattr(operation_worker, "SessionLocal", testing_session)
    monkeypatch.setattr(operation_worker, "get_settings", lambda: configured)
    with testing_session() as db:
        ids = _store(db, _traffic(), STORED)
    stop = Event()
    real_check = operation_worker.run_automatic_detection
    order = []

    def check_then_stop(db, *, settings, between_batches):
        order.append("automatic check")
        result = real_check(db, settings=settings, between_batches=between_batches)
        stop.set()
        return result

    real_once = operation_worker.run_worker_once

    def once(db, **kwargs):
        order.append("queued jobs")
        if len(order) > 400:
            stop.set()  # the check never ran: end the loop so the test fails instead of hanging
        return real_once(db, **kwargs)

    monkeypatch.setattr(operation_worker, "run_automatic_detection", check_then_stop)
    monkeypatch.setattr(operation_worker, "run_worker_once", once)

    assert operation_worker.run_worker_loop(worker_id="worker-one", stop_event=stop) == []

    assert order[:2] == ["queued jobs", "automatic check"]
    with testing_session() as db:
        assert db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.last_detection_run_id.is_(None))) == 0
        job = db.scalar(select(OperationJob).where(OperationJob.requested_by == AUTO_DETECTION_ACTOR))
        assert job.status == "completed" and job.result_summary_json["logs_evaluated"] == len(ids)
        assert db.scalar(select(func.count(Alert.id))) >= 1


def test_the_coverage_api_tells_the_page_about_automatic_checks():
    from atdr.app.db.database import get_db
    from atdr.app.main import app
    from atdr.tests.test_api import _client, _login

    client = _client()
    try:
        admin = _login(client, "admin", "admin123")
        coverage = client.get("/api/demo/detection-coverage", headers=admin).json()
        automatic = coverage["automatic"]
        assert coverage["live_feed"]["state"] in {"off", "not_started"}
        assert app.dependency_overrides[get_db] is not None
    finally:
        app.dependency_overrides.clear()

    assert automatic == {
        "enabled": get_settings().auto_detection_enabled,
        "worker_running": False,
        "quiet_seconds": int(get_settings().auto_detection_quiet_seconds),
        "window_minutes": 5,
        "last_check": None,
    }


def test_a_worker_killed_moments_ago_does_not_keep_the_next_one_from_starting():
    # scripts\stop_system ends the worker at once, so it cannot say it stopped. Restarted within three heartbeats, the
    # new worker found the old one's fresh heartbeat, refused to start, and ATDR ran with no worker at all: queued
    # imports waited and automatic checks never ran.
    import os
    import subprocess
    import sys

    from atdr.app.db.models import OperationWorkerHeartbeat
    from atdr.app.services.operation_worker import WorkerConcurrencyError, enforce_worker_concurrency

    ended = subprocess.Popen([sys.executable, "-c", "pass"])
    ended.wait()
    assert operation_worker._process_exists(os.getpid()) and not operation_worker._process_exists(ended.pid)
    here = operation_worker._local_worker_prefix()
    killed, running, elsewhere = f"{here}{ended.pid}", f"{here}{os.getpid()}", f"another-laptop-operation-worker-{ended.pid}"

    testing_session = _sessions()
    with testing_session() as db:
        record_worker_heartbeat(db, worker_id=killed, status="idle")
        enforce_worker_concurrency(db, worker_id="the-new-worker", heartbeat_seconds=15)
        left_behind = db.get(OperationWorkerHeartbeat, killed)
        assert (left_behind.status, left_behind.details_json["shutdown"]) == ("stopped", "process_gone")

        # A worker whose process is running keeps a second one out, and so does one this machine cannot see.
        for other in (running, elsewhere):
            record_worker_heartbeat(db, worker_id=other, status="idle")
            with pytest.raises(WorkerConcurrencyError, match="SQLite permits one"):
                enforce_worker_concurrency(db, worker_id="the-new-worker", heartbeat_seconds=15)
            record_worker_heartbeat(db, worker_id=other, status="stopped")


def test_a_process_that_was_given_the_stopped_workers_number_is_not_the_worker():
    # Windows gives a process number out again within seconds. On 11 October 2026 a release stopped the worker and
    # built the dashboard; thirty seconds later the new worker found the old one's number in use by another process,
    # refused to start ("SQLite permits one ATDR operation worker"), and ATDR ran with none.
    import subprocess
    import sys
    from datetime import timezone

    from atdr.app.db.models import OperationWorkerHeartbeat
    from atdr.app.services.operation_worker import WorkerConcurrencyError, enforce_worker_concurrency

    other_process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        number = other_process.pid
        started = operation_worker._process_started_at(number)
        assert operation_worker._process_exists(number)
        assert operation_worker._process_started_at(2147483000) is None, "no such process"
        worker = f"{operation_worker._local_worker_prefix()}{number}"
        testing_session = _sessions()
        with testing_session() as db:
            record_worker_heartbeat(db, worker_id=worker, status="idle")
            row = db.get(OperationWorkerHeartbeat, worker)
            if started is None:
                # Off Windows the moment a process started is not asked for: a number that is in use counts as the worker.
                assert sys.platform != "win32"
                with pytest.raises(WorkerConcurrencyError, match="SQLite permits one"):
                    enforce_worker_concurrency(db, worker_id="the-new-worker", heartbeat_seconds=15)
                return
            assert abs((datetime.now(timezone.utc) - started).total_seconds()) < 30

            # Last heard from after that process started: it may well be the worker, and a second one is kept out.
            with pytest.raises(WorkerConcurrencyError, match="SQLite permits one"):
                enforce_worker_concurrency(db, worker_id="the-new-worker", heartbeat_seconds=15)

            # Last heard from before that process existed (and still within three heartbeats): the number was given
            # to another process since. The worker is gone, its heartbeat is closed, and the new one starts.
            row.last_seen_at = started - timedelta(seconds=5)
            db.commit()
            # Five seconds old against a limit of three hours: fresh, so it is the number that decides.
            enforce_worker_concurrency(db, worker_id="the-new-worker", heartbeat_seconds=3600)
            db.refresh(row)
            assert (row.status, row.details_json["shutdown"]) == ("stopped", "process_gone")
    finally:
        other_process.kill()
        other_process.wait()


def test_the_sign_in_start_waits_for_the_start_script_alone_and_installs_one_entry():
    # Read through a pipe, the start script's output never ended: ATDR's own processes keep the pipe open, the
    # sign-in task stayed "running", and Windows would have stopped it, and ATDR with it, at the task's time limit.
    from pathlib import Path

    scripts = Path(__file__).resolve().parents[2] / "scripts"
    launcher = (scripts / "start_at_sign_in.ps1").read_text(encoding="utf-8")
    code = "\n".join(line for line in launcher.splitlines() if not line.lstrip().startswith("#"))
    assert "-RedirectStandardOutput $out" in code and "-RedirectStandardError $err" in code and "-NoBrowser" in code
    assert "$start.WaitForExit()" in code and "$null = $start.Handle" in code
    assert "Out-String" not in code and "-Wait" not in code

    installer = (scripts / "autostart.ps1").read_text(encoding="utf-8")
    assert "New-ScheduledTaskTrigger -AtLogOn -User $user" in installer and "-RunLevel Limited" in installer
    assert 'GetFolderPath("Startup")' in installer and "Unregister-ScheduledTask" in installer
    assert "autostart.ps1" in (scripts / "autostart.cmd").read_text(encoding="utf-8")
