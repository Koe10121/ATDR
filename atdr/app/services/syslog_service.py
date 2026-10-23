"""UDP syslog receiver.

A thread takes datagrams off the socket into memory as they arrive; the calling thread saves them in batches. Saving
one line at a time in the receiving loop capped the receiver at about 500 lines a second, below MFU's firewall rate
(about 600 a second, bursts above 1,000), and while it saved, datagrams waited in the operating system's small socket
buffer, which drops overflow without telling anyone. A detection run holding the database made the save raise
"database is locked", which ended the receiver. Now a busy database is waited out, and every line is accounted for:
saved, counted as a repeat, or counted as dropped when max_pending lines are already waiting in memory.
"""

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import logging
from pathlib import Path
import queue
import shutil
import socket
import threading
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import AuditLog, IngestionRun, LogSource, TrafficHourlySummary
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.log_service import StoredBatch, store_parsed_batch
from atdr.app.services.operation_run_service import complete_ingestion_run, start_ingestion_run
from atdr.app.services.runtime_parser_quality_service import (
    empty_runtime_parser_quality,
    merge_runtime_parser_quality,
)
from atdr.app.services.source_service import get_or_create_source, record_source_ingestion


logger = logging.getLogger(__name__)

SOURCE_TYPE = "syslog_udp"
AUDIT_EVERY_SECONDS = 3600.0
BUSY_RETRY_DELAYS = (0.1, 0.25, 0.5, 1.0, 2.0)
# Once asked to stop, a database busy this long is given up on, and every line still unsaved is counted as dropped.
# Closing the receiver's run, a single small write, gets its own wait.
STOPPING_BUSY_LIMIT_SECONDS = 60.0
CLOSING_BUSY_LIMIT_SECONDS = 10.0
RATE_WINDOW_SECONDS = 60.0
# How often the receiver looks at the free disk space.
DISK_CHECK_SECONDS = 10.0


@dataclass
class _Datagram:
    text: str
    host: str
    port: int
    arrived: float


@dataclass
class _Received:
    """Written only by the receiving thread."""

    received: int = 0
    dropped: int = 0
    socket_errors: int = 0
    timed_out: bool = False
    senders: set[str] = field(default_factory=set)
    non_loopback_sender_observed: bool = False
    last_received_at: datetime | None = None


@dataclass
class _Saved:
    """Written only by the saving thread."""

    stored: int = 0
    parsed: int = 0
    failed: int = 0
    duplicates: int = 0
    unstorable: int = 0
    dropped_at_stop: int = 0
    dropped_disk_low: int = 0
    disk_low: bool = False
    free_disk_gb: float | None = None
    gave_up: bool = False
    batches: int = 0
    busy_retries: int = 0
    parser_quality: dict[str, Any] = field(default_factory=empty_runtime_parser_quality)

    def add(self, stored: StoredBatch) -> None:
        self.stored += stored.stored
        self.parsed += stored.parsed
        self.failed += stored.failed
        self.duplicates += stored.skipped_repeats
        if stored.stored:
            self.parser_quality = merge_runtime_parser_quality(self.parser_quality, stored.parser_quality)


def _dropped(state: "_Received", saved: _Saved) -> int:
    """Every line received and not saved: no room in memory, the disk nearly full, or still unsaved at a stop."""

    return state.dropped + saved.dropped_at_stop + saved.dropped_disk_low


def _database_folder(make_session: Callable[[], Session]) -> Path | None:
    """The folder of a SQLite database file, whose disk the receiver watches; None for any other database."""

    with make_session() as db:
        url = db.get_bind().url
    if not url.drivername.startswith("sqlite") or url.database in (None, "", ":memory:"):
        return None
    return Path(url.database).resolve().parent


def _look_at_disk(folder: Path | None, min_free_gb: float, saved: _Saved) -> None:
    if folder is None or min_free_gb <= 0:
        saved.disk_low = False
        return
    try:
        saved.free_disk_gb = shutil.disk_usage(folder).free / 1e9
    except OSError:
        return
    was_low, saved.disk_low = saved.disk_low, saved.free_disk_gb < min_free_gb
    if saved.disk_low and not was_low:
        logger.warning("Disk almost full (%.1f GB free): syslog lines are counted as lost, not saved.", saved.free_disk_gb)
    elif was_low and not saved.disk_low:
        logger.info("Disk space is back (%.1f GB free): syslog lines are saved again.", saved.free_disk_gb)


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _database_busy(exc: BaseException) -> bool:
    text = str(getattr(exc, "orig", exc)).lower()
    return isinstance(exc, OperationalError) and ("locked" in text or "busy" in text)


def _request_receive_buffer(sock: socket.socket, wanted: int) -> int:
    """Ask for a socket buffer big enough to ride out a pause; the system may grant less. Returns what it granted."""

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(wanted))
    except OSError:
        pass
    return int(sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))


def _receive(
    sock: socket.socket,
    pending: "queue.Queue[_Datagram]",
    state: _Received,
    finished: threading.Event,
    *,
    max_messages: int | None,
    socket_timeout: float | None,
    stop_event: threading.Event | None,
) -> None:
    sock.settimeout(0.2)
    last_datagram = time.monotonic()
    try:
        while not finished.is_set():
            if stop_event is not None and stop_event.is_set():
                break
            if max_messages is not None and state.received >= max_messages:
                break
            try:
                payload, address = sock.recvfrom(65535)
            except (TimeoutError, socket.timeout):
                if socket_timeout is not None and time.monotonic() - last_datagram >= socket_timeout:
                    state.timed_out = True
                    break
                continue
            except OSError:
                # Windows reports some ICMP errors as receive errors on a UDP socket; the socket stays usable.
                state.socket_errors += 1
                continue
            now = time.monotonic()
            last_datagram = now
            text = payload.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            host = str(address[0])
            state.received += 1
            state.last_received_at = datetime.now(timezone.utc)
            if host not in state.senders:
                state.senders.add(host)
                state.non_loopback_sender_observed = state.non_loopback_sender_observed or not _is_loopback(host)
            try:
                pending.put_nowait(_Datagram(text, host, int(address[1]), now))
            except queue.Full:
                state.dropped += 1
    finally:
        finished.set()


def _next_batch(
    pending: "queue.Queue[_Datagram]", size: int, within: float, finished: threading.Event
) -> list[_Datagram]:
    """Up to `size` lines, returned no later than `within` seconds after the oldest of them arrived."""

    try:
        first = pending.get(timeout=0.2)
    except queue.Empty:
        return []
    batch = [first]
    deadline = first.arrived + within
    while len(batch) < size:
        remaining = deadline - time.monotonic()
        try:
            batch.append(pending.get_nowait() if remaining <= 0 else pending.get(timeout=min(remaining, 0.2)))
        except queue.Empty:
            if remaining <= 0 or (finished.is_set() and pending.empty()):
                break
    return batch


def _source_for(db: Session, item: _Datagram, cache: dict[str, int]) -> LogSource:
    known = cache.get(item.host)
    source = db.get(LogSource, known) if known is not None else None
    if source is None:
        source = get_or_create_source(
            db, name=f"syslog_udp:{item.host}", source_type=SOURCE_TYPE, host=item.host, port=item.port
        )
        cache[item.host] = int(source.id)
    return source


def _store(db: Session, batch: list[_Datagram], sources: dict[str, int]) -> list[StoredBatch]:
    by_sender: dict[str, list[_Datagram]] = {}
    for item in batch:
        by_sender.setdefault(item.host, []).append(item)
    results = []
    for items in by_sender.values():
        source = _source_for(db, items[0], sources)
        parsed = [parse_log_line_for_profile(item.text, source.parser_profile) for item in items]
        stored = store_parsed_batch(db, parsed, source_id=source.id, parser_profile=source.parser_profile)
        record_source_ingestion(
            source,
            logs_received=len(items),
            parsed_successfully=stored.parsed,
            parse_failures=stored.failed,
            latest_error=stored.latest_error,
            parser_quality=stored.parser_quality if stored.stored else None,
        )
        results.append(stored)
    return results


def _commit_with_retry(
    make_session: Callable[[], Session],
    work: Callable[[Session], Any],
    saved: _Saved,
    stopping: threading.Event,
    *,
    own_limit: float | None = None,
) -> Any:
    """Run `work` and commit, waiting out a busy database for as long as the receiver is running.

    Once asked to stop, it gives up after STOPPING_BUSY_LIMIT_SECONDS of a busy database, or the caller's own limit.
    """

    attempt = 0
    busy_since: float | None = None
    limit = STOPPING_BUSY_LIMIT_SECONDS if own_limit is None else own_limit
    while True:
        try:
            with make_session() as db:
                outcome = work(db)
                db.commit()
                return outcome
        except OperationalError as exc:
            if not _database_busy(exc):
                raise
            now = time.monotonic()
            busy_since = busy_since if busy_since is not None else now
            if stopping.is_set() and now - busy_since >= limit:
                raise
            saved.busy_retries += 1
            time.sleep(BUSY_RETRY_DELAYS[min(attempt, len(BUSY_RETRY_DELAYS) - 1)])
            attempt += 1


_last_warning: dict[str, float] = {}


def _warn_now_and_then(message: str, *args: Any) -> None:
    key = message
    now = time.monotonic()
    if now - _last_warning.get(key, -1e9) >= 60:
        _last_warning[key] = now
        logger.warning(message, *args)


def _save(
    make_session: Callable[[], Session],
    batch: list[_Datagram],
    sources: dict[str, int],
    saved: _Saved,
    stopping: threading.Event,
) -> None:
    """Save a batch. A line that cannot be stored is found by halving the batch, counted, and skipped."""

    try:
        results = _commit_with_retry(make_session, lambda db: _store(db, batch, sources), saved, stopping)
    except Exception as exc:
        if _database_busy(exc):
            saved.dropped_at_stop += len(batch)
            saved.gave_up = True
            _warn_now_and_then("Syslog receiver stopping: the database stayed busy; unsaved lines are counted as dropped.")
            return
        if len(batch) == 1:
            saved.unstorable += 1
            _warn_now_and_then("A syslog line could not be stored (%s); it is counted as unstorable.", exc.__class__.__name__)
            return
        middle = len(batch) // 2
        _save(make_session, batch[:middle], sources, saved, stopping)
        _save(make_session, batch[middle:], sources, saved, stopping)
        return
    for stored in results:
        saved.add(stored)
    saved.batches += 1


def _status(
    state: _Received, saved: _Saved, pending: "queue.Queue[_Datagram]", rate: float | None, base: dict[str, Any]
) -> dict[str, Any]:
    return {
        **base,
        "dropped": _dropped(state, saved),
        "pending": pending.qsize(),
        "unstorable": saved.unstorable,
        "busy_retries": saved.busy_retries,
        "batches": saved.batches,
        "dropped_disk_low": saved.dropped_disk_low,
        "disk_low": saved.disk_low,
        "free_disk_gb": None if saved.free_disk_gb is None else round(saved.free_disk_gb, 1),
        "lines_per_second": None if rate is None else round(rate, 1),
        "last_received_at": state.last_received_at.isoformat() if state.last_received_at else None,
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "sender_count": len(state.senders),
        "non_loopback_sender_observed": state.non_loopback_sender_observed,
        "socket_errors": state.socket_errors,
    }


def _report(make_session: Callable[[], Session], run_id: int, counts: dict[str, int], details: dict[str, Any]) -> None:
    """Best effort: the dashboard reads the run's counts while the receiver runs; a busy database skips one report."""

    try:
        with make_session() as db:
            run = db.get(IngestionRun, run_id)
            if run is None:
                return
            for name, value in counts.items():
                setattr(run, name, value)
            run.details_json = {**(run.details_json or {}), **details}
            db.commit()
    except OperationalError as exc:
        if not _database_busy(exc):
            raise


def _stopped_reporting(run: IngestionRun, now: datetime, stale_after: float) -> bool:
    reported = _moment((run.details_json or {}).get("reported_at")) or _moment(run.started_at)
    return reported is None or (now - reported).total_seconds() > stale_after


def _close_runs_left_open(db: Session, stale_after: float) -> int:
    """A receiver stopped by ending its process (stop_system) cannot close its run; close it now.

    Only runs that stopped reporting: another receiver, on another port, may still be running.
    """

    now = datetime.now(timezone.utc)
    running = db.scalars(select(IngestionRun).where(IngestionRun.source_type == SOURCE_TYPE, IngestionRun.status == "running"))
    open_runs = [run for run in running if _stopped_reporting(run, now, stale_after)]
    for run in open_runs:
        details = run.details_json or {}
        complete_ingestion_run(
            db,
            run,
            total_lines_received=run.total_lines_received,
            raw_logs_created=run.raw_logs_created,
            parsed_successfully=run.parsed_successfully,
            parse_failures=run.parse_failures,
            duplicate_raw_logs=run.duplicate_raw_logs,
            status="stopped",
            error_summary="The receiver's process ended before it could close this run; counts are from its last report.",
            details={"status": "stopped", "closed_by_next_start": True, "last_report": details.get("reported_at")},
        )
    return len(open_runs)


def run_udp_syslog_receiver(
    host: str | None = None,
    port: int | None = None,
    batch_size: int | None = None,
    *,
    max_messages: int | None = None,
    socket_timeout: float | None = None,
    flush_seconds: float | None = None,
    session_factory: Callable[[], Session] | None = None,
    initialize_database: bool = True,
    on_ready: Callable[[], None] | None = None,
    stop_event: threading.Event | None = None,
    receive_buffer_bytes: int | None = None,
    max_pending: int | None = None,
    status_seconds: float | None = None,
    min_free_disk_gb: float | None = None,
) -> dict:
    """Receive UDP syslog until max_messages lines, socket_timeout seconds without a datagram, or stop_event.

    Lines are saved in batches of batch_size, and no later than flush_seconds after they arrive, so a quiet stream
    is neither left unsaved nor holds the database's write lock while the receiver waits. Every status_seconds the
    run's counts are saved for the dashboard. Returns the session's counts.
    """
    settings = get_settings()
    bind_host = host or settings.syslog_host
    bind_port = port or settings.syslog_port
    flush_every = max(1, int(batch_size or settings.syslog_batch_size))
    save_within = flush_seconds or settings.syslog_flush_seconds
    pending_limit = max(1, int(max_pending or settings.syslog_max_pending_lines))
    report_every = status_seconds or settings.syslog_status_seconds
    min_free_gb = float(settings.syslog_min_free_disk_gb if min_free_disk_gb is None else min_free_disk_gb)

    # Tables are made only where ATDR may make them; in the production profile (AUTO_CREATE_TABLES=false) only the
    # migrations do. The receiver had made them at every start whatever the setting said (found 23 Oct 2026).
    if initialize_database and settings.auto_create_tables:
        init_db()
    make_session = session_factory or SessionLocal
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pending: queue.Queue[_Datagram] = queue.Queue(maxsize=pending_limit)
    state = _Received()
    saved = _Saved()
    finished = threading.Event()
    reader: threading.Thread | None = None
    try:
        granted_buffer = _request_receive_buffer(sock, receive_buffer_bytes or settings.syslog_receive_buffer_bytes)
        sock.bind((bind_host, bind_port))
        base_details = {
            "batch_size": flush_every,
            "max_messages": max_messages,
            "max_pending": pending_limit,
            "receive_buffer_bytes": granted_buffer,
            "min_free_disk_gb": min_free_gb,
        }
        with make_session() as db:
            closed = _close_runs_left_open(db, _stale_after(report_every))
            run = start_ingestion_run(
                db,
                source_type=SOURCE_TYPE,
                input_name=f"udp:{bind_host}:{bind_port}",
                details={**base_details, "status": "receiving", "runs_closed_at_start": closed},
            )
            # Save the run now: an open write would hold SQLite's only write lock while no traffic arrives.
            db.commit()
            run_id = int(run.id)
        logger.info("ATDR syslog receiver listening on %s:%s (socket buffer %s bytes)", bind_host, bind_port, granted_buffer)
        reader = threading.Thread(
            target=_receive,
            args=(sock, pending, state, finished),
            kwargs={"max_messages": max_messages, "socket_timeout": socket_timeout, "stop_event": stop_event},
            name="atdr-syslog-receive",
            daemon=True,
        )
        reader.start()
        if on_ready is not None:
            on_ready()

        sources: dict[str, int] = {}
        samples: deque[tuple[float, int]] = deque()
        folder = _database_folder(make_session)
        _look_at_disk(folder, min_free_gb, saved)
        next_disk_look = time.monotonic() + DISK_CHECK_SECONDS
        next_report = time.monotonic() + report_every
        next_audit = time.monotonic() + AUDIT_EVERY_SECONDS
        while True:
            batch = _next_batch(pending, flush_every, save_within, finished)
            if time.monotonic() >= next_disk_look:
                _look_at_disk(folder, min_free_gb, saved)
                next_disk_look = time.monotonic() + DISK_CHECK_SECONDS
            if batch and saved.disk_low:
                # A full disk breaks every part of ATDR, so the feed gives way first; the page says so.
                saved.dropped_disk_low += len(batch)
            elif batch:
                _save(make_session, batch, sources, saved, finished)
            if saved.gave_up:
                # Asked to stop, and the database stayed busy: the rest would each wait as long again. Count them.
                while True:
                    try:
                        pending.get_nowait()
                    except queue.Empty:
                        break
                    saved.dropped_at_stop += 1
                break
            now = time.monotonic()
            if now >= next_report:
                samples.append((now, state.received))
                while samples and now - samples[0][0] > RATE_WINDOW_SECONDS:
                    samples.popleft()
                rate = (samples[-1][1] - samples[0][1]) / (samples[-1][0] - samples[0][0]) if len(samples) > 1 else None
                _report(make_session, run_id, _run_counts(state, saved), _status(state, saved, pending, rate, base_details))
                next_report = now + report_every
            if now >= next_audit:
                _commit_with_retry(make_session, lambda db: db.add(_audit(state, saved, bind_host, bind_port)), saved, finished)
                next_audit = now + AUDIT_EVERY_SECONDS
            if not batch and finished.is_set() and pending.empty():
                break
        reader.join(timeout=5)

        def close(db: Session) -> None:
            db.add(_audit(state, saved, bind_host, bind_port))
            recorded = db.get(IngestionRun, run_id)
            complete_ingestion_run(
                db,
                recorded,
                **_run_counts(state, saved),
                details={
                    **_status(state, saved, pending, None, base_details),
                    "status": "stopped",
                    "timed_out": state.timed_out,
                    "parser_quality": saved.parser_quality,
                },
            )

        _commit_with_retry(make_session, close, saved, finished, own_limit=CLOSING_BUSY_LIMIT_SECONDS)
    finally:
        finished.set()
        sock.close()
        if reader is not None:
            reader.join(timeout=5)

    return {
        "host": bind_host,
        "port": bind_port,
        "received": state.received,
        "saved": saved.stored,
        "parsed": saved.parsed,
        "failed": saved.failed,
        "duplicates": saved.duplicates,
        "dropped": _dropped(state, saved),
        "dropped_disk_low": saved.dropped_disk_low,
        "disk_low": saved.disk_low,
        "unstorable": saved.unstorable,
        "busy_retries": saved.busy_retries,
        "batches": saved.batches,
        "timed_out": state.timed_out,
        "sender_count": len(state.senders),
        "non_loopback_sender_observed": state.non_loopback_sender_observed,
        "parser_quality": saved.parser_quality,
        "receive_buffer_bytes": granted_buffer,
        "run_id": run_id,
    }


def _moment(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _stale_after(status_seconds: float) -> float:
    """A receiver that saves its counts every status_seconds has stopped if three reports in a row are missing."""

    return max(30.0, 3 * float(status_seconds))


def live_feed_status(db: Session, *, settings: Any = None, now: datetime | None = None) -> dict[str, Any]:
    """What the Data & Detection page says about the live syslog feed, from the receiver's latest run."""

    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)
    run = db.scalar(select(IngestionRun).where(IngestionRun.source_type == SOURCE_TYPE).order_by(IngestionRun.id.desc()).limit(1))
    details = (run.details_json or {}) if run is not None else {}
    reported = _moment(details.get("reported_at")) or (_moment(run.started_at) if run is not None else None)
    stale_after = _stale_after(settings.syslog_status_seconds)
    if run is not None and run.status == "running":
        state = "receiving" if reported is not None and (now - reported).total_seconds() <= stale_after else "not_reporting"
    elif not settings.syslog_enabled:
        state = "off"
    elif run is None:
        state = "not_started"
    else:
        state = "stopped"
    started = _moment(run.started_at) if run is not None else None
    finished = _moment(run.finished_at) if run is not None else None
    summaries_from, summaries_to = db.execute(
        select(func.min(TrafficHourlySummary.hour_start), func.max(TrafficHourlySummary.hour_start))
    ).one()
    return {
        "enabled": bool(settings.syslog_enabled),
        "state": state,
        "port": int(settings.syslog_port),
        "started_at": started.isoformat() if started else None,
        "finished_at": finished.isoformat() if finished else None,
        "received": int(run.total_lines_received) if run is not None else 0,
        "saved": int(run.raw_logs_created) if run is not None else 0,
        "dropped": int(details.get("dropped") or 0),
        "lines_per_second": details.get("lines_per_second"),
        "last_received_at": details.get("last_received_at"),
        "reported_at": reported.isoformat() if reported else None,
        # Saving pauses below the free-disk floor; lines received meanwhile are counted as lost.
        "disk_low": state == "receiving" and bool(details.get("disk_low")),
        "dropped_disk_low": int(details.get("dropped_disk_low") or 0),
        "free_disk_gb": details.get("free_disk_gb"),
        "min_free_disk_gb": float(settings.syslog_min_free_disk_gb),
        # Live logs are kept this long, then summarised by hour (the worker does it).
        "keep_hours": float(settings.syslog_retention_hours),
        "summaries_from": _moment(summaries_from).isoformat() if summaries_from else None,
        "summaries_to": _moment(summaries_to).isoformat() if summaries_to else None,
    }


def _run_counts(state: _Received, saved: _Saved) -> dict[str, int]:
    return {
        "total_lines_received": state.received,
        "raw_logs_created": saved.stored,
        "parsed_successfully": saved.parsed,
        "parse_failures": saved.failed,
        "duplicate_raw_logs": saved.duplicates,
    }


def _audit(state: _Received, saved: _Saved, bind_host: str, bind_port: int) -> AuditLog:
    return AuditLog(
        actor="syslog_receiver",
        action="ingest_syslog_batch",
        target_type="syslog",
        target_value=f"udp:{bind_host}:{bind_port}",
        details={
            "received": state.received,
            "saved": saved.stored,
            "parsed": saved.parsed,
            "failed": saved.failed,
            "duplicates": saved.duplicates,
            "dropped": _dropped(state, saved),
            "unstorable": saved.unstorable,
            "sender_count": len(state.senders),
            "non_loopback_sender_observed": state.non_loopback_sender_observed,
            "parser_quality": saved.parser_quality,
        },
    )
