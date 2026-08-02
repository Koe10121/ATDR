from __future__ import annotations

from collections import Counter
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from io import BytesIO
import gc
import json
import os
from pathlib import Path
import shutil
import socket
import threading
import time
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    IngestionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
    User,
)
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.routers import alerts as alerts_router
from atdr.app.routers import audit as audit_router
from atdr.app.routers import ingestion as ingestion_router
from atdr.app.routers import jobs as jobs_router
from atdr.app.routers import logs as logs_router
from atdr.app.routers import sources as sources_router
from atdr.app.services.alert_service import get_alert, list_alerts
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.source_service import create_source, source_to_dict
from atdr.app.services.syslog_service import run_udp_syslog_receiver
from atdr.scripts.replay_logs import replay_logs


V523_VERSION = "v5.23-live-source-acceptance-v1"
V523_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V523_LATEST = "v5_23_live_source_acceptance_latest.json"
_ACTOR = "v523-live-source-acceptance"
_CONFIGURED_DB_FILES = ("", "-wal", "-shm")
_EXTERNAL_SENDER_KINDS = {"second_laptop", "firewall", "router"}


class _StopAfterFirstCommittedChunk:
    def __init__(self) -> None:
        self._checks = 0

    def is_set(self) -> bool:
        self._checks += 1
        return self._checks >= 3


def _safe_failure(status: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "status": status,
        "message": message,
        "version": V523_VERSION,
        "configured_database_modified": False,
        "private_path_returned": False,
        "raw_evidence_returned": False,
        "secrets_exposed": False,
        "production_ready": False,
        "phase_complete": False,
        "real_device_validated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _configured_sqlite_path() -> Path | None:
    try:
        url = make_url(get_settings().database_url)
    except Exception:
        return None
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None
    path = Path(url.database).expanduser()
    return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()


def _database_marker(path: Path | None) -> tuple[tuple[bool, int | None, int | None], ...] | None:
    if path is None:
        return None
    markers: list[tuple[bool, int | None, int | None]] = []
    for suffix in _CONFIGURED_DB_FILES:
        candidate = Path(f"{path}{suffix}")
        if not candidate.exists():
            markers.append((False, None, None))
            continue
        stat = candidate.stat()
        markers.append((True, int(stat.st_size), int(stat.st_mtime_ns)))
    return tuple(markers)


def _safe_environment(*, database_url: str, staging_root: Path) -> dict[str, str]:
    return {
        "DATABASE_URL": database_url,
        "ENVIRONMENT": "development",
        "AUTO_CREATE_TABLES": "false",
        "JWT_SECRET_KEY": "v523-isolated-acceptance-secret-not-for-deployment",
        "RESPONSE_SIMULATION": "true",
        "RESPONSE_PROVIDER": "simulation",
        "ASSISTANT_LLM_ENABLED": "false",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": "false",
        "ASSISTANT_REDACT_IPS": "true",
        "OPERATION_WORKER_ENABLED": "false",
        "OPERATION_MAX_QUEUED_IMPORTS": "1",
        "OPERATION_MAX_QUEUED_JOBS_PER_ACTOR": "1",
        "OPERATION_STAGING_ROOT": str(staging_root.resolve()),
        "OPERATION_STAGING_STORAGE_ID": "v523-temp",
        "OPERATION_STAGING_MIN_FREE_BYTES": "0",
        "OPERATION_STAGING_MAX_TOTAL_BYTES": str(64 * 1024 * 1024),
        "OPERATION_JOB_MAX_INPUT_BYTES": str(16 * 1024 * 1024),
        "INGESTION_CHUNK_SIZE": "2",
        "INGESTION_PROGRESS_UPDATE_INTERVAL": "1",
    }


@contextmanager
def _isolated_runtime(database_url: str, staging_root: Path) -> Iterator[Settings]:
    with patch.dict(
        os.environ,
        _safe_environment(database_url=database_url, staging_root=staging_root),
        clear=False,
    ):
        get_settings.cache_clear()
        try:
            yield get_settings()
        finally:
            get_settings.cache_clear()


def _free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _port_bindable(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _build_api(session_factory: sessionmaker[Session], settings: Settings) -> FastAPI:
    api = FastAPI()
    for router in (
        logs_router.router,
        jobs_router.router,
        sources_router.router,
        alerts_router.router,
        ingestion_router.router,
        audit_router.router,
    ):
        api.include_router(router)

    admin = User(
        username=_ACTOR,
        role="admin",
        password_hash="not-used-by-disposable-acceptance",
        is_active=True,
    )
    analyst = User(
        username="v523-analyst",
        role="analyst",
        password_hash="not-used-by-disposable-acceptance",
        is_active=True,
    )

    def override_get_db() -> Generator[Session, None, None]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    api.dependency_overrides[get_db] = override_get_db
    api.dependency_overrides[get_settings] = lambda: settings
    api.dependency_overrides[require_admin] = lambda: admin
    api.dependency_overrides[require_analyst_or_admin] = lambda: analyst
    return api


def _safe_source_summary(db: Session, source_id: int) -> dict[str, Any]:
    source = db.get(LogSource, source_id)
    if source is None:
        return {"available": False}
    detail = source_to_dict(source, include_quality=True, db=db)
    health = detail.get("health") or {}
    quality = detail.get("quality") or {}
    return {
        "available": True,
        "source_type": source.source_type,
        "parser_profile": source.parser_profile,
        "status": health.get("status"),
        "enabled": bool(source.enabled),
        "logs_received": int(source.logs_received_count or 0),
        "parse_successes": int(source.parse_success_count or 0),
        "parse_failures": int(source.parse_failure_count or 0),
        "parser_quality_state": quality.get("parser_quality_state"),
        "parser_contract_state": quality.get("parser_contract_state"),
        "alert_count": int(quality.get("alert_count") or 0),
        "ingestion_run_count": len(detail.get("recent_ingestion_runs") or []),
        "detection_run_count": len(detail.get("recent_detection_runs") or []),
    }


def _row_counts(db: Session) -> dict[str, int]:
    models = {
        "raw_logs": RawLog,
        "normalized_logs": NormalizedLog,
        "alerts": Alert,
        "alert_evidence": AlertEvidence,
        "ingestion_runs": IngestionRun,
        "detection_runs": DetectionRun,
        "operation_jobs": OperationJob,
        "audit_logs": AuditLog,
        "response_actions": ResponseAction,
        "labels": MLLabel,
        "model_runs": MLModelRun,
        "users": User,
    }
    return {
        key: int(db.scalar(select(func.count(model.id))) or 0)
        for key, model in models.items()
    }


def _alert_group_counts(alert: Alert | None) -> tuple[int, int]:
    if alert is None:
        return 0, 0
    metadata = next(
        (
            item
            for item in (alert.matched_rules_json or [])
            if isinstance(item, dict) and item.get("code") == "group_metadata"
        ),
        {},
    )
    evidence_count = len(alert.evidence)
    occurrence_count = int(
        metadata.get("occurrence_count")
        or metadata.get("evidence_count")
        or evidence_count
    )
    related_log_count = int(
        metadata.get("related_log_count")
        or metadata.get("evidence_count")
        or evidence_count
    )
    return occurrence_count, related_log_count


def _safe_job_summary(job: OperationJob) -> dict[str, Any]:
    return {
        "job_id": int(job.id),
        "job_type": job.job_type,
        "status": job.status,
        "attempt_count": int(job.attempt_count or 0),
        "progress_current": int(job.progress_current or 0),
        "progress_total": int(job.progress_total or 0),
        "checkpoint_line": int(job.checkpoint_line or 0),
        "chunk_commits": int(job.chunk_commits or 0),
        "related_ingestion_run_id": job.related_ingestion_run_id,
        "input_size_bytes": int(job.input_size_bytes or 0),
        "staging_path_returned": False,
        "input_fingerprint_returned": False,
    }


def _remove_temp_root(path: Path) -> bool:
    gc.collect()
    for _ in range(20):
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            return True
        time.sleep(0.1)
    return not path.exists()


def _write_resumable_input(path: Path, count: int = 8) -> bytes:
    lines = [
        "2026-08-02T10:00:00Z v523-router "
        f"event_id=resume-{index:03d} action=allow protocol=tcp service=https"
        for index in range(count)
    ]
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return payload


def _run_udp_transport(
    *,
    session_factory: sessionmaker[Session],
    sample_path: Path,
    transport_mode: str,
    bind_host: str,
    port: int,
    message_count: int,
    timeout_seconds: float,
    external_sender_kind: str | None,
) -> dict[str, Any]:
    if transport_mode == "external_sender":
        receiver = run_udp_syslog_receiver(
            host=bind_host,
            port=port,
            batch_size=max(1, min(message_count, 10)),
            max_messages=message_count,
            socket_timeout=timeout_seconds,
            session_factory=session_factory,
            initialize_database=False,
        )
        sender_result = {"sent": None}
    else:
        ready = threading.Event()
        receiver: dict[str, Any] = {}

        def receive() -> None:
            receiver.update(
                run_udp_syslog_receiver(
                    host="127.0.0.1",
                    port=port,
                    batch_size=max(1, min(message_count, 10)),
                    max_messages=message_count,
                    socket_timeout=timeout_seconds,
                    session_factory=session_factory,
                    initialize_database=False,
                    on_ready=ready.set,
                )
            )

        thread = threading.Thread(target=receive, name="v523-udp-receiver", daemon=True)
        thread.start()
        if not ready.wait(min(5.0, timeout_seconds)):
            return {
                "passed": False,
                "mode": "local_loopback",
                "status": "receiver_not_ready",
                "real_device_validated": False,
                "second_laptop_transport_validated": False,
            }
        sender_result = replay_logs(
            sample_path=str(sample_path),
            rate=0,
            limit=message_count,
            loop=True,
            send_to="syslog",
            host="127.0.0.1",
            port=port,
            actor=_ACTOR,
        )
        thread.join(timeout_seconds + 2.0)
        if thread.is_alive():
            return {
                "passed": False,
                "mode": "local_loopback",
                "status": "receiver_did_not_stop",
                "real_device_validated": False,
                "second_laptop_transport_validated": False,
            }

    received = int(receiver.get("received") or 0)
    parsed = int(receiver.get("parsed") or 0)
    failed = int(receiver.get("failed") or 0)
    non_loopback = bool(receiver.get("non_loopback_sender_observed"))
    transport_passed = bool(
        received == message_count
        and parsed + failed == message_count
        and not receiver.get("timed_out")
        and (
            int(sender_result.get("sent") or 0) == message_count
            if transport_mode == "local_loopback"
            else non_loopback
        )
    )
    second_laptop = bool(
        transport_passed
        and transport_mode == "external_sender"
        and external_sender_kind == "second_laptop"
        and non_loopback
    )
    real_device = bool(
        transport_passed
        and transport_mode == "external_sender"
        and external_sender_kind in {"firewall", "router"}
        and non_loopback
    )
    return {
        "passed": transport_passed,
        "mode": transport_mode,
        "status": "transport_validated" if transport_passed else "transport_not_validated",
        "messages_expected": message_count,
        "messages_sent": sender_result.get("sent"),
        "messages_received": received,
        "parsed": parsed,
        "parse_failures": failed,
        "sender_count": int(receiver.get("sender_count") or 0),
        "non_loopback_sender_observed": non_loopback,
        "second_laptop_transport_validated": second_laptop,
        "real_device_validated": real_device,
        "sender_kind_operator_attested": external_sender_kind,
        "raw_evidence_returned": False,
        "sender_addresses_returned": False,
    }


def _write_reports(result: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    json_path = output_dir / f"v5_23_live_source_acceptance_{stamp}.json"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / V523_LATEST).write_text(
        json.dumps(result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    lines = [
        "# v5.23 Live-Source Acceptance",
        "",
        f"- Status: `{result.get('status')}`",
        f"- Transport: `{(result.get('transport') or {}).get('status')}`",
        f"- Phase complete: `{result.get('phase_complete')}`",
        f"- Real device validated: `{result.get('real_device_validated')}`",
        f"- Configured database modified: `{result.get('configured_database_modified')}`",
        f"- Failed checks: `{len(result.get('failed_checks') or [])}`",
        "- Rules remain alert-authoritative; response automation and real blocking remain disabled.",
    ]
    (output_dir / f"v5_23_live_source_acceptance_{stamp}.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def run_v523_live_source_acceptance(
    *,
    use_temp_db: bool,
    sample_path: str | Path | None = None,
    preflight_only: bool = False,
    transport_mode: str = "local_loopback",
    bind_host: str = "0.0.0.0",
    port: int = 5515,
    message_count: int = 5,
    timeout_seconds: float = 15.0,
    external_sender_kind: str | None = None,
    temp_parent: str | Path | None = None,
    output_dir: str | Path = V523_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    if not use_temp_db:
        return _safe_failure(
            "explicit_temp_database_required",
            "Re-run with --use-temp-db; configured databases are never acceptance targets.",
        )
    if transport_mode not in {"local_loopback", "external_sender"}:
        return _safe_failure("invalid_transport_mode", "Choose local_loopback or external_sender.")
    if not 1 <= int(message_count) <= 100:
        return _safe_failure("invalid_message_count", "Message count must be between 1 and 100.")
    if timeout_seconds <= 0 or timeout_seconds > 300:
        return _safe_failure("invalid_timeout", "Timeout must be greater than 0 and at most 300 seconds.")
    if transport_mode == "external_sender" and external_sender_kind not in _EXTERNAL_SENDER_KINDS:
        return _safe_failure(
            "external_sender_attestation_required",
            "Choose second_laptop, firewall, or router for --external-sender-kind.",
        )

    safe_sample = PROJECT_ROOT / "data" / "samples" / "scenarios" / "normal_allowed_traffic.txt"
    selected_sample = Path(sample_path).expanduser() if sample_path else safe_sample
    if not selected_sample.is_absolute():
        selected_sample = (PROJECT_ROOT / selected_sample).resolve()
    if not selected_sample.is_file():
        return _safe_failure("sample_unavailable", "The selected evidence file is unavailable.")
    scan_path = PROJECT_ROOT / "data" / "samples" / "scenarios" / "port_scan_like_traffic.txt"
    if not scan_path.is_file():
        return _safe_failure("safe_scenario_unavailable", "The controlled port-scan scenario is unavailable.")

    configured_path = _configured_sqlite_path()
    marker_before = _database_marker(configured_path)
    selected_port = _free_udp_port() if transport_mode == "local_loopback" else int(port)
    selected_host = "127.0.0.1" if transport_mode == "local_loopback" else bind_host
    preflight = {
        "temp_database_required": True,
        "sample_available": True,
        "private_sample_supplied": sample_path is not None,
        "safe_scenario_available": True,
        "udp_bind_available": _port_bindable(selected_host, selected_port),
        "transport_mode": transport_mode,
        "external_sender_attestation_present": (
            transport_mode == "local_loopback" or external_sender_kind in _EXTERNAL_SENDER_KINDS
        ),
        "configured_database_marker_available": marker_before is not None,
        "private_path_returned": False,
        "sender_address_returned": False,
    }
    if preflight_only:
        result = {
            "ok": all(
                bool(preflight[key])
                for key in (
                    "sample_available",
                    "safe_scenario_available",
                    "udp_bind_available",
                    "external_sender_attestation_present",
                )
            ),
            "status": "preflight_passed" if preflight["udp_bind_available"] else "preflight_failed",
            "version": V523_VERSION,
            "preflight_only": True,
            "preflight": preflight,
            "configured_database_modified": False,
            "private_path_returned": False,
            "raw_evidence_returned": False,
            "secrets_exposed": False,
            "production_ready": False,
            "phase_complete": False,
            "real_device_validated": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        }
        return result

    parent = Path(temp_parent or (PROJECT_ROOT / ".tmp")).resolve()
    temp_root = parent / f"v523-live-source-{uuid4().hex[:12]}"
    database_path = temp_root / "acceptance.sqlite3"
    staging_root = temp_root / "staging"
    resumable_input = temp_root / "v523-resumable.log"
    database_url = f"sqlite:///{database_path.as_posix()}"
    result: dict[str, Any] | None = None
    engine = None
    started = time.perf_counter()
    temp_root.mkdir(parents=True, exist_ok=False)
    try:
        resumable_payload = _write_resumable_input(resumable_input)
        with _isolated_runtime(database_url, staging_root) as settings:
            engine = create_engine(
                database_url,
                connect_args={"check_same_thread": False},
                future=True,
            )
            Base.metadata.create_all(engine)
            SessionFactory = sessionmaker(
                bind=engine,
                autoflush=False,
                autocommit=False,
                expire_on_commit=False,
                future=True,
            )

            with SessionFactory() as db:
                file_source = create_source(
                    db,
                    name="v523-file-firewall",
                    source_type="firewall",
                    parser_profile="palo_alto",
                )
                first_file = import_log_file(
                    db,
                    scan_path,
                    limit=10,
                    actor=_ACTOR,
                    source_id=file_source.id,
                    parser_profile="palo_alto",
                )
                first_detection = run_detection(
                    db,
                    limit=None,
                    use_ml=False,
                    actor=_ACTOR,
                    source_id=file_source.id,
                    source_name=file_source.name,
                    source_type=file_source.source_type,
                )
                second_file = import_log_file(
                    db,
                    scan_path,
                    limit=10,
                    actor=_ACTOR,
                    source_id=file_source.id,
                    parser_profile="palo_alto",
                )
                second_detection = run_detection(
                    db,
                    limit=None,
                    use_ml=False,
                    actor=_ACTOR,
                    source_id=file_source.id,
                    source_name=file_source.name,
                    source_type=file_source.source_type,
                )

            api = _build_api(SessionFactory, settings)
            with TestClient(api) as client:
                api_import = client.post(
                    "/api/logs/import",
                    files={
                        "upload": (
                            "v523-api-upload.log",
                            safe_sample.read_bytes(),
                            "text/plain",
                        )
                    },
                    data={"limit": "5", "parser_profile": "palo_alto"},
                )
                queued = client.post(
                    "/api/jobs/import",
                    files={"upload": ("v523-resumable.log", resumable_payload, "text/plain")},
                    data={
                        "job_type": "import_logs",
                        "source_type": "router",
                        "parser_profile": "generic_syslog",
                        "limit": "8",
                    },
                )
                backpressure = client.post(
                    "/api/jobs/import",
                    files={"upload": ("v523-backpressure.log", resumable_payload, "text/plain")},
                    data={
                        "job_type": "import_logs",
                        "source_type": "router",
                        "parser_profile": "generic_syslog",
                        "limit": "8",
                    },
                )

            if api_import.status_code != 200 or queued.status_code != 200:
                raise RuntimeError("Disposable API import acceptance failed.")
            queued_payload = queued.json()
            queued_job_id = int(queued_payload["job_id"])
            with SessionFactory() as db:
                interrupted = run_worker_once(
                    db,
                    worker_id="v523-interrupted-worker",
                    stop_event=_StopAfterFirstCommittedChunk(),
                )
                resumed = run_worker_once(db, worker_id="v523-resume-worker")
                db.expire_all()
                persisted_job = db.get(OperationJob, queued_job_id)
                if persisted_job is None:
                    raise RuntimeError("Disposable resumable import job disappeared.")
                resumable_summary = {
                    "queued": True,
                    "backpressure_http_status": backpressure.status_code,
                    "backpressure_enforced": backpressure.status_code == 429,
                    "interrupted_at_committed_boundary": bool(interrupted.get("shutdown_requested")),
                    "resume_completed": bool(resumed.get("ok") and persisted_job.status == "completed"),
                    "progress_current": int(persisted_job.progress_current or 0),
                    "progress_total": int(persisted_job.progress_total or 0),
                    "checkpoint_line": int(persisted_job.checkpoint_line or 0),
                    "chunk_commits": int(persisted_job.chunk_commits or 0),
                    "public_job": _safe_job_summary(persisted_job),
                }

            transport = _run_udp_transport(
                session_factory=SessionFactory,
                sample_path=selected_sample,
                transport_mode=transport_mode,
                bind_host=selected_host,
                port=selected_port,
                message_count=message_count,
                timeout_seconds=timeout_seconds,
                external_sender_kind=external_sender_kind,
            )

            with SessionFactory() as db:
                file_source = db.scalar(
                    select(LogSource).where(LogSource.name == "v523-file-firewall")
                )
                if file_source is None:
                    raise RuntimeError("Disposable file source disappeared.")
                source_alerts = list_alerts(db, source_id=file_source.id, limit=20)
                alert = get_alert(db, source_alerts[0].id) if source_alerts else None
                explanation = build_alert_detection_summary(db, alert) if alert is not None else None
                cases = list_alert_cases(db, source_id=file_source.id, limit=20)
                occurrence_count, related_log_count = _alert_group_counts(alert)
                evidence_source_ids = {
                    evidence.normalized_log.raw_log.source_id
                    for evidence in (alert.evidence if alert is not None else [])
                    if evidence.normalized_log is not None
                    and evidence.normalized_log.raw_log is not None
                }
                source_rows = list(db.scalars(select(LogSource).order_by(LogSource.id)))
                source_summaries = {
                    f"source_{index + 1}": _safe_source_summary(db, source.id)
                    for index, source in enumerate(source_rows)
                }
                audit_counts = Counter(db.scalars(select(AuditLog.action)))
                counts = _row_counts(db)
                api_source_id = int(api_import.json().get("source_id") or 0)
                api_source = _safe_source_summary(db, api_source_id) if api_source_id else {"available": False}
                udp_source = db.scalar(
                    select(LogSource)
                    .where(LogSource.source_type == "syslog_udp")
                    .order_by(LogSource.id.desc())
                    .limit(1)
                )
                udp_source_summary = (
                    _safe_source_summary(db, udp_source.id)
                    if udp_source is not None
                    else {"available": False}
                )

                checks = {
                    "file_import_exact": bool(
                        first_file.get("raw_logs_imported") == 10
                        and second_file.get("raw_logs_imported") == 10
                        and first_file.get("normalized_logs_created") == 10
                        and second_file.get("normalized_logs_created") == 10
                    ),
                    "api_upload_exact": bool(
                        api_import.status_code == 200
                        and api_import.json().get("raw_logs_imported") == 5
                        and api_source.get("available")
                    ),
                    "resumable_import_recovered": bool(
                        resumable_summary["interrupted_at_committed_boundary"]
                        and resumable_summary["resume_completed"]
                        and resumable_summary["progress_current"]
                        == resumable_summary["progress_total"]
                    ),
                    "queue_backpressure_enforced": resumable_summary["backpressure_enforced"],
                    "udp_replay_transport_validated": bool(transport.get("passed")),
                    "source_health_and_quality_available": bool(
                        source_summaries
                        and all(item.get("available") for item in source_summaries.values())
                        and udp_source_summary.get("available")
                    ),
                    "source_scoped_detection_recorded": bool(
                        first_detection.get("detection_run_id")
                        and second_detection.get("detection_run_id")
                        and first_detection.get("rule_detection_authoritative")
                        and second_detection.get("rule_detection_authoritative")
                    ),
                    "alert_created_then_deduplicated": bool(
                        first_detection.get("created_alerts") == 1
                        and second_detection.get("deduplicated_alert_updates") == 1
                        and alert is not None
                        and alert.alert_type == "possible_port_scan"
                        and occurrence_count >= 20
                        and related_log_count >= 20
                    ),
                    "alert_and_case_traceable_to_source": bool(
                        alert is not None
                        and file_source.id in evidence_source_ids
                        and cases
                        and cases[0].get("total_related_logs", 0) >= 20
                    ),
                    "explanation_and_recommendation_available": bool(
                        explanation
                        and explanation.get("why_flagged")
                        and explanation.get("analyst_next_steps")
                        and explanation.get("decision_support_only")
                    ),
                    "audit_history_complete": all(
                        int(audit_counts.get(action) or 0) > 0
                        for action in (
                            "import_logs",
                            "ingest_syslog_batch",
                            "operation_job_queued",
                            "operation_job_completed",
                            "run_detection",
                        )
                    ),
                    "no_response_or_ml_authority_writes": bool(
                        counts["response_actions"] == 0
                        and counts["labels"] == 0
                        and counts["model_runs"] == 0
                        and counts["users"] == 0
                    ),
                }
                failed_checks = [name for name, passed in checks.items() if not passed]
                second_laptop_validated = bool(
                    transport.get("second_laptop_transport_validated")
                )
                real_device_validated = bool(transport.get("real_device_validated"))
                phase_complete = bool(
                    not failed_checks
                    and (second_laptop_validated or real_device_validated)
                )
                if failed_checks:
                    status = "v5_23_live_source_acceptance_failed"
                elif real_device_validated:
                    status = "v5_23_real_device_acceptance_passed"
                elif second_laptop_validated:
                    status = "v5_23_external_transport_acceptance_passed"
                else:
                    status = "v5_23_local_acceptance_passed_external_sender_pending"
                result = {
                    "ok": not failed_checks,
                    "status": status,
                    "version": V523_VERSION,
                    "scope": {
                        "disposable_database": True,
                        "transport_mode": transport_mode,
                        "local_loopback_transport_validated": bool(
                            transport.get("passed") and transport_mode == "local_loopback"
                        ),
                        "second_laptop_transport_validated": bool(
                            transport.get("second_laptop_transport_validated")
                        ),
                        "real_device_validated": bool(transport.get("real_device_validated")),
                        "transport_validation_is_not_device_validation": True,
                        "private_sample_supplied": sample_path is not None,
                    },
                    "preflight": preflight,
                    "channels": {
                        "file_import": {
                            "passed": checks["file_import_exact"],
                            "attempted": 20,
                            "raw_logs_imported": int(first_file.get("raw_logs_imported") or 0)
                            + int(second_file.get("raw_logs_imported") or 0),
                            "normalized_logs_created": int(first_file.get("normalized_logs_created") or 0)
                            + int(second_file.get("normalized_logs_created") or 0),
                            "parse_failures": int(first_file.get("parse_failures") or 0)
                            + int(second_file.get("parse_failures") or 0),
                        },
                        "api_upload": {
                            "passed": checks["api_upload_exact"],
                            "http_status": api_import.status_code,
                            "raw_logs_imported": int(api_import.json().get("raw_logs_imported") or 0),
                            "normalized_logs_created": int(
                                api_import.json().get("normalized_logs_created") or 0
                            ),
                        },
                        "resumable_import": resumable_summary,
                        "replay_udp": transport,
                    },
                    "sources": {
                        "count": len(source_summaries),
                        "summaries": source_summaries,
                    },
                    "detection": {
                        "rules_alert_authoritative": True,
                        "ml_alert_authority": False,
                        "first_created": int(first_detection.get("created_alerts") or 0),
                        "second_deduplicated": int(
                            second_detection.get("deduplicated_alert_updates") or 0
                        ),
                        "alert_type": alert.alert_type if alert is not None else None,
                        "occurrence_count": occurrence_count,
                        "related_log_count": related_log_count,
                    },
                    "investigation": {
                        "source_traceable": bool(alert and file_source.id in evidence_source_ids),
                        "case_available": bool(cases),
                        "why_flagged_available": bool(explanation and explanation.get("why_flagged")),
                        "missing_context_available": bool(
                            explanation is not None and "missing_context" in explanation
                        ),
                        "analyst_next_steps_available": bool(
                            explanation and explanation.get("analyst_next_steps")
                        ),
                        "decision_support_only": True,
                    },
                    "audit": {
                        "required_actions_present": checks["audit_history_complete"],
                        "action_counts": {
                            action: int(audit_counts.get(action) or 0)
                            for action in (
                                "import_logs",
                                "ingest_syslog_batch",
                                "operation_job_queued",
                                "operation_job_completed",
                                "run_detection",
                            )
                        },
                    },
                    "counts": counts,
                    "checks": checks,
                    "failed_checks": failed_checks,
                    "transport": transport,
                    "configured_database_marker_checked": marker_before is not None,
                    "configured_database_modified": False,
                    "temporary_artifacts_removed": None,
                    "private_path_returned": False,
                    "raw_evidence_returned": False,
                    "sender_addresses_returned": False,
                    "secrets_exposed": False,
                    "lifecycle_state": "shadow_observation",
                    "production_ready": False,
                    "phase_complete": phase_complete,
                    "external_transport_gate": {
                        "required_for_phase_completion": True,
                        "satisfied": phase_complete,
                        "second_laptop_accepted_as_transport_only": second_laptop_validated,
                        "real_device_validated": real_device_validated,
                    },
                    "real_device_validated": real_device_validated,
                    "response_automation_allowed": False,
                    "real_firewall_blocking_enabled": False,
                    "runtime_seconds": round(time.perf_counter() - started, 4),
                }
    except Exception as exc:
        result = _safe_failure(
            "v5_23_live_source_acceptance_error",
            f"Acceptance stopped safely during disposable execution: {exc.__class__.__name__}.",
        )
    finally:
        if engine is not None:
            engine.dispose()
        removed = _remove_temp_root(temp_root)

    marker_after = _database_marker(configured_path)
    configured_unchanged = marker_before == marker_after
    if result is None:
        result = _safe_failure("v5_23_live_source_acceptance_error", "Acceptance produced no result.")
    result["configured_database_modified"] = not configured_unchanged
    result["temporary_artifacts_removed"] = removed
    result["ok"] = bool(result.get("ok") and configured_unchanged and removed)
    if not configured_unchanged:
        result["status"] = "configured_database_changed"
    elif not removed:
        result["status"] = "temporary_cleanup_incomplete"
    if write_output:
        _write_reports(result, Path(output_dir))
    return result
