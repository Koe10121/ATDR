import argparse
import json
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.detection_service import run_detection
from atdr.app.services.demo_service import resolve_demo_sample_path
from atdr.app.services.job_service import build_result_summary, complete_job, fail_job, start_job
from atdr.app.services.log_service import import_raw_log_line
from atdr.app.services.operation_run_service import complete_ingestion_run, fail_ingestion_run, start_ingestion_run
from atdr.app.services.source_service import get_or_create_source


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _resolve_sample_path(sample_path: str | None) -> Path:
    if sample_path:
        path = Path(sample_path)
        return path if path.is_absolute() else PROJECT_ROOT / path
    return resolve_demo_sample_path(None)


def _iter_replay_lines(path: Path, *, limit: int | None, loop: bool) -> Iterable[tuple[int, str]]:
    emitted = 0
    while True:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if limit is not None and emitted >= limit:
                    return
                emitted += 1
                yield line_number, line.rstrip("\r\n")
        if not loop:
            return


def _sleep_for_rate(rate: float) -> None:
    if rate > 0:
        time.sleep(1.0 / rate)


def _send_syslog(line: str, *, host: str, port: int) -> int:
    payload = line.encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (host, port))
    finally:
        sock.close()
    return len(payload)


def replay_logs(
    db: Session | None = None,
    *,
    sample_path: str | None = None,
    rate: float = 1.0,
    limit: int | None = 100,
    dry_run: bool = False,
    loop: bool = False,
    send_to: str = "syslog",
    run_detection_after: bool = False,
    detection_limit: int | None = None,
    host: str | None = None,
    port: int | None = None,
    source_name: str | None = None,
    source_type: str = "replay",
    source_host: str | None = None,
    source_port: int | None = None,
    parser_profile: str = "palo_alto",
    actor: str = "log_replay",
) -> dict[str, Any]:
    settings = get_settings()
    path = _resolve_sample_path(sample_path)
    if not path.exists():
        return {"ok": False, "error": f"Sample log path does not exist: {path}", "path": str(path)}

    mode = "direct" if send_to == "api" else send_to
    if mode not in {"syslog", "direct"}:
        return {"ok": False, "error": f"Unsupported send target: {send_to}"}

    target_host = host or settings.syslog_host
    target_port = port or settings.syslog_port
    result: dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "path": str(path),
        "rate_per_second": rate,
        "limit": limit,
        "loop": loop,
        "send_to": send_to,
        "effective_mode": mode,
        "target": {"host": target_host, "port": target_port} if mode == "syslog" else {"database": settings.database_url},
        "source": {
            "name": source_name or path.name,
            "source_type": source_type,
            "host": source_host,
            "port": source_port,
            "parser_profile": parser_profile,
        },
        "read": 0,
        "sent": 0,
        "imported": 0,
        "parsed": 0,
        "failed": 0,
        "duplicate_raw_logs": 0,
        "blank": 0,
        "bytes_sent": 0,
        "errors": [],
        "detection": {"skipped": True, "reason": "Pass --run-detection to run detection after direct replay."},
        "warnings": [
            "Replay mode never resets the database.",
            "Dry-run mode parses only and does not send syslog or write database rows.",
        ],
    }
    if send_to == "api":
        result["warnings"].append("API replay is mapped to the local import service in v0.2; HTTP-auth replay remains future work.")

    owns_session = db is None and mode == "direct" and not dry_run
    if owns_session:
        init_db()
        db = SessionLocal()
    run = None
    job = None
    if db is not None and mode == "direct" and not dry_run:
        source = get_or_create_source(
            db,
            name=source_name or path.name,
            source_type=source_type,
            parser_profile=parser_profile,
            host=source_host,
            port=source_port,
        )
        job = start_job(
            db,
            job_type="replay_logs",
            requested_by=actor,
            details={
                "rate": rate,
                "limit": limit,
                "loop": loop,
                "send_to": send_to,
                "source_id": source.id,
                "source_name": source.name,
                "source_type": source.source_type,
                "parser_profile": source.parser_profile,
            },
        )
        run = start_ingestion_run(
            db,
            source_type="replay_direct",
            input_name=str(path),
            details={
                "rate": rate,
                "limit": limit,
                "loop": loop,
                "run_detection_after": run_detection_after,
                "source_id": source.id,
                "source_name": source.name,
                "source_type": source.source_type,
                "parser_profile": source.parser_profile,
            },
        )
    else:
        source = None

    try:
        for line_number, line in _iter_replay_lines(path, limit=limit, loop=loop):
            result["read"] += 1
            if not line.strip():
                result["blank"] += 1
                continue
            parsed = parse_log_line_for_profile(line, parser_profile)
            if parsed.error:
                result["failed"] += 1
                result["errors"].append({"line_number": line_number, "error": parsed.error})
            else:
                result["parsed"] += 1

            if dry_run:
                _sleep_for_rate(rate)
                continue

            if mode == "syslog":
                result["bytes_sent"] += _send_syslog(line, host=target_host, port=target_port)
                result["sent"] += 1
            else:
                if db is None:
                    raise RuntimeError("direct replay requires a database session")
                import_result = import_raw_log_line(
                    db,
                    line,
                    source_name=path.name,
                    actor=actor,
                    commit=False,
                    source_id=source.id if source is not None else None,
                    source_type=source_type,
                    parser_profile=parser_profile,
                    host=source_host,
                    port=source_port,
                )
                result["imported"] += 1
                result["duplicate_raw_logs"] = int(result.get("duplicate_raw_logs") or 0) + (
                    1 if import_result.get("duplicate_raw_log") else 0
                )
                if not import_result["parsed"] and not parsed.error:
                    result["failed"] += 1
                    result["errors"].append({"line_number": line_number, "error": import_result["error"]})
            _sleep_for_rate(rate)

        if db is not None and mode == "direct" and not dry_run and run_detection_after:
            detection_result = run_detection(
                db,
                limit=detection_limit or limit,
                use_ml=True,
                actor=actor,
                source_id=source.id if source is not None else None,
                source_name=source.name if source is not None else source_name,
                source_type=source.source_type if source is not None else source_type,
            )
            result["detection"] = detection_result
            result["alerts_created"] = detection_result.get("created_alerts", 0)
            result["alerts_deduplicated"] = detection_result.get("deduplicated_alert_updates", 0)
            result["alerts_suppressed"] = detection_result.get("suppressed_low_groups", 0) + detection_result.get("suppressed_by_rules", 0)

        if run is not None and db is not None:
            complete_ingestion_run(
                db,
                run,
                total_lines_received=result["read"],
                raw_logs_created=result["imported"],
                parsed_successfully=result["parsed"],
                parse_failures=result["failed"],
                duplicate_raw_logs=int(result.get("duplicate_raw_logs") or 0),
                alerts_created=int(result.get("alerts_created") or 0),
                alerts_deduplicated=int(result.get("alerts_deduplicated") or 0),
                alerts_suppressed=int(result.get("alerts_suppressed") or 0),
                details={
                    "actor": actor,
                    "send_to": send_to,
                    "source_id": source.id if source is not None else None,
                    "source_name": source.name if source is not None else source_name,
                    "source_type": source.source_type if source is not None else source_type,
                    "parser_profile": source.parser_profile if source is not None else parser_profile,
                },
            )
            db.commit()
            result["run_id"] = run.id
        if job is not None and db is not None:
            complete_job(
                db,
                job,
                result_summary=build_result_summary("replay_logs", result),
                related_ingestion_run_id=run.id if run is not None else None,
                related_detection_run_id=(result.get("detection") or {}).get("detection_run_id")
                if isinstance(result.get("detection"), dict)
                else None,
            )
            result["job_id"] = job.id
    except Exception as exc:
        if run is not None and db is not None:
            fail_ingestion_run(db, run, error=f"{exc.__class__.__name__}: {exc}", details={"read_before_failure": result["read"]})
            db.commit()
        if job is not None and db is not None:
            fail_job(db, job, exc)
        raise
    finally:
        if owns_session and db is not None:
            db.close()

    if result["errors"]:
        result["errors"] = result["errors"][:10]
    return result


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Safely replay Palo Alto log lines to syslog or the local import service.")
    parser.add_argument("--sample-path", default=None, help="Log file to replay. Defaults to the safe demo sample path.")
    parser.add_argument("--rate", type=float, default=1.0, help="Replay rate in lines per second. Use 0 for no delay.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum lines to replay. Use 0 for no limit.")
    parser.add_argument("--dry-run", action="store_true", help="Parse only. Do not send syslog or write database rows.")
    parser.add_argument("--loop", action="store_true", help="Loop over the file until the limit is reached.")
    parser.add_argument("--send-to", choices=["syslog", "direct", "api"], default="syslog")
    parser.add_argument("--run-detection", action="store_true", help="After direct replay, run detection and record alert counts.")
    parser.add_argument("--detection-limit", type=int, default=None)
    parser.add_argument("--host", default=settings.syslog_host)
    parser.add_argument("--port", type=int, default=settings.syslog_port)
    parser.add_argument("--source-name", default=None, help="Optional source/sensor name for direct replay. Defaults to filename.")
    parser.add_argument("--source-type", default="replay", choices=["replay", "firewall", "router", "sample", "file_import"])
    parser.add_argument("--source-host", default=None, help="Optional source/sensor host or IP for direct replay.")
    parser.add_argument("--source-port", type=int, default=None, help="Optional source/sensor port for direct replay.")
    parser.add_argument("--parser-profile", default="palo_alto", choices=["palo_alto", "generic_syslog", "raw_fallback"])
    parser.add_argument("--actor", default="log_replay")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    normalized_limit = None if args.limit <= 0 else args.limit
    result = replay_logs(
        sample_path=args.sample_path,
        rate=args.rate,
        limit=normalized_limit,
        dry_run=args.dry_run,
        loop=args.loop,
        send_to=args.send_to,
        run_detection_after=args.run_detection,
        detection_limit=args.detection_limit,
        host=args.host,
        port=args.port,
        source_name=args.source_name,
        source_type=args.source_type,
        source_host=args.source_host,
        source_port=args.source_port,
        parser_profile=args.parser_profile,
        actor=args.actor,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
