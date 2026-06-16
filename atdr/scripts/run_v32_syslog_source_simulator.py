import argparse
import json
import re
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base, SessionLocal, init_db
from atdr.app.db.models import LogSource, NormalizedLog, RawLog, ResponseAction
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.log_service import import_log_stream
from atdr.app.services.source_service import get_or_create_source, source_to_dict, update_source


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
DEFAULT_BASE_TIME = datetime(2026, 6, 16, 9, 0, 0)


SCENARIO_FILES: dict[str, list[tuple[str, int]]] = {
    "mixed_baseline": [
        ("normal_web_dns_quic_traffic.txt", 6),
        ("port_scan_like_traffic.txt", 3),
        ("malformed_raw_fallback.txt", 1),
    ],
    "normal_web_dns": [("normal_web_dns_quic_traffic.txt", 1)],
    "port_scan_like_traffic": [("port_scan_like_traffic.txt", 1)],
    "malformed_mixed": [
        ("malformed_raw_fallback.txt", 2),
        ("generic_syslog_mixed.txt", 1),
    ],
    "source_idle_recovery": [("normal_allowed_traffic.txt", 1)],
    "parser_quality_mixed": [
        ("normal_allowed_traffic.txt", 7),
        ("generic_syslog_mixed.txt", 2),
        ("malformed_raw_fallback.txt", 1),
    ],
}


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _temp_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _read_nonblank_lines(path: Path) -> list[str]:
    return [line.rstrip("\r\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _line_pool(scenario: str) -> list[tuple[str, str]]:
    if scenario not in SCENARIO_FILES:
        raise ValueError(f"Unknown v3.2 source simulator scenario: {scenario}")
    pool: list[tuple[str, str]] = []
    for filename, weight in SCENARIO_FILES[scenario]:
        path = SCENARIO_DIR / filename
        for _ in range(max(1, weight)):
            pool.extend((filename, line) for line in _read_nonblank_lines(path))
    return pool


def _mutate_line(line: str, index: int, *, base_time: datetime = DEFAULT_BASE_TIME) -> str:
    observed = base_time + timedelta(seconds=index)
    iso = observed.strftime("%Y-%m-%dT%H:%M:%S+07:00")
    palo = observed.strftime("%Y/%m/%d %H:%M:%S")
    iso_payload = observed.strftime("%Y-%m-%dT%H:%M:%S.000+07:00")
    if "," not in line:
        return f"MALFORMED_V32_SEQ_{index}"

    parts = line.split(maxsplit=2)
    if len(parts) == 3:
        _, hostname, payload = parts
        payload = re.sub(r"2026/05/20 \d\d:\d\d:\d\d", palo, payload)
        payload = re.sub(r"2026-05-20T\d\d:\d\d:\d\d\.000\+07:00", iso_payload, payload)
        payload_parts = payload.split(",")
        if len(payload_parts) > 22:
            payload_parts[22] = str(930000 + index)
        payload = ",".join(payload_parts)
        return f"{iso} {hostname} {payload}"

    return f"{iso} LAB-FW.local {line} v32-seq-{index}"


def build_simulated_source_lines(scenario: str, count: int) -> tuple[list[str], dict[str, int]]:
    pool = _line_pool(scenario)
    if not pool:
        return [], {}
    lines: list[str] = []
    distribution: dict[str, int] = {}
    for index in range(max(0, count)):
        filename, source_line = pool[index % len(pool)]
        distribution[filename] = distribution.get(filename, 0) + 1
        lines.append(_mutate_line(source_line, index))
    return lines, distribution


def _parse_lines(lines: list[str], parser_profile: str) -> dict[str, Any]:
    parsed = 0
    failed = 0
    errors: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        parsed_line = parse_log_line_for_profile(line, parser_profile)
        if parsed_line.error:
            failed += 1
            if len(errors) < 10:
                errors.append({"line_number": index, "error": parsed_line.error})
        else:
            parsed += 1
    return {"read": len(lines), "parsed": parsed, "failed": failed, "errors": errors}


def _source_counts(db: Session, source_id: int) -> dict[str, int]:
    raw_logs = int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)
    normalized_logs = int(
        db.scalar(select(func.count(NormalizedLog.id)).join(RawLog).where(RawLog.source_id == source_id)) or 0
    )
    return {"raw_logs": raw_logs, "normalized_logs": normalized_logs}


def simulate_source_import(
    db: Session,
    *,
    source_name: str,
    source_type: str,
    parser_profile: str,
    host: str | None,
    port: int | None,
    count: int,
    scenario: str,
    actor: str = "v32_source_simulator",
) -> dict[str, Any]:
    lines, distribution = build_simulated_source_lines(scenario, count)
    source = get_or_create_source(
        db,
        name=source_name,
        source_type=source_type,
        parser_profile=parser_profile,
        host=host,
        port=port,
    )
    source = update_source(
        db,
        source,
        {
            "source_type": source_type,
            "parser_profile": parser_profile,
            "host": host,
            "port": port,
            "enabled": True,
        },
    )
    before_counts = _source_counts(db, source.id)
    response_actions_before = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    stream = StringIO("\n".join(lines) + ("\n" if lines else ""))
    import_result = import_log_stream(
        db,
        stream,
        source_name=f"v32:{scenario}",
        source_type="replay_direct",
        limit=None,
        actor=actor,
        source_id=source.id,
        parser_profile=parser_profile,
        available_lines=len(lines),
    )
    db.refresh(source)
    after_counts = _source_counts(db, source.id)
    response_actions_after = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    return {
        "source": source_to_dict(source, include_quality=True, db=db),
        "mode": "simulated_source_import",
        "scenario": scenario,
        "requested_count": count,
        "generated_lines": len(lines),
        "scenario_distribution": distribution,
        "before_counts": before_counts,
        "after_counts": after_counts,
        "delta_counts": {
            "raw_logs": after_counts["raw_logs"] - before_counts["raw_logs"],
            "normalized_logs": after_counts["normalized_logs"] - before_counts["normalized_logs"],
        },
        "import_result": import_result,
        "response_actions_before": response_actions_before,
        "response_actions_after": response_actions_after,
    }


def run_v32_syslog_source_simulator(
    *,
    source_name: str = "lab-firewall-sim-1",
    source_type: str = "firewall",
    parser_profile: str = "palo_alto",
    host: str | None = "127.0.0.1",
    port: int | None = 5514,
    count: int = 100,
    rate: float = 5.0,
    scenario: str = "mixed_baseline",
    dry_run: bool = False,
    use_temp_db: bool = False,
    session_factory=None,
) -> dict[str, Any]:
    lines, distribution = build_simulated_source_lines(scenario, count)
    parse_preview = _parse_lines(lines, parser_profile)
    base_result = {
        "ok": True,
        "hardware_required": False,
        "real_device_forwarding_validated": False,
        "production_ready": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "source": {
            "name": source_name,
            "source_type": source_type,
            "parser_profile": parser_profile,
            "host": host,
            "port": port,
        },
        "scenario": scenario,
        "requested_count": count,
        "rate_per_second": rate,
        "mode": "simulated_source_import",
        "scenario_distribution": distribution,
        "parse_preview": parse_preview,
    }
    if dry_run:
        return {
            **base_result,
            "dry_run": True,
            "simulated_source_validated": False,
            "current_database_modified": False,
            "message": "Dry-run parsed generated safe lines only; no source, logs, alerts, or response actions were written.",
        }

    engine = None
    if session_factory is not None:
        SessionFactory = session_factory
    elif use_temp_db:
        engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal
    try:
        with SessionFactory() as db:
            simulated = simulate_source_import(
                db,
                source_name=source_name,
                source_type=source_type,
                parser_profile=parser_profile,
                host=host,
                port=port,
                count=count,
                scenario=scenario,
            )
            import_result = simulated["import_result"]
            return {
                **base_result,
                "dry_run": False,
                "temporary_database_used": use_temp_db,
                "current_database_modified": not use_temp_db and session_factory is None,
                "simulated_source_validated": bool(import_result.get("raw_logs_imported")),
                "real_device_forwarding_validated": False,
                "source_after": simulated["source"],
                "import_result": import_result,
                "counts": {
                    "raw_logs_imported": import_result.get("raw_logs_imported", 0),
                    "normalized_logs_created": import_result.get("normalized_logs_created", 0),
                    "parse_successes": import_result.get("parsed_successfully", 0),
                    "parse_failures": import_result.get("parse_failures", 0),
                    "duplicate_raw_logs": import_result.get("duplicate_raw_logs", 0),
                },
                "response_safety": {
                    "response_actions_before": simulated["response_actions_before"],
                    "response_actions_after": simulated["response_actions_after"],
                    "automatic_response_actions_created": max(
                        0,
                        int(simulated["response_actions_after"]) - int(simulated["response_actions_before"]),
                    ),
                    "response_automation_allowed": False,
                    "real_firewall_blocking_enabled": False,
                },
            }
    finally:
        if engine is not None:
            engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a safe v3.2 no-hardware syslog/source simulator.")
    parser.add_argument("--source-name", default="lab-firewall-sim-1")
    parser.add_argument("--source-type", default="firewall", choices=["file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"])
    parser.add_argument("--parser-profile", default="palo_alto", choices=["palo_alto", "generic_syslog", "raw_fallback"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--rate", type=float, default=5.0)
    parser.add_argument("--scenario", default="mixed_baseline", choices=sorted(SCENARIO_FILES))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v32_syslog_source_simulator(
        source_name=args.source_name,
        source_type=args.source_type,
        parser_profile=args.parser_profile,
        host=args.host,
        port=args.port,
        count=args.count,
        rate=args.rate,
        scenario=args.scenario,
        dry_run=args.dry_run,
        use_temp_db=args.use_temp_db,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
