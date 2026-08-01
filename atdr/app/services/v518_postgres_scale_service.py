from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
from pathlib import Path
import re
import shutil
import subprocess
from threading import Event, Thread
from typing import Any, Iterator

from sqlalchemy import text
from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.engine import create_configured_engine
from atdr.app.services.v514_large_file_runtime_service import (
    _privacy_findings,
)
from atdr.app.services.v516_memory_query_service import (
    process_memory_snapshot,
)
from atdr.app.services.v517_postgres_multiworker_service import (
    _configured_database_marker,
    _database_identity,
    _drop_disposable_database,
    _safe_postgres_target,
    run_v517_postgres_multiworker_acceptance,
)


_CONFIRMATION = "APPROVED_DISPOSABLE_V518_SCALE_DATABASES"
_TARGET_ENV = "ATDR_V518_POSTGRES_DATABASE_URL"
_RESTORE_ENV = "ATDR_V518_RESTORE_DATABASE_URL"
_HOST_APPROVAL_ENV = "ATDR_V518_APPROVED_HOST"
_MIN_POSTGRES_MAJOR = 16
_MIN_FREE_MEMORY_BYTES = 4 * 1024**3
_MIN_FREE_DISK_100K_BYTES = 5 * 1024**3
_MIN_FREE_DISK_250K_BYTES = 10 * 1024**3
_REQUIRED_EXTENSION = "plpgsql"
_DATABASE_NAME = re.compile(r"^[A-Za-z0-9_]+$")

_SLO_BY_SCALE = {
    100_000: {
        "minimum_ingestion_rows_per_second": 250.0,
        "maximum_runtime_seconds": 600.0,
        "maximum_chunk_p99_seconds": 10.0,
        "maximum_full_stage_peak_rss_mb": 4_096.0,
        "maximum_database_growth_bytes": 1_073_741_824,
    },
    250_000: {
        "minimum_ingestion_rows_per_second": 250.0,
        "maximum_runtime_seconds": 1_500.0,
        "maximum_chunk_p99_seconds": 10.0,
        "maximum_full_stage_peak_rss_mb": 8_192.0,
        "maximum_database_growth_bytes": 2_684_354_560,
    },
}

_QUERY_SLO = {
    "overview_cold_seconds": 3.0,
    "overview_cached_seconds": 0.1,
    "alert_list_seconds": 5.0,
    "case_summary_seconds": 3.0,
    "source_detail_seconds": 3.0,
}


def _base_result(status: str, *, ok: bool = False) -> dict[str, Any]:
    return {
        "ok": ok,
        "status": status,
        "production_ready": False,
        "configured_database_modified": False,
        "database_urls_returned": False,
        "credentials_returned": False,
        "private_path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
        "rules_alert_authoritative": True,
        "supervised_lifecycle": "shadow_observation",
        "model_activation_performed": False,
        "model_promotion_performed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _is_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _available_memory_bytes() -> int | None:
    if os.name == "nt":
        try:
            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(
                ctypes.byref(status)
            ):
                return int(status.available_physical)
        except (AttributeError, OSError, TypeError, ValueError):
            return None
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        pages = int(os.sysconf("SC_AVPHYS_PAGES"))
        return page_size * pages
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _host_capacity(*, include_250k: bool) -> dict[str, Any]:
    memory = _available_memory_bytes()
    disk = shutil.disk_usage(PROJECT_ROOT)
    required_disk = (
        _MIN_FREE_DISK_250K_BYTES
        if include_250k
        else _MIN_FREE_DISK_100K_BYTES
    )
    return {
        "ok": bool(
            memory is not None
            and memory >= _MIN_FREE_MEMORY_BYTES
            and disk.free >= required_disk
        ),
        "available_memory_bytes": memory,
        "minimum_memory_bytes": _MIN_FREE_MEMORY_BYTES,
        "free_disk_bytes": int(disk.free),
        "minimum_disk_bytes": required_disk,
        "capacity_path_returned": False,
    }


def _tool_profile(name: str) -> dict[str, Any]:
    executable = shutil.which(name)
    if not executable:
        return {
            "available": False,
            "major": None,
            "minor": None,
            "path_returned": False,
        }
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        match = re.search(
            r"(\d+)(?:\.(\d+))?",
            f"{completed.stdout} {completed.stderr}",
        )
        major = int(match.group(1)) if match else None
        minor = int(match.group(2)) if match and match.group(2) else None
        return {
            "available": completed.returncode == 0,
            "major": major,
            "minor": minor,
            "path_returned": False,
        }
    except (OSError, subprocess.SubprocessError, ValueError):
        return {
            "available": False,
            "major": None,
            "minor": None,
            "path_returned": False,
        }


def _inspection_settings(database_url: str) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL=database_url,
        AUTO_CREATE_TABLES=False,
        RESPONSE_SIMULATION=True,
    )


def _database_profile(
    database_url: str,
    *,
    maximum_workers: int,
) -> dict[str, Any]:
    engine = create_configured_engine(_inspection_settings(database_url))
    try:
        with engine.connect() as connection:
            version_number = int(
                connection.execute(
                    text("SELECT current_setting('server_version_num')")
                ).scalar()
                or 0
            )
            server_major = version_number // 10_000
            max_connections = int(
                connection.execute(
                    text("SELECT current_setting('max_connections')")
                ).scalar()
                or 0
            )
            reserved_connections = int(
                connection.execute(
                    text(
                        "SELECT current_setting("
                        "'superuser_reserved_connections'"
                        ")"
                    )
                ).scalar()
                or 0
            )
            active_connections = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM pg_stat_activity")
                ).scalar()
                or 0
            )
            public_tables = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM information_schema.tables "
                        "WHERE table_schema = 'public'"
                    )
                ).scalar()
                or 0
            )
            extension_count = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM pg_extension")
                ).scalar()
                or 0
            )
            required_extension_present = bool(
                connection.execute(
                    text(
                        "SELECT EXISTS("
                        "SELECT 1 FROM pg_extension WHERE extname = :name"
                        ")"
                    ),
                    {"name": _REQUIRED_EXTENSION},
                ).scalar()
            )
            database_size = int(
                connection.execute(
                    text("SELECT pg_database_size(current_database())")
                ).scalar()
                or 0
            )
    finally:
        engine.dispose()

    required_worker_connections = maximum_workers * 2
    required_connection_headroom = required_worker_connections + 4
    available_connections = max(
        0,
        max_connections - reserved_connections - active_connections,
    )
    settings = _inspection_settings(database_url)
    pool_capacity = settings.db_pool_size + settings.db_max_overflow
    return {
        "ok": bool(
            server_major >= _MIN_POSTGRES_MAJOR
            and public_tables == 0
            and required_extension_present
            and available_connections >= required_connection_headroom
            and pool_capacity >= required_worker_connections
        ),
        "server_major": server_major,
        "minimum_server_major": _MIN_POSTGRES_MAJOR,
        "extension_count": extension_count,
        "required_extension": _REQUIRED_EXTENSION,
        "required_extension_present": required_extension_present,
        "public_table_count": public_tables,
        "empty_database": public_tables == 0,
        "database_size_bytes": database_size,
        "max_connections": max_connections,
        "reserved_connections": reserved_connections,
        "active_connections": active_connections,
        "available_connections": available_connections,
        "required_connection_headroom": required_connection_headroom,
        "configured_pool_capacity": pool_capacity,
        "required_worker_pool_capacity": required_worker_connections,
        "database_identity_returned": False,
    }


def _preflight(
    *,
    target_url: str,
    restore_url: str,
    configured_url: str,
    include_250k: bool,
    maximum_workers: int,
) -> dict[str, Any]:
    target_safe, target_reason = _safe_postgres_target(
        target_url,
        configured_url=configured_url,
    )
    restore_safe, restore_reason = _safe_postgres_target(
        restore_url,
        configured_url=configured_url,
    )
    targets_distinct = False
    if target_safe and restore_safe:
        targets_distinct = (
            _database_identity(target_url)
            != _database_identity(restore_url)
        )

    tools = {
        name: _tool_profile(name)
        for name in ("psql", "pg_dump", "pg_restore")
    }
    host = _host_capacity(include_250k=include_250k)
    target: dict[str, Any] = {
        "ok": False,
        "safe": target_safe,
        "reason": target_reason,
        "available": False,
    }
    restore: dict[str, Any] = {
        "ok": False,
        "safe": restore_safe,
        "reason": restore_reason,
        "available": False,
    }
    if target_safe and restore_safe and targets_distinct:
        try:
            target = {
                **_database_profile(
                    target_url,
                    maximum_workers=maximum_workers,
                ),
                "safe": True,
                "reason": "accepted",
                "available": True,
            }
        except Exception as exc:
            target["error_type"] = exc.__class__.__name__
        try:
            restore = {
                **_database_profile(
                    restore_url,
                    maximum_workers=1,
                ),
                "safe": True,
                "reason": "accepted",
                "available": True,
            }
        except Exception as exc:
            restore["error_type"] = exc.__class__.__name__

    target_major = target.get("server_major")
    tools_compatible = bool(
        target_major
        and all(
            profile["available"]
            and profile["major"] is not None
            and profile["major"] >= target_major
            for profile in tools.values()
        )
    )
    host_approved = _is_enabled(os.environ.get(_HOST_APPROVAL_ENV))
    ok = bool(
        host_approved
        and target_safe
        and restore_safe
        and targets_distinct
        and host["ok"]
        and target.get("ok")
        and restore.get("ok")
        and tools_compatible
    )
    return {
        "ok": ok,
        "status": "ready" if ok else "blocked_by_environment",
        "host_approved": host_approved,
        "host_capacity": host,
        "target": target,
        "restore": restore,
        "targets_distinct": targets_distinct,
        "tools": tools,
        "tools_server_compatible": tools_compatible,
        "database_urls_returned": False,
        "credentials_returned": False,
    }


def _recreate_disposable_database(
    database_url: str,
    *,
    configured_url: str,
) -> bool:
    safe, _ = _safe_postgres_target(
        database_url,
        configured_url=configured_url,
    )
    if not safe:
        return False
    url = make_url(database_url)
    database_name = url.database or ""
    if not _DATABASE_NAME.fullmatch(database_name):
        return False
    admin_url = url.set(database="postgres")
    settings = _inspection_settings(
        admin_url.render_as_string(hide_password=False)
    )
    engine = create_configured_engine(settings).execution_options(
        isolation_level="AUTOCOMMIT"
    )
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) "
                    "FROM pg_stat_activity "
                    "WHERE datname = :database_name "
                    "AND pid <> pg_backend_pid()"
                ),
                {"database_name": database_name},
            )
            connection.exec_driver_sql(
                f'DROP DATABASE IF EXISTS "{database_name}"'
            )
            connection.exec_driver_sql(
                f'CREATE DATABASE "{database_name}"'
            )
        return True
    finally:
        engine.dispose()


def _prepare_disposable_pair(
    *,
    target_url: str,
    restore_url: str,
    configured_url: str,
) -> dict[str, bool]:
    return {
        "target_created": _recreate_disposable_database(
            target_url,
            configured_url=configured_url,
        ),
        "restore_created": _recreate_disposable_database(
            restore_url,
            configured_url=configured_url,
        ),
    }


@contextmanager
def _v517_environment(
    *,
    target_url: str,
    restore_url: str,
) -> Iterator[None]:
    values = {
        "ATDR_V517_POSTGRES_DATABASE_URL": target_url,
        "ATDR_V517_RESTORE_DATABASE_URL": restore_url,
        "ATDR_V517_PRIVATE_EVIDENCE_APPROVED": "false",
    }
    previous = {key: os.environ.get(key) for key in values}
    try:
        os.environ.update(values)
        get_settings.cache_clear()
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


def _current_rss_mb() -> float | None:
    snapshot = process_memory_snapshot()
    current = snapshot.get("current_rss_mb")
    if current is not None:
        return float(current)
    try:
        statm = Path("/proc/self/statm").read_text(
            encoding="ascii",
        ).split()
        pages = int(statm[1])
        return round(
            pages * int(os.sysconf("SC_PAGE_SIZE")) / (1024**2),
            2,
        )
    except (IndexError, OSError, TypeError, ValueError):
        return None


@contextmanager
def _full_stage_memory_monitor() -> Iterator[dict[str, Any]]:
    """Sample current RSS so every worker profile gets an independent peak."""

    before = _current_rss_mb()
    samples = {
        "available": before is not None,
        "before_rss_mb": before,
        "after_rss_mb": None,
        "peak_rss_mb": before,
        "sample_count": 1 if before is not None else 0,
    }
    stopped = Event()

    def sample() -> None:
        while not stopped.wait(0.05):
            current = _current_rss_mb()
            if current is None:
                continue
            samples["available"] = True
            samples["sample_count"] = int(
                samples["sample_count"]
            ) + 1
            peak = samples.get("peak_rss_mb")
            if peak is None or current > float(peak):
                samples["peak_rss_mb"] = current

    monitor = Thread(
        target=sample,
        name="v518-memory-monitor",
        daemon=True,
    )
    monitor.start()
    try:
        yield samples
    finally:
        stopped.set()
        monitor.join(timeout=2.0)
        after = _current_rss_mb()
        samples["after_rss_mb"] = after
        if after is not None:
            samples["sample_count"] = int(
                samples["sample_count"]
            ) + 1
            peak = samples.get("peak_rss_mb")
            if peak is None or after > float(peak):
                samples["peak_rss_mb"] = after
        if before is not None and after is not None:
            samples["retained_growth_mb"] = round(
                max(0.0, after - before),
                2,
            )
        else:
            samples["retained_growth_mb"] = None


def _slo_evaluation(
    result: dict[str, Any],
    *,
    target_rows: int,
) -> dict[str, Any]:
    limits = _SLO_BY_SCALE[target_rows]
    ingestion = result.get("ingestion") or {}
    database = result.get("database") or {}
    dashboard = ((result.get("queries") or {}).get("dashboard") or {})
    full_stage_memory = result.get("full_stage_memory") or {}
    full_stage_peak = full_stage_memory.get("peak_rss_mb")
    checks = {
        "acceptance_contract": bool(result.get("ok")),
        "ingestion_throughput": float(
            ingestion.get("rows_per_second") or 0.0
        )
        >= limits["minimum_ingestion_rows_per_second"],
        "ingestion_runtime": float(
            ingestion.get("runtime_seconds") or float("inf")
        )
        <= limits["maximum_runtime_seconds"],
        "chunk_p99": float(
            (
                ingestion.get("chunk_commit_interval_seconds")
                or {}
            ).get("p99")
            or float("inf")
        )
        <= limits["maximum_chunk_p99_seconds"],
        "full_stage_memory": (
            full_stage_peak is not None
            and float(full_stage_peak)
            <= limits["maximum_full_stage_peak_rss_mb"]
        ),
        "database_growth": int(
            database.get("growth_bytes") or 0
        )
        <= limits["maximum_database_growth_bytes"],
        "pool_no_timeout": int(
            (result.get("pool") or {}).get("timeout_errors") or 0
        )
        == 0,
        "no_lock_waiters": int(
            (result.get("queries") or {}).get(
                "ungranted_lock_count"
            )
            or 0
        )
        == 0,
    }
    for metric, maximum in _QUERY_SLO.items():
        checks[f"query_{metric}"] = (
            float(dashboard.get(metric) or float("inf")) <= maximum
        )
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "passed": sum(1 for passed in checks.values() if passed),
        "total": len(checks),
        "limits": {
            **limits,
            "query_maximum_seconds": _QUERY_SLO,
        },
        "observed_full_stage_peak_rss_mb": full_stage_peak,
    }


def _stage_summary(
    result: dict[str, Any],
    *,
    target_rows: int,
    workers: int,
) -> dict[str, Any]:
    slo = _slo_evaluation(result, target_rows=target_rows)
    return {
        "ok": bool(result.get("ok") and slo["ok"]),
        "status": result.get("status"),
        "target_rows": target_rows,
        "workers": workers,
        "ingestion": result.get("ingestion"),
        "pool": result.get("pool"),
        "memory": result.get("memory"),
        "full_stage_memory": result.get("full_stage_memory"),
        "database": result.get("database"),
        "lease_fencing": result.get("lease_fencing"),
        "idempotency": result.get("idempotency"),
        "stale_recovery": result.get("stale_recovery"),
        "cancellation_resume": result.get("cancellation_resume"),
        "detection": result.get("detection"),
        "queries": result.get("queries"),
        "backup": result.get("backup"),
        "restore": result.get("restore"),
        "safety_counts_before": result.get("safety_counts_before"),
        "safety_counts_after": result.get("safety_counts_after"),
        "safety_counts_unchanged": result.get(
            "safety_counts_unchanged"
        ),
        "configured_database_unchanged": result.get(
            "configured_database_unchanged"
        ),
        "cleanup": result.get("cleanup"),
        "privacy_findings": result.get("privacy_findings"),
        "slo": slo,
    }


def _run_scale_stage(
    *,
    target_url: str,
    restore_url: str,
    configured_url: str,
    target_rows: int,
    workers: int,
) -> dict[str, Any]:
    prepared = _prepare_disposable_pair(
        target_url=target_url,
        restore_url=restore_url,
        configured_url=configured_url,
    )
    if not all(prepared.values()):
        return {
            "ok": False,
            "status": "disposable_database_preparation_failed",
            "target_rows": target_rows,
            "workers": workers,
            "disposable_pair": prepared,
        }
    with _full_stage_memory_monitor() as full_stage_memory:
        with _v517_environment(
            target_url=target_url,
            restore_url=restore_url,
        ):
            acceptance = run_v517_postgres_multiworker_acceptance(
                target_rows=target_rows,
                chunk_size=1_000,
                workers=workers,
                synthetic=True,
                run_detection_after=True,
                test_recovery=True,
            )
    acceptance["full_stage_memory"] = full_stage_memory
    return _stage_summary(
        acceptance,
        target_rows=target_rows,
        workers=workers,
    )


def run_v518_postgres_scale_qualification(
    *,
    execute: bool = False,
    confirmation: str = "",
    include_250k: bool = True,
) -> dict[str, Any]:
    settings = get_settings()
    configured_url = settings.database_url
    target_url = os.environ.get(_TARGET_ENV, "").strip()
    restore_url = os.environ.get(_RESTORE_ENV, "").strip()
    marker_kind, marker_before = _configured_database_marker()
    preflight = _preflight(
        target_url=target_url,
        restore_url=restore_url,
        configured_url=configured_url,
        include_250k=include_250k,
        maximum_workers=4,
    )
    result: dict[str, Any] = {
        **_base_result(preflight["status"], ok=preflight["ok"]),
        "executed": False,
        "include_250k": include_250k,
        "preflight": preflight,
        "configured_database_marker_checked": marker_kind != "unavailable",
        "hundred_k": {
            "attempted": False,
            "passed": False,
            "profiles": [],
        },
        "quarter_million": {
            "attempted": False,
            "passed": False,
            "profiles": [],
        },
        "roadmap": {
            "major_gates_at_start": 4,
            "postgresql_gate_closed": False,
            "remaining_major_gates": 4,
        },
    }
    if not execute:
        result["status"] = (
            "ready_for_confirmed_execution"
            if preflight["ok"]
            else "blocked_by_environment"
        )
        result["privacy_findings"] = _privacy_findings(
            result,
            private_path=Path("<synthetic>"),
        )
        return result
    if confirmation != _CONFIRMATION:
        result.update(
            {
                "ok": False,
                "status": "confirmation_required",
                "required_confirmation": _CONFIRMATION,
            }
        )
        result["privacy_findings"] = _privacy_findings(
            result,
            private_path=Path("<synthetic>"),
        )
        return result
    if not preflight["ok"]:
        result["ok"] = False
        result["status"] = "blocked_by_environment"
        result["privacy_findings"] = _privacy_findings(
            result,
            private_path=Path("<synthetic>"),
        )
        return result

    result["executed"] = True
    try:
        hundred_k_profiles = [
            _run_scale_stage(
                target_url=target_url,
                restore_url=restore_url,
                configured_url=configured_url,
                target_rows=100_000,
                workers=workers,
            )
            for workers in (2, 4)
        ]
        hundred_k_passed = all(
            profile.get("ok") for profile in hundred_k_profiles
        )
        result["hundred_k"] = {
            "attempted": True,
            "passed": hundred_k_passed,
            "profiles": hundred_k_profiles,
        }

        quarter_profiles: list[dict[str, Any]] = []
        if include_250k and hundred_k_passed:
            quarter_profiles = [
                _run_scale_stage(
                    target_url=target_url,
                    restore_url=restore_url,
                    configured_url=configured_url,
                    target_rows=250_000,
                    workers=workers,
                )
                for workers in (2, 4)
            ]
        quarter_attempted = bool(quarter_profiles)
        quarter_passed = bool(
            quarter_attempted
            and all(profile.get("ok") for profile in quarter_profiles)
        )
        result["quarter_million"] = {
            "attempted": quarter_attempted,
            "passed": quarter_passed,
            "skipped_reason": (
                None
                if quarter_attempted
                else (
                    "not_requested"
                    if not include_250k
                    else "hundred_k_gate_failed"
                )
            ),
            "profiles": quarter_profiles,
        }
        passed = bool(
            hundred_k_passed
            and (quarter_passed if include_250k else True)
        )
        result["ok"] = passed
        result["status"] = (
            "postgres_scale_qualification_passed"
            if passed
            else "postgres_scale_qualification_failed"
        )
        result["roadmap"] = {
            "major_gates_at_start": 4,
            "postgresql_gate_closed": passed and include_250k,
            "remaining_major_gates": (
                3 if passed and include_250k else 4
            ),
        }
    except Exception as exc:
        result.update(
            {
                "ok": False,
                "status": "postgres_scale_qualification_failed",
                "error_type": exc.__class__.__name__,
            }
        )
    finally:
        cleanup = {
            "restore_database_removed": _drop_disposable_database(
                restore_url
            ),
            "target_database_removed": _drop_disposable_database(
                target_url
            ),
        }
        marker_kind_after, marker_after = _configured_database_marker()
        configured_unchanged = (
            marker_kind == marker_kind_after
            and marker_before == marker_after
        )
        result["configured_database_unchanged"] = configured_unchanged
        result["configured_database_modified"] = not configured_unchanged
        result["cleanup"] = {
            **cleanup,
            "complete": all(cleanup.values()),
        }
        if not configured_unchanged or not result["cleanup"]["complete"]:
            result["ok"] = False
            result["status"] = "postgres_scale_qualification_failed"

    privacy_findings = _privacy_findings(
        result,
        private_path=Path("<synthetic>"),
    )
    result["privacy_findings"] = privacy_findings
    if privacy_findings:
        result["ok"] = False
        result["status"] = "privacy_validation_failed"
    return result
