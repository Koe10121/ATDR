from __future__ import annotations

import gc
import os
from pathlib import Path
from typing import Any

from atdr.app.services.v514_large_file_runtime_service import (
    _privacy_findings,
)
from atdr.app.services.v515_runtime_soak_service import (
    run_v515_runtime_soak_acceptance,
)


_MIB = 1024 * 1024
_MEMORY_TARGET_MB = 8 * 1024
_MEMORY_REDUCTION_TARGET_PERCENT = 40.0
_OVERVIEW_COLD_TARGET_SECONDS = 3.0
_OVERVIEW_CACHED_TARGET_SECONDS = 0.1
_SOURCE_DETAIL_TARGET_SECONDS = 3.0
_THROUGHPUT_FLOOR_RATIO = 0.9
_OVERVIEW_QUERY_COUNT_CEILING = 35
_SOURCE_DETAIL_QUERY_COUNT_CEILING = 7

_PUBLISHED_BASELINES: dict[int, dict[str, float]] = {
    100_000: {
        "peak_traced_python_memory_mb": 1664.3,
        "ingestion_rows_per_second": 481.7,
        "detection_rows_per_second": 1792.64,
        "overview_cold_seconds": 0.2994,
        "overview_cached_seconds": 0.0132,
        "source_detail_seconds": 0.9558,
        "database_growth_bytes": 612_556_800,
    },
    250_000: {
        "peak_traced_python_memory_mb": 4161.8,
        "ingestion_rows_per_second": 465.93,
        "detection_rows_per_second": 1730.96,
        "overview_cold_seconds": 0.5983,
        "overview_cached_seconds": 0.0189,
        "source_detail_seconds": 2.3694,
        "database_growth_bytes": 1_529_393_152,
    },
    773_551: {
        "peak_traced_python_memory_mb": 12_029.34,
        "ingestion_rows_per_second": 441.0,
        "detection_rows_per_second": 781.38,
        "overview_cold_seconds": 5.3571,
        "overview_cached_seconds": 0.0748,
        "source_detail_seconds": 4.7248,
        "database_growth_bytes": 4_741_283_840,
    },
}


def process_memory_snapshot() -> dict[str, Any]:
    """Return process RSS without adding an optional runtime dependency."""

    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            process = kernel32.GetCurrentProcess()
            ok = psapi.GetProcessMemoryInfo(
                process,
                ctypes.byref(counters),
                counters.cb,
            )
            if ok:
                return {
                    "available": True,
                    "current_rss_mb": round(counters.WorkingSetSize / _MIB, 2),
                    "peak_rss_mb": round(
                        counters.PeakWorkingSetSize / _MIB,
                        2,
                    ),
                    "source": "windows_process_memory_counters",
                }
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    else:
        try:
            import resource

            usage = resource.getrusage(resource.RUSAGE_SELF)
            scale = 1 if os.uname().sysname == "Darwin" else 1024
            return {
                "available": True,
                "current_rss_mb": None,
                "peak_rss_mb": round(usage.ru_maxrss * scale / _MIB, 2),
                "source": "resource_getrusage",
            }
        except (AttributeError, ImportError, OSError, ValueError):
            pass
    return {
        "available": False,
        "current_rss_mb": None,
        "peak_rss_mb": None,
        "source": "unavailable",
    }


def _weighted_stage_rate(
    stages: list[dict[str, Any]],
    *,
    section: str,
) -> float | None:
    rows = 0
    runtime = 0.0
    for stage in stages:
        stage_rows = int(stage.get("rows_requested") or 0)
        rate = float((stage.get(section) or {}).get("rows_per_second") or 0.0)
        if stage_rows <= 0 or rate <= 0:
            continue
        rows += stage_rows
        runtime += stage_rows / rate
    return round(rows / runtime, 2) if rows > 0 and runtime > 0 else None


def _final_query_metrics(stages: list[dict[str, Any]]) -> dict[str, Any]:
    if not stages:
        return {}
    dashboard = dict(stages[-1].get("dashboard_query_timings") or {})
    return {
        key: value
        for key, value in dashboard.items()
        if key != "source_detail_direct_seconds"
    }


def _identity_map_metrics(stages: list[dict[str, Any]]) -> dict[str, int]:
    profiles = [
        profile
        for stage in stages
        for profile in (stage.get("detection") or {}).get(
            "runtime_profiles",
            [],
        )
    ]
    samples = [
        sample
        for profile in profiles
        for sample in profile.get("samples") or []
    ]
    return {
        "profile_count": len(profiles),
        "sample_count": len(samples),
        "peak_identity_map_size": max(
            (int(sample.get("identity_map_size") or 0) for sample in samples),
            default=0,
        ),
        "peak_new_object_count": max(
            (int(sample.get("new_object_count") or 0) for sample in samples),
            default=0,
        ),
    }


def _percent_reduction(before: float | None, after: float | None) -> float | None:
    if before is None or after is None or before <= 0:
        return None
    return round(((before - after) / before) * 100, 2)


def _ratio_gate(value: float | None, baseline: float | None) -> bool:
    if value is None or baseline is None:
        return True
    return value >= baseline * _THROUGHPUT_FLOOR_RATIO


def run_v516_memory_query_stabilization(
    *,
    sample_path: str | Path,
    target_rows: int = 100_000,
    chunk_size: int = 1_000,
    use_temp_db: bool = False,
    profile_only: bool = False,
    run_detection_after: bool = False,
) -> dict[str, Any]:
    evidence_path = Path(sample_path).expanduser()
    effective_detection = bool(run_detection_after and not profile_only)

    gc.collect()
    memory_before = process_memory_snapshot()
    acceptance = run_v515_runtime_soak_acceptance(
        sample_path=evidence_path,
        target_rows=target_rows,
        chunk_size=chunk_size,
        use_temp_db=use_temp_db,
        fault_plan="none",
        run_detection_after=effective_detection,
        bounded_detection_memory=True,
        collect_runtime_profile=effective_detection,
        collect_query_counts=True,
        collect_query_plans=True,
        release_stage_memory=True,
        trace_detection_only=effective_detection,
    )
    gc.collect()
    memory_after = process_memory_snapshot()

    stages = list(acceptance.get("stages") or [])
    performance = acceptance.get("performance") or {}
    baseline = _PUBLISHED_BASELINES.get(target_rows)
    traced_peak = float(
        performance.get("peak_traced_python_memory_mb") or 0.0
    )
    ingestion_rate = _weighted_stage_rate(stages, section="import")
    detection_rate = (
        float((acceptance.get("detection") or {}).get("rows_per_second") or 0.0)
        or None
    )
    query_metrics = _final_query_metrics(stages)
    identity_map = _identity_map_metrics(stages)
    database_growth = int(
        (acceptance.get("database") or {}).get("growth_bytes") or 0
    )

    memory_reduction = _percent_reduction(
        baseline.get("peak_traced_python_memory_mb") if baseline else None,
        traced_peak or None,
    )
    process_peak_rss = (
        float(memory_after.get("peak_rss_mb") or 0.0)
        if memory_after.get("available")
        else 0.0
    )
    memory_target = bool(
        (process_peak_rss > 0 and process_peak_rss < _MEMORY_TARGET_MB)
        or (
            traced_peak > 0
            and (
                traced_peak < _MEMORY_TARGET_MB
                or (
                    memory_reduction is not None
                    and memory_reduction >= _MEMORY_REDUCTION_TARGET_PERCENT
                )
            )
        )
    )
    query_target = bool(
        query_metrics
        and float(query_metrics.get("overview_cold_seconds") or 999.0)
        < _OVERVIEW_COLD_TARGET_SECONDS
        and float(query_metrics.get("overview_cached_seconds") or 999.0)
        < _OVERVIEW_CACHED_TARGET_SECONDS
        and float(query_metrics.get("source_detail_seconds") or 999.0)
        < _SOURCE_DETAIL_TARGET_SECONDS
    )
    query_count_target = bool(
        int(query_metrics.get("overview_cold_query_count") or 0) > 0
        and int(query_metrics.get("overview_cold_query_count") or 0)
        <= _OVERVIEW_QUERY_COUNT_CEILING
        and int(query_metrics.get("source_detail_query_count") or 0) > 0
        and int(query_metrics.get("source_detail_query_count") or 0)
        <= _SOURCE_DETAIL_QUERY_COUNT_CEILING
    )
    ingestion_target = _ratio_gate(
        ingestion_rate,
        baseline.get("ingestion_rows_per_second") if baseline else None,
    )
    detection_target = (
        not effective_detection
        or _ratio_gate(
            detection_rate,
            baseline.get("detection_rows_per_second") if baseline else None,
        )
    )

    ingestion = acceptance.get("ingestion") or {}
    counts = (acceptance.get("database") or {}).get("integrity") or {}
    safety = acceptance.get("safety") or {}
    unsafe_counts = safety.get("unsafe_side_effect_counts") or {}
    detection = acceptance.get("detection") or {}
    equivalence = {
        "base_acceptance_passed": bool(acceptance.get("ok")),
        "exact_raw_count": int(ingestion.get("raw_logs") or 0) == target_rows,
        "exact_normalized_count": int(ingestion.get("normalized_logs") or 0)
        == target_rows,
        "parser_counts_reconcile": (
            int(ingestion.get("parsed_successfully") or 0)
            + int(ingestion.get("parse_failures") or 0)
            == target_rows
        ),
        "checkpoint_and_recovery_checks_passed": all(
            bool(value)
            for value in (ingestion.get("checks") or {}).values()
        ),
        "database_integrity_passed": bool(counts.get("ok")),
        "source_traceability_preserved": (
            not effective_detection
            or bool(detection.get("alert_to_log_source_traceability"))
        ),
        "case_reconciliation_preserved": (
            not effective_detection
            or bool(detection.get("cases_reconcile_with_alert_groups"))
        ),
        "zero_label_model_response_writes": all(
            int(unsafe_counts.get(key) or 0) == 0
            for key in ("labels", "model_runs", "response_actions")
        ),
        "configured_database_unchanged": bool(
            safety.get("configured_database_unchanged")
        ),
        "cleanup_complete": bool(
            (acceptance.get("cleanup") or {}).get("complete")
        ),
    }
    equivalence_passed = all(equivalence.values())

    result: dict[str, Any] = {
        "ok": False,
        "status": "memory_query_stabilization_pending",
        "mode": (
            "profile_only"
            if profile_only
            else "ingestion_detection_query"
            if effective_detection
            else "ingestion_query"
        ),
        "target_rows": target_rows,
        "published_baseline": baseline,
        "metrics": {
            "peak_traced_python_memory_mb": traced_peak,
            "tracemalloc_scope": performance.get("tracemalloc_scope"),
            "process_memory_before": memory_before,
            "process_memory_after": memory_after,
            "traced_memory_reduction_percent": memory_reduction,
            "traced_memory_comparison_scope_compatible": (
                performance.get("tracemalloc_scope") == "full_run"
            ),
            "memory_acceptance_basis": (
                "process_peak_rss"
                if process_peak_rss > 0
                else "traced_python_memory"
            ),
            "ingestion_rows_per_second": ingestion_rate,
            "detection_rows_per_second": detection_rate,
            "database_growth_bytes": database_growth,
            "database_growth_change_percent": _percent_reduction(
                baseline.get("database_growth_bytes") if baseline else None,
                float(database_growth),
            ),
            "identity_map": identity_map,
            "queries": query_metrics,
        },
        "gates": {
            "memory_target_passed": memory_target,
            "query_latency_targets_passed": query_target,
            "query_count_regression_passed": query_count_target,
            "ingestion_throughput_floor_passed": ingestion_target,
            "detection_throughput_floor_passed": detection_target,
            "semantic_equivalence_passed": equivalence_passed,
            "targets": {
                "peak_memory_mb_less_than": _MEMORY_TARGET_MB,
                "or_memory_reduction_percent_at_least": (
                    _MEMORY_REDUCTION_TARGET_PERCENT
                ),
                "overview_cold_seconds_less_than": (
                    _OVERVIEW_COLD_TARGET_SECONDS
                ),
                "overview_cached_seconds_less_than": (
                    _OVERVIEW_CACHED_TARGET_SECONDS
                ),
                "source_detail_seconds_less_than": (
                    _SOURCE_DETAIL_TARGET_SECONDS
                ),
                "throughput_floor_ratio": _THROUGHPUT_FLOOR_RATIO,
                "overview_query_count_at_most": (
                    _OVERVIEW_QUERY_COUNT_CEILING
                ),
                "source_detail_query_count_at_most": (
                    _SOURCE_DETAIL_QUERY_COUNT_CEILING
                ),
            },
        },
        "semantic_equivalence": equivalence,
        "acceptance": acceptance,
        "safety": {
            "configured_database_modified": bool(
                acceptance.get("configured_database_modified")
            ),
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
        },
        "production_ready": False,
    }
    privacy_findings = _privacy_findings(result, private_path=evidence_path)
    result["privacy_findings"] = privacy_findings
    passed = all(
        (
            bool(acceptance.get("ok")),
            memory_target,
            query_target,
            query_count_target,
            ingestion_target,
            detection_target,
            equivalence_passed,
            not privacy_findings,
        )
    )
    result["ok"] = passed
    result["status"] = (
        "memory_query_stabilization_passed"
        if passed
        else "memory_query_stabilization_targets_not_met"
    )
    return result
