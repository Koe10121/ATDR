from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import math
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ReadOnlyEndpoint:
    name: str
    path: str
    budget_seconds: float
    authenticated: bool = True


READ_ONLY_ENDPOINTS = (
    ReadOnlyEndpoint("liveness", "/health/live", 0.5, authenticated=False),
    ReadOnlyEndpoint("readiness", "/health/ready", 0.75, authenticated=False),
    ReadOnlyEndpoint("overview", "/api/dashboard/summary", 2.0),
    ReadOnlyEndpoint("alerts", "/api/alerts?limit=20", 1.0),
    ReadOnlyEndpoint("cases", "/api/alerts/cases?limit=20", 1.0),
    ReadOnlyEndpoint("sources", "/api/sources", 1.0),
    ReadOnlyEndpoint("operations", "/api/jobs/summary", 1.0),
    ReadOnlyEndpoint("assistant_status", "/api/assistant/status", 1.0),
)

RequestFunction = Callable[[str, dict[str, str], float], tuple[int, float]]


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[rank], 4)


def _http_get(url: str, headers: dict[str, str], timeout_seconds: float) -> tuple[int, float]:
    started = time.perf_counter()
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - URL is operator-validated below.
            response.read()
            status = int(response.status)
    except HTTPError as exc:
        status = int(exc.code)
    except (OSError, URLError, TimeoutError):
        status = 0
    return status, time.perf_counter() - started


def is_local_target(base_url: str) -> bool:
    parsed = urlparse(base_url)
    return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() in {
        "127.0.0.1",
        "localhost",
        "::1",
    }


def run_read_only_load_test(
    *,
    base_url: str,
    bearer_token: str,
    requests_per_endpoint: int = 5,
    concurrency: int = 4,
    timeout_seconds: float = 15.0,
    execute: bool = False,
    allow_remote: bool = False,
    remote_confirmed: bool = False,
    request_function: RequestFunction | None = None,
) -> dict:
    if not 1 <= requests_per_endpoint <= 1000:
        raise ValueError("requests_per_endpoint must be between 1 and 1000")
    if not 1 <= concurrency <= 50:
        raise ValueError("concurrency must be between 1 and 50")
    if not 0.1 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be between 0.1 and 120")
    local_target = is_local_target(base_url)
    base = {
        "mode": "read_only",
        "endpoint_count": len(READ_ONLY_ENDPOINTS),
        "requests_per_endpoint": requests_per_endpoint,
        "concurrency": concurrency,
        "local_target": local_target,
        "write_requests_allowed": False,
        "raw_logs_included": False,
        "response_bodies_reported": False,
        "secrets_exposed": False,
        "production_ready": False,
    }
    if not execute:
        return {
            **base,
            "ok": True,
            "status": "dry_run",
            "executed": False,
            "endpoints": [endpoint.name for endpoint in READ_ONLY_ENDPOINTS],
        }
    if not local_target and (not allow_remote or not remote_confirmed):
        return {**base, "ok": False, "status": "remote_confirmation_required", "executed": False}
    if not bearer_token.strip():
        return {**base, "ok": False, "status": "bearer_token_environment_missing", "executed": False}

    requester = request_function or _http_get
    headers = {"Authorization": f"Bearer {bearer_token.strip()}", "Accept": "application/json"}
    work = [(endpoint, urljoin(base_url.rstrip("/") + "/", endpoint.path.lstrip("/"))) for endpoint in READ_ONLY_ENDPOINTS]
    started = time.perf_counter()
    samples: dict[str, list[tuple[int, float]]] = {endpoint.name: [] for endpoint in READ_ONLY_ENDPOINTS}
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(requester, url, headers if endpoint.authenticated else {"Accept": "application/json"}, timeout_seconds): endpoint
            for endpoint, url in work
            for _ in range(requests_per_endpoint)
        }
        for future in as_completed(futures):
            endpoint = futures[future]
            try:
                status, duration = future.result()
            except Exception:
                status, duration = 0, 0.0
            samples[endpoint.name].append((status, max(0.0, float(duration))))

    elapsed = max(time.perf_counter() - started, 0.000001)
    results: list[dict] = []
    warnings: list[str] = []
    total_success = 0
    total_requests = 0
    for endpoint in READ_ONLY_ENDPOINTS:
        rows = samples[endpoint.name]
        durations = [duration for _, duration in rows]
        success = sum(1 for status, _ in rows if 200 <= status < 400)
        total_success += success
        total_requests += len(rows)
        p95 = _percentile(durations, 0.95)
        if p95 is not None and p95 > endpoint.budget_seconds:
            warnings.append(f"{endpoint.name} p95 exceeded {endpoint.budget_seconds:.2f}s budget")
        status_counts: dict[str, int] = {}
        for status, _ in rows:
            key = str(status) if status else "transport_error"
            status_counts[key] = status_counts.get(key, 0) + 1
        results.append(
            {
                "endpoint": endpoint.name,
                "requests": len(rows),
                "successes": success,
                "error_rate": round(1 - (success / len(rows)), 4) if rows else 1.0,
                "p50_seconds": _percentile(durations, 0.50),
                "p95_seconds": p95,
                "p99_seconds": _percentile(durations, 0.99),
                "max_seconds": round(max(durations), 4) if durations else None,
                "budget_seconds": endpoint.budget_seconds,
                "status_counts": status_counts,
            }
        )
    error_rate = 1 - (total_success / total_requests) if total_requests else 1.0
    return {
        **base,
        "ok": error_rate == 0,
        "status": "completed" if error_rate == 0 else "completed_with_errors",
        "executed": True,
        "total_requests": total_requests,
        "successes": total_success,
        "error_rate": round(error_rate, 4),
        "throughput_requests_per_second": round(total_requests / elapsed, 3),
        "runtime_seconds": round(elapsed, 4),
        "performance_budget_warnings": warnings,
        "results": results,
    }
