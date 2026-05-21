import argparse
import json
from typing import Any

import requests


def _check_get(session: requests.Session, url: str, *, headers: dict[str, str] | None = None, timeout: float) -> dict:
    try:
        response = session.get(url, headers=headers, timeout=timeout)
        return {"ok": response.ok, "status_code": response.status_code}
    except requests.RequestException as exc:
        return {"ok": False, "error": exc.__class__.__name__}


def run_demo_health_check(
    *,
    api_base_url: str = "http://127.0.0.1:8000",
    dashboard_url: str = "http://127.0.0.1:8501",
    username: str = "admin",
    password: str = "admin123",
    timeout: float = 5.0,
) -> dict[str, Any]:
    api = api_base_url.rstrip("/")
    session = requests.Session()
    checks: dict[str, dict] = {}

    checks["api_health"] = _check_get(session, f"{api}/health", timeout=timeout)

    token = None
    try:
        response = session.post(
            f"{api}/api/auth/login",
            json={"username": username, "password": password},
            timeout=timeout,
        )
        checks["login"] = {"ok": response.ok, "status_code": response.status_code}
        if response.ok:
            token = response.json().get("access_token")
    except requests.RequestException as exc:
        checks["login"] = {"ok": False, "error": exc.__class__.__name__}

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    checks["dashboard_summary"] = _check_get(session, f"{api}/api/dashboard/summary", headers=headers, timeout=timeout)
    checks["alerts"] = _check_get(session, f"{api}/api/alerts?limit=1", headers=headers, timeout=timeout)
    checks["audit"] = _check_get(session, f"{api}/api/audit?limit=1", headers=headers, timeout=timeout)
    checks["ml_report"] = _check_get(session, f"{api}/api/ml/report", headers=headers, timeout=timeout)
    checks["streamlit"] = _check_get(session, dashboard_url, timeout=timeout)

    ok = all(item.get("ok") for item in checks.values())
    return {"ok": ok, "api_base_url": api, "dashboard_url": dashboard_url, "checks": checks}


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the local ATDR demo stack is ready for presentation.")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--dashboard-url", default="http://127.0.0.1:8501")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    result = run_demo_health_check(
        api_base_url=args.api_base_url,
        dashboard_url=args.dashboard_url,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
