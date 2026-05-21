import argparse
import json
import shutil
import subprocess
from typing import Any

from atdr.scripts.demo_health_check import run_demo_health_check


def _docker_status() -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        return {
            "ok": False,
            "available": False,
            "message": "Docker CLI is not installed or not on PATH. Run Compose validation on a Docker-capable host.",
        }
    try:
        version = subprocess.run(
            [docker, "compose", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "available": True, "message": exc.__class__.__name__}
    return {
        "ok": version.returncode == 0,
        "available": True,
        "message": (version.stdout or version.stderr).strip(),
    }


def run_lab_smoke_check(
    *,
    api_base_url: str = "http://127.0.0.1:8000",
    dashboard_url: str = "http://127.0.0.1:8501",
    username: str = "admin",
    password: str = "admin123",
    timeout: float = 5.0,
    include_docker: bool = True,
) -> dict[str, Any]:
    demo = run_demo_health_check(
        api_base_url=api_base_url,
        dashboard_url=dashboard_url,
        username=username,
        password=password,
        timeout=timeout,
    )
    checks = dict(demo["checks"])
    if include_docker:
        checks["docker_compose"] = _docker_status()
    ok = all(item.get("ok") for name, item in checks.items() if name != "docker_compose")
    docker_check = checks.get("docker_compose")
    return {
        "ok": ok and (not include_docker or bool(docker_check and docker_check.get("ok"))),
        "local_stack_ok": ok,
        "docker_validated": bool(docker_check and docker_check.get("ok")),
        "api_base_url": demo["api_base_url"],
        "dashboard_url": demo["dashboard_url"],
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run lab-pilot smoke checks for the ATDR stack.")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--dashboard-url", default="http://127.0.0.1:8501")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--skip-docker", action="store_true", help="Skip Docker CLI availability check.")
    args = parser.parse_args()

    result = run_lab_smoke_check(
        api_base_url=args.api_base_url,
        dashboard_url=args.dashboard_url,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        include_docker=not args.skip_docker,
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["local_stack_ok"] else 1)


if __name__ == "__main__":
    main()
