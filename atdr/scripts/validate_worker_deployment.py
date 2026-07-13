from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT, Settings, validate_runtime_settings
from atdr.app.db.engine import database_kind


REQUIRED_FILES = {
    "api_service": PROJECT_ROOT / "deploy" / "systemd" / "atdr-api.service.example",
    "worker_service": PROJECT_ROOT / "deploy" / "systemd" / "atdr-worker@.service.example",
    "environment": PROJECT_ROOT / "deploy" / "systemd" / "atdr.env.example",
}

REQUIRED_WORKER_MARKERS = {
    "--watch",
    "KillSignal=SIGTERM",
    "Restart=on-failure",
    "TimeoutStopSec=150s",
    "OPERATION_WORKER_ENABLED=true",
}


def validate_worker_deployment(
    *,
    settings: Settings | None = None,
    require_shared: bool = False,
) -> dict:
    effective = settings or Settings()
    files = {name: path.exists() and path.is_file() for name, path in REQUIRED_FILES.items()}
    worker_text = REQUIRED_FILES["worker_service"].read_text(encoding="utf-8") if files["worker_service"] else ""
    missing_markers = sorted(marker for marker in REQUIRED_WORKER_MARKERS if marker not in worker_text)
    runtime_issues = validate_runtime_settings(effective)
    dialect = database_kind(effective.database_url)
    shared_ready = (
        dialect == "postgresql"
        and effective.operation_staging_shared
        and Path(effective.operation_staging_root).expanduser().is_absolute()
        and effective.operation_staging_storage_id.strip().lower() != "local"
        and effective.operation_worker_concurrency > 1
    )
    ok = all(files.values()) and not missing_markers and not runtime_issues and (shared_ready or not require_shared)
    return {
        "ok": ok,
        "status": "shared_worker_ready" if ok and shared_ready else "local_profile_valid" if ok else "configuration_incomplete",
        "database_dialect": dialect,
        "normal_sqlite_workflow_preserved": dialect == "sqlite",
        "shared_multiworker_ready": shared_ready,
        "managed_files": files,
        "missing_worker_markers": missing_markers,
        "runtime_issue_count": len(runtime_issues),
        "runtime_issues": runtime_issues,
        "response_simulation": effective.response_simulation,
        "assistant_raw_log_context": effective.assistant_allow_raw_log_context,
        "secrets_exposed": False,
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate safe ATDR managed-worker deployment configuration.")
    parser.add_argument("--require-shared", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = validate_worker_deployment(require_shared=args.require_shared)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
