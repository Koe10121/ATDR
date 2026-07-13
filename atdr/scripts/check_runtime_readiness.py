import json

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.observability_service import build_readiness


def check_runtime_readiness() -> dict:
    settings = get_settings()
    with SessionLocal() as db:
        payload, ready = build_readiness(db, settings)
    checks = payload.get("checks", {})
    return {
        "ok": ready,
        "status": payload.get("status"),
        "database_status": (checks.get("database") or {}).get("status"),
        "database_dialect": (checks.get("database") or {}).get("dialect"),
        "migration_status": (checks.get("migration") or {}).get("status"),
        "configuration_status": (checks.get("configuration") or {}).get("status"),
        "configuration_issue_count": (checks.get("configuration") or {}).get("issue_count", 0),
        "response_simulation": settings.response_simulation,
        "secrets_exposed": False,
        "production_ready": False,
    }


def main() -> None:
    result = check_runtime_readiness()
    print(json.dumps(result, default=str))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
