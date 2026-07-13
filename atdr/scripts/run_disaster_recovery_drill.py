import argparse
import json

from atdr.app.core.config import Settings
from atdr.scripts.validate_persistence_profile import validate_persistence_profile


CONFIRMATION = "ISOLATED_V395_DRILL"


def run_disaster_recovery_drill(*, execute: bool = False, confirmed: bool = False) -> dict:
    base = {
        "rpo_assumption_hours": 24,
        "rto_assumption_hours": 4,
        "current_database_modified": False,
        "active_database_restore_allowed": False,
        "response_automation_allowed": False,
        "model_activation_performed": False,
        "secrets_exposed": False,
        "production_ready": False,
    }
    if not execute:
        return {
            **base,
            "ok": True,
            "status": "dry_run",
            "executed": False,
            "required_confirmation": CONFIRMATION,
            "scope": "isolated SQLite migration, backup, checksum, separate-target restore, counts, and revision",
        }
    if not confirmed:
        return {**base, "ok": False, "status": "confirmation_required", "executed": False}
    result = validate_persistence_profile(settings=Settings())
    sqlite = result.get("sqlite_validation", {})
    backup = sqlite.get("backup", {})
    restore = sqlite.get("restore", {})
    ok = bool(
        result.get("ok")
        and result.get("current_database_unchanged")
        and backup.get("ok")
        and restore.get("ok")
        and restore.get("row_counts_match")
        and restore.get("migration_revision_match")
    )
    return {
        **base,
        "ok": ok,
        "status": "isolated_recovery_drill_passed" if ok else "isolated_recovery_drill_failed",
        "executed": True,
        "migration_applied": bool((sqlite.get("migration") or {}).get("ok")),
        "backup_created": bool(backup.get("ok")),
        "checksum_recorded": bool(backup.get("sha256")),
        "restore_validated": bool(restore.get("ok")),
        "integrity_ok": bool(restore.get("integrity_ok")),
        "row_counts_match": bool(restore.get("row_counts_match")),
        "migration_revision_match": bool(restore.get("migration_revision_match")),
        "current_database_unchanged": bool(result.get("current_database_unchanged")),
        "runtime_seconds": result.get("runtime_seconds"),
        "rpo_rto_are_assumptions_not_certified": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an isolated ATDR backup/restore recovery drill. Dry-run is default.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_disaster_recovery_drill(execute=args.execute, confirmed=args.confirm == CONFIRMATION)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
