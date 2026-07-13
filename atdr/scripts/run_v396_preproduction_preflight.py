import argparse
import json

from atdr.app.core.config import Settings
from atdr.app.services.preproduction_acceptance_service import build_preproduction_acceptance_report


CONFIRMATION = "READ_ONLY_V396_PREPRODUCTION_PREFLIGHT"


def run_preproduction_preflight(
    *,
    settings: Settings | None = None,
    probe_database: bool = False,
    confirmation: str = "",
) -> dict:
    confirmed_probe = probe_database and confirmation == CONFIRMATION
    result = build_preproduction_acceptance_report(
        settings or Settings(),
        probe_database=confirmed_probe,
    )
    if probe_database and not confirmed_probe:
        return {
            **result,
            "ok": False,
            "status": "database_probe_confirmation_required",
            "required_confirmation": CONFIRMATION,
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect ATDR preproduction readiness without exposing secrets or changing state.")
    parser.add_argument("--probe-database", action="store_true", help="Perform a read-only database and Alembic-state probe.")
    parser.add_argument("--confirm", default="", help="Required confirmation for a configured database probe.")
    parser.add_argument("--require-accepted", action="store_true", help="Return non-zero unless every approved-host check passes.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_preproduction_preflight(
        probe_database=args.probe_database,
        confirmation=args.confirm,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    exit_ok = result.get("ok") and (result.get("accepted") or not args.require_accepted)
    raise SystemExit(0 if exit_ok else 1)


if __name__ == "__main__":
    main()
