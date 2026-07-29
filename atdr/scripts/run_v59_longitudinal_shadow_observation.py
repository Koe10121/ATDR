from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.v59_shadow_observation_service import (
    inspect_private_longitudinal_drift,
    list_shadow_observations,
    preview_shadow_observation_retention,
    prune_shadow_observations,
    record_governed_shadow_observation,
    shadow_observation_summary,
)


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _print_result(result: dict | list, *, pretty: bool) -> None:
    print(
        json.dumps(
            result,
            indent=2 if pretty else None,
            default=str,
        )
    )


def _private_mode(args: argparse.Namespace) -> dict:
    if (
        not args.sample_path
        or not args.preflight_only
        or not args.use_temp_db
    ):
        return {
            "ok": False,
            "status": "failed_closed_private_arguments_incomplete",
            "required": [
                "--sample-path",
                "--preflight-only",
                "--use-temp-db",
            ],
            "configured_database_accessed": False,
            "private_path_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    with TemporaryDirectory(prefix="atdr-v59-private-"):
        result = inspect_private_longitudinal_drift(
            Path(args.sample_path).expanduser(),
            max_lines=args.limit,
        )
    result["storage_mode"] = "disposable_streaming_workspace"
    result["disposable_workspace_removed"] = True
    result["private_path_returned"] = False
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Record or inspect bounded aggregate v5.9 shadow observations. "
            "Private evidence is aggregate-only and never enters the "
            "configured database."
        )
    )
    parser.add_argument("--execute-shadow", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--source-id", type=int)
    parser.add_argument("--start-at")
    parser.add_argument("--end-at")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--since")
    parser.add_argument("--drift-status")
    parser.add_argument("--retention-preview", action="store_true")
    parser.add_argument("--apply-retention", action="store_true")
    parser.add_argument("--retention-days", type=int)
    parser.add_argument("--sample-path")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    private_requested = bool(
        args.sample_path or args.preflight_only or args.use_temp_db
    )
    configured_modes = sum(
        bool(value)
        for value in (
            args.execute_shadow,
            args.list,
            args.retention_preview,
            args.apply_retention,
        )
    )
    if private_requested:
        if configured_modes:
            result = {
                "ok": False,
                "status": "failed_closed_conflicting_modes",
                "configured_database_accessed": False,
                "private_path_returned": False,
                "raw_logs_returned": False,
                "secrets_exposed": False,
            }
        else:
            result = _private_mode(args)
        _print_result(result, pretty=args.pretty)
        raise SystemExit(0 if result.get("ok") else 1)
    if configured_modes > 1:
        result = {
            "ok": False,
            "status": "failed_closed_multiple_actions_requested",
        }
        _print_result(result, pretty=args.pretty)
        raise SystemExit(2)

    try:
        start_at = _date(args.start_at)
        end_at = _date(args.end_at)
        since = _date(args.since)
    except ValueError:
        result = {
            "ok": False,
            "status": "failed_closed_invalid_datetime",
        }
        _print_result(result, pretty=args.pretty)
        raise SystemExit(2)

    init_db()
    with SessionLocal() as db:
        if args.execute_shadow:
            result = record_governed_shadow_observation(
                db,
                actor="v5.9-cli",
                source_id=args.source_id,
                start_at=start_at,
                end_at=end_at,
                limit=args.limit,
            )
        elif args.list:
            result = {
                "ok": True,
                "status": "shadow_observations_listed",
                "observations": list_shadow_observations(
                    db,
                    source_id=args.source_id,
                    since=since,
                    drift_status=args.drift_status,
                    limit=args.limit or 30,
                ),
                "raw_logs_included": False,
                "private_paths_included": False,
                "fingerprints_included": False,
                "secrets_exposed": False,
            }
        elif args.retention_preview:
            result = preview_shadow_observation_retention(
                db,
                older_than_days=args.retention_days,
            )
        elif args.apply_retention:
            result = prune_shadow_observations(
                db,
                actor="v5.9-cli",
                older_than_days=args.retention_days,
                limit=args.limit or 1000,
            )
        else:
            result = shadow_observation_summary(
                db,
                source_id=args.source_id,
                since=since,
                limit=args.limit,
            )
    _print_result(result, pretty=args.pretty)
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
