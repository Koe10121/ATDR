from __future__ import annotations

import argparse
import json
import os
from contextlib import contextmanager
from typing import Iterator

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.v510_detection_operations_service import (
    governed_historical_observation_plan,
    run_historical_shadow_observations,
    shadow_operational_acceptance_summary,
)


@contextmanager
def _explicit_observation_configuration() -> Iterator[None]:
    names = (
        "GOVERNED_SHADOW_SCORING_ENABLED",
        "GOVERNED_SHADOW_OBSERVATION_ENABLED",
        "LOKY_MAX_CPU_COUNT",
    )
    previous = {name: os.environ.get(name) for name in names}
    try:
        os.environ["GOVERNED_SHADOW_SCORING_ENABLED"] = "true"
        os.environ["GOVERNED_SHADOW_OBSERVATION_ENABLED"] = "true"
        os.environ["LOKY_MAX_CPU_COUNT"] = str(
            max(1, os.cpu_count() or 1)
        )
        get_settings.cache_clear()
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        get_settings.cache_clear()


def _print(value: dict, *, pretty: bool) -> None:
    print(json.dumps(value, indent=2 if pretty else None, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or execute bounded v5.10 development-only historical "
            "shadow observations. Output is aggregate-only."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--acceptance-only", action="store_true")
    mode.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--maximum-sources", type=int, default=8)
    parser.add_argument(
        "--maximum-windows-per-source",
        type=int,
        default=3,
    )
    parser.add_argument("--minimum-rows", type=int, default=50)
    parser.add_argument("--batch-limit", type=int)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        if args.execute:
            with _explicit_observation_configuration():
                result = run_historical_shadow_observations(
                    db,
                    actor="v5.10-cli",
                    maximum_sources=args.maximum_sources,
                    maximum_windows_per_source=(
                        args.maximum_windows_per_source
                    ),
                    minimum_rows=args.minimum_rows,
                    batch_limit=args.batch_limit,
                )
        elif args.acceptance_only:
            result = shadow_operational_acceptance_summary(db)
        else:
            result = governed_historical_observation_plan(
                db,
                maximum_sources=args.maximum_sources,
                maximum_windows_per_source=(
                    args.maximum_windows_per_source
                ),
                minimum_rows=args.minimum_rows,
                batch_limit=args.batch_limit,
            )
            result["execution_performed"] = False
            result["preflight_only"] = True
    _print(result, pretty=args.pretty)
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
