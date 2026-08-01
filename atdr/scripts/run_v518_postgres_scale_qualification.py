from __future__ import annotations

import argparse
import json

from atdr.app.services.v518_postgres_scale_service import (
    run_v518_postgres_scale_qualification,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run fail-closed 100k-before-250k PostgreSQL scale, "
            "multi-worker, recovery, query, and backup qualification."
        )
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--confirm",
        default="",
        help="Required exact disposable-database confirmation phrase.",
    )
    parser.add_argument(
        "--stop-after-100k",
        action="store_true",
        help="Qualify the 100k two/four-worker profiles only.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v518_postgres_scale_qualification(
        execute=args.execute,
        confirmation=args.confirm,
        include_250k=not args.stop_after_100k,
    )
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=str,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
