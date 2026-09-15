from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.repository_cleanup_service import (
    CONFIRMATION,
    cleanup_disposable_caches,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Preview or remove only allowlisted disposable repository caches."
    )
    parser.add_argument("--root", default=str(PROJECT_ROOT))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    try:
        report = cleanup_disposable_caches(
            Path(args.root).expanduser(),
            apply=args.apply,
            confirmation=args.confirm,
        )
    except ValueError as exc:
        report = {
            "ok": False,
            "status": "confirmation_required",
            "required_confirmation": CONFIRMATION,
            "error_type": type(exc).__name__,
        }

    print(json.dumps(report, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
