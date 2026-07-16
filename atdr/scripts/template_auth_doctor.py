from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.template_shell_auth import build_template_google_auth_status


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check MFU shell Google authentication configuration without exposing client values or secrets."
    )
    parser.add_argument("--template-root", required=True, help="Path to the approved MFU supervisor shell.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    report = build_template_google_auth_status(Path(args.template_root))
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if report["ready"] else 1)


if __name__ == "__main__":
    main()
