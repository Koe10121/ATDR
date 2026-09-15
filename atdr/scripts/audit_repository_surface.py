from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.repository_surface_service import build_repository_surface_report


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit tracked Markdown, documented commands, and Python references without changing the repository."
    )
    parser.add_argument("--root", default=str(PROJECT_ROOT))
    parser.add_argument("--include-edges", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    report = build_repository_surface_report(
        Path(args.root).expanduser(),
        include_edges=args.include_edges,
    )
    print(json.dumps(report, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
