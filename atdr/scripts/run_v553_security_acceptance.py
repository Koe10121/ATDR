from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.services.repository_security_service import (
    build_cyclonedx_sbom,
    build_security_acceptance_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run tracked-secret and security-control checks without exposing matched values."
    )
    parser.add_argument("--root", default=str(PROJECT_ROOT))
    parser.add_argument("--write-sbom", default="")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    report = build_security_acceptance_report(root)
    if args.write_sbom:
        sbom = build_cyclonedx_sbom(root)
        output = Path(args.write_sbom).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(sbom, indent=2) + "\n",
            encoding="utf-8",
        )
        report["sbom_written"] = True
        report["sbom_component_count"] = len(sbom["components"])
        report["filesystem_writes_performed"] = True
    else:
        report["sbom_written"] = False
    print(json.dumps(report, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
