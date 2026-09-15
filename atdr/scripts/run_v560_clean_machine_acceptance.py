from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.v560_clean_machine_acceptance_service import (
    EXECUTION_CONFIRMATION,
    build_clean_machine_preflight,
    execute_clean_machine_acceptance,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate ATDR from a genuine disposable origin/main clone without copying private state."
    )
    parser.add_argument("--shell-package", required=True, help="Approved versioned MFU shell companion archive.")
    parser.add_argument("--execute", action="store_true", help="Run the disposable clean-machine acceptance.")
    parser.add_argument("--confirm", default="", help="Exact execution confirmation shown by preflight.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    shell_package = Path(args.shell_package).expanduser().resolve()
    if args.execute and args.confirm != EXECUTION_CONFIRMATION:
        report = {
            "ok": False,
            "status": "execution_confirmation_required",
            "executed": False,
            "required_confirmation": EXECUTION_CONFIRMATION,
            "private_paths_exposed": False,
            "secrets_exposed": False,
        }
    elif args.execute:
        report = execute_clean_machine_acceptance(root=PROJECT_ROOT, shell_package=shell_package)
    else:
        report = build_clean_machine_preflight(root=PROJECT_ROOT, shell_package=shell_package)
        report["required_execution_confirmation"] = EXECUTION_CONFIRMATION

    print(json.dumps(report, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
