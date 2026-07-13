from __future__ import annotations

import argparse
import json

from atdr.app.services.mfu_iam_validation import build_mfu_iam_validation_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely validate ATDR MFU IAM provider readiness.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Run one explicit MFU IAM probe when MFU_IAM_ENABLED=true.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    # Browser credentials belong to the MFU outer shell. Keeping them out of a
    # command-line argument avoids accidental shell-history disclosure.
    report = build_mfu_iam_validation_report(execute=args.execute)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
