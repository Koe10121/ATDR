from __future__ import annotations

import argparse
import json

from atdr.app.core.config import get_settings
from atdr.app.services.evidence_review_service import EvidenceReviewError
from atdr.app.services.v539_independent_evidence_decision_service import (
    get_v539_evaluation_status,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Deprecated v5.36 preflight alias. Frozen evidence evaluation is "
            "governed exclusively by run_v539_independent_evidence_decision."
        )
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    try:
        report = get_v539_evaluation_status(settings=get_settings())
    except EvidenceReviewError as exc:
        report = {
            "ok": False,
            "status": exc.code,
            "message": exc.public_message,
            "secrets_exposed": False,
            "private_paths_exposed": False,
            "reviewer_identities_exposed": False,
        }
    report["legacy_command"] = True
    if report.get("ok"):
        report["message"] = (
            "v5.36 direct evaluation is retired. Use "
            "python -m atdr.scripts.run_v539_independent_evidence_decision "
            "--preflight-only for readiness; execute the frozen decision only "
            "through the confirmed v5.39 command."
        )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))
    raise SystemExit(0 if report.get("ok") else 1)


if __name__ == "__main__":
    main()
