from __future__ import annotations

import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.runtime_contract import current_detection_runtime_status


def _safe_runtime(status: dict) -> bool:
    return bool(
        status.get("rules", {}).get("state") == "active_authoritative"
        and status.get("anomaly", {}).get("state")
        in {"active_advisory", "unavailable", "abstained"}
        and status.get("supervised", {}).get("state")
        in {"active_shadow", "unqualified", "unavailable", "abstained"}
        and status.get("response", {}).get("state") == "simulation_only"
        and not status.get("production_promoted")
        and not status.get("response_automation_allowed")
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect the effective v5.58 detection-layer runtime without "
            "scoring logs or changing model, alert, label, or response state."
        )
    )
    parser.add_argument("--require-safe", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = current_detection_runtime_status(db)
    result["status"] = (
        "governed_hybrid_runtime_safe"
        if _safe_runtime(result)
        else "governed_hybrid_runtime_unsafe"
    )
    result["inspection_only"] = True
    result["database_writes"] = 0
    result["model_activated"] = False
    result["alerts_created"] = 0
    result["response_actions_created"] = 0
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))

    accepted = bool(result.get("ok"))
    if args.require_safe:
        accepted = accepted and _safe_runtime(result)
    raise SystemExit(0 if accepted else 1)


if __name__ == "__main__":
    main()
