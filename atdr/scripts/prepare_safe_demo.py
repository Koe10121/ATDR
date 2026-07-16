from __future__ import annotations

import argparse
import json
from typing import Any

from atdr.scripts.run_source_scenario import _json_default, run_source_scenario


CONFIRMATION = "SAFE_SYNTHETIC_DEMO"
SOURCE_NAME = "atdr-safe-demo-firewall"


def prepare_safe_demo(
    *,
    execute: bool = False,
    confirmation: str | None = None,
    use_temp_db: bool = False,
) -> dict[str, Any]:
    if not execute:
        result = run_source_scenario(
            scenario="port_scan_like_traffic",
            source_name=SOURCE_NAME,
            source_type="firewall",
            parser_profile="palo_alto",
            dry_run=True,
            run_detection_after=False,
            idempotent=True,
        )
        result.update(
            {
                "status": "dry_run",
                "prepared": False,
                "execute_command": (
                    ".\\.venv\\Scripts\\python.exe -m atdr.scripts.prepare_safe_demo "
                    f"--execute --confirm {CONFIRMATION} --pretty"
                ),
                "safety": {
                    "synthetic_sample_only": True,
                    "database_reset": False,
                    "automatic_response": False,
                    "real_firewall_blocking": False,
                },
            }
        )
        return result

    if confirmation != CONFIRMATION:
        return {
            "ok": False,
            "status": "confirmation_required",
            "prepared": False,
            "message": f"Execution requires --confirm {CONFIRMATION}.",
        }

    result = run_source_scenario(
        scenario="port_scan_like_traffic",
        source_name=SOURCE_NAME,
        source_type="firewall",
        parser_profile="palo_alto",
        run_detection_after=True,
        use_temp_db=use_temp_db,
        idempotent=True,
    )
    result["safety"] = {
        "synthetic_sample_only": True,
        "database_reset": False,
        "automatic_response": False,
        "real_firewall_blocking": False,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare one explicit, idempotent synthetic ATDR demonstration scenario.")
    parser.add_argument("--execute", action="store_true", help="Write the synthetic scenario to the configured database.")
    parser.add_argument("--confirm", default=None, help=f"Required execution confirmation: {CONFIRMATION}")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = prepare_safe_demo(execute=args.execute, confirmation=args.confirm)
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
