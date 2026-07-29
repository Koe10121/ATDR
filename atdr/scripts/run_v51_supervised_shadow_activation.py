from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v51_supervised_lifecycle import (
    DEFAULT_OUTPUT_DIR,
    activate_governed_supervised_model,
    supervised_lifecycle_status,
    train_and_register_v51_candidate,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Train and register the governed v5.1 binary SOC queue model, then "
            "activate it only in the requested safe lifecycle mode."
        )
    )
    parser.add_argument("--actor", default="v5.1-cli")
    parser.add_argument(
        "--activation-mode",
        choices=["inactive", "shadow_observation", "decision_support"],
        default="shadow_observation",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-reports", action="store_true")
    parser.add_argument("--full-output", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        training = train_and_register_v51_candidate(
            db,
            actor=args.actor,
            output_dir=args.output_dir,
            write_reports=not args.no_reports,
        )
        activation: dict[str, object] = {
            "ok": False,
            "status": "not_requested" if args.activation_mode == "inactive" else "training_failed",
        }
        if training.get("ok") and args.activation_mode != "inactive":
            activation = activate_governed_supervised_model(
                db,
                model_id=int(training["model_id"]),
                lifecycle_state=args.activation_mode,
                actor=args.actor,
            )
        result = {
            "ok": bool(training.get("ok")) and (
                args.activation_mode == "inactive" or bool(activation.get("ok"))
            ),
            "training": training,
            "activation": activation,
            "lifecycle": supervised_lifecycle_status(db),
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    output = result
    if not args.full_output:
        training_result = result.get("training") or {}
        output = {
            "ok": result["ok"],
            "training": {
                "status": training_result.get("status"),
                "message": training_result.get("message"),
                "model_id": training_result.get("model_id"),
                "model_version": training_result.get("model_version"),
                "model_type": training_result.get("model_type"),
                "target_mode": training_result.get("target_mode"),
                "dataset_rows": (training_result.get("dataset") or {}).get("rows"),
                "dataset_fingerprint": (training_result.get("dataset") or {}).get("fingerprint"),
                "strict_gates": training_result.get("strict_gates"),
                "runtime_checks": training_result.get("runtime_checks"),
                "shadow_safety_passed": training_result.get("shadow_safety_passed"),
                "reports": training_result.get("reports"),
            },
            "activation": activation,
            "lifecycle": result["lifecycle"],
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    print(json.dumps(output, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
