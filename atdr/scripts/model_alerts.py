"""Switch the MFU behaviour model's experimental alerts on or off, and raise them.

Usage:
    python -m atdr.scripts.model_alerts status
    python -m atdr.scripts.model_alerts enable --types all --actor NAME --reason "why"
    python -m atdr.scripts.model_alerts disable --actor NAME --reason "why"
    python -m atdr.scripts.model_alerts run --actor NAME      # raise alerts now for every stored window

The switch is recorded on the model card (who, when, why, and which types passed the quality bar:
so far none) and in the audit log. After switching, restart ATDR so the dashboard reads the card.
Detection runs raise model alerts on their own afterwards; see atdr/app/services/model_alert_service.py.
"""

from __future__ import annotations

import argparse
import json
import sys

from atdr.app.db.database import SessionLocal
from atdr.app.db.models import AuditLog
from atdr.app.ml.attack_simulation import ATTACK_TYPES
from atdr.app.ml.behavior_model import MODEL_PATH, BehaviorModel
from atdr.app.services.model_alert_service import create_model_alerts, experimental_alerting, set_experimental_alerting


def _save(model: BehaviorModel) -> None:
    model.save(MODEL_PATH)
    MODEL_PATH.with_suffix(".card.json").write_text(json.dumps(model.card, indent=2, default=str), encoding="utf-8")


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="The MFU behaviour model's experimental alerts.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    enable = commands.add_parser("enable")
    enable.add_argument("--types", required=True, help=f"'all' or a comma-separated list of {', '.join(ATTACK_TYPES)}")
    for sub in (enable, commands.add_parser("disable")):
        sub.add_argument("--actor", required=True)
        sub.add_argument("--reason", required=True)
    run = commands.add_parser("run")
    run.add_argument("--actor", default="model_alerts")
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        raise SystemExit(f"No behaviour model at {MODEL_PATH}.")
    model = BehaviorModel.load(MODEL_PATH)
    if args.command == "status":
        print(json.dumps(experimental_alerting(model) or {"types": [], "note": "model alerts are off"}, indent=2))
        return
    if args.command == "run":
        with SessionLocal() as db:
            print(json.dumps(create_model_alerts(db, model=model, actor=args.actor), indent=2))
        return

    types = list(ATTACK_TYPES) if args.command == "enable" and args.types.strip() == "all" else (
        [item.strip() for item in args.types.split(",") if item.strip()] if args.command == "enable" else [])
    unknown = sorted(set(types) - set(ATTACK_TYPES))
    if unknown:
        raise SystemExit(f"Unknown attack types: {', '.join(unknown)}")
    switch = set_experimental_alerting(model, types=types, actor=args.actor, reason=args.reason)
    _save(model)
    with SessionLocal() as db:
        db.add(AuditLog(actor=args.actor, action="model_alerts_switched", target_type="mfu_behavior_model",
                        target_value=",".join(types) or "off", details=switch))
        db.commit()
    print(json.dumps(switch, indent=2))
    print("Restart ATDR so the dashboard reads the new setting.")


if __name__ == "__main__":
    main()
