import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.demo_service import export_demo_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a supervisor-ready ATDR demo evidence bundle.")
    parser.add_argument("--actor", default="script", help="Audit actor recorded for the export")
    parser.add_argument("--alert-id", type=int, default=None, help="Alert ID to export; defaults to highest score alert")
    parser.add_argument("--output-dir", default=None, help="Output directory; defaults to ./demo_exports")
    parser.add_argument("--top-alert-limit", type=int, default=10)
    parser.add_argument("--audit-limit", type=int, default=50)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = export_demo_bundle(
            db,
            actor=args.actor,
            alert_id=args.alert_id,
            output_dir=args.output_dir,
            top_alert_limit=args.top_alert_limit,
            audit_limit=args.audit_limit,
        )
    print(json.dumps(result, default=str, indent=2))


if __name__ == "__main__":
    main()
