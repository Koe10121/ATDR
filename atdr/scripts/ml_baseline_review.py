import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.ml_baseline_review_service import export_ml_baseline_review


def main() -> None:
    parser = argparse.ArgumentParser(description="Export an analyst-review package for ATDR ML baseline tuning.")
    parser.add_argument("--output-dir", default=None, help="Base directory for the generated review folder.")
    parser.add_argument("--anomaly-limit", type=int, default=200, help="Maximum anomaly rows to export for analyst review.")
    parser.add_argument("--baseline-limit", type=int, default=200, help="Maximum baseline candidate rows to export.")
    parser.add_argument("--max-app-risk", type=int, default=3, choices=[1, 2, 3, 4, 5])
    parser.add_argument("--actor", default="cli", help="Actor name recorded in audit logs.")
    parser.add_argument("--no-audit", action="store_true", help="Skip writing an audit event.")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = export_ml_baseline_review(
            db,
            output_dir=args.output_dir,
            anomaly_limit=args.anomaly_limit,
            baseline_limit=args.baseline_limit,
            baseline_max_app_risk=args.max_app_risk,
            actor=args.actor,
            audit=not args.no_audit,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
