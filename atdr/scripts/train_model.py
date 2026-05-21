import argparse

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.ml_service import train_anomaly_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ATDR IsolationForest anomaly detector.")
    parser.add_argument("--limit", type=int, default=None, help="Train on the latest N normalized logs")
    parser.add_argument("--baseline-only", action="store_true", help="Train only on safer baseline candidate logs")
    parser.add_argument("--max-app-risk", type=int, default=3, choices=[1, 2, 3, 4, 5])
    parser.add_argument("--include-unknown-apps", action="store_true")
    parser.add_argument("--include-existing-anomalies", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = train_anomaly_model(
            db,
            limit=args.limit,
            actor="cli",
            baseline_only=args.baseline_only,
            max_app_risk=args.max_app_risk,
            exclude_unknown_apps=not args.include_unknown_apps,
            exclude_existing_anomalies=not args.include_existing_anomalies,
        )
    print(result)


if __name__ == "__main__":
    main()
