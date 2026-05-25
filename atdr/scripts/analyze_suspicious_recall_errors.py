import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.suspicious_recall_analysis import (
    DEFAULT_SUSPICIOUS_RECALL_REPORT_PATH,
    write_suspicious_recall_error_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze suspicious recall errors for ATDR supervised ML.")
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output", default=str(DEFAULT_SUSPICIOUS_RECALL_REPORT_PATH))
    args = parser.parse_args()

    with SessionLocal() as db:
        result = write_suspicious_recall_error_report(
            db,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            output_path=args.output,
        )
    print(
        json.dumps(
            {
                "status": result.get("status"),
                "path": result.get("report_path"),
                "suspicious_error_count": result.get("suspicious_error_count"),
                "suspicious_error_counts": result.get("suspicious_error_counts"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
