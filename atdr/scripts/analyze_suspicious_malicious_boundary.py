import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.boundary_analysis import DEFAULT_BOUNDARY_REPORT_PATH, write_boundary_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze suspicious/malicious boundary quality for ATDR supervised ML.")
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output", default=str(DEFAULT_BOUNDARY_REPORT_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_boundary_report(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
