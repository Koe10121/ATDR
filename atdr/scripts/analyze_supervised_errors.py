import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import ERROR_REPORT_PATH, analyze_supervised_errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Export supervised ML error analysis for suspicious/malicious review planning.")
    parser.add_argument("--output", default=str(ERROR_REPORT_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = analyze_supervised_errors(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
