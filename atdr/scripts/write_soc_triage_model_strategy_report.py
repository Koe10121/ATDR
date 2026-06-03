import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import (
    SOC_TRIAGE_MODEL_STRATEGY_REPORT_PATH,
    write_soc_triage_model_strategy_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the SOC triage model strategy comparison report.")
    parser.add_argument("--output", default=str(SOC_TRIAGE_MODEL_STRATEGY_REPORT_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_soc_triage_model_strategy_report(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
