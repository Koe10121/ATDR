import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import run_supervised_recovery_phase


def main() -> None:
    parser = argparse.ArgumentParser(description="Run supervised ML recovery diagnostics and candidate-only rebuild.")
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--review-limit", type=int, default=150)
    parser.add_argument("--status-path", default="ml_baseline_reviews/supervised_recovery/latest_status.json")
    args = parser.parse_args()

    def progress(step: str, status: str) -> None:
        print(f"[supervised-recovery] {step}: {status}", flush=True)

    init_db()
    with SessionLocal() as db:
        result = run_supervised_recovery_phase(
            db,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            review_limit=args.review_limit,
            status_path=Path(args.status_path),
            progress_callback=progress,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
