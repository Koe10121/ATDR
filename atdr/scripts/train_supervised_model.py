import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_detector import train_supervised_classifier


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ATDR supervised classifier from analyst-reviewed ML labels.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--actor", default="cli")
    parser.add_argument("--split", choices=["random", "time"], default="random")
    parser.add_argument(
        "--model",
        choices=["random_forest", "hist_gradient_boosting", "logistic_regression", "extra_trees"],
        default="random_forest",
    )
    parser.add_argument("--class-weight", choices=["balanced", "none"], default="balanced")
    parser.add_argument("--reviewed-weight", type=float, default=3.0)
    parser.add_argument("--weak-weight", type=float, default=0.55)
    parser.add_argument(
        "--threshold-profile",
        choices=["conservative", "balanced", "aggressive", "suspicious_recall", "malicious_recall", "threat_positive"],
        default="balanced",
    )
    parser.add_argument("--save-candidate", action="store_true")
    parser.add_argument("--activate-if-eligible", action="store_true")
    parser.add_argument("--dataset-snapshot-id", default=None)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = train_supervised_classifier(
            db,
            actor=args.actor,
            model_path=args.model_path,
            test_size=args.test_size,
            min_samples=args.min_samples,
            split=args.split,
            model_type=args.model,
            class_weight=None if args.class_weight == "none" else args.class_weight,
            reviewed_weight=args.reviewed_weight,
            weak_weight=args.weak_weight,
            threshold_profile=args.threshold_profile,
            save_candidate=args.save_candidate and not args.activate_if_eligible,
            dataset_snapshot_id=args.dataset_snapshot_id,
            training_command=" ".join(["python", "-m", "atdr.scripts.train_supervised_model"]),
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
