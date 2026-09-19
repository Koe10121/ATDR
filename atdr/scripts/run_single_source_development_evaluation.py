from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.single_source_development_evaluation import (
    SingleSourceDevelopmentEvaluationError,
    evaluation_status,
    run_single_source_development_evaluation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Measure whether a simple classifier shows development-only signal on "
            "the genuinely reviewed rows of the protected v5.62/v5.63 supervised "
            "workspaces. This is explicitly NOT the official supervised "
            "qualification decision (which additionally requires a second "
            "independent physical source) and never touches the sealed "
            "untouched_future_evaluation role."
        )
    )
    parser.add_argument(
        "--status-only",
        action="store_true",
        help="Report how many development-role rows are reviewed so far, with no training.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge disposable, read-only processing of the protected review workspaces.",
    )
    parser.add_argument(
        "--model-type",
        default="logistic_regression",
        choices=("logistic_regression", "random_forest", "extra_trees", "hist_gradient_boosting"),
    )
    parser.add_argument("--v562-output-dir", type=Path, default=None)
    parser.add_argument("--v563-output-dir", type=Path, default=None)
    parser.add_argument("--v565-output-dir", type=Path, default=None)
    parser.add_argument("--v567-output-dir", type=Path, default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {}
    if args.v562_output_dir is not None:
        kwargs["v562_output_dir"] = args.v562_output_dir
    if args.v563_output_dir is not None:
        kwargs["v563_output_dir"] = args.v563_output_dir
    if args.v565_output_dir is not None:
        kwargs["v565_output_dir"] = args.v565_output_dir
    if args.v567_output_dir is not None:
        kwargs["v567_output_dir"] = args.v567_output_dir

    try:
        if args.status_only:
            result = evaluation_status(**kwargs)
        else:
            result = run_single_source_development_evaluation(
                use_temp_db=args.use_temp_db,
                model_type=args.model_type,
                **kwargs,
            )
    except SingleSourceDevelopmentEvaluationError as exc:
        result = {"ok": False, "code": exc.code, "detail": str(exc)}

    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=not args.pretty))


if __name__ == "__main__":
    main()
