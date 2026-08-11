from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.v531_adversarial_reliability import run_v531_adversarial_reliability


OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "detection_validation"


def _write_report(payload: dict) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = OUTPUT_DIR / f"v5_31_adversarial_reliability_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the synthetic v5.31 deterministic detection adversarial reliability corpus."
    )
    parser.add_argument("--corpus", type=Path, help="Optional alternate synthetic corpus path.")
    parser.add_argument("--write-report", action="store_true", help="Write an ignored aggregate JSON report.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    payload = run_v531_adversarial_reliability(args.corpus) if args.corpus else run_v531_adversarial_reliability()
    if args.write_report:
        report_path = _write_report(payload)
        payload["report_written"] = True
        payload["report_name"] = report_path.name
    else:
        payload["report_written"] = False
    print(json.dumps(payload, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if payload["ok"] else 1)


if __name__ == "__main__":
    main()
