from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.services.v512_parser_baseline_service import (
    V512_VERSION,
    audit_private_panos_contract,
    controlled_validation_lock_status,
    v512_comparison_summary,
)
from atdr.scripts.run_layered_detection_validation import (
    run_layered_detection_validation,
)


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"


def _safe_report_name() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"v5_12_parser_profile_baseline_repair_{timestamp}.json"


def _write_report(
    report: dict[str, Any],
    *,
    output_dir: Path,
) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    name = _safe_report_name()
    (output_dir / name).write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    return name


def run_v512_parser_profile_baseline_repair(
    db: Session,
    *,
    sample_path: Path | None = None,
    limit: int = 120_000,
    write_report: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    private_audit = (
        audit_private_panos_contract(
            sample_path,
            max_lines=max(1, int(limit)),
        )
        if sample_path is not None
        else None
    )
    with tempfile.TemporaryDirectory(
        dir=PROJECT_ROOT / "atdr" / "data" / "processed",
    ) as directory:
        temporary_root = Path(directory)
        controlled = run_layered_detection_validation(
            variants=1,
            use_temp_db=True,
            write_output=False,
            variant_output_dir=temporary_root / "variants",
        )
    controlled_lock = controlled_validation_lock_status(controlled)
    comparison = v512_comparison_summary(
        db,
        private_audit=private_audit,
    )
    result: dict[str, Any] = {
        "ok": bool(
            comparison.get("ok")
            and controlled.get("ok")
            and controlled_lock.get("matched")
            and (
                private_audit is None
                or private_audit.get("ok")
            )
        ),
        "version": V512_VERSION,
        "status": "v5.12_parser_profile_baseline_repair_complete",
        "comparison": comparison,
        "private_parser_audit": private_audit,
        "controlled_detection_equivalence": controlled_lock,
        "safety": {
            "private_evidence_persisted": False,
            "configured_database_unchanged": bool(
                (comparison.get("safety") or {}).get(
                    "configured_database_unchanged"
                )
            ),
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "rules_alert_authoritative": True,
            "isolation_forest_advisory_only": True,
        },
        "lifecycle_state": "shadow_observation",
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "source_identifiers_included": False,
        "private_paths_included": False,
        "labels_accessed": False,
        "accuracy_metrics_calculated": False,
        "secrets_exposed": False,
    }
    if write_report:
        result["generated_report"] = {
            "filename": _write_report(result, output_dir=output_dir),
            "ignored_generated_output": True,
            "private_path_included": False,
        }
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit the v5.12 parser contract and profile baselines using "
            "aggregate-only, read-only, and disposable validation."
        )
    )
    parser.add_argument(
        "--sample-path",
        default=None,
        help=(
            "Optional private PAN-OS file. Its path, raw rows, and IPs are "
            "never returned."
        ),
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help=(
            "Required with a private sample for the full comparison. "
            "Controlled validation always uses disposable storage."
        ),
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help=(
            "Run only the bounded private parser audit without opening the "
            "configured database."
        ),
    )
    parser.add_argument("--limit", type=int, default=120_000)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    sample_path = (
        Path(args.sample_path).expanduser()
        if args.sample_path
        else None
    )
    if args.preflight_only:
        result = (
            audit_private_panos_contract(
                sample_path,
                max_lines=max(1, int(args.limit)),
            )
            if sample_path is not None
            else {
                "ok": False,
                "status": "sample_path_required_for_preflight",
                "private_paths_included": False,
                "raw_logs_included": False,
            }
        )
    elif sample_path is not None and not args.use_temp_db:
        result = {
            "ok": False,
            "status": "explicit_temp_database_required",
            "message": (
                "Re-run with --use-temp-db when supplying private evidence. "
                "The configured database is never a private-validation target."
            ),
            "private_paths_included": False,
            "raw_logs_included": False,
            "secrets_exposed": False,
        }
    else:
        from atdr.app.db.database import SessionLocal

        with SessionLocal() as db:
            result = run_v512_parser_profile_baseline_repair(
                db,
                sample_path=sample_path,
                limit=max(1, int(args.limit)),
                write_report=not args.no_report,
                output_dir=(
                    Path(args.output_dir)
                    if args.output_dir
                    else DEFAULT_OUTPUT_DIR
                ),
            )
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            sort_keys=bool(args.pretty),
            default=str,
        )
    )
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
