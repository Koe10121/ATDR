from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import Settings
from atdr.app.services.v553_release_readiness_service import (
    build_v553_evidence_templates,
    build_v553_release_readiness_report,
)


DATABASE_CONFIRMATION = "READ_ONLY_V553_DATABASE_PROBE"
TEMPLATE_CONFIRMATION = "WRITE_EMPTY_V553_EVIDENCE_TEMPLATES"


def _write_templates(output_directory: Path, environment: str) -> dict:
    output_directory = output_directory.expanduser().resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    templates = build_v553_evidence_templates(environment)
    written: list[str] = []
    for filename, payload in templates.items():
        path = output_directory / filename
        if path.exists():
            raise ValueError("An evidence template already exists; existing evidence was preserved.")
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        written.append(filename)
    return {
        "ok": True,
        "status": "unapproved_templates_written",
        "template_count": len(written),
        "filenames": sorted(written),
        "acceptance_granted": False,
        "secrets_exposed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect v5.53 release readiness without changing runtime state or exposing secrets."
    )
    parser.add_argument("--probe-database", action="store_true")
    parser.add_argument("--write-evidence-templates", action="store_true")
    parser.add_argument("--output-directory", default=".atdr_runtime/acceptance")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--require-local-ready", action="store_true")
    parser.add_argument("--require-shared-lab-ready", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    settings = Settings()
    if args.write_evidence_templates:
        if args.confirm != TEMPLATE_CONFIRMATION:
            result = {
                "ok": False,
                "status": "template_write_confirmation_required",
                "required_confirmation": TEMPLATE_CONFIRMATION,
                "acceptance_granted": False,
                "secrets_exposed": False,
            }
        else:
            try:
                result = _write_templates(Path(args.output_directory), settings.environment)
            except (OSError, ValueError) as exc:
                result = {
                    "ok": False,
                    "status": "template_write_failed",
                    "error_type": type(exc).__name__,
                    "detail": "Evidence templates were not written; existing evidence was preserved.",
                    "acceptance_granted": False,
                    "secrets_exposed": False,
                }
    elif args.probe_database and args.confirm != DATABASE_CONFIRMATION:
        result = {
            "ok": False,
            "status": "database_probe_confirmation_required",
            "required_confirmation": DATABASE_CONFIRMATION,
            "database_probe_performed": False,
            "secrets_exposed": False,
        }
    else:
        result = build_v553_release_readiness_report(
            settings,
            probe_database=args.probe_database,
        )
        result["ok"] = True

    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    accepted = bool(result.get("ok"))
    if args.require_local_ready:
        accepted = accepted and bool(result.get("local_controls_ready"))
    if args.require_shared_lab_ready:
        accepted = accepted and bool(result.get("shared_lab_ready"))
    raise SystemExit(0 if accepted else 1)


if __name__ == "__main__":
    main()
