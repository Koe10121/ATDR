import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.scripts.run_v35_real_source_pilot_check import (
    _json_default,
    run_v35_real_source_pilot_check,
)


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "real_source_pilot"


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _evidence_payload(check_result: dict[str, Any]) -> dict[str, Any]:
    source = check_result.get("source") or {}
    latest_ingestion_run = check_result.get("latest_ingestion_run")
    latest_detection_run = check_result.get("latest_detection_run")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "ATDR v3.5 controlled real-source/syslog pilot evidence",
        "safety": {
            "production_ready": False,
            "production_readiness_claim": False,
            "model_activated": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "raw_private_log_contents_included": False,
        },
        "status": check_result.get("status"),
        "source_pipeline_validated": check_result.get("source_pipeline_validated", False),
        "real_device_forwarding_validated": check_result.get("real_device_forwarding_validated", False),
        "simulated_or_replay_source": check_result.get("simulated_or_replay_source", False),
        "source": {
            "source_id": source.get("source_id"),
            "name": source.get("name"),
            "source_type": source.get("source_type"),
            "parser_profile": source.get("parser_profile"),
            "host": source.get("host"),
            "port": source.get("port"),
            "enabled": source.get("enabled"),
            "last_seen": source.get("last_seen"),
            "last_log_received_at": source.get("last_log_received_at"),
        },
        "counts": check_result.get("counts", {}),
        "source_health": check_result.get("source_health", {}),
        "source_quality_summary": check_result.get("source_quality_summary", {}),
        "latest_ingestion_run_id": latest_ingestion_run.get("run_id") if latest_ingestion_run else None,
        "latest_detection_run_id": latest_detection_run.get("run_id") if latest_detection_run else None,
        "latest_ingestion_run": latest_ingestion_run,
        "latest_detection_run": latest_detection_run,
        "source_scoped_alert_ids": check_result.get("source_scoped_alert_ids", []),
        "source_linked_case_ids": check_result.get("source_linked_case_ids", []),
        "latest_parser_errors": check_result.get("latest_parser_errors", []),
        "response_actions": check_result.get("response_actions", {}),
        "checks": check_result.get("checks", []),
        "warnings": check_result.get("warnings", []),
        "runtime_seconds": check_result.get("runtime_seconds"),
    }


def export_real_source_pilot_evidence(
    *,
    source_name: str | None = None,
    expected_min_logs: int = 1,
    window_minutes: int = 60,
    output_dir: Path | str = DEFAULT_OUTPUT_DIR,
    write: bool = False,
    include_redacted_excerpts: bool = False,
    settings: Settings | None = None,
    session_factory=None,
) -> dict[str, Any]:
    check_result = run_v35_real_source_pilot_check(
        source_name=source_name,
        expected_min_logs=expected_min_logs,
        window_minutes=window_minutes,
        include_redacted_excerpts=include_redacted_excerpts,
        settings=settings,
        session_factory=session_factory,
    )
    payload = _evidence_payload(check_result)
    payload["written"] = False
    payload["output_path"] = None
    if write:
        destination_dir = Path(output_dir)
        destination_dir.mkdir(parents=True, exist_ok=True)
        source_label = (payload.get("source") or {}).get("name") or source_name or "latest-source"
        safe_source = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in str(source_label))[:80]
        output_path = destination_dir / f"real_source_pilot_evidence_{safe_source}_{_timestamp()}.json"
        output_path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
        payload["written"] = True
        payload["output_path"] = str(output_path)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Export safe ATDR v3.5 real-source pilot evidence.")
    parser.add_argument("--source-name", default=None, help="Source name. Defaults to latest active source if omitted.")
    parser.add_argument("--expected-min-logs", type=int, default=1)
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--write", action="store_true", help="Write JSON under the output directory. Default prints only.")
    parser.add_argument("--include-redacted-excerpts", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = export_real_source_pilot_evidence(
        source_name=args.source_name,
        expected_min_logs=args.expected_min_logs,
        window_minutes=args.window_minutes,
        output_dir=args.output_dir,
        write=args.write,
        include_redacted_excerpts=args.include_redacted_excerpts,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("status") != "source_missing_not_validated" else 0)


if __name__ == "__main__":
    main()
