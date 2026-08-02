from __future__ import annotations

import argparse
import json

from atdr.app.services.v523_live_source_acceptance_service import (
    run_v523_live_source_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate ATDR file, API, resumable, replay/UDP, source-health, "
            "detection, investigation, and audit contracts in disposable storage."
        )
    )
    parser.add_argument(
        "--sample-path",
        default=None,
        help=(
            "Optional private local evidence used only as bounded UDP replay input. "
            "Its path and contents are never returned."
        ),
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required safety acknowledgement; the configured database is never an acceptance target.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Check inputs and UDP bind availability without creating disposable database rows.",
    )
    parser.add_argument(
        "--transport-mode",
        choices=("local_loopback", "external_sender"),
        default="local_loopback",
    )
    parser.add_argument(
        "--bind-host",
        default="0.0.0.0",
        help="Receiver bind address for external_sender mode (default: 0.0.0.0).",
    )
    parser.add_argument("--port", type=int, default=5515)
    parser.add_argument("--message-count", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--external-sender-kind",
        choices=("second_laptop", "firewall", "router"),
        default=None,
        help=(
            "Required operator attestation for external_sender mode. A second laptop "
            "proves transport only; firewall/router may satisfy device transport evidence."
        ),
    )
    parser.add_argument("--temp-parent", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {
        "use_temp_db": args.use_temp_db,
        "sample_path": args.sample_path,
        "preflight_only": args.preflight_only,
        "transport_mode": args.transport_mode,
        "bind_host": args.bind_host,
        "port": args.port,
        "message_count": args.message_count,
        "timeout_seconds": args.timeout,
        "external_sender_kind": args.external_sender_kind,
        "write_output": not args.no_report,
    }
    if args.temp_parent:
        kwargs["temp_parent"] = args.temp_parent
    if args.output_dir:
        kwargs["output_dir"] = args.output_dir

    result = run_v523_live_source_acceptance(**kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
