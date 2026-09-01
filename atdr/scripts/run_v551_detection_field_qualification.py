from __future__ import annotations

import argparse
import json

from atdr.app.services.v551_field_qualification_service import (
    run_v551_field_qualification,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify ATDR field transport, PAN-OS parsing, rule diagnostics, "
            "and fresh-evidence custody in disposable storage."
        )
    )
    parser.add_argument(
        "--sample-path",
        default=None,
        help="Private evidence path. Its path, raw rows, addresses, and fingerprints are never returned.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required acknowledgement that qualification uses disposable storage only.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate inputs and receiver availability without parsing evidence or creating review packs.",
    )
    parser.add_argument(
        "--transport-mode",
        choices=("local_loopback", "external_sender"),
        default="local_loopback",
    )
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5515)
    parser.add_argument("--message-count", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--source-kind",
        choices=("synthetic_fixture", "second_laptop", "firewall", "router"),
        default="synthetic_fixture",
    )
    parser.add_argument("--source-name", default="v551-controlled-source")
    parser.add_argument("--collection-window", default="v551-controlled-window")
    parser.add_argument(
        "--source-attestation",
        default=None,
        help="Private human source-attestation JSON. The identity and path are never returned.",
    )
    parser.add_argument(
        "--field-expectations",
        default=None,
        help="Private human-confirmed field-expectation JSON used for aggregate parser accuracy.",
    )
    parser.add_argument(
        "--rule-review",
        default=None,
        help="Completed prediction-blind v5.51 review CSV used for aggregate rule FP/FN metrics.",
    )
    parser.add_argument("--max-rows", type=int, default=10_000)
    parser.add_argument("--review-limit", type=int, default=80)
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
        "source_kind": args.source_kind,
        "source_name": args.source_name,
        "collection_window": args.collection_window,
        "source_attestation_path": args.source_attestation,
        "field_expectations_path": args.field_expectations,
        "rule_review_path": args.rule_review,
        "max_rows": args.max_rows,
        "review_limit": args.review_limit,
        "write_output": not args.no_report,
    }
    if args.output_dir:
        kwargs["output_dir"] = args.output_dir

    result = run_v551_field_qualification(**kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
