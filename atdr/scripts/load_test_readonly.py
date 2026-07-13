import argparse
import json
import os

from atdr.app.services.load_test_service import run_read_only_load_test


REMOTE_CONFIRMATION = "READ_ONLY_REMOTE_LOAD_TEST"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a bounded GET-only ATDR load test. Dry-run is the default.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--requests-per-endpoint", type=int, default=5)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_read_only_load_test(
        base_url=args.base_url,
        bearer_token=os.environ.get("ATDR_LOAD_TEST_BEARER_TOKEN", ""),
        requests_per_endpoint=args.requests_per_endpoint,
        concurrency=args.concurrency,
        timeout_seconds=args.timeout,
        execute=args.execute,
        allow_remote=args.allow_remote,
        remote_confirmed=args.confirm == REMOTE_CONFIRMATION,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
