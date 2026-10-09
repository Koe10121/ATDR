"""Serve the built dashboard (frontend/dist) on this machine.

Usage:
    python -m atdr.scripts.serve_dashboard                 # http://127.0.0.1:5173
    python -m atdr.scripts.serve_dashboard --port 5174

scripts/start_system.cmd runs this as the "atdr-frontend" part, after atdr.scripts.build_dashboard has made sure the
build matches the source. For development with live reload use `npm run dev` in frontend/ instead.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from atdr.app.dashboard_server import DASHBOARD_DIRECTORY, create_dashboard_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the built ATDR dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5173)
    parser.add_argument("--directory", type=Path, default=DASHBOARD_DIRECTORY)
    args = parser.parse_args()
    # One line a request would fill the log with nothing an operator needs; errors are still logged.
    uvicorn.run(create_dashboard_app(args.directory), host=args.host, port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
