import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, get_settings


def _resolve_output_dir(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    candidate = candidate.resolve()
    candidate.relative_to(PROJECT_ROOT.resolve())
    return candidate


def create_postgres_backup(
    *,
    output_dir: str | Path = "backups",
    database_url: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    backup_dir = _resolve_output_dir(output_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = backup_dir / f"atdr-postgres-{timestamp}.dump"
    db_url = database_url or get_settings().database_url
    pg_dump = shutil.which("pg_dump")
    command = [pg_dump or "pg_dump", "--format=custom", "--file", str(output_path), db_url]
    if dry_run:
        return {"dry_run": True, "pg_dump_available": bool(pg_dump), "output_path": str(output_path), "command": command}
    if not pg_dump:
        return {
            "dry_run": False,
            "ok": False,
            "error": "pg_dump is not installed or not on PATH.",
            "output_path": str(output_path),
        }
    backup_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    result = subprocess.run(command, capture_output=True, text=True, timeout=300, env=env)
    return {
        "dry_run": False,
        "ok": result.returncode == 0,
        "output_path": str(output_path),
        "returncode": result.returncode,
        "stderr": result.stderr.strip(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a PostgreSQL logical backup with pg_dump.")
    parser.add_argument("--output-dir", default="backups")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    result = create_postgres_backup(output_dir=args.output_dir, database_url=args.database_url, dry_run=args.dry_run)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result.get("dry_run") or result.get("ok") else 1)


if __name__ == "__main__":
    main()
