import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT


LOCAL_SQLITE_VALUES = {
    "DATABASE_URL": '"sqlite:///./atdr.db"',
    "AUTO_CREATE_TABLES": "true",
    "ENVIRONMENT": '"development"',
    "RESPONSE_SIMULATION": "true",
    "RESPONSE_PROVIDER": '"simulation"',
}


def _parse_key(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    return stripped.split("=", 1)[0].strip()


def build_local_sqlite_env_lines(content: str) -> tuple[str, list[dict[str, str]]]:
    lines = content.splitlines()
    seen: set[str] = set()
    changes: list[dict[str, str]] = []
    output: list[str] = []

    for line in lines:
        key = _parse_key(line)
        if key in LOCAL_SQLITE_VALUES:
            desired = f"{key}={LOCAL_SQLITE_VALUES[key]}"
            seen.add(key)
            if line.strip() != desired:
                changes.append({"key": key, "action": "replace"})
                output.append(desired)
            else:
                output.append(line)
            continue
        output.append(line)

    missing = [key for key in LOCAL_SQLITE_VALUES if key not in seen]
    if missing:
        if output and output[-1].strip():
            output.append("")
        output.append("# Local SQLite profile enforced by atdr.scripts.use_local_sqlite_config")
        for key in missing:
            output.append(f"{key}={LOCAL_SQLITE_VALUES[key]}")
            changes.append({"key": key, "action": "append"})

    newline = "\n" if content.endswith(("\n", "\r\n")) else ""
    return "\n".join(output) + newline, changes


def apply_local_sqlite_config(*, env_path: Path, write: bool) -> dict[str, Any]:
    env_path = env_path if env_path.is_absolute() else PROJECT_ROOT / env_path
    if not env_path.exists():
        source = PROJECT_ROOT / ".env.example"
        content = source.read_text(encoding="utf-8") if source.exists() else ""
    else:
        content = env_path.read_text(encoding="utf-8")

    updated, changes = build_local_sqlite_env_lines(content)
    result: dict[str, Any] = {
        "ok": True,
        "env_path": str(env_path),
        "write": write,
        "would_change": bool(changes),
        "changes": changes,
        "recommendation": 'Use DATABASE_URL="sqlite:///./atdr.db" for normal local dashboard testing.',
    }

    if not write:
        return result

    backup_path = None
    if env_path.exists():
        backup_dir = PROJECT_ROOT / ".tmp" / "env-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = backup_dir / f".env.{stamp}.bak"
        shutil.copy2(env_path, backup_path)
    env_path.write_text(updated, encoding="utf-8")
    result["backup_path"] = str(backup_path) if backup_path is not None else None
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely switch ATDR .env values back to the local SQLite profile.")
    parser.add_argument("--env-path", default=".env", help="Path to the .env file relative to the project root.")
    parser.add_argument("--write", action="store_true", help="Write changes. Default is dry-run only.")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes only. This is the default.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    result = apply_local_sqlite_config(env_path=Path(args.env_path), write=bool(args.write and not args.dry_run))
    print(json.dumps(result, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
