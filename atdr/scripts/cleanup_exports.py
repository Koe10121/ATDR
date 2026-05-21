import argparse
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT


def _resolve_cleanup_target(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    candidate = candidate.resolve()
    candidate.relative_to(PROJECT_ROOT.resolve())
    return candidate


def cleanup_exports(
    *,
    target_dir: str | Path = "demo_exports",
    older_than_days: int = 14,
    dry_run: bool = True,
) -> dict[str, Any]:
    if older_than_days < 1:
        raise ValueError("older_than_days must be at least 1")
    target = _resolve_cleanup_target(target_dir)
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    candidates: list[dict[str, Any]] = []
    if target.exists():
        for child in target.iterdir():
            modified = datetime.fromtimestamp(child.stat().st_mtime, timezone.utc)
            if modified < cutoff:
                candidates.append({"path": str(child), "modified_at": modified.isoformat(), "is_dir": child.is_dir()})
    removed = 0
    if not dry_run:
        for item in candidates:
            path = Path(item["path"])
            path.relative_to(PROJECT_ROOT.resolve())
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
            removed += 1
    return {
        "dry_run": dry_run,
        "target_dir": str(target),
        "older_than_days": older_than_days,
        "candidate_count": len(candidates),
        "removed_count": removed,
        "candidates": candidates,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean old ATDR demo export artifacts safely.")
    parser.add_argument("--target-dir", default="demo_exports")
    parser.add_argument("--older-than-days", type=int, default=14)
    parser.add_argument("--execute", action="store_true", help="Actually delete old artifacts. Default is dry-run.")
    args = parser.parse_args()

    result = cleanup_exports(
        target_dir=args.target_dir,
        older_than_days=args.older_than_days,
        dry_run=not args.execute,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
