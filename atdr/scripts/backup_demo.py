import argparse
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT


def _resolve_project_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


def _assert_under_project(path: Path) -> None:
    path.relative_to(PROJECT_ROOT.resolve())


def _add_path(archive: zipfile.ZipFile, path: Path, base: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        archive.write(path, path.relative_to(base))
        return 1
    count = 0
    for file_path in path.rglob("*"):
        if file_path.is_file():
            archive.write(file_path, file_path.relative_to(base))
            count += 1
    return count


def create_demo_backup(
    *,
    output_dir: str | Path = "backups",
    database_path: str | Path = "atdr.db",
    include_models: bool = True,
    include_demo_exports: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    backup_dir = _resolve_project_path(output_dir)
    _assert_under_project(backup_dir)
    db_path = _resolve_project_path(database_path)
    _assert_under_project(db_path)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_path = backup_dir / f"atdr-demo-backup-{timestamp}.zip"
    sources = [db_path]
    if include_models:
        sources.append(_resolve_project_path("atdr/models"))
    if include_demo_exports:
        sources.append(_resolve_project_path("demo_exports"))

    source_records = [{"path": str(path), "exists": path.exists()} for path in sources]
    if dry_run:
        return {"dry_run": True, "archive_path": str(archive_path), "sources": source_records, "files_added": 0}

    backup_dir.mkdir(parents=True, exist_ok=True)
    files_added = 0
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            _assert_under_project(source)
            files_added += _add_path(archive, source, PROJECT_ROOT.resolve())
    return {"dry_run": False, "archive_path": str(archive_path), "sources": source_records, "files_added": files_added}


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a local ATDR demo backup archive.")
    parser.add_argument("--output-dir", default="backups")
    parser.add_argument("--database-path", default="atdr.db")
    parser.add_argument("--no-models", action="store_true")
    parser.add_argument("--no-demo-exports", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    result = create_demo_backup(
        output_dir=args.output_dir,
        database_path=args.database_path,
        include_models=not args.no_models,
        include_demo_exports=not args.no_demo_exports,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
