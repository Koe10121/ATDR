from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


CONFIRMATION = "DELETE_DISPOSABLE_CACHES"
SAFE_ROOT_NAMES = {".pytest_cache", ".ruff_cache"}
SAFE_FRONTEND_NAMES = {"coverage", "dist", "playwright-report", "test-results"}
PROTECTED_PARTS = {
    ".atdr_runtime",
    ".git",
    ".tmp",
    ".uv-python",
    ".venv",
    "data",
    "demo_exports",
    "logs",
    "ml_baseline_reviews",
    "models",
    "node_modules",
    "processed",
    "reviews",
}


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_candidate(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    parts = relative.parts
    if any(part in PROTECTED_PARTS for part in parts):
        return False
    if path.name == "__pycache__":
        return True
    if len(parts) == 1 and path.name in SAFE_ROOT_NAMES:
        return True
    return len(parts) == 2 and parts[0] == "frontend" and path.name in SAFE_FRONTEND_NAMES


def find_disposable_caches(root: Path) -> list[Path]:
    root = root.resolve()
    candidates: list[Path] = []
    for name in SAFE_ROOT_NAMES:
        path = root / name
        if path.is_dir() and not path.is_symlink():
            candidates.append(path.resolve())

    for relative_base in ("atdr", "migrations"):
        base = root / relative_base
        if not base.is_dir() or base.is_symlink():
            continue
        for current, directories, _files in os.walk(base, topdown=True, followlinks=False):
            current_path = Path(current)
            retained: list[str] = []
            for name in directories:
                path = current_path / name
                if path.is_symlink():
                    continue
                if name == "__pycache__":
                    candidates.append(path.resolve())
                    continue
                retained.append(name)
            directories[:] = retained

    frontend = root / "frontend"
    for name in SAFE_FRONTEND_NAMES:
        path = frontend / name
        if path.is_dir() and not path.is_symlink():
            candidates.append(path.resolve())
    return sorted(set(candidates), key=lambda path: _relative(root, path))


def cleanup_disposable_caches(
    root: Path,
    *,
    apply: bool = False,
    confirmation: str | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    if apply and confirmation != CONFIRMATION:
        raise ValueError(f"--apply requires --confirm {CONFIRMATION}")

    candidates = find_disposable_caches(root)
    removed: list[str] = []
    failures: list[dict[str, str]] = []
    if apply:
        for path in candidates:
            relative = _relative(root, path)
            try:
                resolved = path.resolve(strict=False)
                resolved.relative_to(root)
                if not _is_candidate(root, resolved) or path.is_symlink():
                    raise ValueError("candidate failed the deletion safety check")
                shutil.rmtree(path)
                removed.append(relative)
            except (OSError, ValueError) as exc:
                failures.append({"path": relative, "error_type": type(exc).__name__})

    return {
        "ok": not failures,
        "mode": "apply" if apply else "dry_run",
        "candidate_count": len(candidates),
        "candidates": [_relative(root, path) for path in candidates],
        "removed_count": len(removed),
        "removed": removed,
        "failure_count": len(failures),
        "failures": failures,
        "protected_categories": sorted(PROTECTED_PARTS),
        "database_files_allowed": False,
        "log_files_allowed": False,
        "evidence_allowed": False,
        "model_artifacts_allowed": False,
        "environment_files_allowed": False,
        "outside_repository_allowed": False,
    }
