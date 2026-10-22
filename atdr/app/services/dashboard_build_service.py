"""Keeps the dashboard's built files (frontend/dist) in step with its source.

ATDR serves the built dashboard (atdr/app/dashboard_server.py), so a change to the source shows only after a
build. The start script asks for one when the source is newer than the build; nobody has to remember it.

- The build goes into a staging folder and is copied into frontend/dist only when it succeeded, so a source file
  that does not compile leaves the dashboard that was working in place.
- index.html is replaced last and in one step: it never names a script that is not there yet.
- The files of the build before stay until the next build: a page left open across an update still finds the
  scripts it loads later.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT

FRONTEND = PROJECT_ROOT / "frontend"
BUILD = "dist"
STAGING = "dist-staging"
STAMP = ".atdr-build.json"
# What a build is made from. A change to any of these makes the build stale.
SOURCE_PATHS = (
    "src", "public", "index.html", "package.json", "package-lock.json", "vite.config.ts", "tsconfig.json",
    "tsconfig.node.json", "postcss.config.cjs", ".env", ".env.local",
)
BUILD_TIMEOUT_SECONDS = 900


def newest_source_change(frontend: Path = FRONTEND) -> float:
    """When the newest source file was last changed (seconds since 1970)."""

    newest = 0.0
    for name in SOURCE_PATHS:
        path = frontend / name
        files = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()] if path.is_dir() else []
        for file in files:
            newest = max(newest, file.stat().st_mtime)
    return newest


def read_stamp(frontend: Path = FRONTEND) -> dict[str, Any] | None:
    try:
        stamp = json.loads((frontend / BUILD / STAMP).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return stamp if isinstance(stamp, dict) and "source_changed" in stamp else None


def _when(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def build_state(frontend: Path = FRONTEND) -> dict[str, Any]:
    """Whether there is a build to serve, and whether the source has changed since it was made."""

    stamp = read_stamp(frontend)
    built = (frontend / BUILD / "index.html").is_file()
    changed = newest_source_change(frontend)
    return {
        "built": built,
        "built_at": stamp.get("built_at") if stamp and built else None,
        "commit": stamp.get("commit") if stamp and built else None,
        # The build was made from source that differs from that commit.
        "uncommitted": bool(stamp.get("uncommitted")) if stamp and built else False,
        # A build made by hand (npm run build) has no stamp: nothing says what it was made from.
        "stale": not built or stamp is None or changed > float(stamp["source_changed"]),
        "source_changed_at": _when(changed) if changed else None,
    }


def _commit(frontend: Path) -> tuple[str | None, bool]:
    """The commit the dashboard's source is at, and whether the source differs from it."""

    try:
        found = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=frontend, capture_output=True, text=True, timeout=10)
        if found.returncode != 0:
            return None, False
        changed = subprocess.run(["git", "status", "--porcelain", "--", "."], cwd=frontend, capture_output=True, text=True, timeout=20)
        return found.stdout.strip(), bool(changed.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None, False


def _files(folder: Path) -> list[str]:
    return sorted(path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file())


def _install(staging: Path, build: Path, *, keep: set[str]) -> None:
    """Copies the new build over the served one: every other file first, index.html last and in one step."""

    new_files = _files(staging)
    for name in new_files:
        if name == "index.html":
            continue
        target = build / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staging / name, target)
    arriving = build / "index.html.arriving"
    shutil.copyfile(staging / "index.html", arriving)
    os.replace(arriving, build / "index.html")
    wanted = set(new_files) | keep
    for name in _files(build):
        if name not in wanted:
            try:
                (build / name).unlink()
            except OSError:
                pass  # being read just now; the next build removes it


def build_dashboard(
    frontend: Path = FRONTEND,
    *,
    force: bool = False,
    run: Callable[..., Any] = subprocess.run,
    npm: str | None = None,
) -> dict[str, Any]:
    """Builds when the source is newer than the build. "ok" says there is a build to serve, new or not."""

    state = build_state(frontend)
    if state["built"] and not state["stale"] and not force:
        return {"ok": True, "status": "current", **state}
    npm = npm or shutil.which("npm")
    if npm is None:
        return {"ok": state["built"], "status": "npm_missing", **state}
    staging = frontend / STAGING
    # Read before the build starts: a file saved while it runs is newer than this, so the next start builds again.
    changed = newest_source_change(frontend)
    started = datetime.now(timezone.utc)
    try:
        done = run([npm, "run", "build", "--", "--outDir", STAGING, "--emptyOutDir"], cwd=frontend, capture_output=True,
                   text=True, encoding="utf-8", errors="replace", timeout=BUILD_TIMEOUT_SECONDS)
        failed = done.returncode != 0 or not (staging / "index.html").is_file()
        output = f"{done.stdout or ''}\n{done.stderr or ''}"
    except (OSError, subprocess.SubprocessError) as exc:
        failed, output = True, f"{exc.__class__.__name__}: {exc}"
    if failed:
        shutil.rmtree(staging, ignore_errors=True)
        lines = [line for line in output.splitlines() if line.strip()]
        return {"ok": state["built"], "status": "build_failed", **state, "output": "\n".join(lines[-12:])}
    previous = read_stamp(frontend) or {}
    commit, uncommitted = _commit(frontend)
    stamp = {"built_at": started.isoformat(), "source_changed": changed, "commit": commit, "uncommitted": uncommitted,
             "files": _files(staging)}
    (staging / STAMP).write_text(json.dumps(stamp, indent=1) + "\n", encoding="utf-8")
    build = frontend / BUILD
    build.mkdir(exist_ok=True)
    _install(staging, build, keep=set(previous.get("files") or []))
    shutil.rmtree(staging, ignore_errors=True)
    return {"ok": True, "status": "built", **build_state(frontend),
            "seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 1)}
