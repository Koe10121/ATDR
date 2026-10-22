"""Compare another folder's model files with this copy's, and check that the new ones load here.

Usage, from the live copy with its own Python:
    .venv\\Scripts\\python.exe -m atdr.scripts.check_models --from C:\\Users\\User\\Desktop\\ATDR\\atdr\\models

Read-only. Trained models are not in git, so a release never carries them: after retraining in the development
folder, this lists the model files that are new or different there, loads each with this copy's packages (a model
saved by another scikit-learn version fails here, not in the running system) and gives each card's version.
Copying them is a separate, deliberate step: docs/OPERATIONS_RUNBOOK.md, "Installing a retrained model".
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT

HERE = PROJECT_ROOT / "atdr" / "models"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _version(path: Path) -> str | None:
    try:
        card = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return str(card.get("version")) if isinstance(card, dict) and card.get("version") else None


def _loads(path: Path) -> str | None:
    """None when the file loads with this environment's packages, else what went wrong, in one line."""

    import joblib

    try:
        joblib.load(path)
    except Exception as exc:  # noqa: BLE001 - any failure to load is the answer
        return f"{exc.__class__.__name__}: {str(exc).splitlines()[0] if str(exc) else ''}".strip(": ")
    return None


def compare_models(source: Path, here: Path | None = None) -> dict[str, Any]:
    here = here or HERE
    files = []
    for path in sorted(item for item in source.rglob("*") if item.is_file() and item.name != ".gitkeep"):
        name = path.relative_to(source).as_posix()
        mine = here / name
        state = "new" if not mine.is_file() else "same" if _digest(mine) == _digest(path) else "different"
        entry: dict[str, Any] = {"file": name, "state": state}
        if state != "same" and path.suffix == ".joblib":
            entry["load_error"] = _loads(path)
        if path.name.endswith(".card.json"):
            entry["version"] = _version(path)
            entry["version_here"] = _version(mine) if mine.is_file() else None
        files.append(entry)
    to_copy = [entry for entry in files if entry["state"] != "same"]
    broken = [entry["file"] for entry in to_copy if entry.get("load_error")]
    return {"source": str(source), "here": str(here), "files": files, "to_copy": [entry["file"] for entry in to_copy],
            "broken": broken, "ok": not broken}


def render(report: dict[str, Any]) -> str:
    lines = []
    if not report["to_copy"]:
        lines.append(f"Every model file in {report['source']} is the same here. Nothing to install.")
    for entry in report["files"]:
        if entry["state"] == "same":
            continue
        words = f"{entry['file']}: {entry['state']}"
        if entry.get("version"):
            words += f", version {entry['version']} (here: {entry.get('version_here') or 'none'})"
        if "load_error" in entry:
            words += f", DOES NOT LOAD here: {entry['load_error']}" if entry["load_error"] else ", loads here"
        lines.append(words)
    if report["broken"]:
        lines.append("Do not copy these: the running system could not load them. Retrain with this copy's packages.")
    elif report["to_copy"]:
        lines.append(f"{len(report['to_copy'])} file(s) to copy; see docs/OPERATIONS_RUNBOOK.md, \"Installing a retrained model\".")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare model files with this copy's and check the new ones load here.")
    parser.add_argument("--from", dest="source", required=True, help="the folder with the new model files")
    parser.add_argument("--json", action="store_true", help="the report as JSON")
    args = parser.parse_args(argv)
    source = Path(args.source)
    if not source.is_dir():
        parser.error(f"{source} is not a folder")
    report = compare_models(source)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
