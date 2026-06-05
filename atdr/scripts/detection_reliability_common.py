import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT


RELIABILITY_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "detection_reliability"


def json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_report_files(
    payload: dict[str, Any],
    *,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
    stem_prefix: str,
    markdown: str,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{stem_prefix}_{utc_stamp()}"
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(payload, default=json_default, indent=2), encoding="utf-8")
    markdown_path.write_text(markdown, encoding="utf-8")
    return {"json": str(json_path), "markdown": str(markdown_path)}


def latest_json_report(pattern: str, *, report_dir: Path = RELIABILITY_OUTPUT_DIR) -> Path | None:
    if not report_dir.exists():
        return None
    candidates = sorted(report_dir.glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def load_latest_json(pattern: str, *, report_dir: Path = RELIABILITY_OUTPUT_DIR) -> dict[str, Any] | None:
    latest = latest_json_report(pattern, report_dir=report_dir)
    if latest is None:
        return None
    return json.loads(latest.read_text(encoding="utf-8"))
