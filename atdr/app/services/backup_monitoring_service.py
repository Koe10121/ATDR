from __future__ import annotations

import json
from pathlib import Path

from atdr.app.services.persistence_service import verify_database_backup_artifact


def verify_latest_backup_status(*, backup_dir: str | Path, max_age_hours: float) -> dict:
    """Verify the newest backup without returning its directory or modifying state."""

    configured = bool(str(backup_dir).strip())
    if not configured:
        return {
            "ok": False,
            "status": "backup_directory_not_configured",
            "backup_directory_configured": False,
            "database_modified": False,
            "secrets_exposed": False,
        }
    root = Path(backup_dir).expanduser().resolve()
    if not root.is_dir():
        return {
            "ok": False,
            "status": "backup_directory_unavailable",
            "backup_directory_configured": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    manifests = sorted(root.glob("*.manifest.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not manifests:
        return {
            "ok": False,
            "status": "backup_manifest_missing",
            "backup_directory_configured": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    manifest_path = manifests[0]
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifact_name = str(payload.get("artifact_name", ""))
    except (OSError, json.JSONDecodeError):
        artifact_name = ""
    if not artifact_name or Path(artifact_name).name != artifact_name:
        return {
            "ok": False,
            "status": "manifest_invalid",
            "backup_directory_configured": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    artifact = (root / artifact_name).resolve()
    try:
        artifact.relative_to(root)
    except ValueError:
        return {
            "ok": False,
            "status": "manifest_invalid",
            "backup_directory_configured": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    result = verify_database_backup_artifact(
        backup_path=artifact,
        manifest_path=manifest_path,
        max_age_hours=max_age_hours,
    )
    return {**result, "backup_directory_configured": True}
