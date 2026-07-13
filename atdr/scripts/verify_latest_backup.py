import argparse
import json
from pathlib import Path

from atdr.app.services.persistence_service import verify_database_backup_artifact


def verify_latest_backup(*, backup_dir: str | Path, max_age_hours: float) -> dict:
    root = Path(backup_dir).expanduser().resolve()
    if not root.is_dir():
        return {
            "ok": False,
            "status": "backup_directory_unavailable",
            "backup_directory_configured": bool(str(backup_dir).strip()),
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the newest ATDR backup artifact without restoring it.")
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--max-age-hours", type=float, default=30.0)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = verify_latest_backup(backup_dir=args.backup_dir, max_age_hours=args.max_age_hours)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
