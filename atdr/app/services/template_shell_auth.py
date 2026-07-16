from __future__ import annotations

import re
from pathlib import Path
from typing import Any


FRONTEND_ENV_RELATIVE = Path("frontend-vue/.env.localdev")
BACKEND_ENV_RELATIVE = Path("backend-node/.env.local")
FRONTEND_SOURCE_RELATIVE = Path("frontend-vue/src/main.js")
BACKEND_SOURCE_RELATIVE = Path("backend-node/server/Project/accounts/service/account.js")
LOCAL_GOOGLE_ORIGIN = "http://localhost:8080"

_LEGACY_CLIENT_PATTERN = re.compile(
    r"(?:VUE_APP_CLIENTID\s*\|\||GOOGLE_CLIENT_ID\s*\|\|)[\s\S]{0,180}?"
    r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",
    re.IGNORECASE,
)


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        clean = value.strip().strip('"').strip("'")
        values[name.strip()] = clean
    return values


def _configured(value: str | None) -> bool:
    clean = (value or "").strip()
    if not clean:
        return False
    lowered = clean.lower()
    return not any(marker in lowered for marker in ("replace", "placeholder", "your-client", "example"))


def _source_has_legacy_fallback(path: Path) -> bool:
    if not path.is_file():
        return False
    return bool(_LEGACY_CLIENT_PATTERN.search(path.read_text(encoding="utf-8", errors="replace")))


def build_template_google_auth_status(template_root: Path) -> dict[str, Any]:
    """Inspect shell Google configuration without returning credential values."""

    root = template_root.expanduser().resolve()
    frontend_env_path = root / FRONTEND_ENV_RELATIVE
    backend_env_path = root / BACKEND_ENV_RELATIVE
    frontend_source_path = root / FRONTEND_SOURCE_RELATIVE
    backend_source_path = root / BACKEND_SOURCE_RELATIVE

    frontend_env = _read_env(frontend_env_path)
    backend_env = _read_env(backend_env_path)
    frontend_value = frontend_env.get("VUE_APP_CLIENTID", "")
    backend_value = backend_env.get("GOOGLE_CLIENT_ID", "")
    frontend_configured = _configured(frontend_value)
    backend_configured = _configured(backend_value)
    ids_match = frontend_configured and backend_configured and frontend_value == backend_value
    frontend_legacy = _source_has_legacy_fallback(frontend_source_path)
    backend_legacy = _source_has_legacy_fallback(backend_source_path)

    if not root.is_dir():
        diagnosis = "template_root_missing"
    elif not frontend_configured:
        diagnosis = "frontend_client_not_configured"
    elif not backend_configured:
        diagnosis = "backend_client_not_configured"
    elif not ids_match:
        diagnosis = "client_id_mismatch"
    elif frontend_legacy or backend_legacy:
        diagnosis = "legacy_fallback_present"
    else:
        diagnosis = "ready"

    return {
        "ready": diagnosis == "ready",
        "diagnosis": diagnosis,
        "template_root_exists": root.is_dir(),
        "frontend_env_exists": frontend_env_path.is_file(),
        "backend_env_exists": backend_env_path.is_file(),
        "frontend_client_configured": frontend_configured,
        "backend_client_configured": backend_configured,
        "client_ids_match": ids_match,
        "frontend_legacy_fallback_present": frontend_legacy,
        "backend_legacy_fallback_present": backend_legacy,
        "approved_local_origin": LOCAL_GOOGLE_ORIGIN,
        "required_private_fields": [
            "frontend-vue/.env.localdev:VUE_APP_CLIENTID",
            "backend-node/.env.local:GOOGLE_CLIENT_ID",
        ],
        "secrets_exposed": False,
    }
