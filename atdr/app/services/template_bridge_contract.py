from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_TEMPLATE_DEFAULT = Path(r"C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response")

SECRET_NAME_RE = re.compile(r"(SECRET|PASSWORD|TOKEN|KEY|PRIVATE)", re.IGNORECASE)
ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")

REQUIRED_TEMPLATE_FILES = {
    "iam_overview_doc": "backend-node/docs/IAM_SYSTEM_OVERVIEW.md",
    "iam_adapter": "backend-node/server/integrations/iam/iam-sdk-adapter.js",
    "b2b_middleware": "backend-node/server/integrations/iam/b2b-auth-middleware.js",
    "project_iam_service": "backend-node/server/integrations/iam/project-iam-service.js",
    "auth_store": "frontend-vue/src/store/modules/Authen/index.js",
    "login_view": "frontend-vue/src/projects/views/Login.vue",
    "signin_dialog": "frontend-vue/src/projects/components/dialog/SignIn.vue",
    "twofa_dialog": "frontend-vue/src/projects/components/dialog/TwoFA.vue",
}

ATDR_HANDOFF_FILES = {
    "login_page": "frontend/src/pages/LoginPage.tsx",
    "auth_router": "atdr/app/routers/auth.py",
    "mfu_iam_service": "atdr/app/services/mfu_iam_service.py",
}

EXPECTED_TEMPLATE_MARKERS = {
    "stores_x_access_token": "x-access-token",
    "signin_action": "signIn",
    "twofa_action": "twofa",
    "twofa_verify_action": "twofaSend",
    "bearer_introspection": "introspectToken",
    "profile_endpoint": "getClientProfile",
}

EXPECTED_ATDR_MARKERS = {
    "accepts_mfu_token_query": "mfu_token",
    "accepts_x_access_token_query": "x_access_token",
    "clears_handoff_url": "replaceState",
    "token_login_endpoint": "/mfu-iam/token-login",
    "token_login_service": "authenticate_mfu_iam_token",
}


@dataclass(frozen=True)
class BridgePath:
    key: str
    relative_path: str
    exists: bool


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _env_files(template_root: Path) -> list[Path]:
    if not template_root.exists():
        return []
    return sorted(
        path
        for path in template_root.rglob(".env*")
        if path.is_file() and "node_modules" not in path.parts
    )


def _scan_env_names(template_root: Path) -> dict[str, Any]:
    env_names: set[str] = set()
    secret_names: set[str] = set()
    env_file_relpaths: list[str] = []
    for env_file in _env_files(template_root):
        env_file_relpaths.append(env_file.relative_to(template_root).as_posix())
        for line in _read_text(env_file).splitlines():
            match = ENV_LINE_RE.match(line)
            if not match:
                continue
            name = match.group(1)
            env_names.add(name)
            if SECRET_NAME_RE.search(name):
                secret_names.add(name)
    return {
        "env_files": env_file_relpaths,
        "env_var_names": sorted(env_names),
        "secret_like_env_var_names": sorted(secret_names),
        "values_redacted": True,
    }


def _path_status(root: Path, files: dict[str, str]) -> list[BridgePath]:
    return [
        BridgePath(key=key, relative_path=relative_path, exists=(root / relative_path).exists())
        for key, relative_path in files.items()
    ]


def _marker_status(root: Path, markers: dict[str, str], search_paths: list[str]) -> dict[str, bool]:
    corpus = "\n".join(_read_text(root / relative_path) for relative_path in search_paths)
    return {key: marker in corpus for key, marker in markers.items()}


def _as_dict(paths: list[BridgePath]) -> list[dict[str, Any]]:
    return [path.__dict__ for path in paths]


def build_template_bridge_contract_report(
    *,
    template_root: Path | str = PROJECT_TEMPLATE_DEFAULT,
    atdr_root: Path | str | None = None,
) -> dict[str, Any]:
    """Inspect the supervisor template-to-ATDR handoff contract without exposing secrets."""

    template_path = Path(template_root)
    atdr_path = Path(atdr_root) if atdr_root is not None else Path.cwd()
    template_paths = _path_status(template_path, REQUIRED_TEMPLATE_FILES)
    atdr_paths = _path_status(atdr_path, ATDR_HANDOFF_FILES)
    template_files_present = all(path.exists for path in template_paths)
    atdr_files_present = all(path.exists for path in atdr_paths)

    template_markers = _marker_status(
        template_path,
        EXPECTED_TEMPLATE_MARKERS,
        [path.relative_path for path in template_paths if path.exists],
    )
    atdr_markers = _marker_status(
        atdr_path,
        EXPECTED_ATDR_MARKERS,
        [path.relative_path for path in atdr_paths if path.exists],
    )
    env_summary = _scan_env_names(template_path)
    has_mfu_iam_env = all(
        name in env_summary["env_var_names"]
        for name in [
            "IAM_SDK_BASE_URL",
            "IAM_SDK_CLIENT_ID",
            "IAM_SDK_CLIENT_SECRET",
            "IAM_SDK_AUDIENCE",
            "IAM_SDK_INTROSPECT_PATH",
            "IAM_SDK_PROFILE_PATH",
        ]
    )

    template_contract_detected = template_files_present and all(template_markers.values()) and has_mfu_iam_env
    atdr_receiver_detected = atdr_files_present and all(atdr_markers.values())
    recommended_local_handoff_url = (
        "http://127.0.0.1:5173/login?"
        "mfu_token=<template_x_access_token_or_short_handoff_code>"
        "&next=/assistant&source=template-shell"
    )

    blockers: list[str] = []
    if not template_files_present:
        blockers.append("One or more expected supervisor-template IAM/login files are missing.")
    missing_template_markers = [key for key, present in template_markers.items() if not present]
    if missing_template_markers:
        blockers.append(f"Template marker(s) missing: {', '.join(missing_template_markers)}.")
    if not has_mfu_iam_env:
        blockers.append("Template IAM env variable names are incomplete or not found.")
    if not atdr_receiver_detected:
        blockers.append("ATDR handoff receiver markers are incomplete.")

    return {
        "ok": template_contract_detected and atdr_receiver_detected,
        "template_root": str(template_path),
        "template_exists": template_path.exists(),
        "template_files": _as_dict(template_paths),
        "atdr_files": _as_dict(atdr_paths),
        "template_markers": template_markers,
        "atdr_markers": atdr_markers,
        "env_summary": env_summary,
        "template_contract_detected": template_contract_detected,
        "atdr_receiver_detected": atdr_receiver_detected,
        "handoff_token_source": "template x-access-token after completed login/2FA, or a future short-lived handoff code",
        "atdr_handoff_parameters": ["mfu_token", "iam_token", "handoff_token", "atdr_handoff_token", "x_access_token", "access_token", "token", "handoff_code", "atdr_handoff_code", "code"],
        "recommended_local_handoff_url": recommended_local_handoff_url,
        "recommended_production_design": "Prefer a short-lived server-side handoff code over a long bearer token in a URL when the template runtime can support it.",
        "secrets_exposed": False,
        "blockers": blockers,
    }
