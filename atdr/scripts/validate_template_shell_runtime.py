from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import requests

from atdr.app.core.config import Settings, get_settings
from atdr.app.services.mfu_iam_service import build_mfu_iam_status
from atdr.app.services.template_bridge_contract import (
    PROJECT_TEMPLATE_DEFAULT,
    build_template_bridge_contract_report,
)


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _safe_http_error(exc: Exception) -> dict[str, str]:
    return {
        "error_type": exc.__class__.__name__,
        "message": "Runtime check failed. Confirm the service is running and the configured URL is correct.",
    }


def _template_profile_payload_has_email(payload: Any) -> bool:
    if isinstance(payload, dict):
        return any(_template_profile_payload_has_email(value) for value in payload.values())
    if isinstance(payload, list):
        return any(_template_profile_payload_has_email(value) for value in payload)
    return isinstance(payload, str) and "@" in payload


def _check_template_profile_endpoint(settings: Settings, *, token: str | None, timeout: float) -> dict[str, Any]:
    if not settings.mfu_iam_template_shell_base_url.strip():
        return {
            "checked": False,
            "reachable": False,
            "protected_endpoint_detected": False,
            "session_validated": False,
            "message": "MFU_IAM_TEMPLATE_SHELL_BASE_URL is not configured.",
        }

    url = _join_url(settings.mfu_iam_template_shell_base_url, settings.mfu_iam_template_shell_me_path)
    headers = {}
    if token:
        headers[settings.mfu_iam_template_shell_header.strip() or "x-access-token"] = token

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        return {
            "checked": True,
            "reachable": False,
            "protected_endpoint_detected": False,
            "session_validated": False,
            "safe_error": _safe_http_error(exc),
        }

    payload: Any = None
    if response.headers.get("content-type", "").lower().startswith("application/json"):
        try:
            payload = response.json()
        except ValueError:
            payload = None

    session_validated = bool(token and response.status_code < 400 and _template_profile_payload_has_email(payload))
    return {
        "checked": True,
        "reachable": response.status_code < 500,
        "status_code": response.status_code,
        "protected_endpoint_detected": response.status_code in {400, 401, 403} and not token,
        "session_token_provided": bool(token),
        "session_validated": session_validated,
        "profile_email_present": bool(session_validated),
        "secrets_exposed": False,
    }


def _check_atdr_api(settings: Settings, *, timeout: float) -> dict[str, Any]:
    health_url = _join_url(settings.api_base_url, "/health")
    status_url = _join_url(settings.api_base_url, "/api/auth/mfu-iam/public-status")
    result: dict[str, Any] = {
        "checked": True,
        "base_url": settings.api_base_url,
        "health_reachable": False,
        "public_status_reachable": False,
        "template_shell_ready": False,
        "token_login_ready": False,
        "secrets_exposed": False,
    }
    try:
        health_response = requests.get(health_url, timeout=timeout)
        result["health_reachable"] = health_response.status_code < 500
        result["health_status_code"] = health_response.status_code
    except requests.RequestException as exc:
        result["health_error"] = _safe_http_error(exc)

    try:
        status_response = requests.get(status_url, timeout=timeout)
        result["public_status_reachable"] = status_response.status_code == 200
        result["public_status_code"] = status_response.status_code
        if status_response.status_code == 200:
            payload = status_response.json()
            if isinstance(payload, dict):
                result["template_shell_ready"] = bool(payload.get("template_shell_ready"))
                result["token_login_ready"] = bool(payload.get("token_login_ready"))
                result["mode"] = payload.get("mode")
    except (requests.RequestException, ValueError) as exc:
        result["public_status_error"] = _safe_http_error(exc)
    return result


def build_template_shell_runtime_report(
    *,
    template_root: Path | str = PROJECT_TEMPLATE_DEFAULT,
    atdr_root: Path | str | None = None,
    settings: Settings | None = None,
    check_runtime: bool = False,
    session_token_env: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    runtime_settings = settings or get_settings()
    mfu_status = build_mfu_iam_status(runtime_settings)
    contract = build_template_bridge_contract_report(template_root=template_root, atdr_root=atdr_root or Path.cwd())
    token = os.environ.get(session_token_env or "") if session_token_env else None
    template_check: dict[str, Any] = {"checked": False, "message": "Pass --check-runtime to probe running services."}
    atdr_check: dict[str, Any] = {"checked": False, "message": "Pass --check-runtime to probe running services."}

    if check_runtime:
        template_check = _check_template_profile_endpoint(runtime_settings, token=token, timeout=timeout)
        atdr_check = _check_atdr_api(runtime_settings, timeout=timeout)

    blocking_config_issues = []
    if not mfu_status["enabled"]:
        blocking_config_issues.append("MFU_IAM_ENABLED is false; ATDR will stay in local-login mode.")
    if not mfu_status["template_shell_enabled"]:
        blocking_config_issues.append("MFU_IAM_TEMPLATE_SHELL_ENABLED is false.")
    if not mfu_status["template_shell_base_url_configured"]:
        blocking_config_issues.append("MFU_IAM_TEMPLATE_SHELL_BASE_URL is not configured.")
    if not mfu_status["allowed_domains"]:
        blocking_config_issues.append("MFU_IAM_ALLOWED_DOMAINS is not configured.")

    ok = bool(contract["ok"] and mfu_status["template_shell_ready"])
    if check_runtime:
        ok = bool(ok and atdr_check.get("public_status_reachable") and template_check.get("reachable"))

    return {
        "ok": ok,
        "static_contract_ok": contract["ok"],
        "template_root": contract["template_root"],
        "template_exists": contract["template_exists"],
        "template_contract_detected": contract["template_contract_detected"],
        "atdr_receiver_detected": contract["atdr_receiver_detected"],
        "launcher_expected": True,
        "mfu_iam": {
            "enabled": mfu_status["enabled"],
            "mode": mfu_status["mode"],
            "token_login_ready": mfu_status["token_login_ready"],
            "template_shell_enabled": mfu_status["template_shell_enabled"],
            "template_shell_ready": mfu_status["template_shell_ready"],
            "template_shell_base_url_configured": mfu_status["template_shell_base_url_configured"],
            "template_shell_me_path": mfu_status["template_shell_me_path"],
            "allowed_domains": mfu_status["allowed_domains"],
            "default_role": mfu_status["default_role"],
            "admin_email_mapping_configured": mfu_status["admin_email_mapping_configured"],
            "secrets_exposed": False,
        },
        "blocking_config_issues": blocking_config_issues,
        "template_runtime": template_check,
        "atdr_runtime": atdr_check,
        "session_token_env_used": bool(session_token_env),
        "session_token_present": bool(token),
        "secrets_exposed": False,
        "recommended_next_step": (
            "Start the template backend/frontend and ATDR backend/frontend, enable the private template-shell IAM settings, "
            "then run this command with --check-runtime. Use a session token env var only for a manual real-session probe."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate ATDR's supervisor-template shell handoff readiness without exposing secrets."
    )
    parser.add_argument("--template-root", default=str(PROJECT_TEMPLATE_DEFAULT), help="Official supervisor template root.")
    parser.add_argument("--atdr-root", default=".", help="ATDR repo root.")
    parser.add_argument("--check-runtime", action="store_true", help="Probe running ATDR/template services.")
    parser.add_argument(
        "--session-token-env",
        default="",
        help="Optional environment variable name containing a template session token for a manual profile probe.",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    report = build_template_shell_runtime_report(
        template_root=Path(args.template_root),
        atdr_root=Path(args.atdr_root),
        check_runtime=args.check_runtime,
        session_token_env=args.session_token_env or None,
        timeout=args.timeout,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
