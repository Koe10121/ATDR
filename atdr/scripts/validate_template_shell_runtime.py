from __future__ import annotations

import argparse
import json
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


def _handoff_status_path(settings: Settings) -> str:
    exchange_path = settings.mfu_iam_handoff_exchange_path.strip() or "/api/v1/atdr/handoff/exchange"
    return exchange_path.rsplit("/", 1)[0] + "/status"


def _check_template_handoff_endpoint(settings: Settings, *, timeout: float) -> dict[str, Any]:
    if not settings.mfu_iam_template_shell_base_url.strip():
        return {
            "checked": False,
            "reachable": False,
            "handoff_status_detected": False,
            "message": "MFU_IAM_TEMPLATE_SHELL_BASE_URL is not configured.",
        }

    url = _join_url(settings.mfu_iam_template_shell_base_url, _handoff_status_path(settings))
    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        return {
            "checked": True,
            "reachable": False,
            "handoff_status_detected": False,
            "safe_error": _safe_http_error(exc),
        }

    payload: Any = None
    if response.headers.get("content-type", "").lower().startswith("application/json"):
        try:
            payload = response.json()
        except ValueError:
            payload = None
    data = payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), dict) else payload
    return {
        "checked": True,
        "reachable": response.status_code < 500,
        "status_code": response.status_code,
        "handoff_status_detected": bool(isinstance(data, dict) and "enabled" in data),
        "handoff_enabled": bool(data.get("enabled")) if isinstance(data, dict) else False,
        "consume_url_configured": bool(data.get("consumeUrlConfigured")) if isinstance(data, dict) else False,
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
        "handoff_ready": False,
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
                result["handoff_ready"] = bool(payload.get("handoff_ready"))
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
    timeout: float = 3.0,
) -> dict[str, Any]:
    runtime_settings = settings or get_settings()
    mfu_status = build_mfu_iam_status(runtime_settings)
    contract = build_template_bridge_contract_report(template_root=template_root, atdr_root=atdr_root or Path.cwd())
    template_check: dict[str, Any] = {"checked": False, "message": "Pass --check-runtime to probe running services."}
    atdr_check: dict[str, Any] = {"checked": False, "message": "Pass --check-runtime to probe running services."}

    if check_runtime:
        template_check = _check_template_handoff_endpoint(runtime_settings, timeout=timeout)
        atdr_check = _check_atdr_api(runtime_settings, timeout=timeout)

    blocking_config_issues: list[str] = []
    if not runtime_settings.template_shell_required:
        blocking_config_issues.append("ATDR_AUTH_MODE is not template_shell.")
    if not mfu_status["enabled"]:
        blocking_config_issues.append("MFU_IAM_ENABLED is false; mandatory shell authentication cannot start.")
    if not mfu_status["template_shell_enabled"]:
        blocking_config_issues.append("MFU_IAM_TEMPLATE_SHELL_ENABLED is false.")
    if not mfu_status["template_shell_base_url_configured"]:
        blocking_config_issues.append("MFU_IAM_TEMPLATE_SHELL_BASE_URL is not configured.")
    if not mfu_status["handoff_enabled"]:
        blocking_config_issues.append("MFU_IAM_HANDOFF_ENABLED is false.")
    if not mfu_status["handoff_secret_configured"]:
        blocking_config_issues.append("MFU_IAM_HANDOFF_SHARED_SECRET is not configured.")
    if not mfu_status["handoff_allowed_origins_configured"]:
        blocking_config_issues.append("MFU_IAM_HANDOFF_ALLOWED_ORIGINS is not configured.")
    if not mfu_status["allowed_domains"]:
        blocking_config_issues.append("MFU_IAM_ALLOWED_DOMAINS is not configured.")

    ok = bool(contract["ok"] and mfu_status["handoff_ready"])
    if check_runtime:
        ok = bool(
            ok
            and atdr_check.get("public_status_reachable")
            and atdr_check.get("handoff_ready")
            and template_check.get("reachable")
            and template_check.get("handoff_status_detected")
        )

    if not contract["ok"]:
        recommended_next_step = "Repair the reported static shell/ATDR contract blockers, then rerun this validation."
    elif blocking_config_issues:
        recommended_next_step = "Repair the reported ATDR handoff configuration issues, then rerun this validation."
    elif not check_runtime:
        recommended_next_step = (
            "Start all four services, rerun with --check-runtime, and validate Google/MFU provider readiness separately "
            "with template_auth_doctor."
        )
    elif ok:
        recommended_next_step = (
            "Static and runtime handoff checks passed. Complete one approved MFU account sign-in to record provider "
            "acceptance."
        )
    else:
        recommended_next_step = "Repair the reported runtime service or handoff-status failure, then rerun this validation."

    return {
        "ok": ok,
        "static_contract_ok": contract["ok"],
        "template_root": contract["template_root"],
        "template_exists": contract["template_exists"],
        "template_contract_detected": contract["template_contract_detected"],
        "atdr_receiver_detected": contract["atdr_receiver_detected"],
        "launcher_expected": True,
        "mfu_iam": {
            "auth_mode": mfu_status["auth_mode"],
            "local_login_enabled": mfu_status["local_login_enabled"],
            "template_shell_required": mfu_status["template_shell_required"],
            "enabled": mfu_status["enabled"],
            "mode": mfu_status["mode"],
            "template_shell_enabled": mfu_status["template_shell_enabled"],
            "template_shell_ready": mfu_status["template_shell_ready"],
            "template_shell_base_url_configured": mfu_status["template_shell_base_url_configured"],
            "handoff_enabled": mfu_status["handoff_enabled"],
            "handoff_ready": mfu_status["handoff_ready"],
            "allowed_domains": mfu_status["allowed_domains"],
            "default_role": mfu_status["default_role"],
            "admin_group_mapping_configured": mfu_status["admin_group_mapping_configured"],
            "secrets_exposed": False,
        },
        "blocking_config_issues": blocking_config_issues,
        "template_runtime": template_check,
        "atdr_runtime": atdr_check,
        "secrets_exposed": False,
        "recommended_next_step": recommended_next_step,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate ATDR's secure supervisor-template shell handoff readiness without exposing secrets."
    )
    parser.add_argument("--template-root", default=str(PROJECT_TEMPLATE_DEFAULT), help="Official supervisor template root.")
    parser.add_argument("--atdr-root", default=".", help="ATDR repo root.")
    parser.add_argument("--check-runtime", action="store_true", help="Probe running ATDR/template services.")
    parser.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    report = build_template_shell_runtime_report(
        template_root=Path(args.template_root),
        atdr_root=Path(args.atdr_root),
        check_runtime=args.check_runtime,
        timeout=args.timeout,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
