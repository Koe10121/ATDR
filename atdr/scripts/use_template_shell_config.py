from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT


DEFAULT_TEMPLATE_BASE_URL = "http://127.0.0.1:8214"
DEFAULT_ALLOWED_DOMAINS = "lamduan.mfu.ac.th"
DEFAULT_ME_PATH = "/api/v1/auth/me"
DEFAULT_HEADER = "x-access-token"
DEFAULT_ROLE = "analyst"
DEFAULT_HANDOFF_EXCHANGE_PATH = "/api/v1/atdr/handoff/exchange"
DEFAULT_HANDOFF_FRONTEND_URL = "http://127.0.0.1:5173"
DEFAULT_HANDOFF_RETURN_PATHS = "/overview,/alerts,/logs,/assistant,/response,/audit,/ml"


def _parse_key(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    return stripped.split("=", 1)[0].strip()


def _quoted(value: str) -> str:
    return json.dumps(value)


def _template_shell_values(
    *,
    template_base_url: str,
    allowed_domains: str,
    default_role: str,
    me_path: str,
    header: str,
) -> dict[str, str]:
    return {
        "MFU_IAM_ENABLED": "true",
        "MFU_IAM_TEMPLATE_SHELL_ENABLED": "true",
        "MFU_IAM_TEMPLATE_SHELL_BASE_URL": _quoted(template_base_url.strip() or DEFAULT_TEMPLATE_BASE_URL),
        "MFU_IAM_TEMPLATE_SHELL_ME_PATH": _quoted(me_path.strip() or DEFAULT_ME_PATH),
        "MFU_IAM_TEMPLATE_SHELL_HEADER": _quoted(header.strip() or DEFAULT_HEADER),
        "MFU_IAM_ALLOWED_DOMAINS": _quoted(allowed_domains.strip() or DEFAULT_ALLOWED_DOMAINS),
        "MFU_IAM_DEFAULT_ROLE": _quoted(default_role.strip() or DEFAULT_ROLE),
        # The bridge stays off until both independent services have the same private
        # shared secret and approved origins. This helper never writes that secret.
        "MFU_IAM_HANDOFF_ENABLED": "false",
        "MFU_IAM_HANDOFF_EXCHANGE_PATH": _quoted(DEFAULT_HANDOFF_EXCHANGE_PATH),
        "MFU_IAM_HANDOFF_FRONTEND_URL": _quoted(DEFAULT_HANDOFF_FRONTEND_URL),
        "MFU_IAM_HANDOFF_ALLOWED_ORIGINS": '""',
        "MFU_IAM_HANDOFF_ALLOWED_RETURN_PATHS": _quoted(DEFAULT_HANDOFF_RETURN_PATHS),
        "MFU_IAM_ADMIN_GROUPS": '""',
    }


def build_template_shell_env_lines(
    content: str,
    *,
    template_base_url: str = DEFAULT_TEMPLATE_BASE_URL,
    allowed_domains: str = DEFAULT_ALLOWED_DOMAINS,
    default_role: str = DEFAULT_ROLE,
    me_path: str = DEFAULT_ME_PATH,
    header: str = DEFAULT_HEADER,
) -> tuple[str, list[dict[str, str]]]:
    values = _template_shell_values(
        template_base_url=template_base_url,
        allowed_domains=allowed_domains,
        default_role=default_role,
        me_path=me_path,
        header=header,
    )
    lines = content.splitlines()
    seen: set[str] = set()
    changes: list[dict[str, str]] = []
    output: list[str] = []

    for line in lines:
        key = _parse_key(line)
        if key in values:
            desired = f"{key}={values[key]}"
            seen.add(key)
            if line.strip() != desired:
                changes.append({"key": key, "action": "replace"})
                output.append(desired)
            else:
                output.append(line)
            continue
        output.append(line)

    missing = [key for key in values if key not in seen]
    if missing:
        if output and output[-1].strip():
            output.append("")
        output.append("# Template shell handoff profile enforced by atdr.scripts.use_template_shell_config")
        for key in missing:
            output.append(f"{key}={values[key]}")
            changes.append({"key": key, "action": "append"})

    newline = "\n" if content.endswith(("\n", "\r\n")) else ""
    return "\n".join(output) + newline, changes


def apply_template_shell_config(
    *,
    env_path: Path,
    write: bool,
    template_base_url: str = DEFAULT_TEMPLATE_BASE_URL,
    allowed_domains: str = DEFAULT_ALLOWED_DOMAINS,
    default_role: str = DEFAULT_ROLE,
    me_path: str = DEFAULT_ME_PATH,
    header: str = DEFAULT_HEADER,
) -> dict[str, Any]:
    env_path = env_path if env_path.is_absolute() else PROJECT_ROOT / env_path
    if env_path.exists():
        content = env_path.read_text(encoding="utf-8")
    else:
        source = PROJECT_ROOT / ".env.example"
        content = source.read_text(encoding="utf-8") if source.exists() else ""

    updated, changes = build_template_shell_env_lines(
        content,
        template_base_url=template_base_url,
        allowed_domains=allowed_domains,
        default_role=default_role,
        me_path=me_path,
        header=header,
    )
    result: dict[str, Any] = {
        "ok": True,
        "env_path": str(env_path),
        "write": write,
        "would_change": bool(changes),
        "changes": changes,
        "template_base_url": template_base_url,
        "allowed_domains": [domain.strip() for domain in allowed_domains.split(",") if domain.strip()],
        "default_role": default_role,
        "handoff_enabled": False,
        "handoff_shared_secret_written": False,
        "admin_mapping_changed": False,
        "secrets_exposed": False,
        "recommendation": (
            "Review the generated non-secret settings, then configure the same private handoff shared secret and "
            "approved template origin in both services before enabling MFU_IAM_HANDOFF_ENABLED. "
            "Run validate_template_shell_runtime --check-runtime after both services are running."
        ),
    }

    if not write:
        return result

    backup_path = None
    if env_path.exists():
        backup_dir = PROJECT_ROOT / ".tmp" / "env-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = backup_dir / f".env.template-shell.{stamp}.bak"
        shutil.copy2(env_path, backup_path)
    env_path.write_text(updated, encoding="utf-8")
    result["backup_path"] = str(backup_path) if backup_path is not None else None
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely prepare private ATDR .env values for supervisor-template shell handoff."
    )
    parser.add_argument("--env-path", default=".env", help="Path to the .env file relative to the project root.")
    parser.add_argument("--template-base-url", default=DEFAULT_TEMPLATE_BASE_URL, help="Template backend base URL.")
    parser.add_argument("--allowed-domains", default=DEFAULT_ALLOWED_DOMAINS, help="Comma-separated school email domains.")
    parser.add_argument("--default-role", default=DEFAULT_ROLE, choices=["analyst", "admin"], help="Default role for mapped school users.")
    parser.add_argument("--me-path", default=DEFAULT_ME_PATH, help="Template profile endpoint path.")
    parser.add_argument("--header", default=DEFAULT_HEADER, help="Template session header name.")
    parser.add_argument("--write", action="store_true", help="Write changes. Default is dry-run only.")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes only. This is the default.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    result = apply_template_shell_config(
        env_path=Path(args.env_path),
        write=bool(args.write and not args.dry_run),
        template_base_url=args.template_base_url,
        allowed_domains=args.allowed_domains,
        default_role=args.default_role,
        me_path=args.me_path,
        header=args.header,
    )
    print(json.dumps(result, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
