from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from atdr.app.services.template_shell_auth import (
    BACKEND_SOURCE_RELATIVE,
    FRONTEND_SOURCE_RELATIVE,
    build_template_google_auth_status,
)


SIGN_IN_RELATIVE = Path("frontend-vue/src/projects/components/dialog/SignIn.vue")

_FRONTEND_CLIENT_RE = re.compile(
    r"clientId:\s*process\.env\.VUE_APP_CLIENTID(?:\s*\|\|\s*['\"][^'\"]+['\"])?"
)
_BACKEND_AUDIENCE_RE = re.compile(
    r"const audience\s*=\s*process\.env\.GOOGLE_CLIENT_ID"
    r"(?:\s*\|\|\s*process\.env\.VUE_APP_CLIENTID)?"
    r"(?:\s*\|\|\s*['\"][^'\"]+['\"])?\s*;",
    re.MULTILINE,
)


def _harden_frontend_source(content: str) -> str:
    if "const googleClientId = String(process.env.VUE_APP_CLIENTID || '').trim()" not in content:
        marker = "import GAuth from 'vue-google-oauth2'"
        if marker not in content:
            raise ValueError("MFU shell frontend Google initialization marker was not found.")
        block = (
            f"{marker}\n"
            "const googleClientId = String(process.env.VUE_APP_CLIENTID || '').trim()\n"
            "if (!googleClientId) {\n"
            "  throw new Error('MFU Google sign-in is not configured. Set VUE_APP_CLIENTID privately.')\n"
            "}"
        )
        content = content.replace(marker, block, 1)
    content, replacements = _FRONTEND_CLIENT_RE.subn("clientId: googleClientId", content, count=1)
    if replacements == 0 and "clientId: googleClientId" not in content:
        raise ValueError("MFU shell frontend Google client configuration could not be hardened.")
    return content


def _harden_backend_source(content: str) -> str:
    replacement = (
        "const audience = String(process.env.GOOGLE_CLIENT_ID || '').trim();\n"
        "            if (!audience) {\n"
        "                return response.status(503).json({\n"
        "                    success: false,\n"
        "                    code: 'AUTH_GOOGLE_NOT_CONFIGURED',\n"
        "                    message: 'MFU Google sign-in is not configured.'\n"
        "                });\n"
        "            }"
    )
    if "AUTH_GOOGLE_NOT_CONFIGURED" not in content:
        content, replacements = _BACKEND_AUDIENCE_RE.subn(replacement, content, count=1)
        if replacements != 1:
            raise ValueError("MFU shell backend Google audience configuration could not be hardened.")
    return content


def _harden_sign_in_source(content: str) -> str:
    if "googleSignInMessage(err)" not in content:
        marker = "        methods: {\n          async onAuthenGoogle()"
        replacement = (
            "        methods: {\n"
            "          googleSignInMessage(err) {\n"
            "            const code = String((err && (err.error || err.code || err.message)) || '').toLowerCase();\n"
            "            if (code.indexOf('popup_closed') >= 0) return 'MFU sign in was cancelled.';\n"
            "            if (code.indexOf('access_denied') >= 0) return 'This school account is not permitted for the configured application.';\n"
            "            if (code.indexOf('invalid_client') >= 0 || code.indexOf('invalid_request') >= 0 || code.indexOf('idpiframe') >= 0) {\n"
            "              return 'MFU Google sign in is not configured for this application origin. Contact the system administrator.';\n"
            "            }\n"
            "            return 'MFU sign in could not be completed. Check the school account and try again.';\n"
            "          },\n"
            "          async onAuthenGoogle()"
        )
        if marker not in content:
            raise ValueError("MFU shell sign-in method marker was not found.")
        content = content.replace(marker, replacement, 1)
    content = content.replace(
        "message: this.$t('auth.signIn.errors.google'),",
        "message: this.googleSignInMessage(err),",
        1,
    )
    return content


def harden_template_google_auth(
    template_root: Path,
    *,
    runtime_root: Path,
    apply: bool,
) -> dict[str, object]:
    root = template_root.expanduser().resolve()
    paths = {
        FRONTEND_SOURCE_RELATIVE: root / FRONTEND_SOURCE_RELATIVE,
        BACKEND_SOURCE_RELATIVE: root / BACKEND_SOURCE_RELATIVE,
        SIGN_IN_RELATIVE: root / SIGN_IN_RELATIVE,
    }
    missing = [relative.as_posix() for relative, path in paths.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Approved MFU shell source is incomplete: {', '.join(missing)}")

    original = {relative: path.read_text(encoding="utf-8") for relative, path in paths.items()}
    hardened = {
        FRONTEND_SOURCE_RELATIVE: _harden_frontend_source(original[FRONTEND_SOURCE_RELATIVE]),
        BACKEND_SOURCE_RELATIVE: _harden_backend_source(original[BACKEND_SOURCE_RELATIVE]),
        SIGN_IN_RELATIVE: _harden_sign_in_source(original[SIGN_IN_RELATIVE]),
    }
    changed = [relative for relative in paths if original[relative] != hardened[relative]]
    backup_directory: Path | None = None

    if apply and changed:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_directory = runtime_root.expanduser().resolve() / "template-backups" / stamp
        for relative in changed:
            backup_path = backup_directory / relative
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(paths[relative], backup_path)
            paths[relative].write_text(hardened[relative], encoding="utf-8")

    status = build_template_google_auth_status(root)
    return {
        "ok": bool((not apply and True) or status["ready"]),
        "mode": "apply" if apply else "check",
        "changes_required": bool(changed),
        "changed_file_count": len(changed) if apply else 0,
        "would_change_file_count": len(changed),
        "backup_created": bool(backup_directory),
        "source_hardened": not status["frontend_legacy_fallback_present"]
        and not status["backend_legacy_fallback_present"]
        if apply
        else not changed,
        "google_auth_ready": status["ready"] if apply else bool(status["ready"] and not changed),
        "diagnosis": status["diagnosis"],
        "secrets_exposed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove legacy Google client fallbacks from the approved MFU shell without exposing credentials."
    )
    parser.add_argument("--template-root", required=True)
    parser.add_argument("--runtime-root", default=".atdr_runtime")
    parser.add_argument("--apply", action="store_true", help="Apply the hardening changes; default is a read-only check.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = harden_template_google_auth(
        Path(args.template_root),
        runtime_root=Path(args.runtime_root),
        apply=args.apply,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    if args.apply and not report["google_auth_ready"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
