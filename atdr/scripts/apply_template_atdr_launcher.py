from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.services.template_bridge_contract import PROJECT_TEMPLATE_DEFAULT

TARGET_RELATIVE_PATH = Path(
    "frontend-vue/src/projects/views/mfuaidrivenlogbasedthreatdetectionandresponse/"
    "MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue"
)

LAUNCHER_MARKER = "openAtdrSocDashboard"
BUTTON_ANCHOR = """        <CButton color="primary" variant="outline" :disabled="loading" @click="fetchAll">
          <CIcon name="cil-reload" class="mr-2" />
          Refresh
        </CButton>"""
BUTTON_PATCH = """        <CButton color="primary" :disabled="!canOpenAtdr" @click="openAtdrSocDashboard">
          <CIcon name="cil-shield-alt" class="mr-2" />
          Open ATDR SOC Dashboard
        </CButton>
        <CButton color="primary" variant="outline" :disabled="loading" @click="fetchAll">
          <CIcon name="cil-reload" class="mr-2" />
          Refresh
        </CButton>"""

IMPORT_ANCHOR = "import api from '@/service/api'\n"
IMPORT_PATCH = """import api from '@/service/api'

const ATDR_DASHBOARD_URL = process.env.VUE_APP_ATDR_DASHBOARD_URL || 'http://127.0.0.1:5173'
const X_ACCESS_TOKEN_STORAGE_KEY = 'x-access-token'
"""

COMPUTED_ANCHOR = "  computed: {\n"
COMPUTED_PATCH = """  computed: {
    canOpenAtdr () {
      return Boolean(this.getTemplateAccessToken())
    },
"""

METHODS_ANCHOR = "  methods: {\n"
METHODS_PATCH = """  methods: {
    getTemplateAccessToken () {
      try {
        const stateToken = this.$store && this.$store.state && this.$store.state.XAccessToken
        if (stateToken && String(stateToken).trim()) {
          return String(stateToken).trim()
        }
      } catch (error) {
        // Fall back to browser storage below.
      }
      try {
        const stored = window && window.localStorage
          ? window.localStorage.getItem(X_ACCESS_TOKEN_STORAGE_KEY)
          : ''
        return stored && String(stored).trim() ? String(stored).trim() : ''
      } catch (error) {
        return ''
      }
    },
    openAtdrSocDashboard () {
      const handoffValue = this.getTemplateAccessToken()
      if (!handoffValue) {
        this.errorMessage = 'Sign in again before opening ATDR.'
        return
      }
      const target = new URL('/login', ATDR_DASHBOARD_URL)
      target.searchParams.set('mfu_token', handoffValue)
      target.searchParams.set('next', '/assistant')
      target.searchParams.set('source', 'template-shell')
      window.location.assign(target.toString())
    },
"""


def _replace_once(text: str, anchor: str, replacement: str, label: str) -> tuple[str, str | None]:
    if anchor not in text:
        return text, f"Missing insertion anchor: {label}"
    return text.replace(anchor, replacement, 1), None


def patch_registry_page(text: str) -> tuple[str, list[str], bool]:
    """Return patched template page text, warnings, and whether it was already installed."""

    if LAUNCHER_MARKER in text:
        return text, [], True

    warnings: list[str] = []
    patched = text
    for anchor, replacement, label in [
        (BUTTON_ANCHOR, BUTTON_PATCH, "registry header actions"),
        (IMPORT_ANCHOR, IMPORT_PATCH, "api import"),
        (COMPUTED_ANCHOR, COMPUTED_PATCH, "computed block"),
        (METHODS_ANCHOR, METHODS_PATCH, "methods block"),
    ]:
        patched, warning = _replace_once(patched, anchor, replacement, label)
        if warning:
            warnings.append(warning)

    if warnings:
        return text, warnings, False
    return patched, warnings, False


def build_report(template_root: Path, *, write: bool = False, backup: bool = True) -> dict[str, Any]:
    target = template_root / TARGET_RELATIVE_PATH
    report: dict[str, Any] = {
        "ok": False,
        "write_requested": write,
        "template_root": str(template_root),
        "target_relative_path": TARGET_RELATIVE_PATH.as_posix(),
        "target_exists": target.exists(),
        "already_installed": False,
        "would_change": False,
        "changed": False,
        "backup_created": None,
        "warnings": [],
        "secrets_exposed": False,
        "next_template_env_hint": "Set VUE_APP_ATDR_DASHBOARD_URL=http://127.0.0.1:5173 in the template frontend env for local testing.",
    }
    if not target.exists():
        report["warnings"].append("Template registry page was not found.")
        return report

    original = target.read_text(encoding="utf-8", errors="replace")
    patched, warnings, already_installed = patch_registry_page(original)
    report["already_installed"] = already_installed
    report["warnings"] = warnings
    report["would_change"] = patched != original
    report["ok"] = not warnings

    if warnings or already_installed or not write or patched == original:
        return report

    if backup:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = target.with_suffix(target.suffix + f".bak-{stamp}")
        shutil.copy2(target, backup_path)
        report["backup_created"] = str(backup_path)
    target.write_text(patched, encoding="utf-8")
    report["changed"] = True
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add a safe ATDR launcher button to the official supervisor template registry page."
    )
    parser.add_argument(
        "--template-root",
        default=str(PROJECT_TEMPLATE_DEFAULT),
        help="Path to the official supervisor template project.",
    )
    parser.add_argument("--write", action="store_true", help="Apply the patch. Default is dry-run only.")
    parser.add_argument("--no-backup", action="store_true", help="Do not create a backup when --write is used.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    report = build_report(Path(args.template_root), write=args.write, backup=not args.no_backup)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
