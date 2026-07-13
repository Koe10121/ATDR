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

SAFE_LAUNCHER_MARKER = "submitAtdrHandoff"
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
import { submitAtdrHandoff } from '@/projects/utils/atdr-handoff'

const ATDR_HANDOFF_CONSUME_URL = process.env.VUE_APP_ATDR_HANDOFF_CONSUME_URL || ''
"""

COMPUTED_ANCHOR = "  computed: {\n"
COMPUTED_PATCH = """  computed: {
    canOpenAtdr () {
      return Boolean(ATDR_HANDOFF_CONSUME_URL)
    },
"""

METHODS_ANCHOR = "  methods: {\n"
METHODS_PATCH = """  methods: {
    async openAtdrSocDashboard () {
      this.errorMessage = ''
      try {
        const response = await api.atdrHandoff('start', { return_to: '/assistant' })
        const data = response && response.data && response.data.data ? response.data.data : {}
        submitAtdrHandoff({
          consumeUrl: ATDR_HANDOFF_CONSUME_URL,
          handoffCode: data.handoff_code,
          returnTo: data.return_to || '/assistant'
        })
      } catch (error) {
        this.errorMessage = 'ATDR could not be opened. Sign in again or ask an administrator to check the secure handoff configuration.'
      }
    },
"""


def _replace_once(text: str, anchor: str, replacement: str, label: str) -> tuple[str, str | None]:
    if anchor not in text:
        return text, f"Missing insertion anchor: {label}"
    return text.replace(anchor, replacement, 1), None


def patch_registry_page(text: str) -> tuple[str, list[str], bool]:
    """Install a one-time form handoff launcher without putting tokens in URLs."""

    if SAFE_LAUNCHER_MARKER in text:
        return text, [], True
    if "openAtdrSocDashboard" in text:
        return text, ["Legacy ATDR launcher detected. Apply the v3.91 template handoff files before retrying."], False

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
        "next_template_env_hint": (
            "Set VUE_APP_ATDR_HANDOFF_CONSUME_URL=http://127.0.0.1:8000/api/auth/mfu-iam/handoff/consume "
            "only after the server-side bridge is configured."
        ),
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
        description="Add a secure one-time-code ATDR launcher to the official supervisor template registry page."
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
