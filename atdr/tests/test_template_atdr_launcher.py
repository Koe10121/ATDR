from __future__ import annotations

from pathlib import Path

from atdr.scripts.apply_template_atdr_launcher import TARGET_RELATIVE_PATH, build_report, patch_registry_page


TEMPLATE_PAGE = """<template>
  <div>
    <div class="mfuaidrivenlogbasedthreatdetectionandresponse-header__actions">
        <CButton color="primary" variant="outline" :disabled="loading" @click="fetchAll">
          <CIcon name="cil-reload" class="mr-2" />
          Refresh
        </CButton>
    </div>
  </div>
</template>

<script>
import api from '@/service/api'

export default {
  computed: {
    statCards () {
      return []
    }
  },
  methods: {
    async fetchAll () {
      return Promise.all([this.fetchStats(), this.fetchDocuments()])
    }
  }
}
</script>
"""


def _write_template_page(root: Path, content: str = TEMPLATE_PAGE) -> Path:
    target = root / TARGET_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def test_patch_registry_page_adds_atdr_launcher_once():
    patched, warnings, already_installed = patch_registry_page(TEMPLATE_PAGE)

    assert not warnings
    assert already_installed is False
    assert "openAtdrSocDashboard" in patched
    assert "VUE_APP_ATDR_DASHBOARD_URL" in patched
    assert "x-access-token" in patched
    assert "mfu_token" in patched
    assert "source', 'template-shell'" in patched

    patched_again, second_warnings, second_already_installed = patch_registry_page(patched)
    assert not second_warnings
    assert second_already_installed is True
    assert patched_again == patched


def test_launcher_dry_run_does_not_write_template(tmp_path):
    target = _write_template_page(tmp_path)
    before = target.read_text(encoding="utf-8")

    report = build_report(tmp_path, write=False)

    assert report["ok"] is True
    assert report["write_requested"] is False
    assert report["would_change"] is True
    assert report["changed"] is False
    assert report["secrets_exposed"] is False
    assert target.read_text(encoding="utf-8") == before


def test_launcher_write_creates_backup_and_patches_template(tmp_path):
    target = _write_template_page(tmp_path)

    report = build_report(tmp_path, write=True)

    assert report["ok"] is True
    assert report["changed"] is True
    assert report["backup_created"]
    assert Path(report["backup_created"]).exists()
    patched = target.read_text(encoding="utf-8")
    assert "Open ATDR SOC Dashboard" in patched
    assert "openAtdrSocDashboard" in patched
    assert "template_x_access_token" not in str(report)
