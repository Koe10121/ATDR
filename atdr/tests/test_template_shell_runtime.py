from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import Settings
from atdr.app.services.template_bridge_contract import ATDR_HANDOFF_FILES, REQUIRED_TEMPLATE_FILES
from atdr.scripts import validate_template_shell_runtime
from atdr.scripts.validate_template_shell_runtime import build_template_shell_runtime_report


def _write(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_complete_template(root: Path) -> None:
    marker_text = """
    x-access-token
    signIn
    twofa
    twofaSend
    introspectToken
    getClientProfile
    /atdr/handoff/start
    /exchange
    handoff_code
    /mfu-ai-driven-log-based-threat-detection-and-response/registry
    submitAtdrHandoff
    """
    for relative_path in REQUIRED_TEMPLATE_FILES.values():
        _write(root, relative_path, marker_text)
    _write(
        root,
        "backend-node/.env.local",
        "\n".join(
            [
                "IAM_SDK_BASE_URL=https://iam.example.test",
                "IAM_SDK_CLIENT_ID=atdr-template-local",
                "IAM_SDK_CLIENT_SECRET=secret-value-that-must-not-leak",
                "IAM_SDK_AUDIENCE=atdr-api",
                "IAM_SDK_INTROSPECT_PATH=/api/v1/b2b/introspect",
                "IAM_SDK_PROFILE_PATH=/api/v1/b2b/clients/me",
            ]
        ),
    )


def _write_complete_atdr(root: Path) -> None:
    marker_text = """
    /mfu-iam/handoff/consume
    authenticate_mfu_iam_handoff_code
    httponly=True
    userToCookieSession
    legacy browser-token handoff
    """
    for relative_path in ATDR_HANDOFF_FILES.values():
        _write(root, relative_path, marker_text)


def _template_shell_settings() -> Settings:
    return Settings(
        MFU_IAM_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_BASE_URL="http://template-shell.test",
        MFU_IAM_ALLOWED_DOMAINS="lamduan.mfu.ac.th",
        MFU_IAM_DEFAULT_ROLE="analyst",
        MFU_IAM_HANDOFF_ENABLED=True,
        MFU_IAM_HANDOFF_SHARED_SECRET="test-bridge-secret-that-must-not-leak",
        MFU_IAM_HANDOFF_FRONTEND_URL="http://127.0.0.1:5173",
        MFU_IAM_HANDOFF_ALLOWED_ORIGINS="http://template-shell.test",
    )


def test_template_shell_runtime_static_report_is_secret_safe(tmp_path):
    template_root = tmp_path / "template"
    atdr_root = tmp_path / "atdr"
    _write_complete_template(template_root)
    _write_complete_atdr(atdr_root)

    report = build_template_shell_runtime_report(
        template_root=template_root,
        atdr_root=atdr_root,
        settings=_template_shell_settings(),
    )
    rendered = json.dumps(report)

    assert report["ok"] is True
    assert report["static_contract_ok"] is True
    assert report["mfu_iam"]["mode"] == "template_shell_secure_handoff"
    assert report["mfu_iam"]["handoff_ready"] is True
    assert report["blocking_config_issues"] == []
    assert report["secrets_exposed"] is False
    assert "secret-value-that-must-not-leak" not in rendered
    assert "test-bridge-secret-that-must-not-leak" not in rendered


def test_template_shell_runtime_check_detects_safe_handoff_status(tmp_path, monkeypatch):
    template_root = tmp_path / "template"
    atdr_root = tmp_path / "atdr"
    _write_complete_template(template_root)
    _write_complete_atdr(atdr_root)

    class FakeResponse:
        def __init__(self, status_code: int, payload: dict[str, Any] | None = None):
            self.status_code = status_code
            self._payload = payload or {}
            self.headers = {"content-type": "application/json"}

        def json(self) -> dict[str, Any]:
            return self._payload

    def fake_get(url: str, **kwargs):
        assert "x-access-token" not in (kwargs.get("headers") or {})
        if url == "http://template-shell.test/api/v1/atdr/handoff/status":
            return FakeResponse(200, {"data": {"enabled": True, "consumeUrlConfigured": True}})
        if url == "http://127.0.0.1:8000/health":
            return FakeResponse(200, {"status": "ok"})
        if url == "http://127.0.0.1:8000/api/auth/mfu-iam/public-status":
            return FakeResponse(200, {"template_shell_ready": True, "handoff_ready": True, "mode": "template_shell_secure_handoff"})
        return FakeResponse(404)

    monkeypatch.setattr(validate_template_shell_runtime.requests, "get", fake_get)

    report = build_template_shell_runtime_report(
        template_root=template_root,
        atdr_root=atdr_root,
        settings=_template_shell_settings(),
        check_runtime=True,
    )

    assert report["ok"] is True
    assert report["template_runtime"]["reachable"] is True
    assert report["template_runtime"]["handoff_status_detected"] is True
    assert report["atdr_runtime"]["health_reachable"] is True
    assert report["atdr_runtime"]["handoff_ready"] is True
