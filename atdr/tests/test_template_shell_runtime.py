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
    mfu_token
    x_access_token
    replaceState
    /mfu-iam/token-login
    authenticate_mfu_iam_token
    """
    for relative_path in ATDR_HANDOFF_FILES.values():
        _write(root, relative_path, marker_text)


def _template_shell_settings() -> Settings:
    return Settings(
        MFU_IAM_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_BASE_URL="http://template-shell.test",
        MFU_IAM_TEMPLATE_SHELL_ME_PATH="/api/v1/auth/me",
        MFU_IAM_TEMPLATE_SHELL_HEADER="x-access-token",
        MFU_IAM_ALLOWED_DOMAINS="lamduan.mfu.ac.th",
        MFU_IAM_DEFAULT_ROLE="analyst",
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
    assert report["mfu_iam"]["mode"] == "template_shell_session_handoff"
    assert report["mfu_iam"]["template_shell_ready"] is True
    assert report["blocking_config_issues"] == []
    assert report["secrets_exposed"] is False
    assert "secret-value-that-must-not-leak" not in rendered


def test_template_shell_runtime_check_detects_protected_template_endpoint(tmp_path, monkeypatch):
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
        if url == "http://template-shell.test/api/v1/auth/me":
            assert kwargs.get("headers") == {}
            return FakeResponse(401, {"message": "unauthorized"})
        if url == "http://127.0.0.1:8000/health":
            return FakeResponse(200, {"status": "ok"})
        if url == "http://127.0.0.1:8000/api/auth/mfu-iam/public-status":
            return FakeResponse(
                200,
                {
                    "template_shell_ready": True,
                    "token_login_ready": True,
                    "mode": "template_shell_session_handoff",
                },
            )
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
    assert report["template_runtime"]["protected_endpoint_detected"] is True
    assert report["atdr_runtime"]["health_reachable"] is True
    assert report["atdr_runtime"]["template_shell_ready"] is True


def test_template_shell_runtime_session_probe_hides_token_and_email(tmp_path, monkeypatch):
    template_root = tmp_path / "template"
    atdr_root = tmp_path / "atdr"
    _write_complete_template(template_root)
    _write_complete_atdr(atdr_root)
    token = "template-session-secret-that-must-not-leak"
    email = "student@lamduan.mfu.ac.th"
    monkeypatch.setenv("ATDR_TEMPLATE_SESSION_TOKEN", token)

    class FakeResponse:
        def __init__(self, status_code: int, payload: dict[str, Any] | None = None):
            self.status_code = status_code
            self._payload = payload or {}
            self.headers = {"content-type": "application/json"}

        def json(self) -> dict[str, Any]:
            return self._payload

    def fake_get(url: str, **kwargs):
        if url == "http://template-shell.test/api/v1/auth/me":
            assert kwargs["headers"]["x-access-token"] == token
            return FakeResponse(200, {"data": {"email": email}})
        if url == "http://127.0.0.1:8000/health":
            return FakeResponse(200, {"status": "ok"})
        if url == "http://127.0.0.1:8000/api/auth/mfu-iam/public-status":
            return FakeResponse(200, {"template_shell_ready": True, "token_login_ready": True})
        return FakeResponse(404)

    monkeypatch.setattr(validate_template_shell_runtime.requests, "get", fake_get)

    report = build_template_shell_runtime_report(
        template_root=template_root,
        atdr_root=atdr_root,
        settings=_template_shell_settings(),
        check_runtime=True,
        session_token_env="ATDR_TEMPLATE_SESSION_TOKEN",
    )
    rendered = json.dumps(report)

    assert report["ok"] is True
    assert report["session_token_env_used"] is True
    assert report["session_token_present"] is True
    assert report["template_runtime"]["session_validated"] is True
    assert report["template_runtime"]["profile_email_present"] is True
    assert token not in rendered
    assert email not in rendered

