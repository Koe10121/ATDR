from __future__ import annotations

from typing import Any

from atdr.app.core.config import get_settings
from atdr.app.services import mfu_iam_validation
from atdr.app.services.mfu_iam_validation import build_mfu_iam_validation_report


def _set_live_env(monkeypatch) -> None:
    monkeypatch.setenv("MFU_IAM_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_ENABLED", "false")
    monkeypatch.setenv("MFU_IAM_BASE_URL", "https://iam.example.test")
    monkeypatch.setenv("MFU_IAM_CLIENT_ID", "client-id")
    monkeypatch.setenv("MFU_IAM_CLIENT_SECRET", "secret-that-must-not-leak")
    monkeypatch.setenv("MFU_IAM_AUDIENCE", "atdr-api")
    monkeypatch.setenv("MFU_IAM_SCOPE", "atdr.read")
    monkeypatch.setenv("MFU_IAM_TOKEN_PATH", "/api/v1/b2b/token")
    monkeypatch.setenv("MFU_IAM_INTROSPECT_PATH", "/api/v1/b2b/introspect")
    monkeypatch.setenv("MFU_IAM_PROFILE_PATH", "/api/v1/b2b/clients/me")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "lamduan.mfu.ac.th")
    monkeypatch.setenv("MFU_IAM_DEFAULT_ROLE", "analyst")
    monkeypatch.setenv("MFU_IAM_MOCK_ENABLED", "false")


def test_mfu_iam_validation_disabled_does_not_call_provider(monkeypatch):
    monkeypatch.setenv("MFU_IAM_ENABLED", "false")
    monkeypatch.setenv("MFU_IAM_CLIENT_SECRET", "disabled-secret-that-must-not-leak")
    get_settings.cache_clear()

    def fail_post(*args, **kwargs):  # pragma: no cover - executed only on regression
        raise AssertionError("provider should not be called when MFU IAM is disabled")

    monkeypatch.setattr(mfu_iam_validation.requests, "post", fail_post)

    try:
        report = build_mfu_iam_validation_report(execute=True)
    finally:
        get_settings.cache_clear()

    assert report["ok"] is False
    assert report["executed_provider_call"] is False
    assert report["enabled"] is False
    assert report["secrets_exposed"] is False
    assert "disabled-secret-that-must-not-leak" not in str(report)


def test_mfu_iam_validation_mock_mode_is_secret_safe(monkeypatch):
    monkeypatch.setenv("MFU_IAM_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_MOCK_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "lamduan.mfu.ac.th")
    monkeypatch.setenv("MFU_IAM_CLIENT_SECRET", "mock-secret-that-must-not-leak")
    monkeypatch.setenv("MFU_IAM_DEFAULT_ROLE", "analyst")
    get_settings.cache_clear()

    try:
        report = build_mfu_iam_validation_report(execute=True, token="mock:student@lamduan.mfu.ac.th")
    finally:
        get_settings.cache_clear()

    assert report["ok"] is True
    assert report["executed_provider_call"] is True
    assert report["provider_result"]["mode"] == "mock"
    assert report["provider_result"]["identity_validated"] is True
    assert report["provider_result"]["email_domain"] == "lamduan.mfu.ac.th"
    assert report["provider_result"]["role"] == "analyst"
    assert report["secrets_exposed"] is False
    assert "mock-secret-that-must-not-leak" not in str(report)
    assert "student@lamduan.mfu.ac.th" not in str(report)


def test_mfu_iam_validation_secure_template_shell_mode_does_not_run_b2b(monkeypatch):
    monkeypatch.setenv("MFU_IAM_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_BASE_URL", "http://template-shell.test")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_ME_PATH", "/api/v1/auth/me")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "lamduan.mfu.ac.th")
    monkeypatch.setenv("MFU_IAM_HANDOFF_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_HANDOFF_SHARED_SECRET", "test-bridge-secret")
    monkeypatch.setenv("MFU_IAM_HANDOFF_ALLOWED_ORIGINS", "http://template-shell.test")
    get_settings.cache_clear()

    def fail_post(*args, **kwargs):  # pragma: no cover - executed only on regression
        raise AssertionError("B2B provider should not be called for template-shell mode without an explicit token")

    monkeypatch.setattr(mfu_iam_validation.requests, "post", fail_post)

    try:
        report = build_mfu_iam_validation_report(execute=True)
    finally:
        get_settings.cache_clear()

    assert report["ok"] is True
    assert report["executed_provider_call"] is False
    assert report["mode"] == "template_shell_secure_handoff"
    assert report["template_shell_enabled"] is True
    assert report["template_shell_ready"] is True
    assert report["handoff_ready"] is True
    assert report["secrets_exposed"] is False
    assert "validate_template_shell_runtime" in report["message"]


def test_mfu_iam_validation_live_probe_uses_mocked_provider_and_hides_tokens(monkeypatch):
    _set_live_env(monkeypatch)
    get_settings.cache_clear()
    calls: list[dict[str, Any]] = []

    class FakeResponse:
        def __init__(self, payload: dict[str, Any], status_code: int = 200):
            self._payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise RuntimeError("http error")

        def json(self) -> dict[str, Any]:
            return self._payload

    def fake_post(url: str, **kwargs):
        calls.append({"method": "post", "url": url, "kwargs": kwargs})
        if url.endswith("/api/v1/b2b/token"):
            return FakeResponse({"access_token": "live-token-that-must-not-leak", "expires_in": 300})
        if url.endswith("/api/v1/b2b/introspect"):
            assert kwargs["json"]["token"] == "live-token-that-must-not-leak"
            return FakeResponse({"active": True, "aud": "atdr-api", "scope": "atdr.read"})
        return FakeResponse({}, status_code=404)

    def fake_get(url: str, **kwargs):
        calls.append({"method": "get", "url": url, "kwargs": kwargs})
        assert kwargs["headers"]["Authorization"] == "Bearer live-token-that-must-not-leak"
        return FakeResponse({"email": "service@lamduan.mfu.ac.th", "name": "ATDR Service"})

    monkeypatch.setattr(mfu_iam_validation.requests, "post", fake_post)
    monkeypatch.setattr(mfu_iam_validation.requests, "get", fake_get)

    try:
        report = build_mfu_iam_validation_report(execute=True)
    finally:
        get_settings.cache_clear()

    assert report["ok"] is True
    assert report["executed_provider_call"] is True
    assert report["provider_result"] == {
        "mode": "live",
        "token_acquired": True,
        "introspection_active": True,
        "audience_accepted": True,
        "profile_available": True,
        "profile_email_present": True,
        "secrets_exposed": False,
    }
    assert len(calls) == 3
    assert "secret-that-must-not-leak" not in str(report)
    assert "live-token-that-must-not-leak" not in str(report)
    assert "service@lamduan.mfu.ac.th" not in str(report)
