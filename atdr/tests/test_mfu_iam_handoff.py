from __future__ import annotations

from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import DetectionRun, MLModelRun, ResponseAction, User
from atdr.app.main import app
from atdr.app.services import mfu_iam_service
from atdr.app.services.user_service import create_user


def _client() -> tuple[TestClient, sessionmaker]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with testing_session() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), testing_session


def _configure_handoff(monkeypatch) -> None:
    monkeypatch.setenv("MFU_IAM_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_BASE_URL", "http://template-shell.test")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "lamduan.mfu.ac.th")
    monkeypatch.setenv("MFU_IAM_DEFAULT_ROLE", "analyst")
    monkeypatch.setenv("MFU_IAM_HANDOFF_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_HANDOFF_SHARED_SECRET", "test-bridge-secret-that-must-not-leak")
    monkeypatch.setenv("MFU_IAM_HANDOFF_ALLOWED_ORIGINS", "http://template-shell.test")
    monkeypatch.setenv("MFU_IAM_HANDOFF_FRONTEND_URL", "http://127.0.0.1:5173")
    monkeypatch.setenv("MFU_IAM_HANDOFF_EXCHANGE_PATH", "/api/v1/atdr/handoff/exchange")
    monkeypatch.setenv("MFU_IAM_ADMIN_GROUPS", "atdr-admin")
    get_settings.cache_clear()


class _FakeResponse:
    status_code = 200

    def json(self) -> dict:
        return {
            "data": {
                "email": "school.user@lamduan.mfu.ac.th",
                "subject": "template-account-42",
                "full_name": "School User",
                "groups": ["ATDR-ADMIN"],
            }
        }


def test_secure_template_handoff_sets_http_only_cookie_and_never_uses_url_credentials(monkeypatch):
    _configure_handoff(monkeypatch)
    calls: list[dict] = []

    def fake_post(url, **kwargs):
        calls.append({"url": url, "headers": kwargs.get("headers", {}), "json": kwargs.get("json", {})})
        return _FakeResponse()

    monkeypatch.setattr(mfu_iam_service.requests, "post", fake_post)
    client, session_factory = _client()
    try:
        before = session_factory()
        try:
            response_actions_before = before.scalar(select(func.count(ResponseAction.id))) or 0
            detections_before = before.scalar(select(func.count(DetectionRun.id))) or 0
            models_before = before.scalar(select(func.count(MLModelRun.id))) or 0
        finally:
            before.close()

        response = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "short-lived-code", "return_to": "/assistant"},
            headers={"Origin": "http://template-shell.test"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "http://127.0.0.1:5173/assistant"
        assert "handoff_code" not in response.headers["location"]
        assert "token" not in response.headers["location"].lower()
        assert "httponly" in response.headers["set-cookie"].lower()
        assert "test-bridge-secret-that-must-not-leak" not in response.headers["set-cookie"]
        assert calls == [
            {
                "url": "http://template-shell.test/api/v1/atdr/handoff/exchange",
                "headers": {"x-atdr-handoff-secret": "test-bridge-secret-that-must-not-leak"},
                "json": {"handoff_code": "short-lived-code"},
            }
        ]

        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["username"] == "school.user@lamduan.mfu.ac.th"
        assert me.json()["role"] == "admin"

        iam_status = client.get("/api/auth/mfu-iam/status")
        assert iam_status.status_code == 200
        assert iam_status.json()["last_safe_validation_status"] == "passed"
        assert iam_status.json()["last_safe_validation_reason"] == "template_handoff_validated"
        assert iam_status.json()["last_safe_validation_at"]

        after = session_factory()
        try:
            assert (after.scalar(select(func.count(ResponseAction.id))) or 0) == response_actions_before
            assert (after.scalar(select(func.count(DetectionRun.id))) or 0) == detections_before
            assert (after.scalar(select(func.count(MLModelRun.id))) or 0) == models_before
        finally:
            after.close()
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_handoff_requires_allowed_origin_and_legacy_browser_token_route_is_absent(monkeypatch):
    _configure_handoff(monkeypatch)
    client, _ = _client()
    try:
        rejected = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "short-lived-code"},
            headers={"Origin": "http://untrusted.example"},
            follow_redirects=False,
        )
        assert rejected.status_code == 303
        assert "handoff_origin_not_allowed" in rejected.headers["location"]
        assert "short-lived-code" not in rejected.headers["location"]

        legacy = client.post("/api/auth/mfu-iam/token-login", json={"token": "not-accepted"})
        assert legacy.status_code == 404
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_handoff_does_not_link_a_matching_local_admin_email(monkeypatch):
    _configure_handoff(monkeypatch)

    class LocalMatchResponse:
        status_code = 200

        def json(self) -> dict:
            return {
                "data": {
                    "email": "admin@lamduan.mfu.ac.th",
                    "subject": "template-admin-account",
                    "groups": [],
                }
            }

    monkeypatch.setattr(mfu_iam_service.requests, "post", lambda *args, **kwargs: LocalMatchResponse())
    client, session_factory = _client()
    try:
        db = session_factory()
        try:
            create_user(
                db,
                username="local-school-admin",
                password="admin123",
                role="admin",
                email="admin@lamduan.mfu.ac.th",
                auth_provider="local",
            )
        finally:
            db.close()

        response = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "short-lived-code"},
            headers={"Origin": "http://template-shell.test"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "handoff_rejected" in response.headers["location"]
        assert "admin@lamduan.mfu.ac.th" not in response.headers["location"]

        db = session_factory()
        try:
            existing = db.scalar(select(User).where(User.username == "local-school-admin"))
            assert existing is not None
            assert existing.role == "admin"
            assert existing.auth_provider == "local"
        finally:
            db.close()
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
