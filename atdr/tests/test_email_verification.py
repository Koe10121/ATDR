from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
import re

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import AccountEmailVerificationToken, AuditLog, EmailNotificationEvent, User
from atdr.app.main import app
from atdr.app.services.user_service import create_user


def _client_with_session() -> tuple[TestClient, sessionmaker[Session]]:
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
        create_user(
            db,
            username="analyst",
            password="analyst123",
            role="analyst",
            full_name="Test Analyst",
            email="analyst@school.example",
        )
        create_user(
            db,
            username="student",
            password="student123",
            role="analyst",
            full_name="Student Analyst",
            email="student@school.example",
        )

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), testing_session


def _login(client: TestClient, username: str = "admin", password: str = "admin123") -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _configure_email(monkeypatch, *, enabled: bool = True, mode: str | None = None) -> None:
    delivery_mode = mode or ("dev_outbox" if enabled else "disabled")
    monkeypatch.setenv("EMAIL_VERIFICATION_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("EMAIL_NOTIFICATIONS_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("EMAIL_DELIVERY_MODE", delivery_mode)
    monkeypatch.setenv("EMAIL_VERIFICATION_CODE_TTL_MINUTES", "15")
    monkeypatch.setenv("EMAIL_VERIFICATION_CODE_LENGTH", "6")
    monkeypatch.setenv("EMAIL_VERIFICATION_REQUIRED_FOR_LOGIN", "false")
    monkeypatch.setenv("EMAIL_VERIFICATION_REQUIRED_FOR_ADMIN_ACTIONS", "false")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-secret-that-must-not-leak")
    get_settings.cache_clear()


def _extract_code(text: str) -> str:
    match = re.search(r"Verification code:\s*(\d+)", text)
    assert match is not None
    return match.group(1)


def test_email_status_is_authenticated_disabled_by_default_and_hides_secrets(monkeypatch):
    _configure_email(monkeypatch, enabled=False)
    client, _ = _client_with_session()
    try:
        unauthorized = client.get("/api/auth/email/status")
        assert unauthorized.status_code == 401

        payload = client.get("/api/auth/email/status", headers=_login(client, "analyst", "analyst123")).json()
        assert payload["notifications_enabled"] is False
        assert payload["verification_enabled"] is False
        assert payload["delivery_mode"] == "disabled"
        assert payload["verification_required_for_login"] is False
        assert payload["verification_required_for_admin_actions"] is False
        assert payload["local_email_login_enabled"] is True
        assert payload["school_email_domains"] == []
        assert payload["secrets_exposed"] is False
        assert "smtp-secret-that-must-not-leak" not in str(payload)
        assert "SMTP_PASSWORD" not in str(payload)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_disabled_email_verification_does_not_create_token_or_outbox(monkeypatch):
    _configure_email(monkeypatch, enabled=False)
    client, testing_session = _client_with_session()
    try:
        response = client.post("/api/users/2/send-verification", headers=_login(client))
        assert response.status_code == 200
        payload = response.json()
        assert payload["created"] is False
        assert payload["status"] == "disabled"
        assert payload["delivery_status"] == "disabled"

        with testing_session() as db:
            assert db.scalar(select(func.count(AccountEmailVerificationToken.id))) == 0
            assert db.scalar(select(func.count(EmailNotificationEvent.id))) == 0
            assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "email_verification_request_skipped")) == 1
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_admin_can_trigger_dev_outbox_verification_and_analyst_cannot_view_outbox(monkeypatch):
    _configure_email(monkeypatch)
    client, testing_session = _client_with_session()
    try:
        admin_headers = _login(client)
        analyst_headers = _login(client, "analyst", "analyst123")

        response = client.post("/api/users/2/send-verification", headers=admin_headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["created"] is True
        assert payload["delivery_mode"] == "dev_outbox"
        assert payload["delivery_status"] == "stored"
        assert payload["outbox_id"] is not None

        forbidden = client.get("/api/users/dev-email-outbox", headers=analyst_headers)
        assert forbidden.status_code == 403

        outbox = client.get("/api/users/dev-email-outbox", headers=admin_headers)
        assert outbox.status_code == 200
        outbox_payload = outbox.json()
        assert outbox_payload
        assert "Verification code:" in outbox_payload[0]["body_preview"]
        assert "smtp-secret" not in str(outbox_payload)

        with testing_session() as db:
            assert db.scalar(select(func.count(AccountEmailVerificationToken.id))) == 1
            assert db.scalar(select(func.count(EmailNotificationEvent.id))) == 1
            assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "email_verification_requested")) == 1
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_valid_code_marks_email_verified_and_local_logins_still_work(monkeypatch):
    _configure_email(monkeypatch)
    client, testing_session = _client_with_session()
    try:
        admin_headers = _login(client)
        created = client.post("/api/users/3/send-verification", headers=admin_headers)
        assert created.status_code == 200

        outbox = client.get("/api/users/dev-email-outbox", headers=admin_headers).json()
        code = _extract_code(outbox[0]["body_preview"])

        username_headers = _login(client, "student", "student123")
        email_login = client.post("/api/auth/login", json={"username": "student@school.example", "password": "student123"})
        assert email_login.status_code == 200

        verified = client.post("/api/auth/email/verify", json={"code": code}, headers=username_headers)
        assert verified.status_code == 200
        assert verified.json()["verified"] is True

        with testing_session() as db:
            student = db.scalar(select(User).where(User.username == "student"))
            assert student is not None
            assert student.email_verified is True
            assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "email_verified")) == 1
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_verification_required_flags_default_do_not_block_login(monkeypatch):
    _configure_email(monkeypatch, enabled=True)
    client, _ = _client_with_session()
    try:
        username_login = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
        assert username_login.status_code == 200

        email_login = client.post("/api/auth/login", json={"username": "analyst@school.example", "password": "analyst123"})
        assert email_login.status_code == 200

        payload = client.get("/api/auth/email/status", headers=_login(client, "analyst", "analyst123")).json()
        assert payload["verification_enabled"] is True
        assert payload["verification_required_for_login"] is False
        assert payload["verification_required_for_admin_actions"] is False
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_invalid_and_expired_codes_fail_cleanly_and_are_audited(monkeypatch):
    _configure_email(monkeypatch)
    client, testing_session = _client_with_session()
    try:
        admin_headers = _login(client)
        analyst_headers = _login(client, "analyst", "analyst123")
        response = client.post("/api/users/2/send-verification", headers=admin_headers)
        assert response.status_code == 200

        invalid = client.post("/api/auth/email/verify", json={"code": "000000"}, headers=analyst_headers)
        assert invalid.status_code == 200
        assert invalid.json()["verified"] is False
        assert invalid.json()["status"] == "invalid_code"

        with testing_session() as db:
            token = db.scalar(select(AccountEmailVerificationToken).where(AccountEmailVerificationToken.user_id == 2))
            assert token is not None
            token.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.commit()

        outbox = client.get("/api/users/dev-email-outbox", headers=admin_headers).json()
        code = _extract_code(outbox[0]["body_preview"])
        expired = client.post("/api/auth/email/verify", json={"code": code}, headers=analyst_headers)
        assert expired.status_code == 200
        assert expired.json()["verified"] is False
        assert expired.json()["status"] == "expired"

        with testing_session() as db:
            assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "email_verification_failed")) >= 2
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
