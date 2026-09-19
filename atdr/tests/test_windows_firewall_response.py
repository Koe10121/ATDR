"""Tests for real host-level Windows Firewall response enforcement.

No test here ever invokes a real `netsh` process: `subprocess.run` is always
monkeypatched. These tests prove the connector builds correct, injection-safe
commands and handles failure paths, and that response_service only ever
marks a block "active"/"enforced" when enforcement genuinely succeeded.
"""

from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog, BlockedIP
from atdr.app.services import response_service, windows_firewall_connector


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _settings(**overrides):
    base = dict(response_simulation=False, response_provider="windows_firewall", response_max_block_minutes=1440)
    base.update(overrides)
    return SimpleNamespace(**base)


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_connector_builds_injection_safe_argument_list_for_add_and_delete(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompleted(0)

    monkeypatch.setattr(windows_firewall_connector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows_firewall_connector.subprocess, "run", fake_run)

    result = windows_firewall_connector.apply_block("203.0.113.77")

    assert result.ok is True
    # apply_block calls remove_block first (idempotent cleanup), then adds
    # two rules (in/out): 2 deletes + 2 adds = 4 subprocess invocations.
    assert len(calls) == 4
    for call in calls:
        assert call[0] == "netsh"
        assert "&" not in " ".join(call) and ";" not in " ".join(call)
    add_calls = [c for c in calls if "add" in c]
    assert len(add_calls) == 2
    assert any("remoteip=203.0.113.77" in " ".join(c) for c in add_calls)
    directions = {next(part.split("=", 1)[1] for part in c if part.startswith("dir=")) for c in add_calls}
    assert directions == {"in", "out"}


def test_connector_reports_elevation_required_and_rolls_back(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if "add" in args:
            return _FakeCompleted(1, stderr="This command requires elevation.")
        return _FakeCompleted(0)

    monkeypatch.setattr(windows_firewall_connector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows_firewall_connector.subprocess, "run", fake_run)

    result = windows_firewall_connector.apply_block("203.0.113.78")

    assert result.ok is False
    assert "administrator privileges" in result.message.lower()
    # First add fails immediately (dir=in is attempted first); rollback calls
    # remove_block again. No dir=out add should ever be attempted after the
    # dir=in failure.
    assert not any("dir=out" in c and "add" in c for c in calls)


def test_connector_delete_treats_no_matching_rule_as_success(monkeypatch):
    monkeypatch.setattr(windows_firewall_connector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows_firewall_connector.subprocess,
        "run",
        lambda args, **kwargs: _FakeCompleted(1, stdout="No rules match the specified criteria."),
    )

    result = windows_firewall_connector.remove_block("203.0.113.79")

    assert result.ok is True


def test_connector_refuses_on_non_windows_platform(monkeypatch):
    monkeypatch.setattr(windows_firewall_connector.platform, "system", lambda: "Linux")

    result = windows_firewall_connector.apply_block("203.0.113.80")

    assert result.ok is False
    assert "windows" in result.message.lower()


def test_block_ip_with_real_enforcement_marks_active_only_on_connector_success(monkeypatch):
    monkeypatch.setattr(response_service, "get_settings", lambda: _settings())
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "apply_block",
        lambda ip: windows_firewall_connector.ConnectorResult(True, f"blocked {ip}"),
    )

    with _session() as db:
        action = response_service.block_ip(db, target_ip="203.0.113.81", reason="live containment test", actor="admin")
        row = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.81"))

    assert action.status == "enforced"
    assert action.enforcement == "windows_firewall"
    assert row is not None
    assert row.active is True
    assert row.enforcement == "windows_firewall"


def test_block_ip_with_real_enforcement_failure_never_marks_active(monkeypatch):
    monkeypatch.setattr(response_service, "get_settings", lambda: _settings())
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "apply_block",
        lambda ip: windows_firewall_connector.ConnectorResult(False, "administrator privileges are required"),
    )

    with _session() as db:
        action = response_service.block_ip(db, target_ip="203.0.113.82", reason="expect failure", actor="admin")
        row = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.82"))

    assert action.status == "enforcement_failed"
    assert "administrator privileges" in action.result_message
    assert row is None


def test_unblock_never_marks_inactive_when_real_removal_fails(monkeypatch):
    monkeypatch.setattr(response_service, "get_settings", lambda: _settings())
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "apply_block",
        lambda ip: windows_firewall_connector.ConnectorResult(True, f"blocked {ip}"),
    )

    with _session() as db:
        response_service.block_ip(db, target_ip="203.0.113.83", reason="setup", actor="admin")

        monkeypatch.setattr(
            response_service.windows_firewall_connector,
            "remove_block",
            lambda ip: windows_firewall_connector.ConnectorResult(False, "administrator privileges are required"),
        )
        action = response_service.unblock_ip(db, target_ip="203.0.113.83", reason="attempt removal", actor="admin")
        row = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.83"))

    assert action.status == "enforcement_failed"
    assert row is not None
    assert row.active is True  # still genuinely blocked; dashboard must not lie


def test_self_host_address_is_protected_from_real_enforcement(monkeypatch):
    monkeypatch.setattr(response_service, "get_settings", lambda: _settings())
    monkeypatch.setattr(response_service, "_local_host_addresses", lambda: frozenset({"198.51.100.5"}))
    calls: list[str] = []
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "apply_block",
        lambda ip: calls.append(ip) or windows_firewall_connector.ConnectorResult(True, "blocked"),
    )

    with _session() as db:
        action = response_service.block_ip(db, target_ip="198.51.100.5", reason="should be denied", actor="admin")

    assert action.status == "denied"
    assert "backend host itself" in action.result_message
    assert calls == []  # connector must never even be invoked


def test_duration_minutes_sets_expiry_capped_at_configured_maximum(monkeypatch):
    monkeypatch.setattr(response_service, "get_settings", lambda: _settings(response_max_block_minutes=30))
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "apply_block",
        lambda ip: windows_firewall_connector.ConnectorResult(True, f"blocked {ip}"),
    )

    with _session() as db:
        response_service.block_ip(
            db,
            target_ip="203.0.113.84",
            reason="temporary containment",
            actor="admin",
            duration_minutes=999,
        )
        row = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.84"))

    assert row is not None
    assert row.expires_at is not None
    # Capped at 30 minutes even though 999 was requested. SQLite round-trips
    # DateTime columns as naive, so normalize to UTC before comparing.
    from datetime import datetime, timezone

    expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    delta = expires_at - datetime.now(timezone.utc)
    assert delta.total_seconds() <= 30 * 60 + 5


def test_expired_block_is_swept_and_connector_removal_invoked(monkeypatch):
    from datetime import datetime, timedelta, timezone

    monkeypatch.setattr(response_service, "get_settings", lambda: _settings())
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "apply_block",
        lambda ip: windows_firewall_connector.ConnectorResult(True, f"blocked {ip}"),
    )
    removed: list[str] = []
    monkeypatch.setattr(
        response_service.windows_firewall_connector,
        "remove_block",
        lambda ip: removed.append(ip) or windows_firewall_connector.ConnectorResult(True, "removed"),
    )

    with _session() as db:
        response_service.block_ip(
            db, target_ip="203.0.113.85", reason="short timeout", actor="admin", duration_minutes=5
        )
        row = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.85"))
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

        blocks = response_service.list_blocked_ips(db, active_only=False)
        refreshed = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.85"))
        expiry_audit = db.scalar(select(AuditLog).where(AuditLog.action == "unblock_ip_expired"))

    assert "203.0.113.85" in removed
    assert refreshed.active is False
    assert expiry_audit is not None
    assert all(b.ip_address != "203.0.113.85" or not b.active for b in blocks)
