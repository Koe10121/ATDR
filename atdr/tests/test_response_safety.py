from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AuditLog
from atdr.app.services import response_service


def test_response_without_simulation_is_pending_until_connector_exists(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    monkeypatch.setattr(
        response_service,
        "get_settings",
        lambda: SimpleNamespace(response_simulation=False, response_provider="paloalto_api"),
    )

    with Session() as db:
        action = response_service.block_ip(db, target_ip="203.0.113.99", reason="lab connector test", actor="admin")
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "block_ip"))

    assert action.status == "pending_connector"
    assert "no approved firewall connector" in action.result_message
    assert audit is not None
    assert audit.details["simulation"] is False
    assert audit.details["status"] == "pending_connector"


def test_response_denies_protected_internal_block_and_audits_attempt():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    with Session() as db:
        action = response_service.block_ip(db, target_ip="10.0.0.10", reason="operator test", actor="admin")
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "block_ip_denied"))

    assert action.status == "denied"
    assert "protected internal" in action.result_message
    assert audit is not None
    assert audit.details["status"] == "denied"


def test_response_denies_missing_justification_and_audits_attempt():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    with Session() as db:
        action = response_service.block_ip(db, target_ip="203.0.113.99", reason="", actor="admin")
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "block_ip_denied"))

    assert action.status == "denied"
    assert "justification note is required" in action.result_message
    assert audit is not None


def test_response_denies_alert_without_evidence_and_audits_attempt():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    with Session() as db:
        db.add(
            Alert(
                title="Alert without evidence",
                alert_type="unit_test",
                src_ip="203.0.113.99",
                dst_ip="198.51.100.10",
                threat_score=80,
                severity="High",
                status="open",
                explanation="No evidence links.",
                matched_rules_json=[],
                recommended_response="Review.",
            )
        )
        db.commit()
        action = response_service.block_ip(
            db,
            target_ip="203.0.113.99",
            reason="attempt without evidence",
            alert_id=1,
            actor="admin",
        )
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "block_ip_denied"))

    assert action.status == "denied"
    assert "no evidence logs" in action.result_message
    assert audit is not None
