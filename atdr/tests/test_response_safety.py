from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog
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
