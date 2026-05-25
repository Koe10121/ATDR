from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog, NormalizedLog, RawLog
from atdr.scripts.run_lab_scenario import run_lab_scenario


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def test_lab_scenario_dry_run_does_not_write_rows():
    Session = _session()
    with Session() as db:
        result = run_lab_scenario(db, dry_run=True, use_sample_data=True, limit=5)
        raw_count = db.scalar(select(func.count(RawLog.id)))

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["plan"]["reset_demo"] is False
    assert raw_count == 0


def test_lab_scenario_sample_import_detection_and_audit():
    Session = _session()
    sample_path = Path("data/samples/paloalto-demo.txt")

    with Session() as db:
        result = run_lab_scenario(
            db,
            sample_path=str(sample_path),
            limit=10,
            use_ml=False,
            score_ml=False,
            feature_limit=5,
            actor="unit_test_lab",
        )
        raw_count = db.scalar(select(func.count(RawLog.id)))
        normalized_count = db.scalar(select(func.count(NormalizedLog.id)))
        audit_count = db.scalar(select(func.count(AuditLog.id)))

    assert result["ok"] is True
    assert result["plan"]["reset_demo"] is False
    assert result["import"]["imported"] >= 2
    assert result["detection"]["evaluated"] >= 2
    assert result["feature_generation_smoke"]["rows"] >= 1
    assert result["audit"]["entries_exist"] is True
    assert raw_count >= 2
    assert normalized_count >= 2
    assert audit_count >= 2
