"""Reset checks its sample file and backs the database up before it deletes anything.

"Reset to sample data" deleted every log, every alert, their notes and the audit log after one OK in a browser
box, with no copy kept. With a mistyped sample path it deleted them all and then reported the file missing.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AuditLog, NormalizedLog, RawLog
from atdr.app.main import app
from atdr.app.services import scheduled_backup_service as backups
from atdr.app.services.demo_service import reset_and_seed_demo
from atdr.app.services.scheduled_backup_service import BackupRequired, list_backups
from atdr.app.services.user_service import create_user
from atdr.tests.test_api import TRAFFIC_LINE
from atdr.tests.test_detection_grouping import _session


def _system(tmp_path: Path) -> tuple[Session, Path, Path]:
    """A database file with data worth keeping, the sample file a reset loads, and where the backup goes."""

    database = tmp_path / "C" / "atdr.db"
    database.parent.mkdir(parents=True)
    engine = create_engine(f"sqlite:///{database.as_posix()}", connect_args={"check_same_thread": False}, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, autoflush=False, future=True)()
    db.add_all(RawLog(raw_line=f"line {index}") for index in range(25))
    db.add(Alert(title="Critical: watchlist match", alert_type="watchlist_match", threat_score=90, severity="Critical",
                 status="open", explanation="kept", matched_rules_json=[], recommended_response="look"))
    db.add(AuditLog(actor="koe", action="alert_investigating", target_type="alert", target_value="1", details={}))
    db.commit()
    sample = tmp_path / "sample.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")
    return db, sample, database.parent / "backups" / "scheduled"


def _counts(db: Session) -> tuple[int, int, int]:
    db.expire_all()
    return (db.scalar(select(func.count(RawLog.id))), db.scalar(select(func.count(Alert.id))),
            db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "alert_investigating")))


def test_reset_backs_the_database_up_first_and_says_where(tmp_path):
    db, sample, folder = _system(tmp_path)
    result = reset_and_seed_demo(db, sample_path=sample, limit=10, actor="koe")

    assert result["import"]["parsed"] == 1 and db.scalar(select(func.count(NormalizedLog.id))) == 1
    backup = result["backup"]
    assert backup["folder"] == str(folder) and backup["size_bytes"] > 0
    kept = list_backups(folder)
    assert [(item.path.name, item.purpose) for item in kept] == [(backup["artifact_name"], "before_reset")]
    with closing(sqlite3.connect(f"file:{kept[0].path.as_posix()}?mode=ro&immutable=1", uri=True)) as copy:
        assert copy.execute("select count(*) from raw_logs").fetchone() == (25,), "what the reset deleted"
        assert copy.execute("select title from alerts").fetchall() == [("Critical: watchlist match",)]
        assert copy.execute("select count(*) from audit_logs where action = 'alert_investigating'").fetchone() == (1,)

    # The audit log was deleted with the rest; the new one opens by saying so, and where the old one is.
    first = db.scalar(select(AuditLog).order_by(AuditLog.id).limit(1))
    assert (first.actor, first.action, first.target_value) == ("koe", "data_reset", backup["artifact_name"])
    assert first.details["backup"] == backup and first.details["deleted"]["raw_logs"] == 25
    assert _counts(db)[2] == 0


def test_reset_is_refused_when_the_backup_fails_and_nothing_is_deleted(tmp_path, monkeypatch):
    db, sample, folder = _system(tmp_path)
    before = _counts(db)
    monkeypatch.setattr(backups, "_free_bytes", lambda _folder: 0)
    with pytest.raises(BackupRequired) as refused:
        reset_and_seed_demo(db, sample_path=sample, limit=10)
    assert str(refused.value) == "Nothing was deleted: the backup that comes first did not succeed (there is not enough free space for it)."
    assert refused.value.status == "not_enough_free_space"
    assert _counts(db) == before == (25, 1, 1) and list_backups(folder) == []


def test_a_missing_sample_file_stops_reset_before_anything_is_deleted_or_copied(tmp_path):
    db, sample, folder = _system(tmp_path)
    with pytest.raises(FileNotFoundError) as missing:
        reset_and_seed_demo(db, sample_path=sample.with_name("mistyped.log"), limit=10)
    assert missing.value.filename == str(sample.with_name("mistyped.log"))
    assert _counts(db) == (25, 1, 1)
    assert not folder.exists(), "no backup is taken for a reset that cannot happen"
    with pytest.raises(FileNotFoundError):
        reset_and_seed_demo(db, sample_path=tmp_path, limit=10)  # a folder is not a sample file


def test_a_database_that_is_not_a_file_is_reset_without_a_backup(tmp_path):
    db = _session()
    db.add(RawLog(raw_line="in memory"))
    db.commit()
    sample = tmp_path / "sample.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")
    result = reset_and_seed_demo(db, sample_path=sample, limit=10)
    assert result["backup"] is None and result["import"]["parsed"] == 1
    first = db.scalar(select(AuditLog).order_by(AuditLog.id).limit(1))
    assert (first.action, first.target_value) == ("data_reset", "no backup: the database is not a file")


def test_the_backup_is_of_the_database_being_reset_not_of_the_configured_one(tmp_path):
    # The tests run with DATABASE_URL naming another database; a reset here must never copy that one.
    db, sample, folder = _system(tmp_path)
    result = reset_and_seed_demo(db, sample_path=sample, limit=10)
    with closing(sqlite3.connect(f"file:{(folder / result['backup']['artifact_name']).as_posix()}?mode=ro&immutable=1", uri=True)) as copy:
        assert copy.execute("select count(*) from raw_logs where raw_line like 'line %'").fetchone() == (25,)
    assert Path(result["backup"]["folder"]).parent.parent == tmp_path / "C", "beside the database, when no folder is configured"


def test_the_reset_button_is_told_why_nothing_was_deleted(tmp_path, monkeypatch):
    db, sample, folder = _system(tmp_path)
    create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
    factory = sessionmaker(bind=db.get_bind(), autoflush=False, future=True)

    def override_get_db() -> Generator[Session, None, None]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        body = {"limit": 10, "sample_path": str(sample), "use_ml": False}

        monkeypatch.setattr(backups, "_sqlite_integrity", lambda _path: False)
        refused = client.post("/api/demo/reset", json=body, headers=headers)
        assert refused.status_code == 409
        assert refused.json()["detail"] == "Nothing was deleted: the backup that comes first did not succeed (the copy did not pass its check)."
        assert _counts(db) == (25, 1, 1) and list_backups(folder) == []

        missing = client.post("/api/demo/reset", json={**body, "sample_path": str(sample) + ".typo"}, headers=headers)
        assert missing.status_code == 404 and _counts(db) == (25, 1, 1)

        monkeypatch.undo()
        app.dependency_overrides[get_db] = override_get_db
        done = client.post("/api/demo/reset", json=body, headers=headers)
        assert done.status_code == 200
        assert done.json()["backup"]["artifact_name"] == list_backups(folder)[0].path.name
        assert _counts(db)[1] == 0
    finally:
        app.dependency_overrides.clear()
