"""Removing repeated copies of log lines keeps one copy, what points at it, and never reuses an alert's number."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertArchive, AlertEvidence, AuditLog, MLLabel, MLLabelArchive, NormalizedLog, RawLog
from atdr.app.services.duplicate_log_service import REASON, plan_duplicate_removal, remove_duplicate_logs


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, future=True)() as session:
        yield session
    engine.dispose()


def _log(db, line: str) -> NormalizedLog:
    raw = RawLog(raw_line=line)
    db.add(raw)
    db.flush()
    log = NormalizedLog(raw_log_id=raw.id, parsed_json={})
    db.add(log)
    db.flush()
    return log


def _label(db, log: NormalizedLog, label: str) -> MLLabel:
    row = MLLabel(log_id=log.id, label=label, attack_type="none", confidence=3, reviewer="koe")
    db.add(row)
    db.flush()
    return row


def _alert(db, *logs: NormalizedLog) -> Alert:
    alert = Alert(title="a", alert_type="possible_port_scan", threat_score=90, severity="Critical", status="open",
                  explanation="x", matched_rules_json=[], recommended_response="-")
    db.add(alert)
    db.flush()
    for log in logs:
        db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=log.id))
    db.flush()
    return alert


def _stored_three_times(db):
    """Line A stored three times, line B twice, line C once, with labels, evidence and archives on the copies."""

    a1, a2, a3 = _log(db, "line A"), _log(db, "line A"), _log(db, "line A")
    b1, b2 = _log(db, "line B"), _log(db, "line B")
    c1 = _log(db, "line C")
    old = _label(db, a1, "benign")
    on_copy = _label(db, a2, "benign")
    newest = _label(db, a3, "benign_unusual")
    only_on_copy = _label(db, b2, "suspicious")
    alert = _alert(db, a1, a2, a3, b2, c1)
    db.add(AlertArchive(original_alert_id=40, alert_type="possible_port_scan", severity="High", status="open", threat_score=70,
                        alert_json={}, evidence_log_ids=[a3.id, a2.id, c1.id], reason="old", superseded_by_catalog="v1", archived_by="koe"))
    db.add(MLLabelArchive(original_label_id=900, log_id=b2.id, label="benign", attack_type="none", confidence=3, reviewer="koe",
                          label_source="manual", reviewed=True, reason="earlier", archived_by="koe"))
    db.commit()
    return {"a": (a1.id, a2.id, a3.id), "b": (b1.id, b2.id), "c": c1.id, "old": old.id, "on_copy": on_copy.id,
            "newest": newest.id, "only_on_copy": only_on_copy.id, "alert": alert.id}


def test_the_plan_counts_the_copies_without_changing_anything(db):
    _stored_three_times(db)
    plan = plan_duplicate_removal(db)
    assert plan == {
        "stored_lines": 6, "lines_stored_more_than_once": 2, "copies_to_remove": 3, "logs_to_remove": 3,
        "labels_to_move_to_the_kept_copy": 2, "labels_to_archive": 1, "alert_evidence_rows_on_copies": 3,
        "alerts_citing_a_copy": 1,
    }
    assert db.scalar(select(func.count(RawLog.id))) == 6


def test_one_copy_of_each_line_stays_with_the_newest_label_made_for_it(db):
    # 31,001 of 151,002 stored logs were copies: until 27 September 2026 importing the same file again stored its
    # lines again, and three "brute-force" alerts were each one connection stored six or seven times.
    ids = _stored_three_times(db)
    summary = remove_duplicate_logs(db, actor="koe")

    kept = {ids["a"][0], ids["b"][0], ids["c"]}
    assert set(db.scalars(select(NormalizedLog.id))) == kept
    assert db.scalar(select(func.count(RawLog.id))) == 3 and summary["stored_lines_after"] == 3
    # The newest label made for line A (on its third copy) is now the kept copy's label; the label that sat on
    # the second copy is archived with the reason; line B's only label moved to its kept copy.
    labels = {label.id: (label.log_id, label.label) for label in db.scalars(select(MLLabel))}
    assert labels == {
        ids["old"]: (ids["a"][0], "benign"),
        ids["newest"]: (ids["a"][0], "benign_unusual"),
        ids["only_on_copy"]: (ids["b"][0], "suspicious"),
    }
    archived = db.scalars(select(MLLabelArchive).order_by(MLLabelArchive.original_label_id)).all()
    assert [(row.original_label_id, row.log_id, row.reason) for row in archived] == [
        (ids["on_copy"], ids["a"][0], REASON),
        (900, ids["b"][0], "earlier"),
    ]
    # The alert cites each kept log once, and the archived alert's evidence points at logs that exist.
    assert sorted(db.scalars(select(AlertEvidence.normalized_log_id).where(AlertEvidence.alert_id == ids["alert"]))) == sorted(kept)
    assert db.scalar(select(AlertArchive.evidence_log_ids)) == sorted([ids["a"][0], ids["c"]])
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "duplicate_logs_removed"))
    assert audit.actor == "koe" and audit.details["copies_to_remove"] == 3 and audit.details["applied"] is True

    again = remove_duplicate_logs(db, actor="koe")
    assert again["applied"] is False and again["copies_to_remove"] == 0


def test_a_new_alert_never_takes_the_number_of_an_alert_that_was_removed(db):
    # A rebuild archives the alerts on the list. SQLite then numbered new alerts one above the highest alert left:
    # the 4 October 2026 rehearsal started again at #2638 while #3985 was in the archive.
    first, second = _alert(db), _alert(db)
    db.commit()
    removed = second.id
    db.delete(second)
    db.commit()
    assert _alert(db).id > removed > first.id


def test_the_migration_starts_alert_numbers_after_every_number_ever_used(tmp_path):
    database = tmp_path / "migrated.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{database.as_posix()}", "AUTO_CREATE_TABLES": "false"}

    def alembic(*args: str) -> None:
        result = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, result.stderr[-2000:]

    alembic("upgrade", "7c2e91f4b0a3")
    with sqlite3.connect(database) as connection:
        for alert_id in (5, 6):
            connection.execute(
                "INSERT INTO alerts (id, title, alert_type, threat_score, severity, status, explanation, matched_rules_json, recommended_response)"
                " VALUES (?, 't', 'possible_port_scan', 90, 'Critical', 'open', 'x', '[]', '-')", (alert_id,))
        connection.execute("INSERT INTO alert_evidence (alert_id, normalized_log_id) VALUES (5, 1)")
        connection.execute(
            "INSERT INTO alert_archive (original_alert_id, alert_type, severity, status, threat_score, alert_json, evidence_log_ids, reason,"
            " superseded_by_catalog, archived_by) VALUES (40, 'possible_port_scan', 'High', 'open', 70, '{}', '[]', 'old', 'v1', 'koe')")
    alembic("upgrade", "head")
    with sqlite3.connect(database) as connection:
        assert "AUTOINCREMENT" in connection.execute("SELECT sql FROM sqlite_master WHERE name = 'alerts'").fetchone()[0]
        assert [row[0] for row in connection.execute("SELECT id FROM alerts ORDER BY id")] == [5, 6]
        assert connection.execute("SELECT alert_id FROM alert_evidence").fetchall() == [(5,)]
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE tbl_name = 'alerts' AND type = 'index'")}
        assert {"ix_alerts_status", "ix_alert_status_severity_updated"} <= indexes
        connection.execute("DELETE FROM alerts WHERE id = 6")
        cursor = connection.execute(
            "INSERT INTO alerts (title, alert_type, threat_score, severity, status, explanation, matched_rules_json, recommended_response)"
            " VALUES ('t', 'possible_port_scan', 90, 'Critical', 'open', 'x', '[]', '-')")
        assert cursor.lastrowid == 41, "numbered after the archived #40, not after the highest alert left (#5)"
    alembic("downgrade", "7c2e91f4b0a3")
    with sqlite3.connect(database) as connection:
        assert "AUTOINCREMENT" not in connection.execute("SELECT sql FROM sqlite_master WHERE name = 'alerts'").fetchone()[0]
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
