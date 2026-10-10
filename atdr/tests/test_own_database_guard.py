"""The tests never open the database of the system running on the machine they are run on.

There the tests are pointed at a copy (DATABASE_URL). A test that names "./atdr.db" itself would open the real
one; own_database_guard.py refuses that connection and fails the test.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from atdr.tests import own_database_guard as guard

guarded = pytest.mark.skipif(not guard.guarding(), reason="./atdr.db is these tests' own database (no DATABASE_URL)")


@guarded
def test_a_connection_to_the_projects_own_database_is_refused_however_it_is_named(tmp_path):
    before = len(guard.opened_own_database)
    own = guard.OWN_DATABASE
    for name in (str(own), own, own.as_posix(), f"file:{own.as_posix()}?mode=ro", "atdr.db", "./atdr.db", str(own).encode()):
        with pytest.raises(sqlite3.OperationalError, match="this is the project's own atdr.db"):
            sqlite3.connect(name)
    for url in ("sqlite:///./atdr.db", "sqlite:///atdr.db", f"sqlite:///{own.as_posix()}"):
        with pytest.raises(OperationalError, match="this is the project's own atdr.db"):
            with create_engine(url, future=True).connect() as connection:
                connection.execute(text("select 1"))
    assert len(guard.opened_own_database) == before + 10, "each try is on record, for the check after every test"
    # These tries were this test's subject.
    del guard.opened_own_database[before:]

    # Any other database opens as ever: one of the same name elsewhere, one in memory, a temporary one.
    for other in (tmp_path / "atdr.db", ":memory:", ""):
        with closing(sqlite3.connect(other)) as connection:
            assert connection.execute("select 1").fetchone() == (1,)
    with create_engine(f"sqlite:///{(tmp_path / 'atdr.db').as_posix()}", future=True).connect() as connection:
        assert connection.execute(text("select 1")).scalar() == 1
    assert len(guard.opened_own_database) == before


@guarded
def test_the_check_after_every_test_fails_the_one_that_tried(tmp_path):
    # The check itself, run by hand: code that swallows the refusal (the settings doctor does) must not hide the try.
    check = guard.no_test_opens_the_projects_own_database.__wrapped__()
    next(check)
    with pytest.raises(sqlite3.OperationalError):
        sqlite3.connect(guard.OWN_DATABASE)
    with pytest.raises(AssertionError, match=r"tried to open the project's own database \(atdr.db\)"):
        next(check)
    del guard.opened_own_database[-1:]

    quiet = guard.no_test_opens_the_projects_own_database.__wrapped__()
    next(quiet)
    sqlite3.connect(tmp_path / "another.db").close()
    with pytest.raises(StopIteration):
        next(quiet)


def test_which_database_the_tests_were_given_decides_whether_the_projects_own_is_guarded(monkeypatch):
    root = guard.PROJECT_ROOT
    assert guard.database_file("sqlite:///./atdr.db") == guard.OWN_DATABASE == (root / "atdr.db").resolve()
    assert guard.database_file("sqlite:///./.tmp/idle_copy_for_tests.db") == (root / ".tmp" / "idle_copy_for_tests.db").resolve()
    assert guard.database_file(f"sqlite:///{(root / 'atdr.db').as_posix()}?timeout=5") == guard.OWN_DATABASE
    assert guard.database_file("postgresql+psycopg2://atdr@db.example/atdr") is None
    assert guard.database_file("sqlite://") is None
    assert isinstance(guard.OWN_DATABASE, Path)

    monkeypatch.setenv("DATABASE_URL", "sqlite:///./.tmp/idle_copy_for_tests.db")
    assert guard.guarding() is True
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://atdr@db.example/atdr")
    assert guard.guarding() is True
    # As in CI: the tests' own database is "./atdr.db", and it must open.
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./atdr.db")
    assert guard.guarding() is False
    monkeypatch.delenv("DATABASE_URL")
    assert guard.guarding() is False
