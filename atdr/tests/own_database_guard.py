"""No test opens the database of the system running on the machine the tests are run on.

On such a machine the tests are pointed at a copy of its data: DATABASE_URL names it. A test that names
"./atdr.db" itself would then open the real one. Two tests of the settings doctor did, at every run, until
9 October 2026: the doctor connects to the database it is given, to read its migration. conftest.py installs
this guard: such a connection is refused, and the test that tried fails, also when the code under test swallowed
the refusal (as the doctor does).

Without DATABASE_URL, as in CI, "./atdr.db" is the tests' own database and nothing is refused.
"""

from __future__ import annotations

import os
import sqlite3
import sqlite3.dbapi2
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OWN_DATABASE = (PROJECT_ROOT / "atdr.db").resolve()
# Every refused connection, as it was named.
opened_own_database: list[str] = []
_connect = sqlite3.connect


def database_file(url: str) -> Path | None:
    if not url.startswith("sqlite:///"):
        return None
    name = url[len("sqlite:///"):].split("?")[0]
    return (Path(name) if Path(name).is_absolute() else PROJECT_ROOT / name).resolve()


def guarding() -> bool:
    return database_file(os.environ.get("DATABASE_URL", "sqlite:///./atdr.db")) != OWN_DATABASE


def _connect_unless_it_is_the_projects_own(database, *args, **kwargs):
    name = os.fsdecode(database) if isinstance(database, (bytes, os.PathLike)) else str(database)
    file = name[5:].split("?")[0] if name.startswith("file:") else name
    if file and not file.startswith(":"):
        try:
            own = Path(file).resolve() == OWN_DATABASE
        except OSError:
            own = False
        if own:
            opened_own_database.append(name)
            raise sqlite3.OperationalError("the tests run against another database; this is the project's own atdr.db")
    return _connect(database, *args, **kwargs)


def install() -> None:
    if guarding():
        sqlite3.connect = _connect_unless_it_is_the_projects_own
        sqlite3.dbapi2.connect = _connect_unless_it_is_the_projects_own


@pytest.fixture(autouse=True)
def no_test_opens_the_projects_own_database():
    before = len(opened_own_database)
    yield
    assert len(opened_own_database) == before, (
        "this test tried to open the project's own database (atdr.db) although the tests were told to use another; "
        "give it a database file of its own"
    )
