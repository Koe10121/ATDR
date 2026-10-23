"""ATDR's own flow gives the same figures on PostgreSQL as on SQLite.

Until 23 October 2026 ATDR's pages, detection and assistant had never run on PostgreSQL: CI's PostgreSQL job ran the
migrations and the backup scripts there, and its API tests used SQLite. The same flow (postgres_smoke_flow.py: import
the scenario files, run detection, open every page's data and the assistant's look-ups) runs on a new SQLite file and
on a new PostgreSQL database, and both must give the same answers.

The PostgreSQL database is set to Asia/Bangkok on purpose: on a server not set to UTC, every time ATDR wrote came back
7 hours off until its connections began working in UTC (CI's PostgreSQL is in UTC and would not show it otherwise).

Needs ATDR_TEST_POSTGRES_URL: a PostgreSQL server on which this test may create and drop a database of its own.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT

SERVER = os.environ.get("ATDR_TEST_POSTGRES_URL", "").strip()
pytestmark = pytest.mark.skipif(not SERVER, reason="set ATDR_TEST_POSTGRES_URL to a PostgreSQL server this test may use")

# What differs by nature between the two runs: which database it is, the free disk space, folders, and the time.
DIFFERS_BY_DATABASE = {
    "postgres_detection_coordination",
    "postgres_lab_status",
    "sqlite_local_workflow_valid",
    "database_profile",
    "missing_host_requirement_count",
    "free_bytes",
    "folder",
    "checked_seconds_ago",
    "request_id",
    "dialect",
    "database_kind",
}
TIME_KEY = re.compile(r"(_at|time|seconds|_ms|duration|timestamp|generated|started|finished|since|until|expires|first_seen|last_seen)$", re.I)
TIMES = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(\+00:00|Z)?|\d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}")


def _norm(value):
    if isinstance(value, dict):
        return {key: _norm(item) for key, item in sorted(value.items()) if key not in DIFFERS_BY_DATABASE and not TIME_KEY.search(key)}
    if isinstance(value, list):
        return [_norm(item) for item in value]
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        return TIMES.sub("<time>", value)
    return value


def _run_flow(database_url: str, out) -> dict:
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    env.update(
        DATABASE_URL=database_url,
        AUTO_CREATE_TABLES="false",
        ATDR_AUTH_MODE="local_recovery",
        MFU_IAM_ENABLED="false",
        OIDC_ENABLED="false",
        SMTP_ENABLED="false",
        ASSISTANT_LLM_ENABLED="false",
        OPERATION_WORKER_ENABLED="false",
        ENVIRONMENT="development",
        PYTHONIOENCODING="utf-8",
    )
    for command in ([sys.executable, "-m", "alembic", "upgrade", "head"], [sys.executable, "-m", "atdr.tests.postgres_smoke_flow", str(out)]):
        done = subprocess.run(command, cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
        assert done.returncode == 0, f"{command[2]} failed on {make_url(database_url).get_backend_name()}:\n{done.stderr[-3000:]}"
    return json.loads(out.read_text(encoding="utf-8"))


def _paths(left, right, path: str, found: list[str]) -> None:
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                found.append(f"{path}.{key}: only on {'postgres' if key not in left else 'sqlite'}")
            else:
                _paths(left[key], right[key], f"{path}.{key}", found)
    elif isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        for index, (one, other) in enumerate(zip(left, right)):
            _paths(one, other, f"{path}[{index}]", found)
    elif left != right:
        found.append(f"{path}: sqlite {str(left)[:160]!r} / postgres {str(right)[:160]!r}")


def _differences(sqlite: dict, postgres: dict) -> list[str]:
    found: list[str] = []
    for section in ("imports", "detection", "routes", "tools"):
        _paths(_norm(sqlite[section]), _norm(postgres[section]), section, found)
    return found


def test_atdr_gives_the_same_answers_on_postgresql_as_on_sqlite(tmp_path):
    name = f"atdr_smoke_{uuid.uuid4().hex[:10]}"
    server = make_url(SERVER)
    admin = create_engine(server, isolation_level="AUTOCOMMIT", future=True)
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
            connection.execute(text(f"ALTER DATABASE \"{name}\" SET timezone TO 'Asia/Bangkok'"))
        postgres_url = server.set(database=name).render_as_string(hide_password=False)
        sqlite = _run_flow(f"sqlite:///{(tmp_path / 'smoke.sqlite3').as_posix()}", tmp_path / "sqlite.json")
        postgres = _run_flow(postgres_url, tmp_path / "postgres.json")
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()

    assert sum(item["imported"] for item in sqlite["imports"]) > 150
    assert sqlite["detection"]["alerts_created"] > 10
    assert len(sqlite["routes"]) > 100 and len(sqlite["tools"]) > 100
    differences = _differences(sqlite, postgres)
    assert not differences, f"{len(differences)} answers differ:\n" + "\n".join(differences[:8])
