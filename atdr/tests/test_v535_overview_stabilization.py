from __future__ import annotations

import os
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, func, inspect, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.services.dashboard_service import (
    _source_alert_volumes,
    build_dashboard_summary,
)


NORMALIZED_COVER_INDEX = "ix_normalized_logs_id_raw_log_id_cover"
RAW_COVER_INDEX = "ix_raw_logs_id_source_id_cover"
ANOMALY_COVER_INDEXES = {
    "ix_normalized_anomaly_src_ip": ["is_anomaly", "src_ip"],
    "ix_normalized_anomaly_dst_ip": ["is_anomaly", "dst_ip"],
    "ix_normalized_anomaly_protocol": ["is_anomaly", "protocol"],
}


def _session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        future=True,
    )


def _alert(index: int, *, status: str = "open") -> Alert:
    return Alert(
        title=f"Synthetic v5.35 alert {index}",
        alert_type="possible_port_scan",
        src_ip=f"192.0.2.{index}",
        dst_ip="198.51.100.10",
        threat_score=80,
        severity="High",
        status=status,
        explanation="Synthetic source-volume regression evidence.",
        matched_rules_json=[
            {
                "code": "group_metadata",
                "occurrence_count": index + 1,
            }
        ],
        recommended_response="Analyst review only.",
    )


def _stable_summary(payload: dict) -> dict:
    stable = deepcopy(payload)
    stable.pop("performance", None)
    for alert in stable.get("recent_alerts", []):
        sla = alert.get("sla")
        if isinstance(sla, dict):
            sla.pop("age_minutes", None)
            sla.pop("minutes_remaining", None)
    return stable


def _query_count(bind, fn) -> tuple[int, object]:
    count = 0

    def before_cursor_execute(
        conn,
        cursor,
        statement,
        parameters,
        context,
        executemany,
    ):
        nonlocal count
        count += 1

    event.listen(bind, "before_cursor_execute", before_cursor_execute)
    try:
        result = fn()
        return count, result
    finally:
        event.remove(bind, "before_cursor_execute", before_cursor_execute)


def _seed_source_evidence(db) -> None:
    first_source = LogSource(
        name="v535-firewall-a",
        source_type="firewall",
        parser_profile="palo_alto",
    )
    second_source = LogSource(
        name="v535-firewall-b",
        source_type="firewall",
        parser_profile="palo_alto",
        enabled=False,
    )
    db.add_all([first_source, second_source])
    db.flush()

    raw_rows: list[RawLog] = []
    for index, source in enumerate(
        [first_source, first_source, second_source],
        start=1,
    ):
        raw = RawLog(
            source_id=source.id,
            raw_line=f"synthetic v5.35 row {index}",
            raw_line_hash=f"{index:064x}",
        )
        raw.normalized = NormalizedLog(
            generated_time=datetime.now(timezone.utc),
            src_ip=f"192.0.2.{index}",
            dst_ip="198.51.100.10",
            action="allow",
            protocol="tcp",
            app="ssl",
            app_risk=2,
            parsed_json={},
        )
        raw_rows.append(raw)
    db.add_all(raw_rows)
    db.flush()

    first_alert = _alert(1)
    second_alert = _alert(2, status="investigating")
    db.add_all([first_alert, second_alert])
    db.flush()
    db.add_all(
        [
            AlertEvidence(
                alert_id=first_alert.id,
                normalized_log_id=raw_rows[0].normalized.id,
            ),
            AlertEvidence(
                alert_id=first_alert.id,
                normalized_log_id=raw_rows[1].normalized.id,
            ),
            AlertEvidence(
                alert_id=first_alert.id,
                normalized_log_id=raw_rows[1].normalized.id,
            ),
            AlertEvidence(
                alert_id=second_alert.id,
                normalized_log_id=raw_rows[2].normalized.id,
            ),
        ]
    )
    db.commit()


def test_source_alert_volume_uses_covering_hops_and_distinct_alert_semantics():
    engine, Session = _session_factory()
    try:
        with Session() as db:
            _seed_source_evidence(db)
            result = _source_alert_volumes(db)
            normalized_index = next(
                index
                for index in NormalizedLog.__table__.indexes
                if index.name == NORMALIZED_COVER_INDEX
            )
            raw_index = next(
                index
                for index in RawLog.__table__.indexes
                if index.name == RAW_COVER_INDEX
            )

        assert result == [
            {"source_id": 1, "name": "v535-firewall-a", "count": 1},
            {"source_id": 2, "name": "v535-firewall-b", "count": 1},
        ]
        assert [column.name for column in normalized_index.columns] == [
            "id",
            "raw_log_id",
        ]
        assert [column.name for column in raw_index.columns] == [
            "id",
            "source_id",
        ]
    finally:
        engine.dispose()


def test_anomaly_distribution_indexes_cover_governance_groupings():
    declared = {
        str(index.name): [column.name for column in index.columns]
        for index in NormalizedLog.__table__.indexes
    }

    for index_name, columns in ANOMALY_COVER_INDEXES.items():
        assert declared[index_name] == columns


def test_anomaly_distribution_queries_use_covering_indexes():
    engine, _Session = _session_factory()
    try:
        with engine.connect() as connection:
            for index_name, columns in ANOMALY_COVER_INDEXES.items():
                grouping_column = columns[1]
                plan = connection.execute(
                    text(
                        "EXPLAIN QUERY PLAN "
                        f"SELECT {grouping_column}, count(*) "
                        "FROM normalized_logs "
                        "WHERE is_anomaly = 1 "
                        f"AND {grouping_column} IS NOT NULL "
                        f"GROUP BY {grouping_column}"
                    )
                ).all()
                plan_text = " ".join(str(row[-1]) for row in plan)
                assert index_name in plan_text
    finally:
        engine.dispose()


def test_overview_payload_is_exact_with_or_without_covering_indexes_and_read_only():
    engine, Session = _session_factory()
    try:
        with Session() as db:
            _seed_source_evidence(db)
            db.execute(text(f'DROP INDEX "{NORMALIZED_COVER_INDEX}"'))
            db.execute(text(f'DROP INDEX "{RAW_COVER_INDEX}"'))
            db.commit()
            authority_before = {
                "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
                "models": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
                "responses": int(
                    db.scalar(select(func.count(ResponseAction.id))) or 0
                ),
                "detection_runs": int(
                    db.scalar(select(func.count(DetectionRun.id))) or 0
                ),
            }
            before = build_dashboard_summary(db)

            db.execute(
                text(
                    f'CREATE INDEX "{NORMALIZED_COVER_INDEX}" '
                    "ON normalized_logs (id, raw_log_id)"
                )
            )
            db.execute(
                text(
                    f'CREATE INDEX "{RAW_COVER_INDEX}" '
                    "ON raw_logs (id, source_id)"
                )
            )
            db.commit()
            query_count, after = _query_count(
                engine,
                lambda: build_dashboard_summary(db),
            )
            authority_after = {
                "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
                "models": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
                "responses": int(
                    db.scalar(select(func.count(ResponseAction.id))) or 0
                ),
                "detection_runs": int(
                    db.scalar(select(func.count(DetectionRun.id))) or 0
                ),
            }

        assert _stable_summary(before) == _stable_summary(after)
        assert query_count <= 35
        assert authority_before == authority_after == {
            "labels": 0,
            "models": 0,
            "responses": 0,
            "detection_runs": 0,
        }
    finally:
        engine.dispose()


def test_v535_migration_is_additive_and_preserves_existing_rows(tmp_path):
    database_path = tmp_path / "pre-v535.sqlite3"
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": f"sqlite:///{database_path}",
            "RESPONSE_SIMULATION": "true",
            "JWT_SECRET_KEY": "v535-test-migration-secret-not-for-deployment",
        }
    )
    before_upgrade = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "e7f8a9b0c1d2"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert before_upgrade.returncode == 0, before_upgrade.stderr

    engine = create_engine(f"sqlite:///{database_path}", future=True)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO raw_logs (raw_line, raw_line_hash) "
                    "VALUES ('synthetic migration evidence', :fingerprint)"
                ),
                {"fingerprint": "a" * 64},
            )
        with engine.connect() as connection:
            before_rows = connection.execute(
                text("SELECT id, raw_line, raw_line_hash FROM raw_logs")
            ).all()
    finally:
        engine.dispose()

    upgraded = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert upgraded.returncode == 0, upgraded.stderr

    engine = create_engine(f"sqlite:///{database_path}", future=True)
    try:
        inspector = inspect(engine)
        normalized_indexes = {
            str(index["name"])
            for index in inspector.get_indexes("normalized_logs")
        }
        raw_indexes = {
            str(index["name"])
            for index in inspector.get_indexes("raw_logs")
        }
        with engine.connect() as connection:
            after_rows = connection.execute(
                text("SELECT id, raw_line, raw_line_hash FROM raw_logs")
            ).all()
    finally:
        engine.dispose()

    assert before_rows == after_rows
    assert NORMALIZED_COVER_INDEX in normalized_indexes
    assert RAW_COVER_INDEX in raw_indexes
    assert set(ANOMALY_COVER_INDEXES).issubset(normalized_indexes)


def test_v535_migration_renders_portable_postgresql_index_sql():
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": (
                "postgresql+psycopg2://atdr:unused@127.0.0.1:5432/"
                "atdr_v535_offline"
            ),
            "RESPONSE_SIMULATION": "true",
            "JWT_SECRET_KEY": "v535-test-offline-secret-not-for-deployment",
        }
    )
    rendered = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "upgrade",
            "e7f8a9b0c1d2:head",
            "--sql",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )

    assert rendered.returncode == 0, rendered.stderr
    assert NORMALIZED_COVER_INDEX in rendered.stdout
    assert RAW_COVER_INDEX in rendered.stdout
    for index_name in ANOMALY_COVER_INDEXES:
        assert index_name in rendered.stdout
    assert "DROP TABLE" not in rendered.stdout.upper()
    assert "DELETE FROM" not in rendered.stdout.upper()
