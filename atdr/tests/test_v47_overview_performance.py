from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import case, create_engine, event, func, or_, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    IngestionRun,
    LogSource,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.services import dashboard_service
from atdr.app.services.dashboard_service import (
    _dashboard_cache_signature_statement,
    _quality_aggregate,
    _quality_app_counts_statement,
    _quality_missing_counts_statement,
    _source_alert_volumes_statement,
    build_dashboard_summary,
    build_dashboard_summary_cached,
    clear_dashboard_summary_cache,
)
from atdr.scripts.profile_dashboard_summary import profile_dashboard_summary


def _session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _raw_with_normalized(index: int, **normalized_values) -> RawLog:
    raw = RawLog(raw_line=f"synthetic overview row {index}", raw_line_hash=f"{index:064x}")
    raw.normalized = NormalizedLog(parsed_json={}, **normalized_values)
    return raw


def _alert(index: int, *, status: str = "open") -> Alert:
    return Alert(
        title=f"Synthetic alert {index}",
        alert_type="test_alert",
        src_ip=f"192.0.2.{(index % 200) + 1}",
        dst_ip="198.51.100.10",
        threat_score=60,
        severity="High",
        status=status,
        explanation="Synthetic evidence for Overview tests.",
        matched_rules_json=[],
        recommended_response="Analyst review only.",
    )


def _legacy_quality_aggregate(db) -> dict[str, int]:
    def sum_if(condition):
        return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)

    row = db.execute(
        select(
            sum_if(NormalizedLog.generated_time.is_(None) & NormalizedLog.receive_time.is_(None)).label(
                "missing_timestamp"
            ),
            sum_if(or_(NormalizedLog.src_ip.is_(None), NormalizedLog.src_ip == "")).label("missing_source_ip"),
            sum_if(or_(NormalizedLog.dst_ip.is_(None), NormalizedLog.dst_ip == "")).label(
                "missing_destination_ip"
            ),
            sum_if(or_(NormalizedLog.action.is_(None), NormalizedLog.action == "")).label("missing_action"),
            sum_if(func.lower(NormalizedLog.app).in_(dashboard_service.UNKNOWN_APPS)).label("unknown_app_count"),
        )
    ).mappings().one()
    return {key: int(value or 0) for key, value in row.items()}


def _query_count(bind, fn):
    count = 0

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        nonlocal count
        count += 1

    event.listen(bind, "before_cursor_execute", before_cursor_execute)
    try:
        result = fn()
    finally:
        event.remove(bind, "before_cursor_execute", before_cursor_execute)
    return count, result


def _sqlite_plan(db, statement) -> list[str]:
    compiled = statement.compile(db.get_bind(), compile_kwargs={"literal_binds": True})
    return [
        str(row[3])
        for row in db.connection().exec_driver_sql(f"EXPLAIN QUERY PLAN {compiled}").all()
    ]


def test_quality_counts_match_legacy_semantics_and_use_existing_indexes():
    engine, Session = _session_factory()
    try:
        with Session() as db:
            db.add_all(
                [
                    _raw_with_normalized(
                        1,
                        generated_time=None,
                        receive_time=None,
                        src_ip=None,
                        dst_ip="",
                        action=None,
                        app="Unknown-TCP",
                    ),
                    _raw_with_normalized(
                        2,
                        generated_time=datetime.now(timezone.utc),
                        receive_time=None,
                        src_ip="192.0.2.2",
                        dst_ip="198.51.100.2",
                        action="allow",
                        app="web-browsing",
                    ),
                    _raw_with_normalized(
                        3,
                        generated_time=None,
                        receive_time=datetime.now(timezone.utc),
                        src_ip="",
                        dst_ip=None,
                        action="",
                        app="incomplete",
                    ),
                ]
            )
            db.commit()

            assert _quality_aggregate(db) == _legacy_quality_aggregate(db)
            missing_plan = _sqlite_plan(db, _quality_missing_counts_statement())
            app_plan = _sqlite_plan(db, _quality_app_counts_statement())

        assert "SCAN normalized_logs" not in missing_plan
        assert "SCAN normalized_logs" not in app_plan
        assert any("normalized_logs" in step and "USING" in step for step in missing_plan)
        assert any("USING COVERING INDEX ix_normalized_logs_app" in step for step in app_plan)
    finally:
        engine.dispose()


def test_summary_preserves_empty_and_disabled_source_data_without_side_effects():
    engine, Session = _session_factory()
    try:
        with Session() as db:
            empty = build_dashboard_summary(db)
            assert empty["total_logs"] == 0
            assert empty["total_raw_logs"] == 0
            assert empty["total_alerts"] == 0

            source = LogSource(
                name="disabled-overview-source",
                source_type="firewall",
                parser_profile="palo_alto",
                enabled=False,
            )
            db.add(source)
            db.flush()
            raw = _raw_with_normalized(
                10,
                generated_time=datetime.now(timezone.utc),
                src_ip="192.0.2.10",
                dst_ip="198.51.100.10",
                action="allow",
                app="ssl",
            )
            raw.source_id = source.id
            db.add(raw)
            db.flush()
            alert = _alert(10)
            db.add(alert)
            db.flush()
            db.add_all(
                [
                    AlertEvidence(alert_id=alert.id, normalized_log_id=raw.normalized.id),
                    AlertEvidence(alert_id=alert.id, normalized_log_id=raw.normalized.id),
                ]
            )
            db.commit()

            before_ml = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
            before_response = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
            summary = build_dashboard_summary(db)
            after_ml = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
            after_response = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

        assert summary["total_logs"] == 1
        assert summary["total_raw_logs"] == 1
        assert summary["recent_alerts"][0]["evidence_count"] == 2
        assert before_ml == after_ml == 0
        assert before_response == after_response == 0
    finally:
        engine.dispose()


def test_cache_uses_one_warm_query_and_invalidates_for_raw_alert_and_failed_run(monkeypatch):
    engine, Session = _session_factory()
    monkeypatch.setattr(
        dashboard_service,
        "get_settings",
        lambda: SimpleNamespace(dashboard_summary_cache_seconds=30),
    )
    clear_dashboard_summary_cache()
    try:
        with Session() as db:
            db.add(
                _raw_with_normalized(
                    20,
                    generated_time=datetime.now(timezone.utc),
                    src_ip="192.0.2.20",
                    dst_ip="198.51.100.20",
                    action="allow",
                    app="ssl",
                )
            )
            run = IngestionRun(source_type="file_import", input_name="safe-sample", status="running")
            db.add(run)
            db.commit()

            cold_queries, first = _query_count(engine, lambda: build_dashboard_summary_cached(db))
            warm_queries, second = _query_count(engine, lambda: build_dashboard_summary_cached(db))
            assert cold_queries <= 35
            assert warm_queries == 1
            assert first["performance"]["cached"] is False
            assert second["performance"]["cached"] is True

            db.add(RawLog(raw_line="raw-only parser failure", raw_line_hash="f" * 64))
            db.commit()
            raw_changed = build_dashboard_summary_cached(db)
            assert raw_changed["performance"]["cached"] is False
            assert raw_changed["total_raw_logs"] == 2

            alert = _alert(20)
            db.add(alert)
            db.commit()
            alert_changed = build_dashboard_summary_cached(db)
            assert alert_changed["performance"]["cached"] is False
            assert alert_changed["total_alerts"] == 1

            alert.status = "false_positive"
            alert.updated_at = datetime.now(timezone.utc) + timedelta(seconds=1)
            db.commit()
            alert_updated = build_dashboard_summary_cached(db)
            assert alert_updated["performance"]["cached"] is False
            assert alert_updated["false_positive_alerts"] == 1

            run.status = "failed"
            run.finished_at = datetime.now(timezone.utc) + timedelta(seconds=1)
            run.error_summary = "synthetic failure"
            db.commit()
            run_changed = build_dashboard_summary_cached(db)
            assert run_changed["performance"]["cached"] is False
            assert run_changed["latest_ingestion_run"]["status"] == "failed"
    finally:
        clear_dashboard_summary_cache()
        engine.dispose()


def test_dashboard_statements_compile_for_postgresql_without_sqlite_only_functions():
    dialect = postgresql.dialect()
    statements = [
        _quality_missing_counts_statement(),
        _quality_app_counts_statement(),
        _dashboard_cache_signature_statement(),
        _source_alert_volumes_statement(),
    ]
    rendered = "\n".join(str(statement.compile(dialect=dialect)) for statement in statements).lower()

    assert "normalized_logs" in rendered
    assert "json_extract" not in rendered
    assert "pragma" not in rendered


def test_concurrent_sqlite_overview_reads_do_not_lock_or_diverge(monkeypatch):
    temp_root = Path(".pytest_tmp")
    temp_root.mkdir(exist_ok=True)
    database_path = temp_root / f"v47-overview-concurrency-{uuid4().hex}.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 10},
        future=True,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    monkeypatch.setattr(
        dashboard_service,
        "get_settings",
        lambda: SimpleNamespace(dashboard_summary_cache_seconds=30),
    )
    clear_dashboard_summary_cache()
    try:
        with Session() as db:
            db.add_all(
                [
                    _raw_with_normalized(
                        index,
                        generated_time=datetime.now(timezone.utc),
                        src_ip=f"192.0.2.{(index % 200) + 1}",
                        dst_ip="198.51.100.40",
                        action="allow",
                        protocol="tcp",
                        app="ssl",
                    )
                    for index in range(1, 101)
                ]
            )
            db.commit()

        def read_summary():
            with Session() as db:
                return build_dashboard_summary_cached(db)

        with ThreadPoolExecutor(max_workers=4) as executor:
            summaries = list(executor.map(lambda _: read_summary(), range(8)))

        assert all(summary["total_logs"] == 100 for summary in summaries)
        assert all(summary["total_raw_logs"] == 100 for summary in summaries)
        assert all(summary["total_alerts"] == 0 for summary in summaries)
    finally:
        clear_dashboard_summary_cache()
        engine.dispose()
        for candidate in (database_path, Path(f"{database_path}-wal"), Path(f"{database_path}-shm")):
            candidate.unlink(missing_ok=True)


def test_profile_reports_repeatable_query_counts_and_does_not_mutate_data(monkeypatch):
    engine, Session = _session_factory()
    try:
        with Session() as db:
            db.add_all(
                [
                    _raw_with_normalized(
                        index,
                        generated_time=datetime.now(timezone.utc),
                        src_ip=f"192.0.2.{(index % 200) + 1}",
                        dst_ip="198.51.100.30",
                        action="allow",
                        protocol="tcp",
                        app="ssl",
                        app_risk=2,
                    )
                    for index in range(1, 501)
                ]
            )
            db.commit()
            before = int(db.scalar(select(func.count(RawLog.id))) or 0)

        monkeypatch.setattr("atdr.scripts.profile_dashboard_summary.SessionLocal", Session)
        monkeypatch.setattr(
            dashboard_service,
            "get_settings",
            lambda: SimpleNamespace(dashboard_summary_cache_seconds=30),
        )
        result = profile_dashboard_summary(include_full_summary=True, runs=3)

        with Session() as db:
            after = int(db.scalar(select(func.count(RawLog.id))) or 0)

        assert result["ok"] is True
        assert result["read_only"] is True
        assert result["measurement_runs"] == 3
        assert result["all_responses_equal"] is True
        assert all(item["cold_query_count"] <= 35 for item in result["application_cache_runs"])
        assert all(item["warm_query_count"] == 1 for item in result["application_cache_runs"])
        assert result["application_cache_distribution"]["cold_seconds"]["p95"] < 1.0
        assert "source_alert_volumes" in result["query_plans"]
        assert before == after == 500
    finally:
        clear_dashboard_summary_cache()
        engine.dispose()


def test_failed_detection_run_is_visible_without_ml_or_response_changes(monkeypatch):
    engine, Session = _session_factory()
    monkeypatch.setattr(
        dashboard_service,
        "get_settings",
        lambda: SimpleNamespace(dashboard_summary_cache_seconds=30),
    )
    clear_dashboard_summary_cache()
    try:
        with Session() as db:
            run = DetectionRun(detection_type="rules", status="running")
            db.add(run)
            db.commit()
            first = build_dashboard_summary_cached(db)
            assert first["latest_detection_run"]["status"] == "running"

            run.status = "failed"
            run.finished_at = datetime.now(timezone.utc) + timedelta(seconds=1)
            run.error_summary = "synthetic failure"
            db.commit()
            second = build_dashboard_summary_cached(db)

            assert second["performance"]["cached"] is False
            assert second["latest_detection_run"]["status"] == "failed"
            assert int(db.scalar(select(func.count(MLModelRun.id))) or 0) == 0
            assert int(db.scalar(select(func.count(ResponseAction.id))) or 0) == 0
    finally:
        clear_dashboard_summary_cache()
        engine.dispose()
