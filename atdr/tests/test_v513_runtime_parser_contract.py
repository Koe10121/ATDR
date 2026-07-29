from __future__ import annotations

from io import StringIO
import json

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import (
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.log_service import import_log_stream, import_raw_log_line
from atdr.app.services.runtime_parser_quality_service import (
    empty_runtime_parser_quality,
    finalize_runtime_parser_quality,
    historical_reparse_impact_preview,
    merge_runtime_parser_quality,
    observe_parser_result,
)
from atdr.app.services.source_service import source_health, source_quality
from atdr.tests.test_parser import TRAFFIC_LINE


def _session() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        future=True,
    )


def _counts(db: Session) -> dict[str, int]:
    return {
        model.__tablename__: int(
            db.scalar(select(func.count()).select_from(model)) or 0
        )
        for model in (
            RawLog,
            NormalizedLog,
            MLLabel,
            MLModelRun,
            DetectionRun,
            ResponseAction,
        )
    }


def test_unresolved_application_is_quality_context_not_parser_failure():
    SessionLocal = _session()
    line = TRAFFIC_LINE.replace(",,,ping,", ",,,incomplete,")
    with SessionLocal() as db:
        result = import_raw_log_line(
            db,
            line,
            source_name="runtime-contract-source",
            source_type="firewall",
            parser_profile="palo_alto",
            actor="unit_test",
        )
        source = db.scalar(
            select(LogSource).where(
                LogSource.name == "runtime-contract-source"
            )
        )
        assert source is not None
        health = source_health(source)
        quality = source_quality(db, source.id)

    assert result["parsed"] is True
    assert result["parser_quality"]["parser_error_rows"] == 0
    assert health["status"] == "healthy"
    assert health["runtime_parser_error_count"] == 0
    assert health["unresolved_application_count"] == 1
    assert quality["unresolved_application_count"] == 1
    assert quality["parser_error_count"] == 0
    assert not any(
        alert["severity"] in {"warning", "error"}
        for alert in quality["operational_alerts"]
    )


def test_generic_syslog_and_raw_fallback_have_distinct_runtime_states():
    SessionLocal = _session()
    with SessionLocal() as db:
        for index in range(3):
            import_raw_log_line(
                db,
                f"2026-05-22T00:00:0{index}Z host generic message {index}",
                source_name="generic-runtime-source",
                source_type="router",
                parser_profile="generic_syslog",
                actor="unit_test",
            )
            import_raw_log_line(
                db,
                f"unstructured evidence {index}",
                source_name="fallback-runtime-source",
                source_type="sample",
                parser_profile="raw_fallback",
                actor="unit_test",
            )
        generic = db.scalar(
            select(LogSource).where(
                LogSource.name == "generic-runtime-source"
            )
        )
        fallback = db.scalar(
            select(LogSource).where(
                LogSource.name == "fallback-runtime-source"
            )
        )
        assert generic is not None
        assert fallback is not None
        generic_health = source_health(generic)
        fallback_health = source_health(fallback)
        fallback_quality = source_quality(db, fallback.id)

    assert generic_health["status"] == "warning"
    assert generic_health["parser_quality_state"] == "limited"
    assert generic_health["generic_syslog_count"] == 3
    assert fallback_health["status"] == "warning"
    assert fallback_health["runtime_parser_error_count"] == 0
    assert fallback_health["raw_fallback_count"] == 3
    assert fallback.latest_error is None
    assert fallback_quality["parse_failure_examples"] == []
    assert any(
        alert["code"] == "prolonged_raw_fallback"
        for alert in fallback_health["operational_alerts"]
    )


def test_runtime_parser_errors_and_structural_layouts_alert_separately():
    quality = empty_runtime_parser_quality()
    for _ in range(3):
        quality = observe_parser_result(
            quality,
            parse_log_line_for_profile("malformed evidence", "palo_alto"),
        )
    summary = finalize_runtime_parser_quality(quality)

    assert summary["parser_error_rows"] == 3
    assert summary["raw_fallback_rows"] == 0
    assert summary["layout_statuses"]["unsupported"] == 3
    codes = {alert["code"] for alert in summary["operational_alerts"]}
    assert "parser_error_rate_high" in codes
    assert "unsupported_layout" in codes


def test_source_quality_lists_actual_errors_but_redacts_raw_evidence():
    SessionLocal = _session()
    with SessionLocal() as db:
        for _ in range(3):
            result = import_raw_log_line(
                db,
                "malformed evidence",
                source_name="malformed-runtime-source",
                source_type="firewall",
                parser_profile="palo_alto",
                actor="unit_test",
            )
        quality = source_quality(db, result["source_id"])

    assert quality["parser_error_count"] == 3
    assert len(quality["parse_failure_examples"]) == 3
    assert all(
        row["raw_line_excerpt"]
        == "<redacted; open authorized raw evidence by log ID>"
        for row in quality["parse_failure_examples"]
    )


def test_runtime_parser_error_increase_compares_latest_window_to_baseline():
    baseline = empty_runtime_parser_quality()
    for _ in range(20):
        baseline = observe_parser_result(
            baseline,
            parse_log_line_for_profile(TRAFFIC_LINE, "palo_alto"),
        )
    baseline = finalize_runtime_parser_quality(baseline)

    degraded = empty_runtime_parser_quality()
    for _ in range(3):
        degraded = observe_parser_result(
            degraded,
            parse_log_line_for_profile("malformed evidence", "palo_alto"),
        )
    combined = merge_runtime_parser_quality(
        baseline,
        finalize_runtime_parser_quality(degraded),
    )

    codes = {
        alert["code"] for alert in combined["operational_alerts"]
    }
    assert "parser_error_rate_increase" in codes
    assert combined["baseline"]["parser_error_rate"] == 0.0
    assert combined["latest_window"]["parser_error_rate"] == 1.0


def test_unresolved_application_shift_is_informational_not_source_failure():
    baseline = empty_runtime_parser_quality()
    for _ in range(20):
        baseline = observe_parser_result(
            baseline,
            parse_log_line_for_profile(TRAFFIC_LINE, "palo_alto"),
        )
    baseline = finalize_runtime_parser_quality(baseline)

    unresolved = empty_runtime_parser_quality()
    unresolved_line = TRAFFIC_LINE.replace(
        ",,,ping,",
        ",,,incomplete,",
    )
    for _ in range(5):
        unresolved = observe_parser_result(
            unresolved,
            parse_log_line_for_profile(unresolved_line, "palo_alto"),
        )
    combined = merge_runtime_parser_quality(
        baseline,
        finalize_runtime_parser_quality(unresolved),
    )

    shift = next(
        alert
        for alert in combined["operational_alerts"]
        if alert["code"] == "unresolved_application_shift"
    )
    assert shift["severity"] == "info"
    assert combined["parser_error_rows"] == 0


def test_file_import_records_contract_aggregates_without_ml_or_response_writes():
    SessionLocal = _session()
    with SessionLocal() as db:
        before = _counts(db)
        result = import_log_stream(
            db,
            StringIO(f"{TRAFFIC_LINE}\n{TRAFFIC_LINE}\n"),
            source_name="synthetic-runtime.log",
            source_type="file_import",
            actor="unit_test",
        )
        after = _counts(db)
        source = db.get(LogSource, result["source_id"])
        assert source is not None

    assert result["raw_logs_imported"] == 2
    assert result["normalized_logs_created"] == 2
    assert result["parser_quality"]["observed_rows"] == 2
    assert result["parser_quality"]["layout_statuses"]["compatible"] == 2
    assert source.parser_quality_json["observed_rows"] == 2
    assert after["raw_logs"] - before["raw_logs"] == 2
    assert after["normalized_logs"] - before["normalized_logs"] == 2
    for table in (
        "ml_labels",
        "ml_model_runs",
        "detection_runs",
        "response_actions",
    ):
        assert after[table] == before[table]


def test_historical_reparse_impact_preview_is_read_only_and_redacted():
    SessionLocal = _session()
    with SessionLocal() as db:
        source = LogSource(
            name="legacy-runtime-source",
            source_type="file_import",
            parser_profile="palo_alto",
            logs_received_count=1,
            parse_success_count=1,
            parse_failure_count=0,
        )
        raw = RawLog(
            source=source,
            raw_line="private historical evidence 198.51.100.10",
        )
        raw.normalized = NormalizedLog(
            app="incomplete",
            log_type="TRAFFIC",
            parsed_json={},
        )
        db.add(raw)
        db.commit()
        before = _counts(db)
        preview = historical_reparse_impact_preview(
            db,
            source_id=source.id,
            scan_limit=100,
        )
        after = _counts(db)

    serialized = json.dumps(preview)
    assert preview["preview_only"] is True
    assert preview["reparse_performed"] is False
    assert preview["database_mutated"] is False
    assert preview["legacy_contract_rows_scanned"] == 1
    assert preview["raw_evidence_accessed"] is False
    assert preview["source_identity_included"] is False
    assert before == after
    assert "198.51.100.10" not in serialized
    assert "private historical evidence" not in serialized
    assert "legacy-runtime-source" not in serialized
