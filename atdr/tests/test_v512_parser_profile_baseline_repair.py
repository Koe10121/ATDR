from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    MLShadowObservation,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services import v512_parser_baseline_service as v512


def _catalog_report() -> dict:
    return {
        "drift_profile": {
            "role_distributions": {
                "development_fit": {
                    "application": [
                        {"value": "ssl", "count": 350},
                        {"value": "incomplete", "count": 50},
                    ],
                    "schema": [
                        {"value": "traffic_complete", "count": 400}
                    ],
                    "quality": {
                        "rows": 400,
                        "parser_error_rate": 0.0,
                        "required_missing_per_row": 0.0,
                        "unknown_app_rate": 0.125,
                    },
                }
            }
        }
    }


def _catalog() -> dict:
    return v512.build_governed_parser_baseline_catalog(
        report=_catalog_report(),
        minimum_support=200,
    )


def _normalized(
    *,
    app: str,
    parsed_json: dict | None = None,
) -> NormalizedLog:
    return NormalizedLog(
        raw_log_id=1,
        receive_time=datetime(2026, 7, 1, tzinfo=timezone.utc),
        generated_time=datetime(2026, 7, 1, tzinfo=timezone.utc),
        log_type="TRAFFIC",
        subtype="end",
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
        app=app,
        action="allow",
        parsed_json=parsed_json
        or {
            "field_count": 115,
            "parse_status": "parsed",
            "parser_profile": "palo_alto",
            "parser_warnings": [],
            "parser_compatibility": {
                "status": "known_layout",
                "confidence": "high",
            },
        },
    )


def _session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _authoritative_counts(db) -> dict[str, int]:
    models = (
        RawLog,
        NormalizedLog,
        Alert,
        MLLabel,
        MLModelRun,
        DetectionRun,
        ResponseAction,
    )
    return {
        model.__tablename__: int(
            db.scalar(select(func.count()).select_from(model)) or 0
        )
        for model in models
    }


def test_profile_baseline_selection_and_sparse_fallback_are_conservative():
    catalog = _catalog()
    exact = v512.select_parser_baseline(
        catalog,
        parser_profile="palo_alto",
        source_type="firewall",
    )
    global_fallback = v512.select_parser_baseline(
        catalog,
        parser_profile="palo_alto",
        source_type="file_import",
    )
    incompatible = v512.select_parser_baseline(
        catalog,
        parser_profile="generic_syslog",
        source_type="router",
    )

    assert exact["scope"] == "parser_profile_source_type"
    assert exact["comparable"] is True
    assert global_fallback["scope"] == "global_fallback"
    assert global_fallback["comparable"] is True
    assert incompatible["comparable"] is False

    evaluation = v512.evaluate_parser_profile_baseline(
        [_normalized(app="ssl")],
        parser_profile="palo_alto",
        source_type="firewall",
        catalog=catalog,
    )
    assert evaluation["status"] == "Insufficient Evidence"
    assert "short_or_sparse_window" in evaluation["root_cause_codes"]


def test_unresolved_application_is_not_a_structural_parser_warning():
    log = _normalized(
        app="incomplete",
        parsed_json={
            "field_count": 115,
            "parse_status": "parsed",
            "parser_profile": "palo_alto",
            "parser_warnings": ["unknown or incomplete application"],
            "parser_compatibility": {
                "status": "known_layout",
                "confidence": "high",
            },
        },
    )
    result = v512.parser_quality_from_logs([log])

    assert result["quality"]["parser_error_rate"] == 0.0
    assert (
        result["quality"]["parser_structural_warning_per_row"]
        == 0.0
    )
    assert result["quality"]["unresolved_application_rate"] == 1.0


def test_private_parser_audit_returns_only_bounded_aggregates(tmp_path):
    sample = tmp_path / "private.log"
    fields = [""] * 115
    fields[1] = "2026/07/01 10:00:00"
    fields[2] = "serial"
    fields[3] = "TRAFFIC"
    fields[4] = "end"
    fields[6] = "2026/07/01 10:00:00"
    fields[7] = "198.51.100.10"
    fields[8] = "192.0.2.10"
    fields[14] = "incomplete"
    fields[15] = "vsys1"
    fields[16] = "outside"
    fields[17] = "inside"
    fields[25] = "443"
    fields[29] = "tcp"
    fields[30] = "allow"
    fields[31] = "100"
    fields[32] = "60"
    fields[33] = "40"
    fields[34] = "2"
    fields[35] = "2026/07/01 10:00:00"
    fields[46] = "aged-out"
    fields[98] = "2026-07-01T10:00:00.000+00:00"
    fields[101] = "networking"
    fields[102] = "internet-utility"
    fields[103] = "client-server"
    fields[104] = "3"
    fields[105] = "evasive"
    sample.write_text(
        "2026-07-01T10:00:00+00:00 firewall "
        + ",".join(fields)
        + "\n",
        encoding="utf-8",
    )

    result = v512.audit_private_panos_contract(sample, max_lines=1)
    serialized = json.dumps(result)

    assert result["ok"] is True
    assert result["rows_observed"] == 1
    assert result["bounded_in_memory_aggregates_only"] is True
    assert result["persistent_storage_created"] is False
    assert str(sample) not in serialized
    assert "198.51.100.10" not in serialized
    assert "192.0.2.10" not in serialized
    assert "raw_line" not in serialized


def test_system_contract_clears_traffic_only_fields():
    fields = [""] * 26
    fields[1] = "2026/07/01 10:00:00"
    fields[2] = "serial"
    fields[3] = "SYSTEM"
    fields[4] = "general"
    fields[6] = "2026/07/01 10:00:00"
    fields[7] = "vsys1"
    fields[8] = "event-id"
    fields[12] = "general"
    fields[13] = "informational"
    fields[14] = "System description"
    fields[22] = "device"
    fields[25] = "2026-07-01T10:00:00.000+00:00"
    parsed = parse_log_line(
        "2026-07-01T10:00:00+00:00 firewall "
        + ",".join(fields)
    )

    for field in (
        "src_ip",
        "dst_ip",
        "app",
        "action",
        "src_port",
        "dst_port",
        "src_zone",
        "dst_zone",
    ):
        assert parsed.normalized[field] is None
    assert parsed.normalized["vsys"] == "vsys1"
    assert parsed.parsed_json["system_event_id"] == "event-id"


def test_operational_diagnostics_are_read_only_and_private():
    Session = _session_factory()
    with Session() as db:
        source = LogSource(
            name="private-source-name",
            source_type="firewall",
            parser_profile="palo_alto",
        )
        db.add(source)
        db.flush()
        start = datetime(2026, 7, 1, tzinfo=timezone.utc)
        for index, app in enumerate(("ssl", "incomplete"), 1):
            raw = RawLog(
                source_id=source.id,
                raw_line=f"private raw evidence {index}",
                syslog_timestamp=start + timedelta(seconds=index),
            )
            db.add(raw)
            db.flush()
            normalized = _normalized(app=app)
            normalized.raw_log_id = raw.id
            normalized.generated_time = start + timedelta(seconds=index)
            db.add(normalized)
        observation = MLShadowObservation(
            observation_key="a" * 64,
            candidate_name="private-candidate-name",
            candidate_version="v5.12-test",
            contract_fingerprint="b" * 64,
            status="evaluated_shadow_read_only",
            contract_matched=True,
            source_id=source.id,
            window_start=start,
            window_end=start + timedelta(minutes=1),
            requested_limit=2,
            rows_evaluated=2,
            queue_count=0,
            queue_rate=0.0,
            disagreement_count=0,
            disagreement_rate=0.0,
            isolation_anomaly_count=0,
            isolation_anomaly_rate=0.0,
            aggregate_json={
                "drift": {
                    "quality": {
                        "parser_warning_per_row": 0.5
                    }
                }
            },
            created_by="test",
            created_at=start,
        )
        db.add(observation)
        db.commit()
        before = _authoritative_counts(db)
        result = v512.build_parser_profile_operational_diagnostics(
            db,
            catalog=_catalog(),
        )
        after = _authoritative_counts(db)

    serialized = json.dumps(result, default=str)
    assert before == after
    assert result["labels_accessed"] is False
    assert result["accuracy_metrics_calculated"] is False
    assert result["source_identifiers_included"] is False
    assert result["raw_logs_included"] is False
    assert "private-source-name" not in serialized
    assert "private raw evidence" not in serialized
    assert "private-candidate-name" not in serialized


def test_controlled_projection_is_stable_and_contains_no_dynamic_paths():
    report = {
        "ok": True,
        "scenario_count": 24,
        "mode_run_count": 96,
        "passed_count": 96,
        "failed_count": 0,
        "false_positive_count": 0,
        "false_negative_count": 0,
        "scenario_summary": [{"scenario": "normal", "passed": True}],
        "generated_at": "dynamic",
        "variant_manifest": {"output_dir": "private-path"},
    }
    projection = v512.controlled_validation_projection(report)
    serialized = json.dumps(projection)

    assert "generated_at" not in projection
    assert "variant_manifest" not in projection
    assert "private-path" not in serialized
