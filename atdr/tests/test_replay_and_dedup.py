from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, AuditLog, DetectionRun, IngestionRun, LogSource, NormalizedLog, RawLog
from atdr.app.services.dashboard_service import build_dashboard_summary
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file, import_raw_log_line
from atdr.app.services.source_service import get_or_create_source, recent_source_detection_runs
from atdr.scripts.performance_smoke import run_performance_smoke
from atdr.scripts.register_log_source import register_log_source
from atdr.scripts.replay_logs import replay_logs


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def test_replay_logs_dry_run_does_not_write_rows():
    Session = _session()
    with Session() as db:
        result = replay_logs(db, sample_path="data/samples/paloalto-demo.txt", rate=0, limit=2, dry_run=True)
        raw_count = db.scalar(select(func.count(RawLog.id)))
        run_count = db.scalar(select(func.count(IngestionRun.id)))

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["read"] == 2
    assert result["parsed"] == 2
    assert raw_count == 0
    assert run_count == 0


def test_replay_logs_direct_import_preserves_raw_evidence():
    Session = _session()
    with Session() as db:
        result = replay_logs(
            db,
            sample_path="data/samples/paloalto-demo.txt",
            rate=0,
            limit=1,
            dry_run=False,
            send_to="direct",
            source_name="lab-firewall-replay",
            source_type="firewall",
            source_host="192.0.2.50",
            source_port=514,
            actor="unit_replay",
        )
        raw_count = db.scalar(select(func.count(RawLog.id)))
        normalized_count = db.scalar(select(func.count(NormalizedLog.id)))
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "ingest_syslog"))
        run = db.scalar(select(IngestionRun))
        source = db.scalar(select(LogSource).where(LogSource.name == "lab-firewall-replay"))

    assert result["ok"] is True
    assert result["imported"] == 1
    assert result["run_id"] == run.id
    assert raw_count == 1
    assert normalized_count == 1
    assert audit is None
    assert run.source_type == "replay_direct"
    assert run.parsed_successfully == 1
    assert source is not None
    assert source.source_type == "firewall"
    assert source.host == "192.0.2.50"
    assert source.port == 514
    assert source.logs_received_count == 1
    assert source.parse_success_count == 1


def test_replay_logs_direct_detection_run_links_to_source():
    Session = _session()
    with Session() as db:
        result = replay_logs(
            db,
            sample_path="data/samples/paloalto-demo.txt",
            rate=0,
            limit=2,
            dry_run=False,
            send_to="direct",
            run_detection_after=True,
            source_name="lab-firewall-detection",
            source_type="firewall",
            actor="unit_replay",
        )
        source = db.scalar(select(LogSource).where(LogSource.name == "lab-firewall-detection"))
        runs = recent_source_detection_runs(db, source.id)

    assert result["ok"] is True
    assert source is not None
    assert result["detection"]["source_id"] == source.id
    assert runs
    assert runs[0]["details"]["source_id"] == source.id
    assert runs[0]["logs_evaluated"] == 2


def test_replay_logs_dry_run_accepts_source_metadata_without_writing():
    Session = _session()
    with Session() as db:
        result = replay_logs(
            db,
            sample_path="data/samples/paloalto-demo.txt",
            rate=0,
            limit=1,
            dry_run=True,
            send_to="direct",
            source_name="dry-run-firewall",
            source_type="firewall",
            source_host="192.0.2.60",
            source_port=514,
        )
        source_count = db.scalar(select(func.count(LogSource.id)))

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["source"]["name"] == "dry-run-firewall"
    assert result["source"]["source_type"] == "firewall"
    assert source_count == 0


def test_register_log_source_helper_creates_and_updates(monkeypatch):
    Session = _session()
    monkeypatch.setattr("atdr.scripts.register_log_source.init_db", lambda: None)
    monkeypatch.setattr("atdr.scripts.register_log_source.SessionLocal", Session)

    created = register_log_source(
        name="helper-firewall",
        source_type="firewall",
        parser_profile="palo_alto",
        host="192.0.2.70",
        port=514,
    )
    updated = register_log_source(
        name="helper-firewall",
        source_type="syslog_udp",
        parser_profile="generic_syslog",
        host="192.0.2.71",
        port=5514,
        enabled=False,
    )

    assert created["ok"] is True
    assert created["action"] == "created"
    assert updated["ok"] is True
    assert updated["action"] == "updated"
    assert updated["source"]["source_type"] == "syslog_udp"
    assert updated["source"]["parser_profile"] == "generic_syslog"
    assert updated["source"]["health"]["status"] == "disabled"


def test_parser_profiles_preserve_raw_evidence_without_crashing():
    Session = _session()
    with Session() as db:
        generic = import_raw_log_line(
            db,
            "2026-05-22T00:00:00Z lab-router-1 generic syslog payload without Palo Alto CSV",
            source_name="generic-router",
            source_type="router",
            parser_profile="generic_syslog",
            actor="unit_test",
        )
        raw_fallback = import_raw_log_line(
            db,
            "not a syslog or Palo Alto line",
            source_name="unknown-raw-source",
            source_type="sample",
            parser_profile="raw_fallback",
            actor="unit_test",
        )
        generic_source = db.scalar(select(LogSource).where(LogSource.name == "generic-router"))
        fallback_source = db.scalar(select(LogSource).where(LogSource.name == "unknown-raw-source"))
        rows = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id.asc())))

    assert generic["parsed"] is True
    assert raw_fallback["parsed"] is False
    assert generic_source.parse_success_count == 1
    assert fallback_source.parse_failure_count == 1
    assert rows[0].parsed_json["parser_profile"] == "generic_syslog"
    assert rows[1].parsed_json["parser_profile"] == "raw_fallback"
    assert rows[1].parsed_json["raw_fallback"] is True


def test_alert_dedup_updates_existing_alert_and_keeps_raw_logs():
    Session = _session()
    sample_path = Path("data/samples/paloalto-demo.txt")
    with Session() as db:
        first_import = import_log_file(db, sample_path, actor="unit_test")
        first_detection = run_detection(db, limit=50, use_ml=False, actor="unit_test")
        first_alert_count = int(db.scalar(select(func.count(Alert.id))) or 0)
        first_evidence_count = int(db.scalar(select(func.count(AlertEvidence.id))) or 0)

        second_import = import_log_file(db, sample_path, actor="unit_test")
        second_detection = run_detection(db, limit=50, use_ml=False, actor="unit_test")
        second_alert_count = int(db.scalar(select(func.count(Alert.id))) or 0)
        second_evidence_count = int(db.scalar(select(func.count(AlertEvidence.id))) or 0)
        raw_count = int(db.scalar(select(func.count(RawLog.id))) or 0)
        alert = db.scalar(select(Alert).where(Alert.alert_type == "deny_drop_action"))
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "alert_deduplicated"))
        detection_runs = list(db.scalars(select(DetectionRun).order_by(DetectionRun.id.asc())))

    assert first_import["parsed"] == 2
    assert second_import["parsed"] == 2
    assert first_detection["created_alerts"] >= 1
    assert second_detection["created_alerts"] == 0
    assert second_detection["deduplicated_alert_updates"] >= 1
    assert second_detection["detection_run_id"] == detection_runs[-1].id
    assert second_alert_count == first_alert_count
    assert second_evidence_count > first_evidence_count
    assert raw_count == 4
    assert alert is not None
    metadata = next(rule for rule in alert.matched_rules_json if rule["code"] == "group_metadata")
    assert metadata["deduplicated"] is True
    assert metadata["occurrence_count"] >= 2
    assert audit is not None
    assert detection_runs[-1].alerts_deduplicated >= 1


def test_detection_run_attack_types_exclude_unrelated_historical_alerts():
    Session = _session()
    with Session() as db:
        db.add(
            Alert(
                title="Historical unrelated alert",
                alert_type="paloalto_threat_log",
                src_ip="198.51.100.20",
                dst_ip="203.0.113.20",
                threat_score=90,
                severity="Critical",
                status="open",
                explanation="Historical alert outside the current run.",
                matched_rules_json=[
                    {
                        "code": "paloalto_threat_log",
                        "title": "Historical threat",
                        "score": 90,
                    }
                ],
                recommended_response="Review.",
            )
        )
        source = get_or_create_source(
            db,
            name="run-scoped-port-scan",
            source_type="firewall",
            parser_profile="palo_alto",
        )
        db.commit()
        db.refresh(source)
        import_log_file(
            db,
            "data/samples/scenarios/port_scan_like_traffic.txt",
            actor="unit_test",
            source_id=source.id,
            parser_profile="palo_alto",
        )

        result = run_detection(
            db,
            limit=100,
            use_ml=False,
            actor="unit_test",
            source_id=source.id,
            source_name=source.name,
            source_type=source.source_type,
        )
        run = db.get(DetectionRun, result["detection_run_id"])

    assert result["top_attack_types"] == [{"name": "port_scan", "count": 1}]
    assert run is not None
    assert run.top_attack_types_json == [{"name": "port_scan", "count": 1}]


def test_dashboard_data_quality_counts_parser_errors_and_duplicates():
    Session = _session()
    with Session() as db:
        import_raw_log_line(db, "bad line", actor="unit_test")
        import_log_file(db, "data/samples/paloalto-demo.txt", limit=1, actor="unit_test")
        import_log_file(db, "data/samples/paloalto-demo.txt", limit=1, actor="unit_test")

        summary = build_dashboard_summary(db)
        runs = list(db.scalars(select(IngestionRun).order_by(IngestionRun.id.asc())))

    assert summary["ingestion_stats"]["parse_failure_count"] == 1
    assert summary["ingestion_stats"]["parse_success_count"] == 2
    assert summary["ingestion_stats"]["duplicate_raw_line_groups"] == 1
    assert "syslog timestamp" in summary["data_quality"]["parser_error_examples"][0]["parser_error"]
    assert len(runs) == 2
    assert runs[-1].duplicate_raw_logs == 1


def test_performance_smoke_runs_read_only(monkeypatch):
    Session = _session()
    with Session() as db:
        import_log_file(db, "data/samples/paloalto-demo.txt", limit=2, actor="unit_test")
        before = int(db.scalar(select(func.count(RawLog.id))) or 0)

    monkeypatch.setattr("atdr.scripts.performance_smoke.SessionLocal", Session)
    result = run_performance_smoke(feature_limit=2)

    with Session() as db:
        after = int(db.scalar(select(func.count(RawLog.id))) or 0)

    assert result["read_only"] is True
    assert result["total_raw_logs"] == before
    assert after == before
    assert "overview_summary_seconds" in result["timings"]
    assert "ml_governance_lightweight_summary_seconds" in result["timings"]
    assert "ingestion_run_history_query_seconds" in result["timings"]
    assert "detection_run_history_query_seconds" in result["timings"]
    assert "alert_list_query_seconds" in result["timings"]
