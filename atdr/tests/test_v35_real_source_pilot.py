import json
from pathlib import Path

from sqlalchemy import func, select

from atdr.app.core.config import Settings
from atdr.app.db.models import RawLog, ResponseAction
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.source_service import get_or_create_source
from atdr.scripts.export_real_source_pilot_evidence import export_real_source_pilot_evidence
from atdr.scripts.run_source_scenario import SCENARIO_DIR, _temp_session_factory
from atdr.scripts.run_v35_real_source_pilot_check import run_v35_real_source_pilot_check


def _simulation_settings() -> Settings:
    return Settings(RESPONSE_SIMULATION=True, RESPONSE_PROVIDER="simulation")


def _seed_source_with_sample(
    SessionFactory,
    *,
    source_name: str,
    sample_name: str,
    source_type: str = "firewall",
    parser_profile: str = "palo_alto",
    run_detection_after: bool = True,
):
    sample_path = SCENARIO_DIR / sample_name
    with SessionFactory() as db:
        source = get_or_create_source(
            db,
            name=source_name,
            source_type=source_type,
            parser_profile=parser_profile,
        )
        db.commit()
        db.refresh(source)
        import_log_file(
            db,
            sample_path,
            actor="pytest",
            source_id=source.id,
            parser_profile=parser_profile,
        )
        if run_detection_after:
            run_detection(
                db,
                limit=100,
                use_ml=False,
                actor="pytest",
                source_id=source.id,
                source_name=source.name,
                source_type=source.source_type,
            )
        source_id = source.id
    return source_id


def test_v35_missing_source_reports_not_validated_and_read_only():
    engine, SessionFactory = _temp_session_factory()
    try:
        result = run_v35_real_source_pilot_check(
            source_name="missing-lab-firewall",
            session_factory=SessionFactory,
            settings=_simulation_settings(),
        )

        assert result["ok"] is True
        assert result["status"] == "source_missing_not_validated"
        assert result["real_device_forwarding_validated"] is False
        assert result["current_database_modified"] is False
        assert result["response_actions_before"] == result["response_actions_after"] == 0
    finally:
        engine.dispose()


def test_v35_source_with_logs_reports_counts_detection_and_simulated_status():
    engine, SessionFactory = _temp_session_factory()
    try:
        _seed_source_with_sample(
            SessionFactory,
            source_name="lab-firewall-alpha",
            sample_name="port_scan_like_traffic.txt",
        )

        result = run_v35_real_source_pilot_check(
            source_name="lab-firewall-alpha",
            expected_min_logs=10,
            session_factory=SessionFactory,
            settings=_simulation_settings(),
        )

        assert result["ok"] is True
        assert result["counts"]["raw_logs"] == 10
        assert result["counts"]["normalized_logs"] == 10
        assert result["latest_detection_run"]["logs_evaluated"] == 10
        assert result["source_pipeline_validated"] is True
        assert result["real_device_forwarding_validated"] is True
        assert result["response_actions"]["before"] == result["response_actions"]["after"] == 0
        assert result["response_automation_allowed"] is False
        assert result["real_firewall_blocking_enabled"] is False
    finally:
        engine.dispose()


def test_v35_simulated_source_is_not_marked_as_real_device_forwarding():
    engine, SessionFactory = _temp_session_factory()
    try:
        _seed_source_with_sample(
            SessionFactory,
            source_name="scenario-simulated-firewall",
            sample_name="port_scan_like_traffic.txt",
        )

        result = run_v35_real_source_pilot_check(
            source_name="scenario-simulated-firewall",
            expected_min_logs=10,
            session_factory=SessionFactory,
            settings=_simulation_settings(),
        )

        assert result["source_pipeline_validated"] is True
        assert result["simulated_or_replay_source"] is True
        assert result["real_device_forwarding_validated"] is False
        assert result["status"] == "simulated_source_pipeline_validated"
    finally:
        engine.dispose()


def test_v35_parser_failure_rate_appears_for_raw_fallback_source():
    engine, SessionFactory = _temp_session_factory()
    try:
        _seed_source_with_sample(
            SessionFactory,
            source_name="pytest-raw-fallback-source",
            sample_name="malformed_raw_fallback.txt",
            source_type="sample",
            parser_profile="raw_fallback",
            run_detection_after=False,
        )

        result = run_v35_real_source_pilot_check(
            source_name="pytest-raw-fallback-source",
            session_factory=SessionFactory,
            settings=_simulation_settings(),
        )

        assert result["counts"]["raw_logs"] > 0
        assert result["counts"]["parser_error_count"] > 0
        assert result["counts"]["parse_failure_rate_percent"] > 0
        assert result["latest_parser_errors"]
        assert "raw_line_redacted_excerpt" not in result["latest_parser_errors"][0]
    finally:
        engine.dispose()


def test_v35_evidence_export_omits_full_raw_log_contents_by_default(tmp_path: Path):
    engine, SessionFactory = _temp_session_factory()
    try:
        _seed_source_with_sample(
            SessionFactory,
            source_name="pytest-evidence-firewall",
            sample_name="port_scan_like_traffic.txt",
        )
        with SessionFactory() as db:
            raw_line = db.scalar(select(RawLog.raw_line).limit(1))
            before_responses = db.scalar(select(func.count(ResponseAction.id)))

        result = export_real_source_pilot_evidence(
            source_name="pytest-evidence-firewall",
            expected_min_logs=10,
            output_dir=tmp_path,
            write=False,
            session_factory=SessionFactory,
            settings=_simulation_settings(),
        )
        rendered = json.dumps(result, default=str)

        assert result["written"] is False
        assert result["source_scoped_alert_ids"]
        assert raw_line not in rendered
        assert result["safety"]["raw_private_log_contents_included"] is False
        with SessionFactory() as db:
            after_responses = db.scalar(select(func.count(ResponseAction.id)))
        assert before_responses == after_responses == 0
    finally:
        engine.dispose()


def test_v35_evidence_export_write_mode_uses_explicit_output_dir(tmp_path: Path):
    engine, SessionFactory = _temp_session_factory()
    try:
        _seed_source_with_sample(
            SessionFactory,
            source_name="pytest-write-firewall",
            sample_name="port_scan_like_traffic.txt",
        )

        result = export_real_source_pilot_evidence(
            source_name="pytest-write-firewall",
            expected_min_logs=10,
            output_dir=tmp_path,
            write=True,
            session_factory=SessionFactory,
            settings=_simulation_settings(),
        )

        assert result["written"] is True
        assert result["output_path"]
        assert Path(result["output_path"]).exists()
        assert Path(result["output_path"]).parent == tmp_path
    finally:
        engine.dispose()
