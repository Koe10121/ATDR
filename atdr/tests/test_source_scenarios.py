import shutil
import importlib
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base
from atdr.app.db.models import LogSource, RawLog, ResponseAction
from atdr.app.services.log_service import import_log_file
from atdr.app.services.source_service import get_or_create_source
from atdr.scripts.export_lab_validation_report import export_lab_validation_report
from atdr.scripts.run_source_scenario import SCENARIOS, _temp_session_factory, run_source_scenario
from atdr.scripts.prepare_safe_demo import CONFIRMATION, prepare_safe_demo
from atdr.scripts.validate_live_source import validate_live_source


def _repo_test_output_dir(name: str) -> Path:
    path = PROJECT_ROOT / ".pytest_tmp" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_source_scenario_samples_parse_in_dry_run():
    for scenario in SCENARIOS:
        result = run_source_scenario(scenario=scenario, dry_run=True)

        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["read"] == result["available_lines"]


def test_normal_allowed_scenario_does_not_create_high_critical_alerts():
    result = run_source_scenario(
        scenario="normal_allowed_traffic",
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
    assert checks["no_high_or_critical_alerts"]["passed"] is True
    assert result["expected_outcome"]["source_counts"]["alerts"] == 0


def test_negative_control_scenarios_do_not_create_high_critical_alerts():
    for scenario in [
        "normal_web_dns_quic_traffic",
        "normal_high_volume_but_allowed_traffic",
        "normal_repeated_same_service_traffic",
    ]:
        result = run_source_scenario(
            scenario=scenario,
            use_temp_db=True,
            run_detection_after=True,
        )

        checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
        assert result["ok"] is True
        assert checks["no_high_or_critical_alerts"]["passed"] is True


def test_port_scan_scenario_creates_source_scoped_alert():
    result = run_source_scenario(
        scenario="port_scan_like_traffic",
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["detection_results"][0]["source_id"] == result["source_after"]["source_id"]
    assert result["detection_results"][0]["top_attack_types"] == [
        {"name": "port_scan", "count": 1}
    ]
    assert result["source_after"]["recent_detection_runs"][0][
        "top_attack_types"
    ] == [{"name": "port_scan", "count": 1}]
    assert result["expected_outcome"]["source_counts"]["alerts"] >= 1
    assert any(alert["alert_type"] == "possible_port_scan" for alert in result["expected_outcome"]["alert_summaries"])
    assert result["expected_outcome"]["response_safety"] == {
        "response_actions_before": 0,
        "response_actions_after": 0,
        "automatic_response_actions_created": 0,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    assert any(
        "Data quality note:" in warning
        for warning in result["source_after"]["quality"]["warnings"]
    )


def test_policy_violation_suspicious_app_scenario_creates_alert():
    result = run_source_scenario(
        scenario="policy_violation_suspicious_app",
        use_temp_db=True,
        run_detection_after=True,
    )

    checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
    assert result["ok"] is True
    assert checks["suspicious_app_alert_created"]["passed"] is True
    assert result["expected_outcome"]["source_counts"]["alerts"] >= 1


def test_mixed_small_subnet_scenario_exercises_multiple_threat_types():
    result = run_source_scenario(
        scenario="mixed_small_subnet_validation",
        use_temp_db=True,
        run_detection_after=True,
    )

    checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
    assert result["ok"] is True
    assert checks["mixed_port_scan_alert_created"]["passed"] is True
    assert checks["mixed_brute_force_alert_created"]["passed"] is True
    assert checks["mixed_beaconing_alert_created"]["passed"] is True
    assert result["expected_outcome"]["source_counts"]["raw_logs"] == 27


def test_repeated_dedup_scenario_updates_occurrence_count():
    result = run_source_scenario(
        scenario="repeated_dedup_traffic",
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
    assert checks["alert_deduplicated"]["passed"] is True
    assert checks["dedup_count_recorded"]["passed"] is True
    assert result["expected_outcome"]["alert_summaries"][0]["occurrence_count"] >= 2


def test_generic_and_raw_fallback_scenarios_preserve_evidence():
    generic = run_source_scenario(scenario="generic_syslog_mixed", use_temp_db=True)
    fallback = run_source_scenario(scenario="malformed_raw_fallback", use_temp_db=True)

    assert generic["ok"] is True
    assert generic["source_after"]["health"]["status"] == "warning"
    assert generic["expected_outcome"]["source_counts"]["raw_logs"] == 3
    assert generic["import_results"][0]["parser_quality"][
        "generic_syslog_rows"
    ] == 3
    assert fallback["ok"] is True
    assert fallback["source_after"]["health"]["status"] == "warning"
    assert fallback["source_after"]["health"]["parser_quality_state"] == "warning"
    assert fallback["source_after"]["health"]["raw_fallback_count"] == 3
    assert fallback["source_after"]["parse_failure_count"] == 3
    assert fallback["expected_outcome"]["source_counts"]["raw_logs"] == 3
    assert fallback["import_results"][0]["parser_quality"][
        "raw_fallback_rows"
    ] == 3
    assert fallback["expected_outcome"]["response_safety"][
        "automatic_response_actions_created"
    ] == 0


def test_source_scenario_disable_preserves_existing_rows():
    result = run_source_scenario(
        scenario="malformed_raw_fallback",
        use_temp_db=True,
        disable_source_after=True,
    )

    assert result["ok"] is True
    assert result["source_after"]["health"]["status"] == "disabled"
    assert result["disabled_source_check"]["data_preserved"] is True
    assert result["disabled_source_check"]["raw_logs_after_disable"] == 3


def test_safe_demo_requires_confirmation_and_creates_no_response_action():
    preview = prepare_safe_demo()
    denied = prepare_safe_demo(execute=True, confirmation="wrong", use_temp_db=True)
    executed = prepare_safe_demo(execute=True, confirmation=CONFIRMATION, use_temp_db=True)

    assert preview["status"] == "dry_run"
    assert preview["prepared"] is False
    assert denied["status"] == "confirmation_required"
    assert executed["ok"] is True
    assert executed["prepared"] is True
    assert executed["expected_outcome"]["response_safety"]["automatic_response_actions_created"] == 0
    assert executed["safety"]["automatic_response"] is False


def test_idempotent_source_scenario_does_not_duplicate_existing_demo(monkeypatch):
    scenario_module = importlib.import_module("atdr.scripts.run_source_scenario")
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    SessionFactory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    monkeypatch.setattr(scenario_module, "SessionLocal", SessionFactory)
    monkeypatch.setattr(scenario_module, "init_db", lambda: None)
    try:
        first = run_source_scenario(
            scenario="port_scan_like_traffic",
            source_name="fixed-safe-demo",
            run_detection_after=True,
            idempotent=True,
        )
        second = run_source_scenario(
            scenario="port_scan_like_traffic",
            source_name="fixed-safe-demo",
            run_detection_after=True,
            idempotent=True,
        )
        with SessionFactory() as db:
            raw_count = int(db.scalar(select(func.count(RawLog.id))) or 0)
            response_count = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

        assert first["status"] == "prepared"
        assert second["status"] == "already_prepared"
        assert second["import_results"] == []
        assert second["detection_results"] == []
        assert raw_count == first["expected_outcome"]["source_counts"]["raw_logs"]
        assert response_count == 0
    finally:
        engine.dispose()


def test_validate_live_source_checks_source_scoped_detection_without_response_actions():
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            source = get_or_create_source(
                db,
                name="validation-lab-firewall",
                source_type="firewall",
                parser_profile="palo_alto",
            )
            db.commit()
            db.refresh(source)
            import_log_file(
                db,
                PROJECT_ROOT / "data" / "samples" / "scenarios" / "port_scan_like_traffic.txt",
                actor="pytest",
                source_id=source.id,
                parser_profile="palo_alto",
            )

            result = validate_live_source(
                db=db,
                source_name=source.name,
                source_type="firewall",
                parser_profile="palo_alto",
                duration=0,
                run_detection_after=True,
                write_report=False,
            )

            checks = {item["name"]: item for item in result["checks"]}
            assert result["ok"] is True
            assert checks["source_exists"]["passed"] is True
            assert checks["raw_evidence_preserved"]["passed"] is True
            assert checks["no_response_actions_created"]["passed"] is True
            assert result["detection_result"]["source_id"] == source.id
            assert result["detection_result"]["created_alerts"] >= 1
            assert result["counts_after"]["raw_logs"] == 10
    finally:
        engine.dispose()


def test_lab_validation_report_exports_safe_source_summary():
    output_dir = _repo_test_output_dir("lab_validation_report_exports_safe_source_summary")
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            source = get_or_create_source(
                db,
                name="report-lab-firewall",
                source_type="firewall",
                parser_profile="palo_alto",
            )
            db.commit()
            db.refresh(source)
            import_log_file(
                db,
                PROJECT_ROOT / "data" / "samples" / "scenarios" / "port_scan_like_traffic.txt",
                actor="pytest",
                source_id=source.id,
                parser_profile="palo_alto",
            )
            validate_live_source(
                db=db,
                source_name=source.name,
                source_type="firewall",
                parser_profile="palo_alto",
                duration=0,
                run_detection_after=True,
                write_report=False,
            )

            result = export_lab_validation_report(source_name=source.name, output_dir=output_dir, db=db)

            assert result["ok"] is True
            assert result["alert_count"] >= 1
            assert result["paths"]["json"].endswith(".json")
            assert result["paths"]["markdown"].endswith(".md")
            assert "decision support" in " ".join(result["report"]["limitations"]).lower()
            assert "simulated" in " ".join(result["report"]["limitations"]).lower()
            assert Path(result["path"]).exists()
            markdown = Path(result["paths"]["markdown"]).read_text(encoding="utf-8")
            assert "ATDR Simulation Validation Report" in markdown
            assert "Real hardware validation: not_performed" in markdown
            assert "Simulated response only: yes" in markdown
    finally:
        engine.dispose()


def test_lab_validation_report_missing_source_does_not_create_source():
    output_dir = _repo_test_output_dir("lab_validation_report_missing_source")
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            before = int(db.scalar(select(func.count(LogSource.id))) or 0)
            result = export_lab_validation_report(source_name="missing-source", output_dir=output_dir, db=db)
            after = int(db.scalar(select(func.count(LogSource.id))) or 0)

            assert result["ok"] is False
            assert "Source not found" in result["error"]
            assert after == before
    finally:
        engine.dispose()
