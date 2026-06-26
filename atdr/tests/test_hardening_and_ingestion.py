from pathlib import Path
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings, validate_runtime_settings
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.services.alert_service import alert_sla
from atdr.app.services.log_service import import_raw_log_line
from atdr.app.services.tuning_service import build_detection_tuning_report
from atdr.dashboard.ui_fragments import (
    badge_html,
    command_panel_html,
    empty_state_html,
    key_value_grid_html,
    page_hero_html,
    plotly_theme,
    presentation_mode_default,
    ranked_list_html,
    readiness_grid_html,
    result_card_html,
    timeline_row_html,
)
from atdr.scripts.demo_health_check import run_demo_health_check
from atdr.scripts import backup_demo, backup_postgres, cleanup_exports
from atdr.scripts.config_doctor import run_config_doctor
from atdr.scripts.lab_smoke_check import run_lab_smoke_check
from atdr.tests.test_parser import TRAFFIC_LINE


def test_production_config_validation_rejects_unsafe_defaults():
    settings = Settings(
        ENVIRONMENT="production",
        JWT_SECRET_KEY="change-this-secret-before-production",
        AUTO_CREATE_TABLES=True,
        RESPONSE_SIMULATION=False,
        CORS_ALLOWED_ORIGINS="*",
    )

    issues = validate_runtime_settings(settings)

    assert "JWT_SECRET_KEY must be changed for production." in issues
    assert "AUTO_CREATE_TABLES must be false in production; use Alembic migrations." in issues
    assert "RESPONSE_SIMULATION should remain true until a firewall connector is formally approved." in issues
    assert "CORS_ALLOWED_ORIGINS must not include '*' in production." in issues


def test_config_doctor_accepts_local_demo_settings():
    result = run_config_doctor(
        Settings(
            ENVIRONMENT="development",
            DATABASE_URL="sqlite:///./atdr.db",
            AUTO_CREATE_TABLES=True,
            RESPONSE_SIMULATION=True,
            JWT_SECRET_KEY="change-this-secret-before-production",
            CORS_ALLOWED_ORIGINS="http://127.0.0.1:8501",
            SYSLOG_ENABLED=False,
            DEMO_SAMPLE_LOG_PATH="paloalto-firewall(1).log",
            ML_MODEL_PATH="atdr/models/isolation_forest.joblib",
        )
    )

    assert result["ok"] is True
    assert result["critical_count"] == 0
    assert any(issue["code"] == "default-jwt-secret" for issue in result["issues"])
    assert any(issue["code"] == "local-sqlite-profile" for issue in result["issues"])


def test_config_doctor_warns_for_docker_postgres_host_in_local_mode():
    db_password = "db-password-that-must-not-leak"
    result = run_config_doctor(
        Settings(
            ENVIRONMENT="development",
            DATABASE_URL=f"postgresql+psycopg2://atdr:{db_password}@postgres:5432/atdr",
            RESPONSE_SIMULATION=True,
            ASSISTANT_ENABLED=False,
            ASSISTANT_PROVIDER="disabled",
            ASSISTANT_API_KEY="",
            ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
        )
    )
    rendered = str(result)
    codes = {issue["code"] for issue in result["issues"]}

    assert result["ok"] is True
    assert result["database"] == "postgresql"
    assert result["database_host"] == "postgres"
    assert "postgres-docker-host-local" in codes
    assert "postgres-local-optional" in codes
    assert db_password not in rendered
    assert 'sqlite:///./atdr.db' in result["local_workflow_recommendation"]


def test_config_doctor_flags_assistant_unsafe_context_and_provider():
    result = run_config_doctor(
        Settings(
            ENVIRONMENT="development",
            ASSISTANT_ENABLED=True,
            ASSISTANT_PROVIDER="external-test",
            ASSISTANT_API_KEY="assistant-secret",
            ASSISTANT_ALLOW_RAW_LOG_CONTEXT=True,
        )
    )
    codes = {issue["code"] for issue in result["issues"]}
    rendered = str(result)

    assert "assistant-external-enabled" in codes
    assert "assistant-provider-configured" in codes
    assert "assistant-raw-log-context" in codes
    assert "assistant-secret" not in rendered


def test_config_doctor_flags_unsafe_production_defaults():
    result = run_config_doctor(
        Settings(
            ENVIRONMENT="production",
            DATABASE_URL="sqlite:///./atdr.db",
            AUTO_CREATE_TABLES=True,
            RESPONSE_SIMULATION=False,
            JWT_SECRET_KEY="change-this-secret-before-production",
            CORS_ALLOWED_ORIGINS="*",
            SYSLOG_ENABLED=True,
            SYSLOG_HOST="0.0.0.0",
        )
    )

    codes = {issue["code"] for issue in result["issues"] if issue["severity"] == "critical"}
    assert result["ok"] is False
    assert "production-sqlite" in codes
    assert "default-jwt-secret" in codes
    assert "wildcard-cors" in codes
    assert "response-simulation-disabled" in codes


def test_syslog_line_ingestion_preserves_valid_and_malformed_logs():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    with session() as db:
        valid = import_raw_log_line(db, TRAFFIC_LINE, source_name="unit-test")
        malformed = import_raw_log_line(db, "bad line", source_name="unit-test")

        assert valid["parsed"] is True
        assert malformed["parsed"] is False
        assert db.scalar(select(RawLog).where(RawLog.raw_line == "bad line")) is not None
        assert db.scalar(select(NormalizedLog).where(NormalizedLog.id == valid["normalized_log_id"])) is not None


def test_demo_health_check_handles_unavailable_services():
    result = run_demo_health_check(
        api_base_url="http://127.0.0.1:9",
        dashboard_url="http://127.0.0.1:9",
        timeout=0.2,
    )

    assert result["ok"] is False
    assert result["checks"]["api_health"]["ok"] is False
    assert "error" in result["checks"]["api_health"]


def test_lab_smoke_check_handles_unavailable_services():
    result = run_lab_smoke_check(
        api_base_url="http://127.0.0.1:9",
        dashboard_url="http://127.0.0.1:9",
        timeout=0.2,
        include_docker=False,
    )

    assert result["ok"] is False
    assert result["local_stack_ok"] is False
    assert result["checks"]["api_health"]["ok"] is False


def test_dashboard_html_fragments_are_compact_and_escape_values():
    html = command_panel_html(
        [
            {
                "label": "Security Posture",
                "value": "<Stable>",
                "detail": "Rule-first detection",
                "color": "#22c55e",
            }
        ]
    )
    ranked = ranked_list_html([{"name": "<script>", "count": 3}], tone="#14b8a6")

    assert "\n" not in html
    assert "&lt;Stable&gt;" in html
    assert "<script>" not in ranked
    assert "&lt;script&gt;" in ranked


def test_dashboard_badges_and_plotly_theme_are_safe_and_consistent():
    badge = badge_html("<Critical>", color="#ef4444")
    theme = plotly_theme()

    assert "&lt;Critical&gt;" in badge
    assert "<Critical>" not in badge
    assert theme["paper_bgcolor"] == "rgba(0,0,0,0)"
    assert theme["plot_bgcolor"] == "rgba(0,0,0,0)"
    assert theme["font"]["color"] == "#e5edf6"


def test_dashboard_polish_fragments_escape_values_and_stay_compact():
    hero = page_hero_html("<Overview>", "Rule-first <proof>", badges=["<Safe>"])
    empty = empty_state_html("<No data>", "Import <logs>")
    result = result_card_html("<Done>", "Created <alerts>", status="<Success>")
    timeline = timeline_row_html("<time>", "<Action>", "<Details>", actor="<admin>")
    grid = key_value_grid_html([{"label": "<Source>", "value": "<10.0.0.1>"}])

    combined = hero + empty + result + timeline + grid

    assert "<Overview>" not in combined
    assert "<script>" not in combined
    assert "&lt;Overview&gt;" in combined
    assert "&lt;admin&gt;" in combined
    assert "\n" not in combined


def test_dashboard_readiness_and_presentation_defaults_are_safe():
    readiness = readiness_grid_html(
        [
            {"label": "<API>", "ok": True, "detail": "healthy"},
            {"label": "Alerts", "ok": False, "detail": "<missing>"},
        ]
    )

    assert presentation_mode_default() is True
    assert "&lt;API&gt;" in readiness
    assert "&lt;missing&gt;" in readiness
    assert "Ready" in readiness
    assert "Needs Attention" in readiness
    assert "\n" not in readiness


def test_demo_docs_do_not_contain_mojibake():
    docs = [
        Path("docs/FINAL_DEMO_SCRIPT.md"),
        Path("docs/SCREENSHOT_CHECKLIST.md"),
        Path("docs/DEMO_DAY_RUNBOOK.md"),
        Path("README.md"),
    ]
    bad_markers = ["â€œ", "â€", "Ã", "�"]

    for path in docs:
        text = path.read_text(encoding="utf-8")
        assert not any(marker in text for marker in bad_markers), path


def test_environment_profiles_and_docs_are_consistent():
    demo_env = Path(".env.example").read_text(encoding="utf-8")
    lab_env = Path(".env.lab.example").read_text(encoding="utf-8")
    prod_env = Path(".env.production.example").read_text(encoding="utf-8")
    environment_guide = Path("docs/ENVIRONMENT_GUIDE.md").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 'DATABASE_URL="sqlite:///./atdr.db"' in demo_env
    assert 'DATABASE_URL="postgresql+psycopg2://' in lab_env
    assert "AUTO_CREATE_TABLES=false" in lab_env
    assert "RESPONSE_SIMULATION=true" in lab_env
    assert "change-this-secret-before-production" not in prod_env
    assert "RESPONSE_SIMULATION=true" in prod_env
    for name in [".env.example", ".env.lab.example", ".env.production.example"]:
        assert name in environment_guide
        assert name in readme
    assert "python -m atdr.scripts.config_doctor" in environment_guide


def test_backup_and_cleanup_scripts_are_safe_in_dry_run(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_demo, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(cleanup_exports, "PROJECT_ROOT", tmp_path)
    db_path = tmp_path / "atdr.db"
    db_path.write_text("sqlite placeholder", encoding="utf-8")
    (tmp_path / "atdr" / "models").mkdir(parents=True)
    exports = tmp_path / "demo_exports"
    exports.mkdir()
    old_export = exports / "old_bundle"
    old_export.mkdir()
    old_mtime = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp()
    old_export.touch()
    import os

    os.utime(old_export, (old_mtime, old_mtime))

    backup = backup_demo.create_demo_backup(output_dir="backups", dry_run=True)
    cleanup = cleanup_exports.cleanup_exports(target_dir="demo_exports", older_than_days=14, dry_run=True)

    assert backup["dry_run"] is True
    assert backup["files_added"] == 0
    assert cleanup["dry_run"] is True
    assert cleanup["candidate_count"] == 1
    assert old_export.exists()


def test_postgres_backup_dry_run_reports_command(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_postgres, "PROJECT_ROOT", tmp_path)

    result = backup_postgres.create_postgres_backup(
        output_dir="backups",
        database_url="postgresql+psycopg2://atdr:secret@localhost:5432/atdr",
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert result["command"][0] in {"pg_dump", None} or str(result["command"][0]).endswith("pg_dump")
    assert str(tmp_path) in result["output_path"]


def test_alert_sla_calculation_by_severity_and_owner():
    now = datetime(2026, 5, 21, 12, 0, tzinfo=timezone.utc)
    critical = Alert(
        title="Critical test",
        alert_type="test",
        threat_score=90,
        severity="Critical",
        status="open",
        explanation="test",
        matched_rules_json=[],
        recommended_response="test",
        created_at=now - timedelta(hours=2),
    )
    high_owned = Alert(
        title="High test",
        alert_type="test",
        threat_score=70,
        severity="High",
        status="investigating",
        assigned_to="analyst",
        explanation="test",
        matched_rules_json=[],
        recommended_response="test",
        created_at=now - timedelta(hours=2),
    )
    resolved = Alert(
        title="Resolved test",
        alert_type="test",
        threat_score=45,
        severity="Medium",
        status="resolved",
        explanation="test",
        matched_rules_json=[],
        recommended_response="test",
        created_at=now - timedelta(days=10),
    )

    assert alert_sla(critical, now=now)["state"] == "needs_owner"
    assert alert_sla(high_owned, now=now)["state"] == "on_track"
    assert alert_sla(resolved, now=now)["state"] == "closed"


def test_tuning_report_identifies_alert_noise_and_readiness():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    with session() as db:
        import_raw_log_line(db, TRAFFIC_LINE, source_name="unit-test")
        for index in range(30):
            db.add(
                Alert(
                    title=f"Medium noisy alert {index}",
                    alert_type="noisy_medium_rule",
                    threat_score=40,
                    severity="Medium",
                    status="open",
                    explanation="Noisy test alert.",
                    matched_rules_json=[],
                    recommended_response="Review.",
                )
            )
        db.add(
            Alert(
                title="False positive known benign source",
                alert_type="noisy_medium_rule",
                src_ip="203.0.113.10",
                threat_score=40,
                severity="Medium",
                status="false_positive",
                explanation="Reviewed benign test alert.",
                matched_rules_json=[{"code": "noisy_medium_rule", "title": "Noisy rule"}],
                recommended_response="Suppress only after review.",
            )
        )
        db.commit()

        report = build_detection_tuning_report(db)

    assert report["summary"]["total_alerts"] == 31
    assert report["alert_type_pressure"][0]["alert_type"] == "noisy_medium_rule"
    assert report["suppression_candidates"][0]["alert_type"] == "noisy_medium_rule"
    assert report["false_positive_learning"]["false_positive_count"] == 1
    assert report["false_positive_learning"]["suppression_recommendations"][0]["src_ip"] == "203.0.113.10"
    assert any(item["name"] == "Alert Noise" for item in report["production_readiness"])
