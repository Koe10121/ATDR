import inspect
import json

from atdr.app.benchmarks.readiness import readiness_gate_v9_production_readiness_track
from atdr.app.core.config import KNOWN_DEFAULT_SECRETS, KNOWN_DEMO_PASSWORDS, PROJECT_ROOT, Settings
from atdr.app.services.repository_security_service import example_secret_settings, scan_repository_paths
from atdr.scripts import config_doctor
from atdr.scripts import production_readiness_doctor as doctor_module
from atdr.scripts.database_portability_audit import run_database_portability_audit
from atdr.scripts.production_readiness_doctor import run_production_readiness_doctor


def test_readiness_v9_never_marks_production_ready():
    result = readiness_gate_v9_production_readiness_track(
        final_controlled_validation_passed=True,
        real_source_pilot_validated=True,
        postgres_lab_validated=True,
        no_hardware_source_pilot_validated=True,
        real_device_forwarding_validated=True,
        backup_restore_validated=True,
        production_doctor_blockers=[],
        observability_plan_exists=True,
        ml_monitoring_plan_exists=True,
        runbook_updated=True,
    )

    assert result["version"] == "v9"
    assert result["decision"] == "shared_lab_readiness_candidate"
    assert result["production_ready"] is False
    assert result["production_readiness_claim"] is False
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False
    assert result["no_hardware_source_pilot_validated"] is True
    assert result["real_device_forwarding_validated"] is True
    assert result["backup_restore_validated"] is True


def test_production_readiness_doctor_is_secret_safe(monkeypatch):
    monkeypatch.setattr(doctor_module, "_tracked_files", lambda: [])
    settings = Settings(
        JWT_SECRET_KEY="change-this-dev-secret",
        OIDC_CLIENT_SECRET="super-secret-value",
        DEMO_ADMIN_PASSWORD="admin123",
        DEMO_ANALYST_PASSWORD="analyst123",
    )

    result = run_production_readiness_doctor(settings=settings)
    rendered = json.dumps(result)

    assert result["production_ready"] is False
    assert result["response_automation_allowed"] is False
    assert "super-secret-value" not in rendered
    assert any("jwt" in item.lower() for item in result["warnings"])
    assert any("performance_smoke" in step for step in result["recommended_next_steps"])




def test_database_portability_audit_reports_sqlite_without_production_claim(tmp_path):
    database_path = tmp_path / "portability.sqlite3"
    database_path.touch()
    settings = Settings(
        _env_file=None,
        DATABASE_URL=f"sqlite:///{database_path.as_posix()}",
    )

    result = run_database_portability_audit(settings=settings)

    assert result["ok"] is True
    assert result["database_kind"] == "sqlite"
    assert result["portability_status"] == "sqlite_local_ready_postgres_pending"
    assert result["production_ready"] is False
    assert any("SQLite is valid" in warning for warning in result["warnings"])


def test_v33_docs_exist_and_reference_safe_commands():
    docs = {
        "docs/archive/phases/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md": "run_postgres_lab_validation",
        "docs/archive/phases/V3_3_BACKUP_RESTORE_AND_RETENTION_PLAN.md": "backup_postgres --dry-run",
        "docs/archive/phases/V3_3_DOCKER_POSTGRES_LAB_RUNBOOK.md": "AUTO_CREATE_TABLES=false",
    }
    for path, phrase in docs.items():
        text = (PROJECT_ROOT / path).read_text(encoding="utf-8")
        assert phrase in text
        assert "automatic response" in text.lower()
        assert "production readiness" in text.lower() or "not production ready" in text.lower()






def test_doctor_finds_no_sensitive_file_among_the_tracked_files():
    # The placeholder-only .env.preproduction.example and .env.shell.example were reported as tracked secrets, so the
    # doctor said "blocked" on every run (23 Oct 2026).
    tracked = doctor_module._tracked_files()
    assert ".env.preproduction.example" in tracked and ".env.shell.example" in tracked

    assert doctor_module._tracked_sensitive_files(tracked) == []


def test_doctor_still_catches_a_real_secret_in_an_example_file(tmp_path):
    # Built from pieces: written out whole, this file would hold a key-shaped value and fail the scan itself.
    api_key = "sk-" + "proj-" + "a1b2c3d4" * 4
    (tmp_path / ".env.shell.example").write_text(
        'JWT_SECRET_KEY="9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddcc"\nASSISTANT_API_KEY=""\n', encoding="utf-8"
    )
    (tmp_path / ".env.preproduction.example").write_text(
        f"JWT_SECRET_KEY=<managed-secret>\nASSISTANT_LLM_API_KEY={api_key}\n", encoding="utf-8"
    )
    (tmp_path / ".env.lab.example").write_text("# SMTP_PASSWORD=my-real-app-password\n", encoding="utf-8")
    (tmp_path / ".env.production.example").write_text('JWT_SECRET_KEY="replace-with-a-secret"\n', encoding="utf-8")
    (tmp_path / ".env.staging").write_text("ENVIRONMENT=staging\n", encoding="utf-8")
    for name in ("exports/paloalto-firewall-may.txt", "atdr/data/processed/features.csv", "atdr/data/processed/.gitkeep"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    files = [
        ".env.shell.example",
        ".env.preproduction.example",
        ".env.lab.example",
        ".env.production.example",
        ".env.staging",
        "exports/paloalto-firewall-may.txt",
        "atdr/data/processed/features.csv",
        "atdr/data/processed/.gitkeep",
    ]

    found = doctor_module._tracked_sensitive_files(files, root=tmp_path)
    rules = {(item["path"], item["rule"]) for item in scan_repository_paths(tmp_path, files)["findings"]}

    assert found == [
        ".env.lab.example",
        ".env.preproduction.example",
        ".env.shell.example",
        ".env.staging",
        "atdr/data/processed/features.csv",
        "exports/paloalto-firewall-may.txt",
    ]
    assert (".env.shell.example", "secret_value_in_example") in rules
    assert (".env.preproduction.example", "openai_api_key") in rules
    assert (".env.lab.example", "secret_value_in_example") in rules
    assert (".env.staging", "private_environment_file") in rules
    assert "9f8e7d6c5b4a" not in json.dumps(scan_repository_paths(tmp_path, files))


def test_example_settings_may_hold_placeholders_and_values_that_ship_with_atdr():
    text = "\n".join(
        [
            'JWT_SECRET_KEY="change-this-secret-before-production"',
            'DEMO_ADMIN_PASSWORD="admin123"',
            'DEMO_ANALYST_PASSWORD="replace-this-lab-analyst-password"',
            "MFU_SHELL_LOCAL_KEY=replace-during-private-setup",
            "ASSISTANT_LLM_API_KEY=<from the secret manager>",
            'SMTP_PASSWORD="" # app password, set privately',
            "export OIDC_CLIENT_SECRET=",
            "MFU_IAM_CLIENT_SECRET= # given by MFU IT",
            'ATDR_NOTIFY_CHAT_WEBHOOK_URL=""',
            # Not secrets: a key's path, a header's and a provider's name, a token limit, a token's lifetime.
            "DEPLOYMENT_TLS_PRIVATE_KEY_PATH=/etc/atdr/tls/privkey.pem",
            'MFU_IAM_HANDOFF_SECRET_HEADER="x-atdr-handoff-secret"',
            "DEPLOYMENT_SECRET_PROVIDER=vault",
            "ASSISTANT_LLM_MAX_OUTPUT_TOKENS=800",
            "ACCESS_TOKEN_EXPIRE_MINUTES=480",
        ]
    )

    assert example_secret_settings(text) == []
    assert example_secret_settings('SMTP_PASSWORD="hunter22" # set privately\nMFU_IAM_ACCESS_TOKEN=abc123\n') == [
        "SMTP_PASSWORD",
        "MFU_IAM_ACCESS_TOKEN",
    ]
    assert example_secret_settings("ATDR_NOTIFY_CHAT_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/xyz\n") == [
        "ATDR_NOTIFY_CHAT_WEBHOOK_URL"
    ]


def test_the_doctors_use_the_shared_lists_of_known_values_and_private_files():
    assert doctor_module.DEFAULT_SECRETS is KNOWN_DEFAULT_SECRETS
    assert doctor_module.DEMO_PASSWORDS is KNOWN_DEMO_PASSWORDS
    assert config_doctor.DEFAULT_SECRETS is KNOWN_DEFAULT_SECRETS
    assert config_doctor.DEMO_PASSWORDS is KNOWN_DEMO_PASSWORDS
    # No list of its own to drift from the repository scan's.
    source = inspect.getsource(doctor_module)
    assert ".example" not in source.replace(".env.preproduction.example and .env.shell.example", "")
    assert "scan_repository_paths" in inspect.getsource(doctor_module._tracked_sensitive_files)
