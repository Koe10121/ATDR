import json
from pathlib import Path

from atdr.app.core.config import Settings
from atdr.scripts.check_dev_environment import check_database_url
from atdr.scripts.use_local_sqlite_config import apply_local_sqlite_config, build_local_sqlite_env_lines
from atdr.scripts.use_template_shell_config import apply_template_shell_config, build_template_shell_env_lines


def test_check_dev_environment_missing_sqlite_does_not_create_file(tmp_path):
    db_path = tmp_path / "missing-atdr.db"

    result = check_database_url("sqlite:///./missing-atdr.db", root=tmp_path)

    assert result.status == "warning"
    assert "missing" in result.message.lower()
    assert not db_path.exists()


def test_check_dev_environment_flags_docker_postgres_host_for_local_workflow():
    result = check_database_url("postgresql+psycopg2://atdr:secret@postgres:5432/atdr")

    assert result.status == "error"
    assert "sqlite:///./atdr.db" in result.message
    assert result.details is not None
    assert result.details["database_url"] == "postgresql+psycopg2://atdr:***@postgres:5432/atdr"
    assert "secret" not in str(result.to_dict())


def test_local_sqlite_config_helper_is_dry_run_safe(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                'DATABASE_URL="postgresql+psycopg2://atdr:secret@postgres:5432/atdr"',
                "AUTO_CREATE_TABLES=false",
                'ENVIRONMENT="production"',
                "RESPONSE_SIMULATION=true",
            ]
        ),
        encoding="utf-8",
    )

    result = apply_local_sqlite_config(env_path=env_path, write=False)

    assert result["would_change"] is True
    assert result["write"] is False
    assert "postgresql" in env_path.read_text(encoding="utf-8")
    assert "secret" not in str(result)


def test_local_sqlite_config_builder_sets_expected_values():
    updated, changes = build_local_sqlite_env_lines(
        'DATABASE_URL="postgresql+psycopg2://atdr:secret@postgres:5432/atdr"\n'
    )

    assert 'DATABASE_URL="sqlite:///./atdr.db"' in updated
    assert "AUTO_CREATE_TABLES=true" in updated
    assert 'ENVIRONMENT="development"' in updated
    assert {item["key"] for item in changes} >= {"DATABASE_URL", "AUTO_CREATE_TABLES", "ENVIRONMENT"}


def test_template_shell_config_helper_is_dry_run_safe(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "MFU_IAM_ENABLED=false",
                "MFU_IAM_CLIENT_SECRET=existing-secret-that-must-not-leak",
                "MFU_IAM_ADMIN_EMAILS=admin@lamduan.mfu.ac.th",
            ]
        ),
        encoding="utf-8",
    )

    result = apply_template_shell_config(env_path=env_path, write=False)
    text = env_path.read_text(encoding="utf-8")

    assert result["would_change"] is True
    assert result["write"] is False
    assert "MFU_IAM_ENABLED=false" in text
    assert "existing-secret-that-must-not-leak" in text
    assert result["admin_mapping_changed"] is False
    assert "existing-secret-that-must-not-leak" not in str(result)


def test_template_shell_config_builder_sets_expected_values_and_preserves_admin_mapping():
    updated, changes = build_template_shell_env_lines(
        "MFU_IAM_ENABLED=false\nMFU_IAM_ADMIN_EMAILS=admin@lamduan.mfu.ac.th\n"
    )

    assert "MFU_IAM_ENABLED=true" in updated
    assert "MFU_IAM_TEMPLATE_SHELL_ENABLED=true" in updated
    assert 'MFU_IAM_TEMPLATE_SHELL_BASE_URL="http://127.0.0.1:8214"' in updated
    assert 'MFU_IAM_TEMPLATE_SHELL_ME_PATH="/api/v1/auth/me"' in updated
    assert 'MFU_IAM_TEMPLATE_SHELL_HEADER="x-access-token"' in updated
    assert 'MFU_IAM_ALLOWED_DOMAINS="lamduan.mfu.ac.th"' in updated
    assert 'MFU_IAM_DEFAULT_ROLE="analyst"' in updated
    assert "MFU_IAM_ADMIN_EMAILS=admin@lamduan.mfu.ac.th" in updated
    assert "MFU_IAM_ADMIN_EMAILS" not in {item["key"] for item in changes}


def test_template_shell_config_write_creates_backup(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("MFU_IAM_ENABLED=false\n", encoding="utf-8")

    result = apply_template_shell_config(env_path=env_path, write=True)
    text = env_path.read_text(encoding="utf-8")

    assert result["write"] is True
    assert result["backup_path"]
    assert Path(result["backup_path"]).exists()
    assert "MFU_IAM_ENABLED=true" in text
    assert "MFU_IAM_TEMPLATE_SHELL_ENABLED=true" in text


def test_quickstart_references_existing_project_files():
    quickstart = Path("docs/QUICKSTART_FOR_TEAM.md")
    assert quickstart.exists()
    text = quickstart.read_text(encoding="utf-8")

    for phrase in [
        ".env.example",
        "frontend/.env.example",
        "data/samples/paloalto-demo.txt",
        "python -m atdr.scripts.check_dev_environment",
        "python -m atdr.scripts.seed_users",
        "npm.cmd run dev",
    ]:
        assert phrase in text

    assert Path(".env.example").exists()
    assert Path(".env.lab.example").exists()
    assert Path("frontend/.env.example").exists()
    assert Path("data/samples/paloalto-demo.txt").exists()


def test_quickstart_documents_database_choice_without_mongodb_migration():
    text = Path("docs/QUICKSTART_FOR_TEAM.md").read_text(encoding="utf-8")

    assert "SQLite" in text
    assert "PostgreSQL" in text
    assert "MongoDB is not used currently" in text
    assert "Do not migrate ATDR to MongoDB" in text


def test_no_env_backend_defaults_match_safe_react_workflow():
    settings = Settings(_env_file=None)

    assert settings.demo_sample_log_path == "data/samples/paloalto-demo.txt"
    assert "http://127.0.0.1:5173" in settings.cors_origins
    assert settings.response_simulation is True
    assert settings.assistant_llm_enabled is False
    assert settings.assistant_allow_raw_log_context is False


def test_frontend_declares_supported_node_engine():
    package = json.loads(Path("frontend/package.json").read_text(encoding="utf-8"))

    assert package["engines"]["node"] == ">=20.19.0"
