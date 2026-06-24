from pathlib import Path

from atdr.scripts.check_dev_environment import check_database_url
from atdr.scripts.use_local_sqlite_config import apply_local_sqlite_config, build_local_sqlite_env_lines


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
