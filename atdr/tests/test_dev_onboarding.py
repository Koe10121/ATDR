from pathlib import Path

from atdr.scripts.check_dev_environment import check_database_url


def test_check_dev_environment_missing_sqlite_does_not_create_file(tmp_path):
    db_path = tmp_path / "missing-atdr.db"

    result = check_database_url("sqlite:///./missing-atdr.db", root=tmp_path)

    assert result.status == "warning"
    assert "missing" in result.message.lower()
    assert not db_path.exists()


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
