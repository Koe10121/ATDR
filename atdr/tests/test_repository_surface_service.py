from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from atdr.app.services import repository_surface_service
from atdr.app.services.repository_surface_service import build_repository_surface_report


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_repository_surface_accepts_valid_links_commands_and_imports(tmp_path):
    _write(tmp_path / "README.md", "# Home\n\n[Guide](docs/guide.md#run)\n\n`python -m atdr.scripts.tool`\n")
    _write(tmp_path / "docs" / "guide.md", "# Guide\n\n## Run\n")
    _write(tmp_path / "atdr" / "__init__.py", "")
    _write(tmp_path / "atdr" / "app" / "__init__.py", "")
    _write(tmp_path / "atdr" / "app" / "core.py", 'VALUE = 1\nGUIDE = "docs/guide.md"\n')
    _write(tmp_path / "atdr" / "scripts" / "__init__.py", "")
    _write(
        tmp_path / "atdr" / "scripts" / "tool.py",
        "from atdr.app import core\n\nif __name__ == '__main__':\n    print(core.VALUE)\n",
    )

    report = build_repository_surface_report(tmp_path, include_edges=True)

    assert report["ok"] is True
    assert report["markdown"]["broken_count"] == 0
    assert report["python"]["missing_command_count"] == 0
    assert report["python"]["document_reference_count"] == 1
    assert report["python"]["missing_document_reference_count"] == 0
    assert report["inventory"]["counts"]["versioned_scripts"] == 0
    assert report["inventory"]["documentation_classification_counts"]["keep_active"] == 2
    tool = next(item for item in report["python"]["script_inventory"] if item["path"].endswith("tool.py"))
    assert tool["classification"] == "keep_referenced"
    assert report["filesystem_writes_performed"] is False


def test_repository_surface_reports_broken_and_nonportable_references(tmp_path):
    _write(
        tmp_path / "README.md",
        "# Home\n\n[Missing](docs/missing.md)\n[Private](C:/Users/example/private.md)\n"
        "\n`python -m atdr.scripts.missing`\n",
    )
    _write(tmp_path / "atdr" / "__init__.py", "")
    _write(tmp_path / "atdr" / "app" / "core.py", 'DOC = "docs/not-present.md"\n')

    report = build_repository_surface_report(tmp_path)

    assert report["ok"] is False
    assert report["markdown"]["broken_count"] == 1
    assert report["markdown"]["portable_failure_count"] == 1
    assert report["python"]["missing_command_count"] == 1
    assert report["python"]["missing_document_reference_count"] == 1
    assert report["private_evidence_accessed"] is False


def test_repository_surface_classifies_archives_references_and_operator_surfaces(tmp_path):
    _write(tmp_path / "docs" / "OPERATIONS_RUNBOOK.md", "# Operations\n")
    _write(tmp_path / "docs" / "archive" / "phases" / "V1.md", "# Historical\n")
    _write(tmp_path / "docs" / "reference" / "template.md", "# Reference\n")
    _write(tmp_path / "atdr" / "scripts" / "run_v1_check.py", "if __name__ == '__main__':\n    pass\n")
    _write(tmp_path / "scripts" / "start_system.ps1", "Write-Output 'start'\n")
    _write(tmp_path / "migrations" / "versions" / "001.py", "revision = '001'\n")
    _write(tmp_path / "atdr" / "app" / "routers" / "alerts.py", "")
    _write(tmp_path / "atdr" / "app" / "services" / "operation_worker.py", "")
    _write(tmp_path / "atdr" / "tests" / "test_sample.py", "")
    _write(tmp_path / ".github" / "workflows" / "ci.yml", "name: CI\n")

    report = build_repository_surface_report(tmp_path, include_edges=True)

    assert report["inventory"]["counts"] == {
        "documentation": 3,
        "runbooks": 1,
        "allowlists": 0,
        "change_records": 0,
        "versioned_scripts": 1,
        "wrappers": 1,
        "migrations": 1,
        "routers": 1,
        "job_handlers": 1,
        "tests": 1,
        "ci": 1,
    }
    classifications = {
        item["path"]: item["classification"] for item in report["inventory"]["documentation"]
    }
    assert classifications["docs/OPERATIONS_RUNBOOK.md"] == "keep_active"
    assert classifications["docs/archive/phases/V1.md"] == "archive"
    assert classifications["docs/reference/template.md"] == "keep_reference"


def test_repository_surface_ignores_tracked_paths_missing_from_worktree(tmp_path, monkeypatch):
    _write(tmp_path / "README.md", "# Current surface\n")
    outputs = iter((str(tmp_path.resolve()), "README.md\ndocs/archived-away.md\n"))

    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout=next(outputs))

    monkeypatch.setattr(repository_surface_service.subprocess, "run", fake_run)

    report = build_repository_surface_report(tmp_path)

    assert report["ok"] is True
    assert report["path_count"] == 1
    assert report["markdown"]["markdown_file_count"] == 1
