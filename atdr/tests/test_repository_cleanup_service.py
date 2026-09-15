from __future__ import annotations

from pathlib import Path

import pytest

from atdr.app.services.repository_cleanup_service import (
    CONFIRMATION,
    cleanup_disposable_caches,
)


def _write(path: Path, value: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def test_repository_cache_cleanup_dry_run_has_no_side_effects(tmp_path):
    cache = tmp_path / "atdr" / "app" / "__pycache__" / "module.pyc"
    build = tmp_path / "frontend" / "dist" / "index.html"
    _write(cache)
    _write(build)

    report = cleanup_disposable_caches(tmp_path)

    assert report["mode"] == "dry_run"
    assert report["candidate_count"] == 2
    assert report["removed_count"] == 0
    assert cache.exists()
    assert build.exists()
    assert report["database_files_allowed"] is False
    assert report["outside_repository_allowed"] is False


def test_repository_cache_cleanup_does_not_traverse_ignored_tool_storage(tmp_path):
    ignored_cache = tmp_path / ".tmp" / "bundled-python" / "package" / "__pycache__" / "module.pyc"
    uv_cache = tmp_path / ".uv-python" / "Lib" / "__pycache__" / "module.pyc"
    _write(ignored_cache)
    _write(uv_cache)

    report = cleanup_disposable_caches(tmp_path)

    assert report["candidate_count"] == 0
    assert ignored_cache.exists()
    assert uv_cache.exists()


def test_repository_cache_cleanup_requires_confirmation_and_preserves_sensitive_paths(tmp_path):
    _write(tmp_path / ".pytest_cache" / "state")
    database = tmp_path / "data" / "atdr.db"
    log = tmp_path / "logs" / "private.log"
    model = tmp_path / "models" / "active.joblib"
    environment = tmp_path / ".env"
    _write(database)
    _write(log)
    _write(model)
    _write(environment, "SECRET=value")

    with pytest.raises(ValueError, match=CONFIRMATION):
        cleanup_disposable_caches(tmp_path, apply=True)

    report = cleanup_disposable_caches(
        tmp_path,
        apply=True,
        confirmation=CONFIRMATION,
    )

    assert report["ok"] is True
    assert report["removed"] == [".pytest_cache"]
    assert database.exists()
    assert log.exists()
    assert model.exists()
    assert environment.exists()
