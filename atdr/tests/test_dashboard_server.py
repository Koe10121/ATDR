"""ATDR serves the dashboard's built files, and builds them when the source has changed.

It ran Vite's development server: the Overview took about ten seconds to open, and every edit to a source file was
live on the running dashboard at once, tested or not.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from atdr.app.dashboard_server import NOT_BUILT, create_dashboard_app
from atdr.app.services import dashboard_build_service as builds
from atdr.app.services.dashboard_build_service import build_dashboard, build_state
from atdr.scripts import build_dashboard as build_command
from atdr.scripts import serve_dashboard as serve_command

INDEX = '<!doctype html><html><head><script type="module" src="/assets/index-a1b2c3.js"></script></head><body><div id="root"></div></body></html>'


def _built(tmp_path: Path) -> Path:
    dist = tmp_path / "frontend" / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(INDEX, encoding="utf-8")
    (dist / "assets" / "index-a1b2c3.js").write_text("console.log('atdr');" + "// padding\n" * 200, encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    (dist / ".atdr-build.json").write_text('{"source_changed": 1}', encoding="utf-8")
    (tmp_path / "frontend" / "secret.env").write_text("JWT_SECRET_KEY=not-for-the-browser", encoding="utf-8")
    return dist


def test_the_dashboard_server_gives_files_and_its_own_routes_and_nothing_else(tmp_path):
    client = TestClient(create_dashboard_app(_built(tmp_path)))

    for route in ("/", "/overview", "/alerts?alert=4163", "/alerts/", "/logs/42"):
        page = client.get(route)
        assert (page.status_code, page.text) == (200, INDEX), route
        assert page.headers["cache-control"] == "no-cache", "index.html names the current scripts, so it is asked for every time"

    script = client.get("/assets/index-a1b2c3.js", headers={"Accept-Encoding": "gzip"})
    assert script.status_code == 200 and script.text.startswith("console.log('atdr');")
    assert script.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert "javascript" in script.headers["content-type"] and script.headers["content-encoding"] == "gzip"
    icon = client.get("/favicon.svg")
    assert icon.status_code == 200 and icon.headers["cache-control"] == "no-cache"

    # A script that is gone is "not found", never the page's HTML in a script's place.
    gone = client.get("/assets/index-old999.js")
    assert (gone.status_code, gone.text) == (404, "Not found.")
    for outside in ("/%2e%2e/secret.env", "/assets/%2e%2e/%2e%2e/secret.env", "/..%2fsecret.env", "/.atdr-build.json"):
        assert client.get(outside).status_code == 404, outside
    assert "not-for-the-browser" not in client.get("/%2e%2e/secret.env").text

    assert client.head("/").status_code == 200 and client.head("/").text == ""
    assert client.post("/").status_code == 405


def test_every_answer_carries_the_security_headers_of_the_server_install(tmp_path):
    dist = _built(tmp_path)
    client = TestClient(create_dashboard_app(dist))
    for path in ("/", "/assets/index-a1b2c3.js", "/assets/gone.js", "/%2e%2e/secret.env"):
        headers = client.get(path).headers
        assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY", path
        assert headers["referrer-policy"] == "no-referrer"
        policy = headers["content-security-policy"]
        assert "default-src 'self'" in policy and "frame-ancestors 'none'" in policy and "script-src 'self';" in policy
        # The dashboard reads the API on port 8000 of the page's own host name.
        assert policy.endswith("connect-src 'self' http://127.0.0.1:8000 http://localhost:8000")

    example = (Path(__file__).resolve().parents[2] / "deploy" / "nginx" / "atdr.conf.example").read_text(encoding="utf-8")
    server_policy = example.split('add_header Content-Security-Policy "')[1].split('"')[0]
    assert policy == server_policy + " http://127.0.0.1:8000 http://localhost:8000", "the same policy, plus where the API is here"

    other = TestClient(create_dashboard_app(dist, api_origins=("https://atdr.example",)))
    assert other.get("/").headers["content-security-policy"].endswith("connect-src 'self' https://atdr.example")


def test_before_the_first_build_the_page_says_what_to_run(tmp_path):
    empty = tmp_path / "dist"
    empty.mkdir()
    answer = TestClient(create_dashboard_app(empty)).get("/overview")
    assert (answer.status_code, answer.text) == (503, NOT_BUILT)
    assert "start_system.cmd" in NOT_BUILT and "build_dashboard" in NOT_BUILT


def _frontend(tmp_path: Path) -> Path:
    frontend = tmp_path / "frontend"
    (frontend / "src").mkdir(parents=True)
    (frontend / "src" / "main.tsx").write_text("export const version = 1;", encoding="utf-8")
    (frontend / "index.html").write_text("<div id=root></div>", encoding="utf-8")
    (frontend / "package.json").write_text("{}", encoding="utf-8")
    _dated(frontend, 1_000_000)
    return frontend


def _dated(frontend: Path, seconds: float) -> None:
    for path in [frontend / "index.html", frontend / "package.json", *(frontend / "src").rglob("*")]:
        if path.is_file():
            os.utime(path, (seconds, seconds))


class _Npm:
    """Stands in for `npm run build`: writes a build named after the source's version into the staging folder."""

    def __init__(self, frontend: Path) -> None:
        self.frontend = frontend
        self.calls: list[list[str]] = []
        self.fail_with: str | None = None
        self.during = None

    def __call__(self, command, *, cwd, **_kwargs):
        self.calls.append(list(command))
        assert Path(cwd) == self.frontend
        if self.during is not None:
            self.during()
        if self.fail_with is not None:
            half = self.frontend / "dist-staging"
            half.mkdir(exist_ok=True)
            (half / "half-written.js").write_text("broken", encoding="utf-8")
            return SimpleNamespace(returncode=1, stdout="vite v5 building for production...", stderr=self.fail_with)
        version = (self.frontend / "src" / "main.tsx").read_text(encoding="utf-8").split("= ")[1].rstrip(";")
        staging = self.frontend / "dist-staging"
        (staging / "assets").mkdir(parents=True, exist_ok=True)
        (staging / "assets" / f"index-v{version}.js").write_text(f"version {version}", encoding="utf-8")
        (staging / "index.html").write_text(f'<script src="/assets/index-v{version}.js"></script>', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="built in 9.9s", stderr="")


def _change(frontend: Path, version: int, seconds: float) -> None:
    source = frontend / "src" / "main.tsx"
    source.write_text(f"export const version = {version};", encoding="utf-8")
    os.utime(source, (seconds, seconds))


def _served(frontend: Path) -> list[str]:
    return sorted(path.relative_to(frontend / "dist").as_posix() for path in (frontend / "dist").rglob("*") if path.is_file())


def test_the_dashboard_is_built_when_its_source_is_newer_than_the_build_and_only_then(tmp_path):
    frontend = _frontend(tmp_path)
    npm = _Npm(frontend)
    assert build_state(frontend) == {"built": False, "built_at": None, "commit": None, "uncommitted": False, "stale": True,
                                     "source_changed_at": "1970-01-12T13:46:40+00:00"}

    first = build_dashboard(frontend, run=npm, npm="npm")
    assert (first["ok"], first["status"], first["built"], first["stale"]) == (True, "built", True, False)
    assert npm.calls == [["npm", "run", "build", "--", "--outDir", "dist-staging", "--emptyOutDir"]]
    assert _served(frontend) == [".atdr-build.json", "assets/index-v1.js", "index.html"]
    assert not (frontend / "dist-staging").exists()
    stamp = json.loads((frontend / "dist" / ".atdr-build.json").read_text(encoding="utf-8"))
    assert stamp["source_changed"] == 1_000_000 and stamp["files"] == ["assets/index-v1.js", "index.html"]
    # Which commit it was built from, and whether the source differed from it (here: no repository at all).
    assert set(stamp) == {"built_at", "source_changed", "commit", "uncommitted", "files"}
    assert (first["commit"], first["uncommitted"]) == (stamp["commit"], stamp["uncommitted"])

    again = build_dashboard(frontend, run=npm, npm="npm")
    assert (again["status"], again["ok"], len(npm.calls)) == ("current", True, 1), "nothing changed, nothing is built"
    assert build_dashboard(frontend, run=npm, npm="npm", force=True)["status"] == "built" and len(npm.calls) == 2

    _change(frontend, 2, 1_000_100)
    assert build_state(frontend)["stale"] is True
    assert build_dashboard(frontend, run=npm, npm="npm")["status"] == "built"
    assert (frontend / "dist" / "index.html").read_text(encoding="utf-8") == '<script src="/assets/index-v2.js"></script>'
    # A page left open across the update still finds the script of the build before; the one before that is gone.
    assert _served(frontend) == [".atdr-build.json", "assets/index-v1.js", "assets/index-v2.js", "index.html"]
    _change(frontend, 3, 1_000_200)
    build_dashboard(frontend, run=npm, npm="npm")
    assert _served(frontend) == [".atdr-build.json", "assets/index-v2.js", "assets/index-v3.js", "index.html"]
    assert not list((frontend / "dist").glob("*.arriving"))


def test_a_build_that_fails_leaves_the_working_dashboard_in_place(tmp_path):
    frontend = _frontend(tmp_path)
    npm = _Npm(frontend)
    build_dashboard(frontend, run=npm, npm="npm")
    working = _served(frontend), (frontend / "dist" / "index.html").read_text(encoding="utf-8")

    _change(frontend, 2, 1_000_100)
    npm.fail_with = "src/pages/AlertsTriage.tsx(12,7): error TS2322: Type 'string' is not assignable to type 'number'."
    failed = build_dashboard(frontend, run=npm, npm="npm")
    assert (failed["ok"], failed["status"], failed["built"], failed["stale"]) == (True, "build_failed", True, True)
    assert "error TS2322" in failed["output"]
    assert (_served(frontend), (frontend / "dist" / "index.html").read_text(encoding="utf-8")) == working
    assert not (frontend / "dist-staging").exists(), "the half-written build is cleared away"
    assert "FAILED" in build_command.describe(failed) and "serves the last good build" in build_command.describe(failed)

    # Still stale, so the next start tries again, and takes the fix.
    npm.fail_with = None
    assert build_dashboard(frontend, run=npm, npm="npm")["status"] == "built"
    assert "index-v2.js" in (frontend / "dist" / "index.html").read_text(encoding="utf-8")


def test_with_no_build_and_one_that_fails_there_is_nothing_to_serve(tmp_path):
    frontend = _frontend(tmp_path)
    npm = _Npm(frontend)
    npm.fail_with = "npm ERR! missing script: build"
    failed = build_dashboard(frontend, run=npm, npm="npm")
    assert (failed["ok"], failed["status"], failed["built"]) == (False, "build_failed", False)
    assert "no earlier build to serve" in build_command.describe(failed)

    def crashed(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="npm", timeout=900)

    assert build_dashboard(frontend, run=crashed, npm="npm")["status"] == "build_failed"


def test_without_npm_the_last_build_is_served(tmp_path, monkeypatch):
    frontend = _frontend(tmp_path)
    monkeypatch.setattr(builds.shutil, "which", lambda _name: None)
    missing = build_dashboard(frontend, run=lambda *_a, **_k: pytest.fail("there is no npm to run"))
    assert (missing["ok"], missing["status"]) == (False, "npm_missing")
    assert "npm was not found" in build_command.describe(missing)

    build_dashboard(frontend, run=_Npm(frontend), npm="npm")
    _change(frontend, 2, 1_000_100)
    assert build_dashboard(frontend)["ok"] is True, "a build is there to serve, although it is not the newest source"


def test_a_file_saved_while_the_build_runs_makes_the_next_start_build_again(tmp_path):
    frontend = _frontend(tmp_path)
    npm = _Npm(frontend)
    npm.during = lambda: os.utime(frontend / "index.html", (1_000_050, 1_000_050))
    built = build_dashboard(frontend, run=npm, npm="npm")
    assert (built["status"], built["stale"]) == ("built", True)


def test_a_build_made_by_hand_is_rebuilt_once_because_nothing_says_what_it_was_made_from(tmp_path):
    frontend = _frontend(tmp_path)
    (frontend / "dist").mkdir()
    (frontend / "dist" / "index.html").write_text("made by npm run build", encoding="utf-8")
    assert build_state(frontend)["built"] is True and build_state(frontend)["stale"] is True
    npm = _Npm(frontend)
    assert build_dashboard(frontend, run=npm, npm="npm")["status"] == "built"
    assert build_dashboard(frontend, run=npm, npm="npm")["status"] == "current"
    assert "is current" in build_command.describe(build_dashboard(frontend, run=npm, npm="npm"))


def test_the_real_dashboard_source_is_what_a_build_watches():
    watched = {name for name in builds.SOURCE_PATHS if (builds.FRONTEND / name).exists()}
    assert {"src", "index.html", "package.json", "package-lock.json", "vite.config.ts", "tsconfig.json"} <= watched
    assert builds.newest_source_change() > 0
    ignored = (builds.FRONTEND / ".gitignore").read_text(encoding="utf-8").split()
    assert "dist/" in ignored and "dist-staging/" in ignored, "neither the build nor its staging folder is committed"


def test_the_serve_command_listens_where_the_dashboard_always_was(monkeypatch):
    seen = {}
    monkeypatch.setattr(serve_command.uvicorn, "run", lambda app, **kwargs: seen.update(app=app, **kwargs))
    monkeypatch.setattr("sys.argv", ["serve_dashboard"])
    serve_command.main()
    assert (seen["host"], seen["port"], seen["access_log"]) == ("127.0.0.1", 5173, False)
    monkeypatch.setattr("sys.argv", ["serve_dashboard", "--port", "5174", "--host", "0.0.0.0"])
    serve_command.main()
    assert (seen["host"], seen["port"]) == ("0.0.0.0", 5174)
