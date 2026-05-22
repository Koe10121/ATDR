import json
from pathlib import Path


def test_react_frontend_scaffold_exists_and_keeps_streamlit():
    root = Path("frontend")
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))

    assert (root / "src" / "main.tsx").exists()
    assert (root / "src" / "App.tsx").exists()
    assert (root / "src" / "pages" / "ExecutiveOverview.tsx").exists()
    assert (root / "src" / "pages" / "AlertsTriage.tsx").exists()
    assert (root / "src" / "pages" / "DetectionTuning.tsx").exists()
    assert (root / "src" / "pages" / "MLGovernance.tsx").exists()
    assert (root / "src" / "pages" / "ResponseCenter.tsx").exists()
    assert (Path("atdr") / "dashboard" / "streamlit_app.py").exists()
    assert package["scripts"]["dev"].startswith("vite")
    assert "@tanstack/react-query" in package["dependencies"]
    assert "@tanstack/react-table" in package["dependencies"]
    assert "recharts" in package["dependencies"]


def test_react_frontend_docs_and_cors_are_wired():
    readme = Path("README.md").read_text(encoding="utf-8")
    env_example = Path(".env.example").read_text(encoding="utf-8")
    frontend_env = Path("frontend/.env.example").read_text(encoding="utf-8")
    dashboard_path = Path("docs/DASHBOARD_PRODUCTION_PATH.md").read_text(encoding="utf-8")

    assert "frontend/" in readme
    assert "http://127.0.0.1:5173" in readme
    assert "http://127.0.0.1:5173" in env_example
    assert "VITE_API_BASE_URL=http://127.0.0.1:8000" in frontend_env
    assert "Streamlit remains" in dashboard_path
    assert "npm run build" in dashboard_path
