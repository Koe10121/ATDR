import json
from pathlib import Path


def test_react_frontend_scaffold_exists_and_keeps_streamlit():
    root = Path("frontend")
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))

    assert (root / "src" / "main.tsx").exists()
    assert (root / "src" / "App.tsx").exists()
    assert (root / "src" / "pages" / "ExecutiveOverview.tsx").exists()
    assert (root / "src" / "pages" / "AlertsTriage.tsx").exists()
    assert (root / "src" / "pages" / "LogExplorer.tsx").exists()
    assert (root / "src" / "pages" / "AuditLogPage.tsx").exists()
    assert (root / "src" / "pages" / "ThreatControls.tsx").exists()
    assert (root / "src" / "pages" / "UserAdmin.tsx").exists()
    assert (root / "src" / "pages" / "DemoControls.tsx").exists()
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
    assert "Log Explorer" in readme
    assert "Threat Controls" in readme
    assert "http://127.0.0.1:5173" in readme
    assert "http://127.0.0.1:5173" in env_example
    assert "VITE_API_BASE_URL=http://127.0.0.1:8000" in frontend_env
    assert "React application" in dashboard_path
    assert "primary analyst dashboard" in dashboard_path
    assert "legacy continuity only" in dashboard_path
    assert "npm.cmd run build" in dashboard_path


def test_real_data_ai_demo_helper_is_documented_and_private_logs_are_ignored():
    helper = Path("scripts/run_ai_demo_pipeline.ps1").read_text(encoding="utf-8")
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    runbook = Path("docs/AI_TRAINING_RUNBOOK.md").read_text(encoding="utf-8")

    assert "param(" in helper
    assert "$LogPath" in helper
    assert "build_label_review_queue" in helper
    assert "supervised_model_report" in helper
    assert "*.log" in gitignore
    assert "data/private/" in gitignore
    assert "real_logs/" in gitignore
    assert "Real Data Demo Checklist" in runbook
    assert "run_ai_demo_pipeline.ps1" in runbook


def test_assisted_labeling_scripts_and_runbook_warning_exist():
    generator = Path("atdr/scripts/generate_assisted_labels.py").read_text(encoding="utf-8")
    sampler = Path("atdr/scripts/export_label_review_sample.py").read_text(encoding="utf-8")
    runbook = Path("docs/AI_TRAINING_RUNBOOK.md").read_text(encoding="utf-8")
    governance_page = Path("frontend/src/pages/MLGovernance.tsx").read_text(encoding="utf-8")

    assert "--dry-run" in generator
    assert "--apply" in generator
    assert "--min-confidence" in generator
    assert "assisted_label_preview.csv" in generator
    assert "assisted_label_human_review_sample.csv" in sampler
    assert "Assisted labels are weak labels" in runbook
    assert "Human Review Sample" in governance_page
    assert "Import Reviewed CSV" in governance_page
    assert "preserves assisted provenance" in governance_page
    assert "reviewed=true" in runbook
    assert "manual labels are protected" in runbook.lower()
