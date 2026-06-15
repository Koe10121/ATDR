from pathlib import Path


FINAL_DOCS = (
    Path("docs/FINAL_DEMO_RUNBOOK.md"),
    Path("docs/FINAL_DEFENSE_TALKING_POINTS.md"),
    Path("docs/FINAL_ACCEPTANCE_CHECKLIST.md"),
    Path("docs/FINAL_SYSTEM_STATUS.md"),
)


def test_final_project_documents_exist_and_preserve_safety_language():
    for path in FINAL_DOCS:
        assert path.exists(), f"Missing final project document: {path}"
        text = path.read_text(encoding="utf-8")
        assert "production" in text.lower()
        assert "automatic response" in text.lower() or "response automation" in text.lower()
        assert "real firewall" in text.lower()


def test_final_demo_runbook_uses_supported_startup_and_scenario_commands():
    text = Path("docs/FINAL_DEMO_RUNBOOK.md").read_text(encoding="utf-8")

    for phrase in (
        "python.exe -m uvicorn atdr.app.main:app",
        "npm.cmd run dev",
        "run_source_scenario --scenario port_scan_like_traffic",
        "http://127.0.0.1:5173",
        "Decision Support Only",
        "Response Automation Disabled",
        "Not Production Promoted",
        "Final Controlled Validation Candidate",
    ):
        assert phrase in text


def test_final_system_status_records_frozen_v20_decision():
    text = Path("docs/FINAL_SYSTEM_STATUS.md").read_text(encoding="utf-8")

    assert "final_controlled_validation_candidate" in text
    assert "independent_fpr_stabilized" in text
    assert "0.9174" in text
    assert "Production promoted | false" in text
    assert "Model activated | false" in text
    assert "Response automation | disabled" in text
    assert "Real firewall blocking | disabled" in text
