from pathlib import Path


FINAL_DOCS = (
    Path("docs/FINAL_REPORT_OUTLINE.md"),
    Path("docs/FINAL_REPORT_DRAFT.md"),
    Path("docs/FINAL_PRESENTATION_SLIDE_CONTENT.md"),
    Path("docs/FINAL_PRESENTATION_DESIGN_GUIDE.md"),
    Path("docs/FINAL_SCREENSHOT_CAPTURE_PLAN.md"),
    Path("docs/FINAL_REHEARSAL_CHECKLIST.md"),
    Path("docs/FINAL_5_MINUTE_SCRIPT.md"),
    Path("docs/FINAL_10_MINUTE_SCRIPT.md"),
    Path("docs/FINAL_ONE_PAGE_SUMMARY.md"),
    Path("docs/FINAL_SLIDE_ASSET_GUIDE.md"),
    Path("docs/FINAL_DEMO_SCRIPT.md"),
    Path("docs/FINAL_DEFENSE_QA.md"),
    Path("docs/FINAL_EVIDENCE_CHECKLIST.md"),
    Path("docs/SUPERVISOR_FINAL_STATUS_SUMMARY.md"),
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
    texts = (
        Path("docs/FINAL_DEMO_RUNBOOK.md").read_text(encoding="utf-8"),
        Path("docs/FINAL_DEMO_SCRIPT.md").read_text(encoding="utf-8"),
    )

    for text in texts:
        for phrase in (
            "python.exe -m uvicorn atdr.app.main:app",
            "npm.cmd run dev",
            "run_source_scenario --scenario port_scan_like_traffic",
            "--source-name final-demo-firewall-live",
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


def test_final_academic_package_uses_validated_metrics_and_non_production_scope():
    paths = (
        Path("docs/FINAL_REPORT_DRAFT.md"),
        Path("docs/FINAL_PRESENTATION_SLIDE_CONTENT.md"),
        Path("docs/FINAL_DEFENSE_QA.md"),
        Path("docs/SUPERVISOR_FINAL_STATUS_SUMMARY.md"),
    )

    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "0.9174" in text
        assert "0.1303" in text
        assert "0.8556" in text
        assert "0.9000" in text
        assert "automatic response" in text.lower() or "response automation" in text.lower()
        assert "production" in text.lower()


def test_final_rehearsal_package_preserves_demo_commands_and_status_boundaries():
    paths = (
        Path("docs/FINAL_PRESENTATION_DESIGN_GUIDE.md"),
        Path("docs/FINAL_SCREENSHOT_CAPTURE_PLAN.md"),
        Path("docs/FINAL_REHEARSAL_CHECKLIST.md"),
        Path("docs/FINAL_5_MINUTE_SCRIPT.md"),
        Path("docs/FINAL_10_MINUTE_SCRIPT.md"),
        Path("docs/FINAL_ONE_PAGE_SUMMARY.md"),
        Path("docs/FINAL_SLIDE_ASSET_GUIDE.md"),
    )

    for path in paths:
        text = path.read_text(encoding="utf-8")
        for phrase in (
            "Final Controlled Validation Candidate",
            "Decision Support Only",
            "Response Automation Disabled",
            "Not Production Promoted",
        ):
            assert phrase in text

    rehearsal = Path("docs/FINAL_REHEARSAL_CHECKLIST.md").read_text(encoding="utf-8")
    assert "python.exe -m uvicorn atdr.app.main:app" in rehearsal
    assert "npm.cmd run dev" in rehearsal
    assert "--source-name final-demo-firewall-live" in rehearsal
    assert "--use-temp-db" in rehearsal
