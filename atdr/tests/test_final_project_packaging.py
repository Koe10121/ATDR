from pathlib import Path


PRESENTATION_ARCHIVE = Path("docs/archive/presentations")
FINAL_DOCS = tuple(
    PRESENTATION_ARCHIVE / name
    for name in (
        "FINAL_REPORT_OUTLINE.md",
        "FINAL_REPORT_DRAFT.md",
        "FINAL_PRESENTATION_SLIDE_CONTENT.md",
        "FINAL_PRESENTATION_DESIGN_GUIDE.md",
        "FINAL_SCREENSHOT_CAPTURE_PLAN.md",
        "FINAL_REHEARSAL_CHECKLIST.md",
        "FINAL_5_MINUTE_SCRIPT.md",
        "FINAL_10_MINUTE_SCRIPT.md",
        "FINAL_ONE_PAGE_SUMMARY.md",
        "FINAL_SLIDE_ASSET_GUIDE.md",
        "FINAL_DEMO_SCRIPT.md",
        "FINAL_DEFENSE_QA.md",
        "FINAL_EVIDENCE_CHECKLIST.md",
        "SUPERVISOR_FINAL_STATUS_SUMMARY.md",
        "FINAL_DEMO_RUNBOOK.md",
        "FINAL_DEFENSE_TALKING_POINTS.md",
        "FINAL_ACCEPTANCE_CHECKLIST.md",
        "FINAL_SYSTEM_STATUS.md",
    )
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
        (PRESENTATION_ARCHIVE / "FINAL_DEMO_RUNBOOK.md").read_text(encoding="utf-8"),
        (PRESENTATION_ARCHIVE / "FINAL_DEMO_SCRIPT.md").read_text(encoding="utf-8"),
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
    text = (PRESENTATION_ARCHIVE / "FINAL_SYSTEM_STATUS.md").read_text(encoding="utf-8")

    assert "final_controlled_validation_candidate" in text
    assert "independent_fpr_stabilized" in text
    assert "0.9174" in text
    assert "Production promoted | false" in text
    assert "Model activated | false" in text
    assert "Response automation | disabled" in text
    assert "Real firewall blocking | disabled" in text


def test_final_academic_package_uses_validated_metrics_and_non_production_scope():
    paths = (
        PRESENTATION_ARCHIVE / "FINAL_REPORT_DRAFT.md",
        PRESENTATION_ARCHIVE / "FINAL_PRESENTATION_SLIDE_CONTENT.md",
        PRESENTATION_ARCHIVE / "FINAL_DEFENSE_QA.md",
        PRESENTATION_ARCHIVE / "SUPERVISOR_FINAL_STATUS_SUMMARY.md",
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
        PRESENTATION_ARCHIVE / "FINAL_PRESENTATION_DESIGN_GUIDE.md",
        PRESENTATION_ARCHIVE / "FINAL_SCREENSHOT_CAPTURE_PLAN.md",
        PRESENTATION_ARCHIVE / "FINAL_REHEARSAL_CHECKLIST.md",
        PRESENTATION_ARCHIVE / "FINAL_5_MINUTE_SCRIPT.md",
        PRESENTATION_ARCHIVE / "FINAL_10_MINUTE_SCRIPT.md",
        PRESENTATION_ARCHIVE / "FINAL_ONE_PAGE_SUMMARY.md",
        PRESENTATION_ARCHIVE / "FINAL_SLIDE_ASSET_GUIDE.md",
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

    rehearsal = (PRESENTATION_ARCHIVE / "FINAL_REHEARSAL_CHECKLIST.md").read_text(
        encoding="utf-8"
    )
    assert "python.exe -m uvicorn atdr.app.main:app" in rehearsal
    assert "npm.cmd run dev" in rehearsal
    assert "--source-name final-demo-firewall-live" in rehearsal
    assert "--use-temp-db" in rehearsal
