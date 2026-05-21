# Screenshot Checklist

Capture these after resetting demo data, importing sample logs, running detection, and signing in as `admin`.

Recommended browser state:

- URL: `http://127.0.0.1:8501`
- Browser zoom: 90-100%
- Sidebar visible
- Presentation Mode enabled
- No secrets visible

## Required Screenshots

- Executive Demo landing page with command panel and operational story
- Executive Demo mission path and system readiness panel
- Executive Demo AI Governance or Production Roadmap tab
- Overview operations snapshot and alert pressure cards
- Overview severity/workflow/action/protocol charts
- Overview recent alert triage cards
- Alerts page with a High or Critical alert selected
- Alert selected incident strip with severity/status badges
- Alert matched rules tab
- Alert evidence tab with raw evidence expanded
- Alert workflow tab with timeline and notes
- Alert response tab before simulated block
- Alert report tab showing JSON/CSV/HTML/PDF download buttons
- Response Center simulation safety banner after simulated block
- Audit Log actor/action charts and timeline
- Threat Controls suppression review queue
- Threat Controls watchlist indicators
- ML Governance assistive-AI banner and model readiness
- ML Governance anomaly patterns and run history
- Demo Controls pre-demo readiness panel
- Demo Controls evidence bundle result
- HTML incident report opened in browser

## Naming Convention

Use this naming style:

```text
01_executive_demo.png
02_system_readiness.png
03_overview_snapshot.png
04_recent_alerts.png
05_alert_summary.png
06_alert_evidence_raw.png
07_alert_workflow.png
08_response_center.png
09_audit_log.png
10_threat_controls.png
11_ml_governance.png
12_demo_readiness.png
13_demo_bundle.png
14_html_incident_report.png
```

## Visual QA Checklist

- No raw HTML source visible on dashboard.
- No broken import/module errors.
- No empty first impression after reset/import/detection.
- Response mode clearly shows simulated.
- Alert evidence includes raw log proof.
- Technical JSON previews are collapsed during Presentation Mode.
- Executive Demo works as the first page shown to a supervisor.
