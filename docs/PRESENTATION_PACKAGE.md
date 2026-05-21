# Presentation Package

Use this package to present ATDR as a lab-pilot-ready SOC workflow rather than a collection of scripts.

## Opening Message

MFU ATDR imports Palo Alto firewall logs, preserves raw evidence, normalizes key fields, creates explainable alerts with rule-first scoring, applies ML as an assistive signal, and records every analyst or response action in an audit trail.

## Recommended Demo Script

1. Start FastAPI and Streamlit.
2. Log in as `admin`.
3. Open **Executive Demo** first.
4. Explain the four core metrics: evidence logs, active alerts, critical open alerts, and simulated response status.
5. Open **Demo Controls** and reset/import/run detection if a fresh dataset is needed.
6. Open **Overview** and show severity, workflow, top alert types, suspicious sources, anomaly rate, watchlist hits, and suppression counts.
7. Open **Alerts**, choose a high or critical alert, and show:
   - explanation
   - matched rules
   - linked evidence logs
   - raw log excerpt
   - timeline
8. Assign the alert to yourself, mark it investigating, add a note, and escalate with a ticket reference.
9. Use the alert response tab to simulate blocking a source IP.
10. Open **Response Center** and **Audit Log** to show attribution.
11. Open **Threat Controls** to show suppressions, review state, and watchlist indicators.
12. Open **ML Governance** and explain that IsolationForest is assistive, tracked, and reviewed through anomaly rate, run comparison, and drift signals.
13. Export the alert report as JSON or CSV.

## Screenshot Checklist

Capture these screens after importing logs and running detection:

- Executive Demo page
- Overview page with operations snapshot
- Alerts page selected incident summary
- Alert evidence/raw log section
- Alert workflow timeline
- Response Center simulated block list
- Audit Log filtered to response actions
- Threat Controls with suppressions and watchlist
- ML Governance report and drift monitoring
- JSON incident report preview

Store screenshots in a `screenshots/` folder for the final report or slide deck.

## Supervisor Talking Points

- The parser uses `csv.reader` and handles quoted Palo Alto payload fields.
- Raw logs are preserved before parsing for evidence integrity.
- Detection is rule-first and explainable; ML never replaces analyst review.
- Response is simulated by default to avoid damaging real devices.
- Role checks and audit logs are present for every sensitive workflow.
- PostgreSQL, Alembic migrations, Docker scaffolding, and deployment docs provide a path toward lab operation.
