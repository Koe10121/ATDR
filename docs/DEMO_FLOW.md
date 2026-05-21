# MFU ATDR Demo Flow

This demo shows ATDR as a small SOC workflow, not just a parser.

## 1. Start Services

```powershell
uvicorn atdr.app.main:app --reload
streamlit run atdr/dashboard/streamlit_app.py --server.headless true --browser.gatherUsageStats false
```

Open:

```text
http://127.0.0.1:8501
```

Login:

```text
admin / admin123
```

## 2. Reset Demo Data

Go to **Demo Controls**:

- Reset Demo Data
- Import Sample Logs
- Run Detection

Expected result:

- normalized logs are stored
- grouped alerts are created
- audit records are created for admin actions

## 3. Review SOC Overview

Go to **Executive Demo** first, then **Overview**, and explain:

- total normalized logs
- alert severity distribution
- workflow states
- top suspicious sources
- action/protocol/app-risk distributions
- watchlist hit count
- suppression count and suppressed-hit count
- recent alerts

## 4. Investigate An Alert

Go to **Alerts**:

- filter by `High` or `Critical`
- open an alert
- review summary, matched rules, evidence logs, and raw evidence
- assign the alert to yourself
- add an investigation note
- mark it `investigating`

This demonstrates analyst workflow and auditability.

## 5. Simulated Response

In the alert **Response** tab:

- choose a source IP
- click `Block Selected IP`

ATDR records the response action but does not touch any real firewall device.

Go to **Response Center** and **Audit Log** to show:

- blocked IP record
- response action attribution
- audit trail actor/time/details

## 6. ML Governance

Go to **ML Governance**:

- review dataset profile
- review baseline candidate count
- train with baseline-only mode
- apply scoring
- inspect anomaly rate, anomalous apps/IPs/ports, and model run history
- review drift signals and run comparison

Explain that ML is assistive and auditable. The system uses rules first, then ML anomaly scores as a supporting signal.

## 7. Threat Controls

Go to **Threat Controls**:

- show suppression rules and review status
- add or review a watchlist indicator
- explain that noisy benign activity is governed instead of silently deleted

## 8. Export Evidence Bundle

Go to **Demo Controls**:

- click `Generate Demo Evidence Bundle`
- show the exported JSON/CSV/HTML/Markdown files in `demo_exports/`
- explain that the bundle can be attached to the report appendix

## 9. Closing Message

ATDR is defensive by design:

- raw logs are preserved as evidence
- detections are explainable
- response actions are simulated by default
- every workflow action is audited
- ML training and scoring are tracked with metadata
