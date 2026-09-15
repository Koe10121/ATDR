# MFU ATDR Demo Day Runbook

Use this checklist on local Windows before presenting to a supervisor.

## 1. Start Services

Open PowerShell in the project root:

```powershell
cd <ATDR_ROOT>
.\.venv\Scripts\python.exe -m atdr.scripts.seed_users
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000
```

In a second PowerShell window:

```powershell
cd <ATDR_ROOT>
$env:API_BASE_URL="http://127.0.0.1:8000"
.\.venv\Scripts\streamlit.exe run atdr/dashboard/streamlit_app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

Open:

```text
http://127.0.0.1:8501
```

## 2. Sign In

Use the demo admin account:

```text
username: admin
password: admin123
```

Keep **Presentation Mode** enabled in the sidebar for cleaner screenshots and supervisor walkthroughs.

## 3. Prepare Data

Open **Demo Controls** and check **Pre-Demo Readiness**.

Run, in order:

1. **Reset Demo Data**
2. **Import Sample Logs** if reset did not import enough logs for the demo
3. **Run Detection**
4. Optional: **Train ML Model**
5. Optional: **Apply ML Scoring**
6. **Generate Demo Evidence Bundle**

The readiness panel should show:

- API healthy
- database healthy
- sample logs loaded
- alerts exist
- response mode simulated
- recent audit activity present

## 4. Supervisor Walkthrough Order

Present in this order:

1. **Executive Demo**
2. **Overview**
3. **Alerts**
4. **Response Center**
5. **Audit Log**
6. **Threat Controls**
7. **ML Governance**
8. **Demo Controls**

Core message:

```text
ATDR uses explainable rules first, ML only as assistive scoring, preserves raw evidence, and keeps response actions simulated until an approved firewall connector exists.
```

## 5. Capture Evidence

Use `docs/SCREENSHOT_CHECKLIST.md` for the exact screenshot list.

After generating the evidence bundle, confirm the exported folder contains:

- dashboard summary JSON
- top alerts JSON
- recent audit JSON
- ML evaluation JSON
- alert report JSON/CSV/HTML/PDF
- Markdown demo summary

## 6. Quick Troubleshooting

If Streamlit shows `ModuleNotFoundError: No module named 'atdr'`, restart it from the project root with the command above.

If the dashboard says API unavailable, confirm FastAPI is running:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/health
```

If the demo looks empty, open **Demo Controls**, run **Reset Demo Data**, then run **Run Detection**.

For local smoke checks:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.lab_smoke_check --skip-docker
```

Run the full lab smoke check, including Docker availability, on a Docker-capable host:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.lab_smoke_check
```
