# MFU ATDR React Dashboard

This is the production dashboard migration path for ATDR. It runs beside the existing Streamlit dashboard until feature parity is reached.

## Status

The project is scaffolded and verified as the production-dashboard migration path. It currently includes Executive Overview, Alert Workbench, Log Explorer, Response Center, Threat Controls, Audit Log, Detection Tuning, ML Governance, User Admin, and Demo Controls.

## Setup

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

If PowerShell blocks `npm.ps1`, use the Windows command shim instead:

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5173`.

FastAPI must be running at `http://127.0.0.1:8000`. The backend CORS demo settings include the Vite dev origins:

```text
http://127.0.0.1:5173
http://localhost:5173
```

## Verification

```powershell
npm run build
npm run lint
npm run test:e2e
```

If Playwright browsers are missing on a new machine, install Chromium once:

```powershell
npx.cmd playwright install chromium
```

The smoke suite covers login, core protected routes, alert/log deep links, and analyst access-denied behavior.

## Migration Rule

Do not remove Streamlit yet. Streamlit remains the supervisor-demo and admin prototype until React covers the same operational workflows.

## Safety Notes

- Response actions remain simulated.
- Admin-only pages are hidden from analysts and protected by route guards.
- ML views describe anomaly scoring as assistive, not authoritative.
