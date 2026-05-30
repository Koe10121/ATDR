# MFU ATDR React Dashboard

This is the priority SOC dashboard for ATDR. It connects to the FastAPI backend at `http://127.0.0.1:8000` and provides the current React workflow for Overview, Alerts, Investigation, AI Governance, Response & Audit, Threat Controls, Detection Tuning, User Admin, and Demo Controls.

Streamlit remains in the repository only as legacy/demo continuity while React is the main dashboard path.

## Status

The React dashboard is verified for the v0.3 lab-ready release candidate. It includes role-aware navigation, admin route protection, source-aware investigation, AI Governance, simulated response controls, audit visibility, and Playwright smoke/regression coverage.

ATDR remains a lab prototype, not certified production software. Response actions are simulated and analyst-approved only.

## Requirements

- Node.js 20.x LTS or newer
- npm
- FastAPI backend running at `http://127.0.0.1:8000`

Node 16 may fail with the current Vite, ESLint, and Playwright toolchain.

## Setup

```powershell
cd frontend
Copy-Item .env.example .env
npm.cmd install
npm.cmd run dev
```

If you are using a shell where `npm` already works, `npm install` and `npm run dev` are equivalent. On Windows PowerShell, prefer the command shim:

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
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
```

If Playwright browsers are missing on a new machine, install Chromium once:

```powershell
npx.cmd playwright install chromium
```

The smoke suite covers login, core protected routes, alert/log deep links, analyst access-denied behavior, dropdown regressions, action result panels, and demo import controls.

## Safety Notes

- Response actions remain simulated.
- Admin-only pages are hidden from analysts and protected by route guards.
- ML views describe anomaly scoring as assistive, not authoritative.
- Real firewall blocking and automatic response are not enabled.
