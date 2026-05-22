# MFU ATDR React Dashboard

This is the production dashboard migration path for ATDR. It runs beside the existing Streamlit dashboard until feature parity is reached.

## Status

The project is scaffolded and verified as a first production-dashboard migration sprint. Install Node.js 20+ or the current LTS before running frontend commands on another machine.

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

Playwright browser tests are optional until browser dependencies are installed. The production build and lint checks are the required frontend checks for this sprint.

## Migration Rule

Do not remove Streamlit yet. Streamlit remains the supervisor-demo and admin prototype until React covers the same operational workflows.
