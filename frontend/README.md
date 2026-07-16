# MFU ATDR React Dashboard

This is the priority SOC dashboard for ATDR. It connects to FastAPI at `http://127.0.0.1:8000`. In the normal team profile, users enter it through the approved MFU outer shell and secure one-time handoff rather than a direct local login.

Streamlit remains in the repository only as legacy/demo continuity while React is the main dashboard path.

## Status

The React dashboard is the primary SOC console for ATDR. It includes role-aware navigation, admin route protection, optional supervisor-template school-email handoff, source-aware investigation, an optional Gemini-backed read-only assistant with deterministic fallback, AI Governance, simulated response controls, audit visibility, and Playwright regression coverage.

ATDR remains a lab prototype, not certified production software. Response actions are simulated and analyst-approved only.

## Requirements

- Node.js 20.19.0 or newer (Node 20 LTS recommended)
- npm
- FastAPI backend running at `http://127.0.0.1:8000`

Node 16 is unsupported, and Node 20 releases older than 20.19 may emit engine warnings with the current ESLint toolchain.

## Normal Team Startup

From the ATDR repository root, use the portable lifecycle commands:

```powershell
.\scripts\setup_team.cmd -TemplateRoot "D:\Path To\mfu-ai-driven-log-based-threat-detection-and-response"
.\scripts\start_system.cmd
```

The browser opens the MFU shell at `http://127.0.0.1:8080/#/pages/login`. After shell authentication, **Open ATDR SOC Dashboard** establishes an HttpOnly ATDR session through a one-time server-side exchange.

See `docs/TEAM_ONE_COMMAND_START.md` for prerequisites and troubleshooting.

## Direct Frontend Development

The following commands remain available for frontend development, but they are not the normal authenticated user entry path:

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

Open `http://127.0.0.1:5173`. In `template_shell` mode, an unauthenticated browser is directed back to the MFU shell. Local credentials appear only in the explicit `local_recovery` profile.

FastAPI must be running at `http://127.0.0.1:8000`. The backend CORS demo settings include the Vite dev origins:

```text
http://127.0.0.1:5173
http://localhost:5173
```

Optional projector cleanup mode:

```powershell
$env:VITE_ATDR_PRESENTATION_MODE="true"
npm.cmd run dev
```

Presentation mode keeps key metrics and safety badges visible while hiding selected technical/debug-heavy details.

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

It also covers template-shell handoff success/fallback, assistant provider telemetry, actor-scoped follow-up context, context reset, citations, long-answer containment, and the absence of assistant action controls.

## Safety Notes

- Response actions remain simulated.
- Admin-only pages are hidden from analysts and protected by route guards.
- ML views describe anomaly scoring as assistive, not authoritative.
- Real firewall blocking and automatic response are not enabled.
- External LLM use is optional and configured only through the private backend `.env`; the frontend never receives the provider API key.
- The assistant is read-only and raw logs remain excluded from external-provider context by default.
