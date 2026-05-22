# Dashboard Production Path

The current Streamlit dashboard is suitable for supervisor demo and lab-pilot validation. It has SOC-style navigation, triage queues, alert workflow, response simulation, ML governance, and detection tuning.

It should not be described as the final enterprise frontend. Streamlit is excellent for fast Python-heavy security prototypes, but a long-term production SOC console usually needs a dedicated frontend.

## What Is Production-Credible Now

- Authenticated SOC workflow with admin/analyst roles.
- Operational pages for overview, alerts, log evidence, response, audit, ML governance, threat controls, and detection tuning.
- Evidence-first incident views with report export.
- Presentation mode for supervisor review.
- Plotly charts and compact SOC-style status panels.
- Live API smoke checks and release verification.

## What Still Limits Streamlit

- Large-table performance and browser memory under very high event volume.
- Fine-grained frontend state management.
- Full accessibility testing and keyboard navigation control.
- Real-time push updates through WebSockets or server-sent events.
- Component-level frontend test coverage.
- Complex multi-user UI interactions at enterprise scale.

## Recommended End-Game Frontend

ATDR now includes the first React migration scaffold in `frontend/`. Keep FastAPI as the API layer and gradually move production workflows from Streamlit into this dedicated frontend:

- Vite + React + TypeScript.
- TanStack Query for API state and caching.
- TanStack Table for large alert/log tables.
- Tailwind CSS for the SOC visual system.
- Recharts for initial operational charts.
- WebSocket or server-sent events for live alert updates.
- Role-aware routing and guarded admin pages.
- Playwright end-to-end tests in CI.
- Accessibility checks for keyboard and screen-reader behavior.

## Practical Timing

Do not cut over from Streamlit yet. Streamlit remains the supervisor-demo and admin prototype, and the current Streamlit dashboard remains the right tool for lab-pilot iteration. React should become the production dashboard only after it reaches feature parity for Overview, Alerts, Detection Tuning, ML Governance, Response Center, Audit, Threat Controls, User Admin, and Demo Controls.

Node/npm are not available on the current Windows machine, so the first React sprint is scaffolded manually. Build verification should run after Node.js 20+ is installed:

```powershell
cd frontend
npm install
npm run build
npm run lint
npm run test:e2e
```
