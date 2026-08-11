# Dashboard Product Path

## Current Dashboard

The React application in `frontend/` is ATDR's primary analyst dashboard.
It uses Vite, React, TypeScript, TanStack Query, TanStack Table, Tailwind CSS,
Recharts, and Playwright while FastAPI remains the API boundary. Streamlit is
legacy continuity only and is not the normal analyst workflow.

The supported team entry point remains the MFU-compatible outer shell:

```powershell
.\scripts\start_system.cmd
```

The shell authenticates the user and hands off to the React dashboard. Direct
local recovery login is an explicit development/recovery profile, not the
standard shared workflow.

## Current Analyst Surfaces

- **Overview:** system/source health, truthful ingestion counters, controlled
  validation status, detection operations, run history, and job health.
- **Alerts:** triage queue, ownership/status workflow, exact `Why flagged?`
  evidence, related logs, cases, and analyst notes.
- **Investigation:** normalized evidence search, source filters, bounded raw
  evidence detail, labels, and alert linkage.
- **SOC Assistant:** concise, citation-backed, read-only guidance with active
  alert/log/source/case context and deterministic fallback.
- **AI Governance:** rule authority, IsolationForest and supervised shadow
  state, evidence provenance, schema abstention, calibration, and promotion
  blockers.
- **Response & Audit:** analyst-confirmed simulated actions and immutable audit
  visibility. Automatic response and real firewall blocking remain disabled.
- **Admin:** users, source controls, configuration status, and safe lab
  operations under backend-enforced RBAC.

## v5.32 Detection Operations Contract

Overview exposes a compact operational projection derived from existing
records:

- alert volume by primary governed rule;
- distinct source-linked alert volume;
- analyst disposition counts;
- unique alerts, grouped occurrences, and deduplication updates;
- recent detection-run created/deduplicated/suppressed counts; and
- parser warning context.

These are workload and data-quality measures. They are not model accuracy.
When independent labeled evidence is unavailable, the dashboard displays
`Insufficient Evidence` instead of inventing precision, recall, or accuracy.

## Product Quality Contract

- Main pages use concise operational language and keep technical detail
  collapsed until requested.
- Loading, empty, error, and unavailable states must remain explicit.
- Long evidence, JSON, tables, and Assistant output must not create page-level
  horizontal overflow.
- Filters, deep links, and selected entities must survive supported navigation.
- Controls must remain keyboard reachable with visible focus behavior.
- Frontend role visibility is convenience only; FastAPI authorization remains
  authoritative.
- Gemini status is shown only when provider output was actually used. Safe
  deterministic fallback remains available.

## Verification

Use Node.js 20.19 or newer:

```powershell
cd frontend
npm.cmd install
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
```

The release gate also verifies backend authorization, detection and Assistant
safety, simulated response controls, and repository hygiene.

## Remaining External Gates

The React workflow is suitable for controlled lab use, but production claims
remain blocked by independent real-device evidence, qualified human model and
Assistant evaluation, MFU/provider preproduction acceptance, managed-host
security/monitoring, and operational ownership. Real response enforcement is
a separate future safety program.
