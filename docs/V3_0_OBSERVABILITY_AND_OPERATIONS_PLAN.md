# ATDR v3.0 Observability And Operations Plan

ATDR already has health checks, run history, performance smoke, source health, audit logs, and dashboard operations panels. v3.0 formalizes what must be monitored during a real-source pilot.

## Source Evidence

- API health: `atdr/app/main.py`
- Ingestion and detection runs: `atdr/app/db/models.py`, `atdr/app/services/operation_run_service.py`
- Performance smoke: `atdr/scripts/performance_smoke.py`
- Source health: `atdr/app/services/source_service.py`
- Audit logs: `atdr/app/routers/audit.py`
- Dashboard panels: `frontend/src/pages/ExecutiveOverview.tsx`, `frontend/src/pages/MLGovernance.tsx`

## Minimum Pilot Metrics

- API health status.
- Database connection status.
- Latest ingestion run status and runtime.
- Latest detection run status and runtime.
- Source last seen and last log received time.
- Parse success and failure counts.
- Unknown app rate by source.
- Alert count and dedup count.
- Case count.
- Response actions and denied attempts.
- Audit event volume.
- Performance smoke timings.

## Recommended Alert Conditions

- Source enabled but idle beyond pilot threshold.
- Parse failure rate above 10%.
- Unknown app rate unexpectedly high for the source type.
- Detection run failures.
- Performance smoke warnings.
- Any response action status other than simulated/denied in lab mode.
- Any attempt to disable response simulation.

## Current Limitation

ATDR does not yet integrate with external observability tools such as Prometheus, Grafana, ELK, or cloud monitoring. The current plan relies on app-level health, run history, source panels, audit logs, and performance smoke until a deployment target is chosen.
