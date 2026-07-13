# T1-T20: v3.92 Operational Observability And Worker Supervision

## T1 Change Title

- Title: v3.92 Operational Observability And Worker Supervision
- Date: 2026-07-13
- Owner / acting agent: Codex
- Related version: v3.92

## T2 Requirement

Add safe request correlation, explicit liveness/readiness, low-cardinality metrics, worker supervision, operational warnings, and dry-run audit retention while preserving the current FastAPI/React workflow and all response/ML safety controls.

## T3 Source Evidence

| Source | Evidence / Finding |
| --- | --- |
| `atdr/app/main.py` | `/health` existed but liveness/readiness were not separated. |
| `atdr/app/core/middleware.py` | Request IDs existed but accepted arbitrary header length/content. |
| `atdr/app/services/job_service.py` | Durable jobs, leases, stale-job checks, heartbeats, and fail-closed recovery already existed. |
| `atdr/app/services/operation_worker.py` | Manual worker existed; graceful stop and SQLite process guard were missing. |
| `frontend/src/pages/ExecutiveOverview.tsx` | Operations Health already displayed queue/worker state and was the correct warning surface. |
| `atdr/app/db/models.py` | Existing job and heartbeat columns were sufficient; no migration was needed. |

## T4 Current Behavior

Before v3.92, the API had structured access logs and a combined health endpoint. Job leases/heartbeats existed, but worker lifecycle and compact warning behavior were incomplete. No low-cardinality metrics or protected audit-retention CLI existed.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Backend / API | Request correlation, health, metrics, operations health |
| Frontend / Dashboard | Compact Operations Health warnings |
| Security / Response Safety | Secret-safe output, no operational side effects |
| QA/UAT | New observability, worker, and retention tests |
| Release/Ops | Worker and retention commands/runbook |
| Data Model / Database | Existing schema reused; no migration |

## T6 Scope

In scope: visibility, supervision, fail-closed recovery, and operator tooling. Out of scope: external monitoring, scheduled deletion, PostgreSQL runtime proof, Redis, automatic response, firewall enforcement, detection/ML changes, or model promotion.

## T7 Functional Requirements

1. Bound and propagate request IDs.
2. Separate process liveness from DB/migration/config readiness.
3. Export low-cardinality, secret-safe metrics.
4. Warn on stale worker/jobs, backlog, failures, DB/migration/config, and response-mode drift.
5. Reject concurrent SQLite workers and record graceful shutdown.
6. Default audit retention to dry-run and preserve security evidence.

## T8 Acceptance Criteria

- Invalid request IDs are replaced and never become labels.
- Liveness remains available when readiness fails.
- Metrics omit IDs, paths, actors, IPs, evidence, and secrets.
- Monitoring creates no detection, response, label, or model side effect.
- SQLite rejects another fresh worker.
- Audit retention requires exact confirmation and never touches raw logs.

## T9 API Contract

- Added `GET /health/live`.
- Added `GET /health/ready`.
- Added public low-cardinality `GET /metrics`.
- Added admin-only `GET /api/operations/health`.
- Extended `GET /api/jobs/summary` with `health_status`, `warnings`, `warning_count`, and recent failure visibility.
- Preserved `GET /health` and all existing startup/API behavior.

## T10 Data Model / Migration

No schema change. `operation_jobs`, `operation_worker_heartbeats`, `ingestion_runs`, `detection_runs`, and `audit_logs` already provide the necessary persisted fields. Alembic check is required to confirm no drift.

## T11 Backend Plan / Changes

Add metrics and observability services, harden middleware, extend job summary warnings, supervise the manual worker, and add an explicit audit-retention service/CLI.

## T12 Frontend Plan / Changes

Extend operation summary types and show up to four compact warnings in the existing Overview Operations Health panel. Keep detailed run history collapsed.

## T13 Security / Response / AI Safety

No secrets, raw logs, private paths, users, emails, or IP addresses are metric dimensions. Monitoring and retention cannot invoke response, detection, label, model, source, or account actions. Response simulation remains required and real blocking remains disabled.

## T14 Test Plan

Cover request-ID validation, live/ready distinction, safe 503 output, metric privacy, warnings, SQLite worker rejection, graceful shutdown, lease recovery compatibility, retention dry-run/apply against temporary DBs, RBAC, and absence of operational side effects.

## T15 Implementation Summary

Implemented schema-free v3.92 observability, worker supervision, compact UI warnings, and bounded audit retention using existing ATDR services and tables.

## T16 Tests Run / Evidence

Focused v3.92 tests passed (`9 passed`). Ruff and compileall passed; full backend passed (`501 passed, 1 skipped`); Alembic reported no drift; React lint/build passed; Playwright passed (`19 passed, 1 skipped`); replay dry-run wrote no rows; performance smoke returned no warnings with Overview `0.3902s`, cached Overview `0.0052s`, ML Governance `1.1668s`, and job summary `0.0045s`. Audit-retention dry-run would delete `0` and touched no raw logs/response actions. The final release gate returned `ok: true` with all required checks passing.

## T17 PRD / Docs Updated

Updated the PRD, traceability, productization roadmap, lab runbook, task board, and this v3.92 implementation record.

## T18 Risks / Blockers / Assumptions / Decisions

- PostgreSQL multi-worker runtime proof is pending.
- In-process HTTP metrics reset on API restart.
- Audit cleanup remains manual and bounded.
- A private runtime profile that enables an incomplete IAM configuration intentionally fails readiness.
- SQLite stays one-worker only.

## T19 Release / Rollback

Rollback removes the new services/routes/config fields/UI warning block and restores the previous middleware/worker functions. No schema downgrade or data rollback is needed. Do not run audit retention apply as part of release or rollback.

## T20 Final Handoff

Operators may inspect `/health/live`, `/health/ready`, `/metrics`, the Overview Operations Health panel, and admin operations health. Start workers only through the existing explicit CLI. Review audit retention dry-run output before any separately approved apply.
