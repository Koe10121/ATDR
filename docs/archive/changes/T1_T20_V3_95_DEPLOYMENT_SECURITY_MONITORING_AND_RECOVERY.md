# T1-T20: v3.95 Deployment Security, Monitoring, And Recovery Operations

## T1 Change Title

v3.95 Deployment Security, Monitoring, And Recovery Operations.

## T2 Requirement

Add secure reverse-proxy references, persistent monitoring groundwork, safe scheduled maintenance, managed-secret guidance, bounded read-only load testing, and isolated disaster-recovery validation while preserving normal SQLite development and ATDR safety controls.

## T3 Source Evidence

- `atdr/app/main.py`, `atdr/app/core/config.py`, `atdr/app/core/middleware.py`
- `atdr/app/routers/observability.py`
- `atdr/app/services/metrics_service.py`, `atdr/app/services/persistence_service.py`
- `atdr/app/services/operation_worker.py`, `atdr/app/services/staging_service.py`
- `deploy/systemd/*`, `.github/workflows/ci.yml`
- `docs/V3_89_SHARED_LAB_PERSISTENCE_AND_BACKUP_RESTORE.md`
- `docs/V3_92_OPERATIONAL_OBSERVABILITY_AND_WORKER_SUPERVISION.md`
- `docs/V3_94_POSTGRESQL_MULTIWORKER_AND_MANAGED_DEPLOYMENT.md`

## T4 Current Behavior

Before v3.95, ATDR had liveness/readiness, bounded local metrics, persistence drills, resumable jobs, and managed API/worker examples. It did not have a reverse-proxy reference, external scrape/alert files, scheduled report-only maintenance units, a managed-secret operations guide, a purpose-built read-only load command, or a consolidated isolated recovery drill.

## T5 Impacted Areas / Agents

Backend/configuration, observability, persistence, release operations, security, QA, documentation, and CI. No detection, ML inference, response, or database-schema behavior is changed.

## T6 Scope

In scope: optional deployment references, trusted-forwarded-header policy, safe metrics/alerts, report-only timers, secret guidance, read-only load testing, backup verification, recovery drill, tests, CI, and runbooks. Out of scope: installing a production host, obtaining certificates, paging integration, destructive maintenance, real response, model activation, and production certification.

## T7 Functional Requirements

- Local startup remains unchanged and proxy trust defaults off.
- Forwarded headers are accepted only from explicit trusted direct peers.
- Monitoring covers readiness, DB, queue, workers, failures, ingestion, detection, staging, and response-simulation state without sensitive labels.
- Scheduled jobs are non-destructive by default.
- Load testing uses GET only and does not report tokens or bodies.
- Recovery restores only to an isolated target and verifies checksum, revision, integrity, and counts.

## T8 Acceptance Criteria

- Deployment validator passes with all required assets and safety controls.
- New focused tests pass.
- Controlled local read-only load reports zero errors and no budget warnings.
- Isolated recovery drill passes and confirms the configured database is unchanged.
- Full repository verification passes.
- Remote PostgreSQL CI evidence must pass after an explicitly approved push; approved-host deployment evidence remains separate.

## T9 API Contract

No new public business endpoint. Existing `/health/live`, `/health/ready`, `/metrics`, and authenticated read-only API routes are exercised. Trusted-proxy handling can affect request scheme/client metadata only when explicitly enabled and the direct peer is allowlisted.

## T10 Data Model / Migration

No v3.95 schema migration. Recovery validation uses fresh isolated databases and the existing Alembic head.

## T11 Backend Plan / Changes

Add trusted-proxy middleware/config, operational safety metrics, backup artifact verification, deployment validator, readiness/backup checks, read-only load harness, and isolated recovery drill. Keep all execution bounded and fail closed.

## T12 Frontend Plan / Changes

No frontend behavior change is required. Existing Overview, alerts, cases, sources, operations, and assistant status routes are load-tested read-only.

## T13 Security / Response / AI Safety

No secret values are exposed. Raw log context remains disabled. Load testing cannot write. Maintenance timers cannot apply deletion. Recovery cannot overwrite the active DB. Response simulation remains true; no response action, firewall operation, label mutation, or model activation is introduced.

## T14 Test Plan

- Trusted and untrusted proxy-header behavior.
- Invalid proxy network rejection.
- Metric coverage and sensitive-dimension exclusion.
- GET-only load statistics and remote confirmation.
- Backup checksum verification and tamper rejection.
- DR dry-run and isolated execution.
- Deployment asset and timer safety validation.
- Full backend/frontend/release regression.

## T15 Implementation Summary

Implemented optional Nginx, Prometheus, alert-rule, systemd-timer, and secret-management references; added trusted proxy handling, monitoring gauges, non-mutating validators, read-only load testing, isolated recovery validation, and CI checks.

## T16 Tests Run / Evidence

Focused Ruff, compileall, and v3.95 tests passed. Deployment validation passed. The isolated recovery drill passed with checksum, integrity, row-count, and revision validation and no configured-DB change. A 24-request local read-only load sample completed with zero errors and no budget warnings. Local full backend passed `523 passed, 1 skipped`; Alembic had no drift; React lint/build passed; Playwright passed `21 passed, 1 skipped`; replay, performance, task-board checks, and release gate all passed. After the approved push and portability fixes, GitHub Actions run [#49](https://github.com/Koe10121/ATDR/actions/runs/29247673505) passed all jobs on `50c37e5`: backend `525 passed, 1 skipped`, frontend Playwright `21 passed`, and the complete disposable PostgreSQL persistence/multi-worker workflow.

## T17 PRD / Docs Updated

Updated PRD, traceability, productization roadmap, lab runbook, task board, and generated HTML. Added the v3.95 implementation guide, this change record, deployment references, and the v3.94 release allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- Ephemeral PostgreSQL CI passed; multi-host storage permissions and managed-host operation remain unvalidated.
- TLS, DNS, Linux service installation, alert routing, and secret-manager integration require an approved environment.
- RPO 24h and RTO 4h are planning assumptions, not measured guarantees.
- Cold large-SQLite Overview/ML Governance performance remains a known warning.
- Decision: preserve SQLite local workflow and keep all deployment features optional.

## T19 Release / Rollback

Use an exact path allowlist; never `git add .`. Do not commit or push without approval. Drain API mutations/workers, verify a backup, roll back application/proxy configuration, and validate any restore against a separate target before service cutover. Never delete raw evidence during rollback.

## T20 Final Handoff

Repository-side v3.95 controls and ephemeral PostgreSQL CI are verified. Real TLS/monitoring/secret-service installation, multi-host storage validation, and measured recovery exercises remain explicit approved-host deployment gates. Recommended v3.96 is an approved-host deployment rehearsal, not additional runtime features.
