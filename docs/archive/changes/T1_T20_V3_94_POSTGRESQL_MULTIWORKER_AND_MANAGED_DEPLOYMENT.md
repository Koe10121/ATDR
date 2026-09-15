# T1-T20: v3.94 PostgreSQL Multi-Worker And Managed Deployment

## T1 Change Title

v3.94 PostgreSQL Multi-Worker Runtime Validation And Managed Worker Deployment.

## T2 Requirement

Make the durable operation queue safe to validate with concurrent PostgreSQL workers, shared staged input, graceful managed restarts, and coordinated backup/restore without changing normal SQLite startup or ATDR safety controls.

## T3 Source Evidence

`atdr/app/core/config.py`, `atdr/app/db/models.py`, `atdr/app/services/job_service.py`, `resumable_ingestion_service.py`, `staging_service.py`, `source_service.py`, `operation_worker.py`, `persistence_service.py`, v3.89-v3.93 migrations/tests/docs, `.github/workflows/ci.yml`, and the systemd service-manager contract.

## T4 Current Behavior

v3.93 supported one SQLite worker and host-local staging. Queue claims did not have a private generation token, shared workers could not prove staging ownership, graceful shutdown did not requeue an import at its committed checkpoint, and PostgreSQL backup was not coordinated with workers.

## T5 Impacted Areas/Agents

Data model/migration, backend queue and ingestion services, PostgreSQL persistence, worker operations, CI, Release/Ops, QA, security/safety review, PRD, traceability, runbook, roadmap, and task board.

## T6 Scope

PostgreSQL queue concurrency, lease fencing, shared staging identity, graceful worker lifecycle, backup coordination, isolated validation, and managed service examples. Parsing, detection thresholds, ML behavior, IAM, assistant authority, response behavior, and startup commands remain unchanged.

## T7 Functional Requirements

Concurrent claim/recovery locking; stale-worker fencing; storage-aware file claims; same-source counter consistency; graceful import checkpoint release; safe backup drain/refusal; isolated restore validation; unprivileged managed services; SQLite one-worker compatibility.

## T8 Acceptance Criteria

Two PostgreSQL workers do not claim one job; expired leases recover once; stale tokens cannot mutate jobs; shared-storage mismatches fail closed; concurrent imports preserve source counts; replacement worker resumes after graceful stop; backup refuses active mutation and validates after drain; all safety side-effect counts remain unchanged.

## T9 API Contract

No public route or startup command is removed. Operation-job responses continue to hide payload internals and now also hide lease tokens and storage details. Existing queue, cancellation, and resume contracts remain compatible.

## T10 Data Model / Migration

Migration `a3b4c5d6e7f8` adds nullable `lease_token`, defaulted `claim_generation`, and indexed nullable `staging_storage_id` to `operation_jobs`. Existing jobs remain valid; host-local legacy jobs are not claimed by shared workers unless the local profile permits them.

## T11 Backend Plan / Changes

Added token-fenced ownership, PostgreSQL `SKIP LOCKED` claim/recovery, storage-aware claims, relative staged keys, shared-storage validation, source-row locking, graceful import release, advisory worker/backup coordination, deployment validator, PostgreSQL concurrency validator, and backup concurrency drill.

## T12 Frontend Plan / Changes

No new frontend behavior was required. Existing Operations Health progress, ownership-safe actions, and hidden staging details remain the user-facing contract.

## T13 Security / Response / AI Safety

Lease tokens, paths, URLs, and credentials are never public. Validators operate only on named disposable databases with explicit confirmations. Response remains simulated; no response action, label, detection side effect, model activation/promotion, external IAM call, or external LLM call is introduced.

## T14 Test Plan

Compile PostgreSQL locking SQL; exercise token fencing, storage mismatch, path traversal, graceful checkpoint handoff, and SQLite compatibility; run isolated PostgreSQL concurrent claims/recovery/source/import checks; run backup drain/restore checks; run full backend/frontend, Alembic, replay, performance, hygiene, and release gates.

## T15 Implementation Summary

ATDR now has a PostgreSQL-aware multi-worker contract and deployable service examples while preserving its local one-worker SQLite profile. Shared file jobs are tied to an explicit storage identity, job ownership is generation-token fenced, and resumable imports can be handed to a replacement worker at a committed boundary.

## T16 Tests Run / Evidence

Local focused v3.90-v3.94 tests, migration application/check, SQL compilation, deployment validation, and both validator dry runs passed. Full backend passed `515 passed, 1 skipped`; React lint/build and Playwright passed `21 passed, 1 skipped`; replay dry-run wrote zero; release gate returned `ok: true`. Performance smoke completed with cold large-SQLite warnings and a fast cached Overview. GitHub Actions run [#49](https://github.com/Koe10121/ATDR/actions/runs/29247673505) then passed disposable PostgreSQL migrations, restore, drift checking, persistence regressions, concurrent workers/shared staging, lease recovery, and backup coordination on commit `50c37e5`.

## T17 PRD / Docs Updated

`docs/V3_94_POSTGRESQL_MULTIWORKER_AND_MANAGED_DEPLOYMENT.md`, PRD, requirement traceability, productization roadmap, lab runbook, task board, generated task board HTML, and this T1-T20 record.

## T18 Risks / Blockers / Assumptions / Decisions

Local Docker/PostgreSQL/client tools are unavailable, so local evidence is unit/SQL/dry-run only; ephemeral PostgreSQL behavior is validated in CI. Shared storage must be a real common mount with one storage ID, and multi-host permissions remain untested. Advisory locking coordinates ATDR workers, not arbitrary database clients. The queue is lease-fenced at-least-once with chunk replay protection, not global exactly-once.

## T19 Release / Rollback

Apply Alembic before starting v3.94 workers. Install private environment settings and service units only on the approved host. For rollback, gracefully drain workers, back up state, roll back services, and downgrade the migration only if no queued/resumable job needs the new fields. Raw evidence is never rollback cleanup.

## T20 Final Handoff

Keep SQLite and one worker for normal local use. CI-hosted PostgreSQL behavior is validated. Before shared deployment, run the same validators on an approved host, validate its shared mount and service permissions, and inspect secret-safe evidence before deploying separate API and worker services. Production readiness is not claimed.
