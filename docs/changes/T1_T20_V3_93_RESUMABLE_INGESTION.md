# T1-T20: v3.93 Resumable Large-File Ingestion

## T1 Change Title

v3.93 Resumable Large-File Ingestion, Backpressure, And Cooperative Cancellation.

## T2 Requirement

Make durable file imports observable, cancellable at safe boundaries, and resumable after interruption without replaying already committed chunks.

## T3 Source Evidence

`atdr/app/services/log_service.py`, `job_service.py`, `job_dispatcher.py`, `operation_worker.py`, `atdr/app/routers/jobs.py`, operation-job models/migrations/tests, `frontend/src/pages/ExecutiveOverview.tsx`, and `frontend/src/pages/DemoControls.tsx`.

## T4 Current Behavior

The old queued path streamed a file but committed once, did not renew its lease during parsing, always removed staged input after the attempt, and counted duplicate text without preventing replay. It was not safely resumable.

## T5 Impacted Areas/Agents

Backend/API, database migration, worker operations, ingestion/run history, React operations UI, QA, Release/Ops, documentation, and security/safety review.

## T6 Scope

Durable queued import/replay only. Synchronous imports, parsers, detection thresholds, ML behavior, IAM, assistant authority, response behavior, and startup commands remain unchanged.

## T7 Functional Requirements

Transactional chunks; persisted progress/checkpoint; lease/heartbeat renewal; fingerprint-verified resume; cooperative cancellation; bounded queues/staging; dry-run cleanup; safe API/UI visibility.

## T8 Acceptance Criteria

A forced post-commit interruption resumes without duplicating committed rows; changed/missing input is rejected; cancellation preserves committed evidence; limits fail safely; no downstream action is triggered.

## T9 API Contract

Adds `POST /api/jobs/{id}/request-cancel` and `POST /api/jobs/{id}/resume`; extends operation-job reads with progress, checkpoint, cancellation, and resume fields. Existing `/cancel`, `/retry`, and startup contracts remain available.

## T10 Data Model / Migration

Migration `f2a3b4c5d6e7` adds checkpoint, chunk, input verification, cancellation, resume-parent, and expiry fields plus indexes. It only adds nullable/defaulted columns and preserves existing rows.

## T11 Backend Plan / Changes

Added staging safety, resumable ingestion, retention planning, worker cancellation handling, queue backpressure, metrics, API controls, and an explicit cleanup CLI.

## T12 Frontend Plan / Changes

Added durable upload, committed progress bars, staging state, safe cancel/resume controls, readable errors, and collapsed checkpoint details.

## T13 Security / Response / AI Safety

Paths and fingerprints stay private; metrics have bounded labels; cleanup never touches evidence; resume is admin-only; no detection, label, model, response, IAM, or LLM action is introduced.

## T14 Test Plan

Temporary DB/files only: multiple chunks, crash/resume, cancellation, fingerprint/missing input, backpressure, low disk, retention protection, RBAC/API, UI progress/overflow, full regression and release gates.

## T15 Implementation Summary

Queued imports now use transactionally committed chunks tied to operation-job checkpoints and cumulative ingestion/source state. Failed/cancelled inputs remain available for a bounded verified resume.

## T16 Tests Run / Evidence

Focused v3.93 and durable-job tests passed (`15 passed`), operation regressions passed (`23 passed`), and full backend passed (`509 passed, 1 skipped`). Alembic chain/check, React lint/build, Playwright (`21 passed, 1 skipped`), replay dry-run, staged-cleanup dry-run, warning-free performance smoke, and release gate (`ok: true`) passed.

## T17 PRD / Docs Updated

`docs/V3_93_RESUMABLE_LARGE_FILE_INGESTION.md`, PRD, traceability, productization roadmap, lab runbook, task board, and this change record.

## T18 Risks / Blockers / Assumptions / Decisions

SQLite remains single-worker. Local staging is not distributed storage. The guarantee is transactional per verified file chunk, not global exactly-once. PostgreSQL concurrency remains unvalidated.

## T19 Release / Rollback

Apply Alembic revision before running the new code. Roll back the application and migration only after ensuring no resumable jobs depend on the new fields. Raw logs must never be removed as rollback cleanup.

## T20 Final Handoff

Use the unchanged API/frontend commands plus a separately launched operation worker. Recommended next phase is v3.94 PostgreSQL multi-worker and managed-worker validation on an approved host.
