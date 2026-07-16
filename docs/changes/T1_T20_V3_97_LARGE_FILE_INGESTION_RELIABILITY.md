# T1-T20: v3.97 Large-File Ingestion Reliability And Resumability

## T1 Change Title

v3.97 Large-File Ingestion Reliability, Indexed Duplicate Accounting, And Isolated 100k Validation.

## T2 Requirement

Make queued large-file imports measurably scalable, resumable, observable, and safely cancellable while preserving existing synchronous import, parser, detection, ML, IAM, assistant, and response behavior.

## T3 Source Evidence

`atdr/app/services/resumable_ingestion_service.py`, `log_service.py`, `staging_service.py`, `job_service.py`, `operation_worker.py`, `metrics_service.py`, `atdr/app/db/models.py`, `atdr/app/routers/jobs.py`, `frontend/src/pages/ExecutiveOverview.tsx`, v3.93 tests/docs, and the pre-change 5,000-line profile.

## T4 Current Behavior

v3.93 already provided transactional chunks, checkpoints, verified resume, safe cancellation, queue limits, staging limits, and UI progress. The hot path still ran one unindexed raw-text duplicate query and one forced ORM flush per record, making larger files unnecessarily slow. No isolated 100,000-line acceptance command existed.

## T5 Impacted Areas/Agents

Database/migration, ingestion worker, backend services, operations metrics, React Operations Health, QA/UAT, Release/Ops, documentation, and response/ML safety review.

## T6 Scope

In scope: exact indexed duplicate accounting, batched ORM flush, cumulative progress counters, ingestion metrics, disposable validation, tests, and docs. Out of scope: parser/detection/ML tuning, automatic detection, response automation, firewall calls, current-DB migration during implementation, distributed storage, and production claims.

## T7 Functional Requirements

Bounded transactions and memory; monotonic committed progress; checkpoint resume without duplicate insertion; changed-file refusal; cooperative cancellation; optional-source fallback; safe 429/503 backpressure retained; no unsafe side effects; 100,000-line temp-DB validation.

## T8 Acceptance Criteria

The validator imports and normalizes 100,000 synthetic rows, resumes after a forced handoff, inserts zero duplicate rows due to resume, rejects changed input, cancels at a committed boundary, remains inside a 128 MiB traced-memory budget, and creates no detection run, label, model run, response action, or configured-database write.

## T9 API Contract

No endpoint or startup command changed. Existing `GET /api/jobs`, `GET /api/jobs/{id}`, `POST /api/jobs/import`, cancel, request-cancel, retry, and resume contracts remain. Safe job `details` now include cumulative ingestion counters.

## T10 Data Model / Migration

Migration `b4c5d6e7f8a9` adds nullable indexed `raw_logs.raw_line_hash` and backfills existing rows in bounded batches. Raw evidence is unchanged. Downgrade removes only the derived index/column; it must not delete raw logs. The configured DB was not migrated during this work.

## T11 Backend Plan / Changes

Add stable raw fingerprints, batch exact duplicate lookup per chunk, relationship-based raw/normalized persistence, cumulative job counters, low-cardinality ingestion metrics, and `validate_large_ingestion` with an explicit temporary-target gate.

## T12 Frontend Plan / Changes

Keep the existing Operations Health layout and add compact raw/parsed/failed/duplicate counters beneath committed progress. Keep cancel/resume controls, SafeSelect behavior, responsive layout, and technical details unchanged.

## T13 Security / Response / AI Safety

Fingerprints, staged paths, raw evidence, and secrets are not API/metric labels. The validator uses synthetic data and disposable storage only. Response automation, real firewall blocking, model activation/promotion, automatic detection, label mutation, external IAM, and external assistant calls remain disabled or outside scope.

## T14 Test Plan

Fingerprint population/index and migration backfill; bounded exact duplicate queries; progress metrics; isolated validator refusal/pass; existing v3.93 resume/cancel/backpressure/RBAC regressions; frontend lint/build/Playwright; full backend, migration, replay, performance, and release gates.

## T15 Implementation Summary

The large-file path now avoids row-by-row duplicate scans and flushes while keeping exact duplicate reporting and all raw evidence. Operators receive cumulative counters, and a self-cleaning validation command measures 100k ingestion safely.

## T16 Tests Run / Evidence

Targeted persistence/v3.97 checks passed (`40 passed`). The original full backend suite passed (`538 passed, 1 skipped`), and the v3.98 closure worktree passed `544 passed, 1 skipped`. Disposable migration upgrade/check and PostgreSQL offline SQL generation passed. React lint/build passed and Playwright passed (`21 passed, 1 skipped`, hardware-dependent). The original 100,000-line validator passed in 138.0349 seconds at 724.45 rows/second with 8.71 MiB peak traced memory; the 2026-07-14 closure rerun also passed in 146.1105 seconds at 684.41 rows/second with 8.70 MiB peak memory. Both runs had zero resume duplicates and zero unsafe side effects. Read-only performance smoke on a migrated disposable copy of the 145,232-row database passed after warm-cache confirmation. Replay dry-run wrote zero rows. The release gate returned `ok: true` with incomplete private external integrations disabled through process-local verification overrides.

## T17 PRD / Docs Updated

`docs/V3_97_LARGE_FILE_INGESTION_RELIABILITY.md`, this change record, `docs/LAB_RUNBOOK.md`, PRD, traceability, compliance checklist, docs index, and generated task board.

## T18 Risks / Blockers / Assumptions / Decisions

SQLite is still single-worker. The content hash is derived metadata, not evidence replacement. Hash candidates receive a full-line comparison. The 100k run is local synthetic evidence, not an SLA or real-device proof. PostgreSQL/shared-storage runtime acceptance remains blocked by environment availability.

## T19 Release / Rollback

Run `alembic upgrade head` before starting the updated app. Rollback may remove the derived hash column/index only after stopping import workers. Never delete raw/normalized evidence as rollback cleanup. Existing startup commands remain unchanged.

## T20 Final Handoff

Status: implemented and locally validated. Apply the additive migration, start the API/frontend as usual, start one explicit SQLite operation worker for queued imports, and use Operations Health for committed counters and safe controls. No commit or push was performed.
