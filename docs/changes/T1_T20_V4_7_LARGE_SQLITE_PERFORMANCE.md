# T1-T20: v4.7 Large-SQLite Overview Performance Stabilization

## T1 Change Title

v4.7 Large-SQLite Overview Performance Stabilization.

## T2 Requirement

Find and repair the real uncached Overview/ingestion summary bottleneck on the current large SQLite database while preserving response correctness, cache freshness, PostgreSQL compatibility, normal startup, and all safety controls.

## T3 Source Evidence

`atdr/app/routers/dashboard.py`, `atdr/app/services/dashboard_service.py`, `atdr/app/db/models.py`, existing migrations and indexes, `atdr/scripts/performance_smoke.py`, `atdr/scripts/profile_dashboard_summary.py`, related tests, the configured read-only SQLite profile, and the inherited v4.6 `9.341s` cold observation.

## T4 Current Behavior

The cached path was fast, but the uncached summary performed a wide-table data-quality scan, ten lazy recent-alert evidence queries, and multiple freshness round trips. True cold-disk behavior could exceed nine seconds on 145,232 normalized rows.

## T5 Impacted Areas / Agents

Backend/dashboard summary, database query design, local SQLite operations, PostgreSQL portability, QA, release/operations, and documentation.

## T6 Scope

Read-only profiling, query-shape repair, cache-signature consolidation, N+1 removal, repeatable profiler output, regression tests, performance evidence, and workflow documentation. Frontend, API schema, detection, ML, IAM, assistant, response, and database schema changes are out of scope.

## T7 Functional Requirements

- Preserve every Overview response field and meaning.
- Remove the wide normalized-log quality scan using existing indexes.
- Preserve exact case-insensitive unknown-application counts.
- Eliminate recent-alert evidence N+1 behavior.
- Preserve or strengthen cache invalidation after relevant writes.
- Measure at least five cold application-cache and warm requests.
- Keep SQLite and PostgreSQL query compilation portable.
- Create no ML, detection, label, response, or data-deletion side effect.

## T8 Acceptance Criteria

Cold application-cache median is at most `2.0s`, p95 is at most `3.0s`, warm cache is at most `0.05s`, response fields compare equal, relevant writes invalidate cache, no endpoint regression warning appears, and full release verification passes.

## T9 API Contract

No route, request, response-field, authentication, or authorization contract change. `GET /api/dashboard/summary` returns the same business payload and existing `performance` cache metadata.

## T10 Data Model / Migration

No data-model or migration change. Existing single-column indexes are sufficient. No ad hoc index was applied to the configured database.

## T11 Backend Plan / Changes

Replace CASE/LOWER wide-table aggregation with indexed scalar counts and indexed application grouping, correlate recent-alert evidence counts, reuse the raw count, consolidate and strengthen the cache signature, and enhance the existing read-only profiler.

## T12 Frontend Plan / Changes

No frontend change. Manual validation uses the existing Overview page.

## T13 Security / Response / AI Safety

The summary remains read-only. No raw records or secrets are emitted by the profiler. No model activation/promotion, automatic response, real firewall action, IAM behavior, or assistant behavior is introduced.

## T14 Test Plan

Legacy quality-count equality, empty/small/disabled-source behavior, parser examples, recent-alert evidence counts, query plans, query-count ceilings, cold/warm cache behavior, raw/alert/run invalidation, concurrent SQLite readers, PostgreSQL compilation, synthetic data performance, no ML/response side effects, full backend, Alembic, replay, performance, and release gates.

## T15 Implementation Summary

The wide quality scan was replaced by indexed searches, recent evidence is counted in the alert query, cache freshness is checked in one statement, raw counts are reused, and the profiler now reports repeatable distributions, query counts, fingerprints, and SQLite plans.

## T16 Tests Run / Evidence

Before, five warm-OS application-cache misses had median `0.486496s`, p95 `0.494161s`, and 49 queries. The final five-run closure profile has cold median `0.124564s`, p95 `0.159519s`, and 35 queries; warm median is `0.010435s`, p95 is `0.010747s`, with one query. Related targeted tests passed `24`; persistence-path confirmation passed `14`; the full backend suite passed `602 passed, 1 skipped`; Alembic reported no drift; replay dry-run wrote zero rows; performance smoke had no warnings; and the release gate returned `ok: true` with no failed required checks.

## T17 PRD / Docs Updated

v4.7 canonical status, this change record, exact commit allowlist, PRD, traceability, compliance checklist, lab runbook, and task board.

## T18 Risks / Blockers / Assumptions / Decisions

The historical true cold-disk result cannot be reproduced reliably without platform-specific page-cache manipulation. The dominant full-table plan is removed, but SQLite remains local/one-worker and no production SLA is claimed. No index migration is justified by the measured after-state.

## T19 Release / Rollback

No commit or push is authorized without explicit approval of `docs/V4_7_COMMIT_ALLOWLIST.md`. Rollback is a normal source revert; there is no schema or data rollback.

## T20 Final Handoff

Run the documented five-run profiler and performance smoke, open Overview after a safe write, and confirm fresh counts. Keep PostgreSQL/shared-host capacity and true OS-cold validation as separate environment-backed work. Production readiness is not claimed.
