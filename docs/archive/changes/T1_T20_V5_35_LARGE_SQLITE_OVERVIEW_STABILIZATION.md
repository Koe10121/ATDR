# T1-T20: v5.35 Large-SQLite Overview Stabilization

## T1 Change Title

v5.35 Large-SQLite Overview Query and Dashboard Performance Stabilization.

## T2 Requirement

Find and safely repair the measured cold Overview latency on the existing
145k-row SQLite database while preserving exact dashboard results, cache
freshness, PostgreSQL compatibility, user data, and every safety boundary.

## T3 Source Evidence

`atdr/app/services/dashboard_service.py`, dashboard router, database models and
migrations, cache signature, performance smoke, v4.7/v5.16 performance tests,
React Overview query/page, the v5.34 status, task board, read-only SQLAlchemy
timings, SQLite `EXPLAIN QUERY PLAN`, and a disposable consistent database copy.

## T4 Current Behavior

The inherited true disk-cold Overview was `5.8552s`; a fresh process reproduced
`4.8389s`. Warm application-cache misses were about `0.28-0.32s` and cached
hits about `0.012s`, showing a disk-page access problem rather than cache logic.

## T5 Impacted Areas / Agents

Database/data model, backend/dashboard service, performance and release QA,
operations/runbook, governance/traceability, and migration ownership. Frontend
behavior is regression-verified but has no source change.

## T6 Scope

Read-only profiling, two evidence-backed covering indexes, SQLite planner-stat
refresh, profiler and budget improvements, payload/cache/migration tests,
documentation, and full verification. Detection, ML, parser, IAM, Assistant,
response, and UI behavior are out of scope.

## T7 Functional Requirements

- Preserve every Overview field and aggregate exactly.
- Remove random large-table lookup I/O from source-scoped alert volume.
- Keep source counts distinct by alert even with repeated evidence.
- Preserve one-query cached hits and write-driven invalidation.
- Stay within 35 cold queries and one cached query.
- Keep SQLite and PostgreSQL migration/query compatibility.
- Perform no authoritative or destructive data mutation.

## T8 Acceptance Criteria

Cold Overview is at most `1.0s`, ingestion summary at most `2.0s`, cached
Overview at most `0.05s`, alert/case lists at most `0.25s`, lightweight ML
Governance at most `2.0s`, payloads are equal, cache invalidation remains
correct, query ceilings pass, and the full release matrix is green.

## T9 API Contract

No API route, request, response field, authentication, authorization, cache TTL,
or frontend query contract changes. `GET /api/dashboard/summary` remains the
same authenticated read-only endpoint.

## T10 Data Model / Migration

Additive migration `f8a9b0c1d2e3` creates covering indexes on normalized
`(id, raw_log_id)` and raw `(id, source_id)`. Additive migration
`b9c0d1e2f3a4` covers anomaly distributions by source IP, destination IP, and
protocol after refreshed statistics exposed that separate budget regression.
Existing rows are preserved. PostgreSQL receives portable index DDL only.

## T11 Backend Plan / Changes

Keep summary semantics unchanged, make the evidence-to-source lookup index-only,
expose the source-volume step/plan in the read-only profiler, and enforce the
requested performance budgets in smoke output.

## T12 Frontend Plan / Changes

No frontend source change. Verify that Overview renders identical metrics,
loading/error behavior, source links, navigation, dropdowns, and responsive
layouts through the existing Playwright suite.

## T13 Security / Response / AI Safety

No private rows are emitted by profiling. No label/model/detection/response
write is permitted. Rules remain alert-authoritative, ML remains shadow-only,
the Assistant remains read-only, response automation remains disabled, and no
real firewall action is introduced.

## T14 Test Plan

Distinct source-volume semantics, index declarations and plans, full payload
equivalence, fixed query ceiling, no N+1 regression, one-query cache hit,
write invalidation, empty/larger SQLite behavior, additive migration row
preservation, PostgreSQL offline SQL, no authority mutations, backend suite,
frontend suite, detection/Assistant locks, performance, release, and hygiene.

## T15 Implementation Summary

The source-volume join now has two covering lookup hops. Three additional
covering indexes keep ML Governance anomaly distributions within their existing
budget. SQLite receives fresh statistics during migration, profiling names the
source-volume cost and plan, and smoke uses the tighter v5.35 budgets.

## T16 Tests Run / Evidence

The focused regression set passes `24/24` across the complete
v4.7/v5.35/cache/migration matrix. On a disposable current-database
copy, source-volume median improved from `0.139567s` to `0.026895s` with equal
results. The separate Governance proof improved `2.238696s` to
`0.381723-0.395239s` with equal output. Final configured evidence is: source
volume `0.0174s`, full uncached Overview `0.1828s`, five-run cache-miss
median/p95 `0.148659/0.191350s`, cached median/p95
`0.010624/0.011001s`, and query counts `33/1`. Three final smoke processes were
warning-free, with ML Governance `0.2619-0.2658s`. Full backend and release
suites each passed `896 passed, 1 skipped`; Playwright passed `31`, with one
live-hardware skip; controlled/layered/Assistant gates passed
`24/24`, `288/288`, and `20/20`.

## T17 PRD / Docs Updated

v5.35 status, this T1-T20 record, exact allowlist, PRD, traceability,
compliance checklist, lab runbook, and generated task board.

## T18 Risks / Blockers / Assumptions / Decisions

OS file-cache flushing is intentionally not automated. Query-plan evidence and
fresh-process/application-cache measurements are reproducible; a true power-on
disk-cold result remains environment-dependent. The migrations add index
storage but rewrite no evidence rows. This is local SQLite evidence, not a
production SLA.

## T19 Release / Rollback

No commit or push is authorized by this document. Release requires separate
explicit approval of `docs/V5_35_COMMIT_ALLOWLIST.md`. Normal source rollback
plus migration downgrades remove only the five indexes; application rows remain.

## T20 Final Handoff

Run Alembic upgrade, the five-run profiler, performance smoke, and normal
Overview manual check. Verify the unchanged counts and source links. Four
external/evidence programs remain; production readiness is not claimed.
