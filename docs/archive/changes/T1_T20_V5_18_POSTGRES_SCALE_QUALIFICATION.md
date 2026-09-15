# T1-T20: v5.18 Approved-Host PostgreSQL Scale Qualification And SLO Lock

## T1 Change Title

v5.18 Approved-Host PostgreSQL Scale Qualification and SLO Lock.

## T2 Requirement

Qualify ATDR at 100,000 rows and then, only after that gate passes, at 250,000
rows on explicitly approved disposable PostgreSQL targets. Establish fixed
runtime, memory, query, worker, recovery, backup, and safety evidence.

## T3 Source Evidence

- v5.17 PostgreSQL acceptance service, CLI, tests, status, and CI correction;
- operation jobs, workers, leases, resumable ingestion, staging, and source
  services;
- deterministic detection, alert, evidence, case, and explanation services;
- dashboard, source detail, backup, and restore services;
- v5.14-v5.16 bounded runtime and query acceptance;
- SQLAlchemy/Alembic database source; and
- React alert workbench and API contracts.

## T4 Current Behavior

v5.17 proved 2,000-row PostgreSQL behavior after publication but did not lock
100k/250k SLOs. The first v5.18 100k rehearsal exposed three scale-specific
problems: a detection coordination timeout shorter than the valid large run,
an operation-job session release that detached the worker lease record, and
alert/case reads that hydrated the complete evidence ORM graph.

## T5 Impacted Areas/Agents

Database, worker/runtime, ingestion, detection, alerts, cases, API, React
alert display, performance, QA, security/privacy, release, and documentation.

## T6 Scope

Add a strict v5.18 preflight and staged qualification runner, repair only the
measured scale blockers, add regressions, execute all four scale/worker
profiles, and document an honest single-host SLO lock.

## T7 Functional Requirements

- Refuse missing approval, unsafe targets, configured-database identity,
  non-PostgreSQL targets, missing tools, insufficient host capacity, or
  inadequate connection headroom.
- Qualify 100k before permitting 250k.
- Run 2-worker and 4-worker profiles.
- Reconcile exact ingestion, parser, source, detection, alert, evidence, and
  case counts.
- Measure throughput, chunk latency, full-stage RSS, database growth, pool
  behavior, lock state, query counts/plans/timings, and recovery behavior.
- Validate isolated backup/restore and complete disposable cleanup.
- Return aggregate evidence only.

## T8 Acceptance Criteria

All 13 SLO checks pass for both worker profiles at 100k and 250k. The
configured database remains unchanged; labels, model runs, and response
actions remain zero; privacy findings remain zero; and full repository
verification passes.

## T9 API Contract

No route is removed. Alert payloads add
`evidence_log_ids_truncated` so clients can distinguish a bounded ID sample
from the exact evidence count. Existing clients can ignore the additive
field. Alert counts, evidence counts, and source traceability remain exact.

## T10 Data Model / Migration

No schema or Alembic migration is required. Existing PostgreSQL tables,
indexes, leases, jobs, runs, alerts, evidence, and cases are reused.

## T11 Backend Plan / Changes

- Add v5.18 preflight, qualification service, and CLI.
- Partition requested rows exactly across workers.
- Allow a bounded large-run detection coordination timeout.
- Keep worker-owned operation job state attached for lease finalization.
- Replace alert/case full evidence hydration with exact aggregate summaries
  and bounded evidence ID samples.
- Persist bounded source/port/action aggregate metadata on new alert groups.

## T12 Frontend Plan / Changes

Display "first N of total" when alert evidence IDs are intentionally bounded.
No navigation, detection, response, or workflow behavior changes.

## T13 Security / Response / AI Safety

The runner exposes no URL, credential, path, raw row, IP, fingerprint, SQL
parameter, or secret. It cannot write labels, activate/promote models, create
response actions, enable automation, or enable firewall blocking. Rules remain
alert-authoritative and supervised ML remains `shadow_observation`.

## T14 Test Plan

- Preflight fail-closed and approval tests.
- Staged 100k-before-250k tests.
- SLO pass/fail tests.
- Exact partition and safe-target tests.
- Bounded evidence summary and truncation tests.
- Existing detection grouping, API, worker, persistence, and frontend
  regressions.
- Full repository verification and hygiene matrix.

## T15 Implementation Summary

Implementation and measured qualification are complete. Both 100k profiles
and both 250k profiles passed 13/13 SLO checks. Two workers remain the
conservative operating recommendation because four workers did not materially
improve throughput on this host.

## T16 Tests Run / Evidence

- Taskboard render/check, Ruff, and `compileall` passed.
- Focused v5.17/v5.18/detection/API tests passed: `67 passed`.
- The clean full backend suite passed: `782 passed, 1 skipped`.
- Seven affected tests passed under a short temporary root after an initial
  Windows path-length-only failure; no safeguard was weakened.
- Disposable Alembic upgrade/check passed with no drift.
- React lint/build passed; Playwright passed `26 passed, 1 skipped`.
- Controlled detection quality passed `23/23`; layered detection validation
  passed `288/288`; assistant QA passed `20/20`.
- Replay dry-run wrote zero rows; performance smoke passed without warnings.
- The release gate returned `ok: true` with every required check passing.
- 100k, 2 workers: 1,061.94 rows/s, 549.48 MiB peak RSS, 13/13 SLO.
- 100k, 4 workers: 884.46 rows/s, 566.84 MiB peak RSS, 13/13 SLO.
- 250k, 2 workers: 694.97 rows/s, 1,221.77 MiB peak RSS, 13/13 SLO.
- 250k, 4 workers: 699.45 rows/s, 1,256.19 MiB peak RSS, 13/13 SLO.
- Every profile had exact counters, zero parse failures, two completed
  detection runs, seven alerts/cases, no duplicate evidence, zero pool
  timeouts, zero lock waiters, valid backup/restore, complete cleanup, and
  zero safety side effects.
- Full repository verification is recorded in the taskboard and v5.18 status.

## T17 PRD / Docs Updated

README, PRD, traceability, lab runbook, current-state lock, taskboard, v5.18
status, this T1-T20 record, generated taskboard HTML, and
`docs/V5_18_COMMIT_ALLOWLIST.md`.

## T18 Risks / Blockers / Assumptions / Decisions

This is single-host disposable PostgreSQL evidence, not a multi-host or
production SLA. Four workers do not outperform two enough to justify a new
default. Shared storage, Linux service supervision, real devices, independent
labels, MFU/provider lifecycle, TLS, managed secrets, and production
monitoring remain separate gates.

## T19 Release / Rollback

No release, commit, or push is authorized. Rollback removes the v5.18
service/CLI/tests/docs and reverts the bounded alert/case query changes. No
configured database or migration rollback is required.

## T20 Final Handoff

Preserve two workers as the conservative profile. Re-run only against two new
empty disposable databases after strict preflight and exact confirmation.
Proceed next to one of the three remaining external gates; do not reinterpret
this result as production readiness.
