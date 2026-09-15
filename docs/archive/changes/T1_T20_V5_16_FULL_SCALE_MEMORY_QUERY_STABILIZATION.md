# T1-T20: v5.16 Full-Scale Memory And Query Stabilization

## T1 Change Title

v5.16 Full-Scale Memory And Query Stabilization.

## T2 Requirement

Reduce full-file local memory and cold dashboard/source query latency while
preserving exact ingestion, parsing, rule detection, alert evidence,
investigation, source, audit, API, model-lifecycle, and response-safety
semantics.

## T3 Source Evidence

- published v5.14 100,000-row and v5.15 773,551-row runtime evidence;
- detection, alert, case, source, dashboard, staging, and resumable-ingestion
  services;
- SQLAlchemy models and current indexes;
- focused profiling at 100,000 and 250,000 rows; and
- complete private evidence supplied through a CLI argument only.

## T4 Current Behavior

v5.15 passed the complete runtime soak but peaked at 12,029.34 MiB traced
Python memory. Cold Overview was 5.3571 seconds and source detail was
4.7248 seconds at 773,551 rows. Cached Overview remained fast.

## T5 Impacted Areas/Agents

- Runtime profiling and acceptance orchestration.
- Rule detection data loading and session lifecycle.
- Alert deduplication and evidence persistence.
- Case reconciliation and source-detail queries.
- Database, privacy, QA, governance, and release review.

## T6 Scope

Included: bounded scalar detection reads, batched evidence inserts, exact
scalar case counting, stage memory release, source-query consolidation,
process/query profiling, progressive acceptance, tests, and governance.

Excluded: rule/threshold/parser/dedup/case meaning changes, schema migrations,
API changes, configured-database writes, model activation/promotion,
automatic response, real blocking, commit, and push.

## T7 Functional Requirements

1. Keep full-process peak memory below 8 GiB or reduce measured memory by at
   least 40 percent.
2. Keep cold Overview and source detail below 3 seconds and cached Overview
   below 0.1 seconds at full scale.
3. Avoid more than 10 percent ingestion or detection throughput regression.
4. Preserve raw/normalized/parser/source/run/evidence/case reconciliation.
5. Preserve rule-authoritative alert and dedup semantics.
6. Return aggregate, privacy-safe memory/query diagnostics only.
7. Refuse configured-database processing and clean disposable evidence.
8. Create no label, model, response, activation, or promotion writes.

## T8 Acceptance Criteria

- 100,000, 250,000, and 773,551-row disposable runs pass;
- full process stays below the memory ceiling;
- query latency/count and throughput gates pass;
- 773,551 raw/normalized rows reconcile with zero parse failures;
- database integrity, source traceability, and case reconciliation pass;
- configured data and authority remain unchanged;
- privacy findings are zero; and
- full verification and hygiene pass.

## T9 API Contract

No API contract changed. Bounded detection is opt-in and used by the
disposable acceptance path; normal backend routes retain existing behavior.

## T10 Data Model / Migration

No schema or Alembic migration change. Existing indexed queries were measured
before deciding that no new index or aggregate table was justified.

## T11 Backend Plan / Changes

- Stream scalar detection records in bounded batches.
- Defer and globally batch evidence inserts.
- Avoid eager evidence graphs during bounded dedup lookup.
- Count exact case keys without constructing case/evidence objects.
- Release session and Python collections after committed stages.
- Consolidate safe source aggregates and skip unnecessary parser JSON scans.
- Add a fail-closed v5.16 service/CLI with process and query profiling.

## T12 Frontend Plan / Changes

No frontend behavior or API payload changed. Existing Overview, source,
alert, case, AI Governance, and safety wording remain intact.

## T13 Security / Response / AI Safety

Private evidence is accepted only as a CLI argument and is never returned.
All processing uses disposable storage. Rules remain authoritative, supervised
ML stays in `shadow_observation`, and no response or firewall authority is
added.

## T14 Test Plan

Test legacy-versus-bounded detection equivalence, exact evidence/case counts,
bounded identity state, aggregate process memory, query count/plan privacy,
SQLite/PostgreSQL query compilation, disposable refusal, profile-only mode,
private-input redaction, and zero unsafe writes.

## T15 Implementation Summary

ATDR now uses bounded scalar records and globally batched evidence persistence
for full-scale disposable detection. Case and source query paths avoid
unnecessary ORM graphs/scans. v5.16 profiles whole-process RSS, phase-scoped
tracing, query counts/plans, throughput, growth, integrity, privacy, and
safety.

## T16 Tests Run / Evidence

Measured evidence:

- 100,000 rows: 677.13 MiB peak RSS, 0.1772s cold Overview;
- 250,000 rows: 1,498.56 MiB peak RSS, 0.4328s cold Overview;
- 773,551 rows: 1,947.68 MiB peak RSS, 0.9467s cold Overview,
  0.0815s cached Overview, and 1.1927s source detail;
- full ingestion/detection rates: 753.85 / 2,937.96 rows/s;
- 773,551 raw/normalized, zero parse failures, 408,776 evidence links,
  zero response actions, integrity passed, cleanup complete; and
- focused v5.14-v5.16 tests: 22 passed;
- full backend and release suites: 759 passed, 1 skipped;
- Alembic: no drift;
- React lint/build and Playwright: 26 passed, 1 skipped;
- controlled/layered/Assistant: 24/24, 288/288, 20/20;
- replay and warning-free performance smoke: passed; and
- official release gate: passed.

## T17 PRD / Docs Updated

- v5.16 status and this T1-T20 record;
- current system state lock;
- PRD and requirement traceability;
- lab runbook and README;
- taskboard Markdown/HTML; and
- exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- Process RSS is the memory acceptance basis; detection-scoped tracing is
  diagnostic and not directly comparable to v5.15 full-run tracing.
- Fault-injected and no-fault runs differ by three created/dedup operations
  while preserving total operations and exact evidence.
- One wall-clock case bucket differs; byte-for-byte time grouping is not
  claimed.
- One device/unlabeled evidence cannot establish accuracy or multi-device
  reliability.
- PostgreSQL concurrency and approved-host capacity remain external.

## T19 Release / Rollback

Rollback removes the v5.16 service, CLI, tests, and bounded-path changes.
There is no schema/configured-data rollback. Normal API behavior remains
available throughout. This record does not authorize Git publication.

## T20 Final Handoff

Use `<PRIVATE_PANOS_LOG>` only through the disposable CLI. Preserve process-RSS
measurement truth, indexed-query decisions, rule authority,
`shadow_observation`, disabled response automation, and disabled real
blocking. Obtain separate exact-path approval before staging or publication.
