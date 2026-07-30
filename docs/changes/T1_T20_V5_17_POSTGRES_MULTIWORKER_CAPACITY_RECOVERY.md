# T1-T20: v5.17 PostgreSQL Multi-Worker Capacity And Recovery Acceptance

## T1 Change Title

v5.17 PostgreSQL Multi-Worker Capacity and Recovery Acceptance.

## T2 Requirement

Prove or fail closed on concurrent PostgreSQL ingestion, detection,
deduplication, recovery, query capacity, and backup/restore while preserving
the SQLite workflow and all safety boundaries.

## T3 Source Evidence

- `atdr/app/db/database.py`, `atdr/app/db/engine.py`,
  `atdr/app/db/models.py`
- `atdr/app/services/job_service.py`,
  `operation_worker.py`, `resumable_ingestion_service.py`,
  `staging_service.py`, `source_service.py`
- `atdr/app/services/detection_service.py`, `alert_service.py`,
  `case_service.py`
- `atdr/app/services/persistence_service.py`,
  `database_coordination_service.py`
- `atdr/scripts/validate_postgres_multiworker.py`
- `atdr/tests/test_v394_postgres_multiworker.py`
- `.github/workflows/ci.yml`
- v5.14-v5.16 runtime acceptance source and records

## T4 Current Behavior

SQLite has one worker and passed full-file acceptance. Existing PostgreSQL CI
covered basic skip-locked claims, source counters, shared staging, and
backup/restore. It did not measure 100k capacity, cancellation/resume,
same-scope detection dedup contention, query plans, memory, or complete
cleanup in one gate.

## T5 Impacted Areas/Agents

Database/persistence, operation workers, ingestion, detection/alerts,
QA/release, documentation, and CI. No frontend behavior is changed.

## T6 Scope

Add a disposable PostgreSQL acceptance runner, close two proven concurrency
gaps, add focused tests and bounded CI execution, and document environment
evidence honestly.

## T7 Functional Requirements

- Refuse SQLite, configured DB identity, unsafe DB names, missing tools, and
  unavailable targets.
- Validate at least two worker claims, exact counters, fencing, recovery,
  cancel/resume, idempotency, detection/dedup consistency, query capacity,
  backup, restore, and cleanup.
- Return aggregates only.
- Preserve SQLite and safety semantics.

## T8 Acceptance Criteria

All v5.17 checks pass on disposable PostgreSQL, or the runner returns
`blocked_by_environment` without writes. Full repository verification and
privacy/hygiene checks pass.

## T9 API Contract

No route or response contract is removed. Detection responses gain only an
aggregate coordination-wait diagnostic. Internal worker functions accept an
optional test/acceptance chunk callback; normal callers are unchanged.

## T10 Data Model / Migration

No schema or Alembic migration is required. Existing lease, staging, source,
run, alert, evidence, and audit tables are reused.

## T11 Backend Plan / Changes

- Add PostgreSQL transaction-scoped detection coordination.
- Contain concurrent idempotency-key insert races.
- Add v5.17 service and CLI.
- Compose existing migration, worker, ingestion, detection, dashboard, and
  persistence services.

## T12 Frontend Plan / Changes

No frontend feature or UI change.

## T13 Security / Response / AI Safety

No raw/private evidence or credentials are returned. Rules remain
authoritative, ML remains shadow/advisory, and no response, blocking,
activation, promotion, label, or account action is permitted.

## T14 Test Plan

Unit tests cover fail-closed preflight, target refusal, privacy, evidence-mode
selection, lock behavior, idempotency, and safety. Existing worker and
detection grouping regressions run. Ephemeral PostgreSQL CI executes the
bounded integrated gate.

## T15 Implementation Summary

Repository implementation is complete. Local PostgreSQL execution is
environment-blocked because the required server/client tools are absent.

## T16 Tests Run / Evidence

- Ruff and compileall for changed backend files: passed.
- Focused v5.17/v3.94/detection tests: `23 passed`.
- Local v5.17 preflight: correctly `blocked_by_environment`, zero privacy
  findings, configured DB unchanged.
- PostgreSQL offline Alembic SQL generation and CI YAML parsing: passed.
- Full backend through release gate: `771 passed, 1 skipped`.
- React lint/build and Playwright: passed; Playwright `26 passed, 1 skipped`.
- Controlled/layered/Assistant: `24/24`, `288/288`, `20/20`.
- Replay dry-run, warning-free performance smoke, release gate, taskboard,
  exact 34-path allowlist, diff, privacy, staging, and tracked hygiene: passed.
- Actual PostgreSQL execution: honestly `blocked_by_environment`; no
  throughput, recovery, query-plan, or backup/restore result is claimed.

## T17 PRD / Docs Updated

PRD, traceability, runbook, README, state lock, taskboard, v5.17 status, this
record, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Actual PostgreSQL capacity remains unproven until CI or an approved host runs
the gate. Multi-host storage, real devices, independent labels, TLS, secrets,
IAM/provider lifecycle, and production operations remain separate.

## T19 Release / Rollback

No release is authorized. Rollback is removal of the v5.17 runner/tests/docs,
CI step, advisory detection lock, and idempotency conflict handling. No data
migration or configured-database rollback is needed.

## T20 Final Handoff

Run the preflight first. Configure only two empty disposable PostgreSQL
targets. Do not point either variable at `DATABASE_URL`. Publish only after
exact allowlist review and separate owner approval.
