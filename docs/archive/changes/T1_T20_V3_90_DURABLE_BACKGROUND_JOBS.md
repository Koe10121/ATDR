# T1-T20 Change Document: v3.90 Durable Background Jobs And Operation Reliability

| ID | Record |
| --- | --- |
| T1 Change Title | Durable Background Jobs And Operation Reliability |
| T2 Requirement | Provide explicit durable execution for selected long operations without changing normal startup behavior or allowing unsafe automation. |
| T3 Source Evidence | `atdr/app/services/job_service.py`, existing operation routes, `atdr/app/db/models.py`, `docs/ATDR_PRODUCTIZATION_ROADMAP.md`, and `atdr/tests/test_operation_jobs.py`. |
| T4 Current Behavior | v3.7 recorded synchronous operation history but did not provide a worker, lease, retry policy, or ownership-scoped queue API. |
| T5 Impacted Areas/Agents | Database, backend/API, operations, React Overview, QA, release documentation. |
| T6 Scope | Durable job fields, heartbeat, safe worker/dispatcher, queue APIs, selected enqueue integration, Operations Health visibility, tests, and runbook. |
| T7 Functional Requirements | Queue only allowlisted operations; stage imports privately; preserve direct workflows; scope analyst access; audit lifecycle; expose no payload/secrets/raw logs; fail evidence-mutating work closed. |
| T8 Acceptance Criteria | Worker processes queued import/detection; API supports ownership and admin restrictions; retry/cancel is safe; heartbeat is visible; no response/model activation occurs; tests pass. |
| T9 API Contract | `GET /api/jobs`, `/summary`, `/{id}`; `POST /submit`, `/import`, `/{id}/cancel`, `/{id}/retry`; direct detection/ML routes accept explicit `enqueue=true`. |
| T10 Data Model / Migration | Adds private queue payload/idempotency/attempt/lease fields to `operation_jobs`, plus `operation_worker_heartbeats`, in revision `e1f2a3b4c5d6`. |
| T11 Backend Plan / Changes | Introduce queue lifecycle service, allowlisted dispatcher, manual worker CLI, safe staging, audits, and RBAC checks. |
| T12 Frontend Plan / Changes | Extend Operations Health with queue counts, worker status, attempts, and safe retry/cancel controls. |
| T13 Security / Response / AI Safety | No action-response job types; no external provider calls; supervised training is candidate-only; response automation remains disabled. |
| T14 Test Plan | Target operation-job regression, queue worker import/detection, RBAC, idempotency, lease recovery, payload hiding, frontend lint/build/e2e, release gate. |
| T15 Implementation Summary | Implemented as described in `docs/V3_90_DURABLE_BACKGROUND_JOBS.md`. |
| T16 Tests Run / Evidence | See release verification output for this change. Focused durable-job tests validate the queue lifecycle and side-effect constraints. |
| T17 PRD / Docs Updated | PRD, traceability, compliance checklist, lab runbook, README, docs index, and tasklist are updated with the v3.90 worker contract. |
| T18 Risks / Blockers / Assumptions / Decisions | SQLite should use one worker; PostgreSQL/shared-lab worker evidence remains future work. Auto-retry is limited to exports; import retries require a deliberate upload. |
| T19 Release / Rollback | Stop the separate worker to stop dispatch. Set `OPERATION_WORKER_ENABLED=false`; direct APIs continue working. Migration downgrade is available only for controlled rollback after queue use is assessed. |
| T20 Final Handoff | Queue support is opt-in, auditable, and safe by default. It is a controlled lab/shared-lab foundation, not a production orchestration claim. |
