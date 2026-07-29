# T1-T20: v5.9 Longitudinal Shadow Observation And Independent Evidence Acquisition

## T1 Change Title

v5.9 Longitudinal Shadow Observation and Independent Evidence Acquisition.

## T2 Requirement

Operationalize the frozen v5.6/v5.7 candidate as a safe, append-only,
longitudinal shadow observer and document the exact external evidence still
required for honest independent validation.

## T3 Source Evidence

- Frozen candidate/runtime contracts:
  `atdr/app/detection/v57_independent_shadow_revalidation.py` and
  `atdr/app/services/v58_shadow_scoring_service.py`.
- Durable job and operation-worker contracts:
  `atdr/app/services/job_service.py`,
  `atdr/app/services/job_dispatcher.py`, and
  `atdr/app/services/operation_worker.py`.
- Database/API/UI source:
  `atdr/app/db/models.py`, `atdr/app/routers/ml.py`, and
  `frontend/src/pages/MLGovernance.tsx`.
- v5.3-v5.8 evidence locks, status records, tests, and acquisition protocol.
- Official UNB, UNSW, Stratosphere IPS, and Palo Alto dataset/log-contract
  pages listed in the v5.9 acquisition document.

## T4 Current Behavior

v5.8 could run one bounded read-only evaluation and return process-local
aggregate telemetry. It did not preserve a longitudinal observation history,
provide retention controls, run as a durable job, or show aggregate trends.

## T5 Impacted Areas/Agents

Database, Alembic migration, ML governance service/API, durable jobs,
operation worker, AI Governance frontend, privacy/security, QA, release
governance, and documentation.

## T6 Scope

In scope: append-only aggregate observations, idempotency, source/time/row
bounds, durable job execution, safe retry/cancellation, explicit retention,
aggregate API/UI trend, private disposable drift inspection, official-source
evidence research, tests, docs, and exact allowlist.

Out of scope: model activation/promotion, alert/case mutation, label creation,
accuracy claims on unlabeled data, raw evidence persistence/exposure,
automatic retention, external corpus download, response automation, and real
blocking.

## T7 Functional Requirements

1. Observation recording is disabled by default.
2. The exact v5.8 candidate/runtime contract must match.
3. Every request must be source/time/row bounded.
4. Repeated identical requests must return one persisted observation.
5. Only aggregate allowlisted telemetry may be persisted or returned.
6. Durable execution must be admin-only, retry-safe, and cancellable before
   aggregate persistence.
7. Retention must be previewed and explicitly applied by an admin.
8. Retention application must be audited.
9. Private-file inspection must use disposable storage and aggregate output.
10. Rules remain authoritative and no authoritative detection/response state
    may change.

## T8 Acceptance Criteria

- Default-disabled execution writes nothing.
- Source/time bounds and row limits are validated.
- Idempotent repeats do not create duplicate observations.
- API, CLI, jobs, and UI expose no private path, raw row, IP, fingerprint,
  feature list, label, secret, or API key.
- Analyst/admin can read observations; only admins can queue or prune.
- Cancellation occurs before persistence; retry cannot duplicate.
- Retention deletes only expired aggregate observation rows.
- Private inspection does not access the configured database.
- No label, model run, artifact, detection run, alert, case, or response
  action is created or changed.

## T9 API Contract

Adds:

```text
GET  /api/ml/supervised/shadow-observations
GET  /api/ml/supervised/shadow-observations/summary
GET  /api/ml/supervised/shadow-observations/retention/preview
POST /api/ml/supervised/shadow-observations/retention/apply
```

The first two are authenticated analyst/admin reads. Retention endpoints are
admin-only. Existing `POST /api/jobs/submit` accepts the admin-only
`shadow_observation` job type.

## T10 Data Model / Migration

Adds `ml_shadow_observations` through additive migration
`c5d6e7f8a9b0`. The table has a unique observation key, scoped aggregate
telemetry, timestamps, and query indexes. It stores no raw logs, IPs, labels,
private paths, or secrets. Downgrade drops only this table and its indexes.

## T11 Backend Plan / Changes

Add a service that composes v5.8 scoring, verifies before/after authoritative
state, derives a deterministic internal idempotency key, and persists only
safe aggregates. Add list/summary/retention functions, durable job dispatch,
cooperative cancellation, a CLI, and private disposable drift inspection.

## T12 Frontend Plan / Changes

Add a compact AI Governance trend panel with observation count, current drift,
mean queue/disagreement, a bounded line chart, and explicit safety badges.
Expose no row-level evidence or action control.

## T13 Security / Response / AI Safety

Rules remain alert-authoritative. Supervised and IsolationForest outputs are
advisory. No operation may alter alerts, cases, labels, model lifecycle,
users, detection runs, or response actions. Private evidence remains outside
Git and configured storage. Automation and blocking remain disabled.

## T14 Test Plan

Test disabled defaults, source/time scope, idempotency, redaction, no
authoritative mutation, retention isolation/audit, private aggregate-only
inspection, role enforcement, job validation/retry/cancellation, frontend
trend rendering, no model activation, and no response action.

## T15 Implementation Summary

ATDR now records safe aggregate shadow observations through direct service,
authenticated API, CLI, or durable admin job. Explicit retention affects only
the aggregate table. AI Governance shows bounded trends. A complete private
file pass parsed 773,551 rows in disposable storage and found stable
aggregate drift without exposing or mutating private evidence.

## T16 Tests Run / Evidence

Focused v5.9/API backend tests passed `8`; the authoritative backend suite
passed `708 passed, 1 skipped`; Ruff and compileall passed; the migration
passed disposable upgrade/downgrade/re-upgrade; and Alembic is at
`c5d6e7f8a9b0` with no drift. React lint/build passed and Playwright passed
`26 passed, 1 skipped`. Controlled scenarios passed `24/24`; layered
validation passed `288/288` with zero controlled FP/FN; assistant QA passed
`20/20` with no mutation; replay wrote zero; and the release gate returned
`ok: true`. The complete private pass processed 773,551 rows with zero parser
failures or configured-state changes. A cold AI Governance smoke warned at
`11.7734s`; the immediate warm repeat passed at `1.3571s` with no warnings.

## T17 PRD / Docs Updated

v5.9 status, this change record, independent-evidence acquisition brief, PRD,
traceability, compliance checklist, AI runbook, current AI/ML status, docs
index, taskboard, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- The private file is reused development evidence and has no independent
  labels.
- Aggregate stability does not prove detection accuracy.
- No fresh native PAN-OS multi-device labeled corpus was acquired.
- Generic public flow datasets do not satisfy the native source contract.
- Decision: retain `shadow_observation`; collect trends without allowing ML to
  affect authoritative alerts.

## T19 Release / Rollback

Apply the additive migration before using the new endpoints. Rollback removes
the source/API/UI changes and downgrades only `ml_shadow_observations`.
Existing logs, labels, alerts, models, jobs, and response records are
untouched. No commit or push is authorized without separate approval.

## T20 Final Handoff

ATDR has a safe longitudinal observation mechanism and a concrete independent
evidence request package. Model advancement remains blocked until genuinely
new, compatible, multi-device evidence receives independent labels under the
prediction-before-label protocol.
