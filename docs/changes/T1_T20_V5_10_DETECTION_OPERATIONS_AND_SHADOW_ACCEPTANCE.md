# T1-T20: v5.10 Detection Operations Reliability And Longitudinal Shadow Acceptance

## T1 Change Title

v5.10 Detection Operations Reliability and Longitudinal Shadow Acceptance.

## T2 Requirement

Turn the v5.9 aggregate observation mechanism into a repeatable operational
acceptance workflow over existing configured-database source/time scopes,
surface safe longitudinal diagnostics, and repair the inherited cold
AI Governance performance warning without changing detection authority,
model lifecycle, labels, or response behavior.

## T3 Source Evidence

- `atdr/app/services/v58_shadow_scoring_service.py`
- `atdr/app/services/v59_shadow_observation_service.py`
- `atdr/app/services/v510_detection_operations_service.py`
- `atdr/app/services/ml_service.py`
- `atdr/app/routers/ml.py`
- `atdr/app/db/models.py`
- `atdr/scripts/run_v510_detection_operations_acceptance.py`
- `atdr/scripts/profile_ml_governance.py`
- `atdr/scripts/performance_smoke.py`
- `frontend/src/pages/MLGovernance.tsx`
- v5.8/v5.9 tests, status records, runbook, and evidence contract
- configured database aggregate evidence, accessed without returning source
  identity or row values

## T4 Current Behavior

Before v5.10, ATDR could persist an explicitly requested aggregate shadow
observation, but it did not automatically plan bounded historical
source/time scopes or evaluate longitudinal operational acceptance. The
AI Governance cold path could spend about ten seconds in broad
normalized-log profiling on the current large SQLite database.

## T5 Impacted Areas/Agents

- Orchestrator and Product: scope, evidence roles, and acceptance decision.
- Backend and Database: scope planning, aggregate diagnostics, API, migration,
  query plans, idempotency, and retention isolation.
- AI/ML Governance: frozen-candidate contract and shadow-only lifecycle.
- Frontend: compact AI Governance operational panel.
- Security/Response Safety: privacy, no authority, no response mutation.
- QA/Release/Ops: regression, performance, release, and hygiene evidence.
- Documentation: status, runbook, traceability, taskboard, and allowlist.

## T6 Scope

Included:

- bounded non-overlapping historical operational scopes;
- aggregate shadow execution and acceptance diagnostics;
- contract mismatch fail-closed behavior;
- idempotent reruns and cancellation safety;
- read-only analyst/admin plan and acceptance APIs;
- aggregate AI Governance visibility;
- cold/warm ML Governance profiling and query repair;
- additive covering-index migration;
- tests and governance records.

Excluded:

- model selection, retraining, activation, or promotion;
- accuracy calculation over unlabeled operational evidence;
- changes to deterministic detection authority;
- label creation or update;
- automatic response or real blocking;
- fabricated devices or independent evidence;
- automatic retention; and
- commit or push.

## T7 Functional Requirements

1. Discover only existing configured sources and normalized evidence.
2. Partition evidence into bounded, non-overlapping chronological scopes.
3. Hide source identity and all row-level/private evidence from outputs.
4. Mark scopes as reused development operational evidence, not independent.
5. Fail closed before persistence on candidate-contract mismatch.
6. Persist aggregate observations only when explicitly enabled.
7. Report queue, disagreement, drift, quality, anomaly, runtime, and gates.
8. Reuse idempotent observation keys on repeated execution.
9. Preserve authoritative alerts, labels, model state, and response state.
10. Make cold and warm Governance responses equivalent and performant.

## T8 Acceptance Criteria

- At least one bounded source/time plan is produced from current evidence.
- Overlapping scopes are rejected by tests.
- Every executed scope has aggregate-only zero-mutation proof.
- Repeating a run creates no duplicate observations.
- Frozen-contract mismatch and cancellation persist no partial observation.
- No source IDs, names, IPs, paths, logs, labels, fingerprints, or secrets are
  returned.
- No accuracy metric is calculated.
- Operational warnings remain visible.
- Cold/warm Governance responses are equal.
- Local cold Governance performance has no smoke warning.
- Lifecycle remains `shadow_observation`.

## T9 API Contract

Authenticated analyst/admin read-only routes:

```text
GET /api/ml/supervised/shadow-operations/plan
GET /api/ml/supervised/shadow-operations/acceptance
```

The response is aggregate-only and excludes execution controls. Existing
v5.9 observation execution remains an explicit admin job or local CLI
operation.

## T10 Data Model / Migration

Migration `d6e7f8a9b0c1` adds one non-destructive covering index:

```text
ix_normalized_ml_profile_cover
  (is_anomaly, action, app_risk, app)
```

The v5.9 observation schema is reused. Each new row includes an aggregate-only
`operational_contract` under the existing JSON summary. No destructive schema
change or database reset occurs.

## T11 Backend Plan / Changes

- Add v5.10 planner, executor, diagnostic, and acceptance service.
- Add a safe CLI with preflight, execution, and acceptance modes.
- Extend v5.9 persistence with the aggregate operational contract.
- Add read-only plan and acceptance API routes.
- Rewrite broad ML profile aggregates to use narrow scalar subqueries.
- Reuse shared Governance aggregate/distribution work.
- Avoid loading the frozen artifact for lightweight observation summary.
- Add cold/warm profiler and performance-smoke equivalence evidence.

## T12 Frontend Plan / Changes

- Add API types, client call, and query hook.
- Add compact operational metrics and warnings to AI Governance.
- Preserve existing safety badges and progressive disclosure.
- Add a no-horizontal-overflow regression.
- Expose no execution or authority control.

## T13 Security / Response / AI Safety

- Deterministic rules remain alert-authoritative.
- Supervised output remains read-only shadow observation.
- IsolationForest remains advisory.
- No model is activated or promoted.
- No response action, automatic response, or real blocking is allowed.
- No raw evidence, source identity, IP, path, label, fingerprint, or secret is
  exposed.
- Retention remains explicit, admin-only, audited, and aggregate-row scoped.

## T14 Test Plan

- Historical scope bounds, non-overlap, evidence role, and redaction.
- No accuracy/private data in acceptance output.
- Idempotent execution and no authoritative mutation.
- Cancellation and contract mismatch fail closed.
- API authentication/RBAC and privacy.
- Cold/warm response equivalence.
- Migration and Alembic no-drift.
- Frontend metrics, warnings, safety badges, and overflow.
- Full backend, frontend, scenario, assistant, performance, release, and
  hygiene matrix.

## T15 Implementation Summary

ATDR now plans and evaluates governed operational history through eight
aggregate source/time scopes. The first run created eight observations; a
second run reused all eight keys. All eight operational gates passed while
four material warnings remained visible. The large-SQLite Governance query
path was repaired with a covering index and query-plan changes.

## T16 Tests Run / Evidence

Recorded implementation evidence:

- four opaque source scopes and eight chronological scopes planned;
- eight successful observations, zero failed;
- second run: zero created and eight idempotently reused;
- six sufficient and two insufficient scopes;
- current drift: `OOD Warning`;
- queue mean/range: `0.672734` / `0.000000-1.000000`;
- disagreement mean/range: `0.278047` / `0.000000-0.684000`;
- IsolationForest anomaly mean/range: `0.005000` /
  `0.000000-0.020000`;
- eight of eight operational gates passed;
- zero authoritative mutations; and
- cold/warm profiler: `0.290613s` / `0.257297s`, equal responses;
- focused backend/API/performance tests: `15 passed`;
- authoritative backend and release suites: `714 passed, 1 skipped`;
- Alembic: `d6e7f8a9b0c1` at head with no drift;
- Playwright: `26 passed, 1 skipped`;
- controlled/layered detection: `24/24` and `288/288`;
- assistant QA: `20/20`; and
- official release gate: `ok: true`.

The final full verification matrix is recorded in the v5.10 status and task
board.

## T17 PRD / Docs Updated

- `docs/V5_10_DETECTION_OPERATIONS_AND_SHADOW_ACCEPTANCE.md`
- this T1-T20 record
- PRD
- requirement traceability
- university compliance checklist
- AI training runbook
- current AI/ML product status
- AI docs index
- taskboard Markdown/HTML
- exact v5.10 commit allowlist

## T18 Risks / Blockers / Assumptions / Decisions

- Operational evidence is reused development evidence without ground truth.
- Queue/disagreement variation and OOD warnings require continued monitoring.
- Two scopes contain insufficient evidence.
- Source IDs are available internally for bounded queries but are never
  returned by the operational contract.
- SQLite performance is locally repaired, but approved-host PostgreSQL
  capacity remains environment-backed evidence.
- Independent multi-device, chronological, labeled native evidence remains
  the model-readiness blocker.

## T19 Release / Rollback

The database change is additive and reversible by Alembic downgrade. The new
API/UI can be rolled back without affecting authoritative detection. New
aggregate observations can remain inert because both scoring and observation
are disabled by default. Retention is not automatic. No commit or push is
authorized by this change record.

## T20 Final Handoff

v5.10 closes the local operational-shadow acceptance and cold Governance
performance work. It does not close independent model validation. Preserve
the shadow-only lifecycle and acquire the approved independent evidence
package before any model-authority proposal.
