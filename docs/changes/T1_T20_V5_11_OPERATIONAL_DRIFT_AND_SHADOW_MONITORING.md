# T1-T20: v5.11 Operational Drift And Shadow Monitoring Hardening

## T1 Change Title

v5.11 Operational Drift Root-Cause and Shadow Monitoring Hardening.

## T2 Requirement

Explain v5.10 OOD, queue, disagreement, parser, insufficient-evidence, and
anomaly warnings using aggregate operational evidence; add a conservative
disabled-by-default monitoring cadence; expose a privacy-safe dashboard
drill-down; and rehearse aggregate retention without changing model,
detection, label, or response authority.

## T3 Source Evidence

- `atdr/app/services/v59_shadow_observation_service.py`
- `atdr/app/services/v510_detection_operations_service.py`
- `atdr/app/services/v511_shadow_monitoring_service.py`
- `atdr/app/services/job_service.py`
- `atdr/app/services/job_dispatcher.py`
- `atdr/app/routers/ml.py`
- `atdr/app/db/models.py`
- `atdr/scripts/run_v511_shadow_monitoring.py`
- `frontend/src/pages/MLGovernance.tsx`
- v5.9-v5.11 backend, API, and frontend tests
- eight aggregate v5.10 observations in the configured database

## T4 Current Behavior

Before v5.11, v5.10 reported material operational variation but did not
classify likely aggregate root causes, apply alert-state hysteresis, provide a
bounded due-check cadence, or rehearse retention against a disposable
database. The v5.9 public serializer also returned an internal source ID.

## T5 Impacted Areas/Agents

- Orchestrator/Product: scope, warning interpretation, and lifecycle decision.
- Backend/Database: aggregate diagnostics, cadence, jobs, API, and retention.
- AI/ML Governance: thresholds, hysteresis, and no-accuracy contract.
- Frontend: concise aggregate drill-down.
- Security/Response Safety: privacy and zero-authority proof.
- QA/Release/Ops: idempotency, cancellation, retention, and release evidence.
- Documentation: status, PRD, traceability, compliance, runbook, taskboard,
  and allowlist.

## T6 Scope

Included:

- aggregate root-cause classification;
- conservative state hysteresis;
- a disabled, bounded, durable monitoring job;
- authenticated read-only diagnostics;
- AI Governance aggregate drill-down;
- disposable retention rehearsal;
- public source-ID removal;
- tests and governance records.

Excluded:

- model retraining, threshold tuning, activation, or promotion;
- accuracy, false-positive, recall, F1, or calibration calculation;
- human-label creation or update;
- authoritative alert changes;
- automatic response or real blocking;
- automatic always-on scheduling;
- retention on the configured database; and
- commit or push.

## T7 Functional Requirements

1. Diagnose warning causes using aggregate evidence only.
2. Preserve raw and effective drift states.
3. Apply fixed monitoring thresholds without changing predictions.
4. Use hysteresis to avoid one-observation state flapping.
5. Keep monitoring disabled until explicitly configured.
6. Bound sources, windows, rows, retries, and cancellation.
7. Suppress duplicate cadence jobs through idempotency.
8. Expose opaque source/time scopes only.
9. Rehearse retention in disposable storage and preserve every non-observation
   entity.
10. Keep rules authoritative and all ML/anomaly output advisory.

## T8 Acceptance Criteria

- Eight existing observations are diagnosed without labels or accuracy.
- Application, parser, sparse-window, volume, score, disagreement, and
  anomaly causes are distinguishable.
- Threshold and hysteresis tests are deterministic.
- Disabled cadence creates no job.
- Enabled due checks are bounded and idempotent.
- Cancellation leaves no partial observation.
- API/UI return no source ID, raw log, IP, path, label, fingerprint, or secret.
- Retention rehearsal deletes only one expired aggregate observation.
- No alert, case, label, model, detection, user, or response state changes.
- Lifecycle remains `shadow_observation`.

## T9 API Contract

Authenticated analyst/admin read-only route:

```text
GET /api/ml/supervised/shadow-operations/diagnostics
```

The response includes aggregate metrics, root-cause codes, fixed thresholds,
hysteresis, disabled cadence status, and safety fields. It excludes source
identity, row evidence, labels, and accuracy.

## T10 Data Model / Migration

No schema migration is required. v5.11 reuses:

- `ml_shadow_observations` for aggregate history;
- `operation_jobs` for durable bounded work; and
- `audit_logs` for retention evidence.

No database reset or destructive change occurs.

## T11 Backend Plan / Changes

- Add aggregate drift classification and root-cause service.
- Add state hysteresis.
- Add cadence status and idempotent due-check enqueue.
- Add `shadow_monitoring_cycle` to the existing job dispatcher.
- Add a read-only diagnostics API and safe CLI.
- Remove public source IDs from the observation serializer.
- Add disposable retention rehearsal.

## T12 Frontend Plan / Changes

- Add diagnostics API types, client, and query hook.
- Add a collapsed, overflow-safe AI Governance table.
- Show safety, current state, cadence, and no-accuracy badges.
- Expose no execution control or private identity.

## T13 Security / Response / AI Safety

- Rules remain alert-authoritative.
- Supervised output remains shadow observation only.
- IsolationForest remains advisory.
- No label or accuracy information is read.
- No source identity, raw evidence, IP, path, fingerprint, or secret is
  exposed.
- No model activation/promotion, response automation, or real blocking is
  authorized.
- Cadence and observation remain disabled by default.

## T14 Test Plan

- Drift classification boundaries and hysteresis.
- Aggregate-only diagnostics and public source-ID removal.
- No accuracy/private data.
- Disabled/default and enabled/idempotent cadence.
- Admin-only job dispatch, retry, and cancellation.
- No model/alert/label/response mutation.
- Disposable retention isolation and audit.
- API authentication and analyst access.
- AI Governance rendering and horizontal-overflow regression.
- Full project release and hygiene matrix.

## T15 Implementation Summary

v5.11 diagnoses all eight v5.10 observations, classifies likely operational
causes, applies conservative hysteresis, adds a disabled external-due-check
cadence through the durable job layer, exposes aggregate diagnostics in AI
Governance, removes public source IDs, and proves retention isolation in
disposable storage.

## T16 Tests Run / Evidence

Complete evidence:

- eight observations and four opaque scopes;
- current effective state `OOD Warning`;
- root causes: application shift 6, parser limited 3, parser quality shift 3,
  score/queue shift 2, sparse windows 2, volume imbalance 2, disagreement
  shift 1, IsolationForest variation 0;
- v5.11 tests: `7 passed`;
- v5.9/v5.10 regression tests: `13 passed`;
- focused API tests: `8 passed`;
- full backend and release suites: `722 passed, 1 skipped`;
- Alembic at `d6e7f8a9b0c1` with no drift;
- frontend lint/build and Playwright: `26 passed, 1 skipped`;
- controlled detection: `24/24`;
- layered validation: `288/288` with zero controlled FP/FN;
- assistant QA: `20/20` with no mutation;
- replay dry-run: two rows parsed and zero writes;
- performance smoke: no warnings, Overview `0.1551s`, cached `0.0113s`,
  Governance cold/warm `0.2717s/0.2580s`;
- retention preview/delete/preservation/audit: passed;
- taskboard, Ruff, compileall, release gate, exact allowlist, hygiene, and
  `git diff --check`: passed.

The initial global-temp pytest attempt failed at fixture setup due Windows
permissions. An in-repository `.pytest_tmp` rerun then correctly exercised the
backup-root safeguard. The approved ignored `.tmp/` root resolved both
environment constraints; affected persistence tests passed `14/14` and the
authoritative suite passed without weakening safeguards.

## T17 PRD / Docs Updated

- `docs/V5_11_OPERATIONAL_DRIFT_AND_SHADOW_MONITORING.md`
- this T1-T20 record
- PRD
- requirement traceability
- university compliance checklist
- AI training runbook
- AI docs index
- taskboard Markdown/HTML
- exact v5.11 commit allowlist

## T18 Risks / Blockers / Assumptions / Decisions

- Current evidence is unlabeled and reused; no accuracy conclusion is valid.
- Application mix and parser limitations explain most warnings, but do not
  identify prediction correctness.
- Sparse sources cannot clear warnings.
- Cadence still needs an approved external scheduler/worker deployment.
- Independent multi-device, chronological, labeled evidence remains the
  lifecycle blocker.

## T19 Release / Rollback

No migration or destructive operation exists. The monitoring cycle is
disabled by default and can be rolled back by removing the service, job type,
API, and UI. Existing aggregate observations remain inert. The configured
database was not pruned. No commit or push is authorized by this record.

## T20 Final Handoff

v5.11 closes local operational-warning diagnosis, bounded cadence groundwork,
privacy-safe drill-down, and retention rehearsal. Keep lifecycle
`shadow_observation`; keep rules authoritative; acquire independent governed
evidence before proposing any ML authority.
