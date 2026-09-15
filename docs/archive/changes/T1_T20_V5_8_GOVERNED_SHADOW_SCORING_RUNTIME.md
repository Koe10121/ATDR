# T1-T20: v5.8 Governed Shadow Scoring Runtime And Evidence Intake Hardening

## T1 Change Title

v5.8 Governed Shadow Scoring Runtime and Evidence Intake Hardening.

## T2 Requirement

Integrate the frozen v5.6/v5.7 candidate as a bounded, disabled-by-default,
read-only shadow evaluator with aggregate monitoring and fail-closed evidence
intake, without changing authoritative detection or response behavior.

## T3 Source Evidence

- Frozen candidate/evidence contracts:
  `atdr/app/detection/v56_private_panos_model_repair.py` and
  `atdr/app/detection/v57_independent_shadow_revalidation.py`.
- Governed lifecycle and registry:
  `atdr/app/detection/v51_supervised_lifecycle.py`,
  `atdr/app/detection/supervised_workflow.py`, and
  `atdr/app/routers/ml.py`.
- Normalized feature/rule contracts:
  `atdr/app/ml/features.py`, `atdr/app/detection/rules.py`.
- v5.3-v5.7 status, locks, tests, and ignored diagnostic evidence.

## T4 Current Behavior

v5.7 could freeze and validate the candidate contract and qualify future
independent evidence, but the candidate was not integrated into a bounded
runtime telemetry path. AI Governance exposed frozen-validation status rather
than current aggregate shadow observations.

## T5 Impacted Areas/Agents

Backend/API, supervised ML governance, feature/rule evaluation, frontend AI
Governance, privacy/security, QA, release governance, and documentation.

## T6 Scope

In scope: read-only scoring, aggregate telemetry, source/time bounds,
contract validation, idempotent cache, timeout/batch controls, evidence
preflight, authenticated API, AI Governance status, tests, and docs.

Out of scope: model activation/promotion, active artifact replacement,
labeling, accuracy claims on unlabeled rows, alert/case/run mutation, response
actions, real blocking, schema changes, and external evidence fabrication.

## T7 Functional Requirements

1. Shadow scoring is disabled by default.
2. Artifact, hash, code, feature, calibration, class, threshold, and safety
   contracts must all match or evaluation fails closed.
3. Only normalized logs may be scored.
4. Evaluation must preserve chronology and optional source/time boundaries.
5. Batch size and runtime are bounded.
6. Identical process-local scopes are idempotent.
7. Telemetry is aggregate only and labels are not accessed.
8. Rules remain alert-authoritative; IsolationForest is reported separately.
9. Evidence intake rejects reused, overlapping, invalid, or ungoverned input.
10. No authoritative database or model-artifact state may change.

## T8 Acceptance Criteria

- Candidate contract matches all fixed v5.7 fields.
- Missing or altered contract fails closed with no fallback.
- Repeat evaluation yields identical aggregate telemetry.
- Oversized batches fail closed.
- No raw rows, IPs, paths, hashes, feature names, row fingerprints, or secrets
  enter API/CLI/UI output.
- Before/after table and artifact states are identical.
- No blind metrics are calculated without sealed independent labels.
- UI shows all six required governance statuses.

## T9 API Contract

Adds authenticated analyst/admin:

```text
GET /api/ml/supervised/shadow-runtime
```

Optional query fields are `execute`, `source_id`, `start_at`, `end_at`, and
`limit`. The existing supervised lifecycle/model-registry response gains an
optional `governed_shadow_runtime` aggregate payload.

## T10 Data Model / Migration

No schema or migration change. Runtime idempotency is process-local and writes
no persistent evaluation record.

## T11 Backend Plan / Changes

Add the v5.8 service and CLI; validate the frozen candidate; select bounded
chronological normalized rows; build v5.6-compatible features; calculate
aggregate score/confidence/drift/stability/rule-agreement/advisory anomaly
telemetry; compare state before/after; and add governed evidence preflight.

## T12 Frontend Plan / Changes

Add a compact AI Governance status band and four aggregate metrics. Keep
technical reliability details collapsible and expose no row-level evidence.

## T13 Security / Response / AI Safety

No label, alert, case, run, response, user, or artifact mutation is permitted.
Rules remain authoritative. ML and IsolationForest are advisory. External
evidence stays outside Git and configured storage. Automation and blocking
remain disabled.

## T14 Test Plan

Test default disablement, full contract match, tamper failure, no fallback,
idempotency, bounds, aggregate redaction, chronology/source scope, rule
authority, advisory anomaly separation, evidence reuse rejection, no blind
metrics, no state mutation, endpoint authentication, and UI status/overflow.

## T15 Implementation Summary

The service loads only the exact frozen candidate and returns a conservative
status when disabled or mismatched. A scoped 100-row run produced aggregate
queue/drift/agreement telemetry and proved zero database/artifact mutation.
The evidence preflight extends v5.7 qualification without reading labels or
calculating accuracy.

## T16 Tests Run / Evidence

Focused v5.1-v5.8 tests passed `61`; new v5.8/API tests passed `6`.
Ruff, compileall, Alembic no-drift, React lint/build, taskboard checks, and
`git diff --check` passed. The authoritative backend suite passed
`700 passed, 1 skipped`; Playwright passed `26 passed, 1 skipped`, with only
the live-hardware test skipped. Controlled layered validation passed
`288/288` with zero false positives and zero false negatives. The controlled
scenario corpus passed `24/24`, produced 15 expected alerts, and created zero
response actions. Assistant QA passed `20/20` without mutation side effects.
Replay dry-run wrote zero.
Read-only performance smoke had no warnings: Overview `0.1546s`, cached
Overview `0.0102s`, and AI Governance `1.1267s`. The official release gate
returned `ok: true` with no failed required checks.

## T17 PRD / Docs Updated

v5.8 status, this change record, PRD, traceability, compliance checklist, AI
runbook, current AI/ML status, docs index, taskboard, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- Current 100-row shadow queue rate is 47% with 58% rule disagreement.
- Aggregate drift is `Drift Warning`.
- No independent labels exist, so these are monitoring signals, not quality
  metrics.
- Current evidence still represents insufficient independent devices/time.
- Decision: keep the runtime disabled by default and lifecycle in
  `shadow_observation`.

## T19 Release / Rollback

No migration, configured-data write, active-artifact write, commit, or push
is authorized. Rollback is a normal source/UI/docs revert; no database
rollback is required.

## T20 Final Handoff

ATDR can safely observe the frozen candidate on bounded normalized data and
can reject unsuitable future evidence before prediction. It still requires
new multi-device, multi-period, independently labeled evidence before any
decision-support advancement can be considered.
