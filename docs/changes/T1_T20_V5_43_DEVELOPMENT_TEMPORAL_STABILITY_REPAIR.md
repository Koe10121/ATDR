# T1-T20: v5.43 Development Temporal Stability And Calibration Repair

## T1 Change Title

v5.43 Development Temporal Stability and Calibration Repair.

## T2 Requirement

Attempt a fixed, development-only repair of the v5.42 temporal instability
without weakening gates, opening protected evidence, or changing model,
alert, or response authority.

## T3 Source Evidence

v5.39 consumed-evidence custody, v5.40 development contract, v5.41 blind
workspace, v5.42 fixed gates/result, 1,467-row configured development
population, existing causal feature pipeline, nested temporal folds, tests,
and aggregate AI Governance status.

## T4 Current Behavior

v5.42's hierarchical baseline passed `0/3` folds. Recall, calibration, and
queue load were unstable; no candidate was frozen.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, backend/API, frontend/AI Governance,
security/privacy, QA, Release/Ops, and documentation.

## T6 Scope

Five fixed repair variants, feature/drift ablation, nested temporal
development evaluation, optional immutable diagnostic freeze, aggregate
status, tests, measured result, governance, and allowlist. New labels,
protected/blind evaluation, activation, rule changes, response changes,
migrations, commit, and push are excluded.

## T7 Functional Requirements

- Revalidate v5.39-v5.42 custody before modeling.
- Evaluate exactly five predeclared variants and unchanged v5.42 gates.
- Use only isolated development fit/calibration/threshold/evaluation roles.
- Down-weight assisted provenance without changing its identity.
- Audit unstable, redundant, constant, and potentially label-derived features.
- Freeze at most one ignored inactive candidate only if every gate passes.
- Preserve deterministic-rule authority and disabled response automation.

## T8 Acceptance Criteria

Custody passes; exactly five variants run; no protected row is modeled; no
gate is relaxed; failure remains visible; no authoritative database or active
artifact state changes; API/UI is authenticated, aggregate, and action-free;
tests and repository verification pass.

## T9 API Contract

`GET /api/evidence-review/temporal-stability/status` returns only aggregate
status, best variant, passing folds, calibration, queue stability, blockers,
remaining phases, and fixed safety state.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Generated JSON, Markdown, manifests, and any
diagnostic artifact remain ignored under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the v5.43 evaluator and CLI, weighting contracts, feature ablation,
calibrated hierarchical comparison, immutable freeze guard, safe serializer,
schema, route, and focused tests.

## T12 Frontend Plan / Changes

Add one compact read-only Temporal Stability panel. Expose no train, freeze,
activate, promote, alert, or response control.

## T13 Security / Response / AI Safety

Protected labels/predictions remain sealed. No labels, model runs, detection
runs, alerts, or response actions are written. Rules remain authoritative;
ML stays in `shadow_observation`; automation and blocking stay disabled.

## T14 Test Plan

Test exact variant/gate contracts, weighting, feature contract, all-fold
stability, public redaction, immutable/no-write behavior, authenticated API,
frontend rendering/overflow, and the full repository matrix.

## T15 Implementation Summary

Implemented the fixed five-variant repair evaluator, aggregate diagnosis,
read-only status API/UI, tests, CLI, reports, and governance records.

## T16 Tests Run / Evidence

Custody preflight passes on 1,467 rows. The measured leader is
`temporal_provenance_balanced_weighting`, with `0/3` passing folds, minimum F1
`0.4053`, maximum FPR `0.4458`, maximum ECE `0.5019`, and queue spread
`0.2641`. Focused backend/API regression passes `20/20`. Full backend/release
passes `962 passed, 1 skipped`; Alembic has no drift; React lint/build and
Playwright `35 passed, 1 skipped` pass; layered detection passes `288/288`;
Assistant QA passes `20/20`; replay, warning-free performance, and release
gate pass. Complete closure evidence is recorded on the taskboard.

## T17 PRD / Docs Updated

v5.43 status, this record, PRD, traceability, compliance checklist, AI
runbook, current AI/ML status, taskboard Markdown/HTML, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Evidence is one-source, three-minute, duplicate-concentrated, partly assisted,
and materially shifted. Weighting and compact features do not make it stable.
The result is a valid fail-closed decision; it is not a reason to lower gates.

## T19 Release / Rollback

No commit/push is authorized. Rollback removes the v5.43 module, CLI,
API/UI status, tests, and docs. There is no database, label, active-model,
alert, or response rollback.

## T20 Final Handoff

Keep lifecycle at `shadow_observation`, rules authoritative, and response
automation disabled. Do not freeze or activate a candidate from v5.43. Future
progress requires broader development evidence or genuine independent future
evidence, followed by a separately governed decision.
