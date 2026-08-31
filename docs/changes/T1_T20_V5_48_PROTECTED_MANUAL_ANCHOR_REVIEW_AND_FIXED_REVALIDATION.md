# T1-T20: v5.48 Protected Manual-Anchor Review And Fixed Revalidation

## T1 Change Title

v5.48 Protected Manual-Anchor Review And Fixed Revalidation.

## T2 Requirement

Provide an authenticated human-review workflow for the sealed v5.47 pack and
predeclare one immutable development revalidation before decisions exist.

## T3 Source Evidence

ATDR auth/RBAC, audit, v5.37 review patterns, v5.42 fixed gates, v5.45 strategy
contracts, and the sealed v5.47 private development workspace.

## T4 Current Behavior

v5.47 prepared 120 prediction-blind rows but offered aggregate progress only.
Review was `0/120`, and no fixed post-review protocol or protected row-level UI
existed.

## T5 Impacted Areas / Agents

Evidence governance, Detection/ML, Backend/API, Frontend, Security/Privacy,
QA, Release/Ops, and documentation.

## T6 Scope

Protocol lock, authenticated owner-isolated review, revision control, formal
closure, fixed one-time revalidation, aggregate governance status, tests,
docs, and hygiene. Automated labeling/import, active artifacts, response, and
deployment are out of scope.

## T7 Functional Requirements

- Lock evidence roles, partitions, features, strategies, and gates first.
- Show only approved evidence and withhold predictions and private values.
- Require a genuine authenticated human decision with confirmation.
- Reject cross-user access, stale revisions, tamper, and post-closure edits.
- Block evaluation until complete review, class support, closure, and explicit
  confirmation.
- Permit at most one development-only evaluation and no authority change.

## T8 Acceptance Criteria

All protected routes require authentication; owner isolation and revision
conflicts work; protocol/pack/state tamper fails closed; UI supports responsive
save-and-next review; preflight reports zero evaluation and zero side effects;
and the complete verification matrix passes.

## T9 API Contract

Seven `/api/evidence-review/manual-anchors/*` status, start, list, item, save,
and close routes plus the
`python -m atdr.scripts.run_v548_manual_anchor_fixed_revalidation` CLI.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Protocol, state, working copy, and any result
remain private ignored files under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the immutable protocol/evaluator, owner-isolated review service, typed
schemas, authenticated routes, audit events, and safe CLI.

## T12 Frontend Plan / Changes

Add a Manual Anchors tab with progress, protocol status, filters, approved
evidence, decision controls, save-and-next behavior, closure, and safety badges;
add aggregate readiness to AI Governance.

## T13 Security / Response / AI Safety

No prediction, score, assisted label, raw log, IP, identity, path, fingerprint,
secret, or reviewer identity is disclosed. No automatic import, training,
activation, alert, detection run, or response action is possible.

## T14 Test Plan

Cover authentication, protocol-first locking, field allowlisting, filters,
owner isolation, optimistic revision, audit, zero authoritative writes,
automated-reviewer rejection, incomplete closure, protocol/state tamper,
post-closure immutability, responsive UI, and fail-closed revalidation.

## T15 Implementation Summary

Implemented the fixed protocol, protected review service/API, CLI, React
workspace, AI Governance projection, backend/Playwright coverage, and measured
private preflight.

## T16 Tests Run / Evidence

Focused backend tests passed `8/8`. Full backend and release testing passed
`1005 passed, 1 skipped`; taskboard, Ruff, compileall, Alembic, React
lint/build, and Playwright (`36 passed, 1 skipped`) passed. The private
preflight locked eight strategies and reported `0/120`, zero evaluations, and
no activation/import/response/private disclosure. Port-scan acceptance passed;
layered detection passed `288/288`; Assistant QA passed `20/20`; replay wrote
nothing; warning-free performance passed; and release returned `ok: true` in
`460.7s`.

## T17 PRD / Docs Updated

v5.48 status, this change record, PRD, traceability, compliance checklist, AI
runbook, current AI/ML status, taskboard, and exact cumulative allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

All 120 rows still require genuine human decisions. One source does not prove
generalization. The fixed evaluation is development evidence and cannot replace
future independent evidence. Automated systems cannot satisfy the review gate.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes v5.48 code/API/UI/tests/docs
and ignored v5.48 state; no configured data or active model requires rollback.

## T20 Final Handoff

Use the dashboard workspace for genuine review. Close only after all decisions
are valid, then run the single fixed development revalidation. Keep lifecycle
`shadow_observation`, rules authoritative, and response automation disabled.
