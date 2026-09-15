# T1-T20: v5.42 Development Candidate Freeze Readiness

## T1 Change Title

v5.42 Development Candidate Freeze Readiness and Shadow Stability Lock.

## T2 Requirement

Produce at most one immutable supervised diagnostic candidate from
development-only evidence, or fail closed with exact reasons, without opening
protected or future blind evidence and without changing model authority.

## T3 Source Evidence

The consumed v5.39 custody state and review pack, v5.40 development evaluator
and ignored result, v5.41 development boundary and private workspace state,
existing nested temporal partition/calibration utilities, configured database
and artifact counters, AI Governance UI, tests, and governance documents.

## T4 Current Behavior

v5.40 ranked six development strategies but passed `0/3` folds and froze no
candidate. v5.41 implemented future evidence custody but could not open review
without a frozen diagnostic candidate. There was no dedicated fixed
five-candidate freeze protocol, immutable artifact seal, or aggregate freeze
readiness surface.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, backend/API, frontend/AI Governance,
security/privacy, QA, Release/Ops, and documentation.

## T6 Scope

Boundary revalidation, fixed five-strategy comparison, nested temporal fold
gates, aggregate drift/error diagnosis, at-most-one immutable diagnostic
freeze, typed read-only API/UI status, tests, measured run, governance, and
exact allowlist.

Labels, locked-final evaluation, v5.39 metric reuse, v5.41 blind prediction or
review, active artifact replacement, model activation/promotion, rule changes,
response changes, real blocking, schema migrations, and commit/push are out of
scope.

## T7 Functional Requirements

- Revalidate v5.39-v5.41 evidence boundaries before fitting.
- Use exactly five predeclared strategies and development-only roles.
- Isolate duplicate groups across every nested fold.
- Apply fixed quality, calibration, and queue-stability gates to every fold.
- Freeze at most one diagnostic candidate only if all gates pass.
- Reuse an identical immutable freeze and reject different/tampered state.
- Keep v5.41 byte-identical and predictions withheld.
- Keep rules authoritative and all model/response authority disabled.

## T8 Acceptance Criteria

All protected boundaries match; zero protected or blind rows enter modeling;
all five strategies are evaluated; failure reasons are aggregate and precise;
no candidate is forced; immutable freeze tests pass; no database, label, run,
alert, response, or active artifact changes; API/UI is authenticated, compact,
safe, and responsive; complete verification passes.

## T9 API Contract

Add authenticated read-only endpoint:

```text
GET /api/evidence-review/candidate-freeze/status
```

It returns aggregate readiness only and never exposes paths, hashes, private
rows, identities, fingerprints, blind predictions, or secrets.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Optional diagnostic artifact,
immutable manifest, and generated reports remain ignored under
`ml_baseline_reviews/v5_42_candidate_freeze/`.

## T11 Backend Plan / Changes

Add the v5.42 evaluator and CLI; reuse v5.39 boundary validation, v5.40
features/strategies, v5.41 custody projection, and v5.5 nested temporal folds;
add stricter fixed gates, drift/pattern diagnosis, immutable freeze integrity,
and a safe public projection.

## T12 Frontend Plan / Changes

Add one compact AI Governance panel for candidate status, best diagnostic,
passing folds, calibration, and remaining phases. Add no train, freeze,
activate, promote, review, or response controls.

## T13 Security / Response / AI Safety

Protected labels/predictions remain unread; future blind evidence remains
unused; generated artifacts stay ignored; public output is aggregate. No label,
model-run, detection-run, alert, response, or active-artifact write occurs.
Rules remain alert-authoritative; automatic response and real blocking remain
disabled.

## T14 Test Plan

Test fixed candidate list, every fixed gate, duplicate isolation, queue
stability, immutable reuse, conflicting-freeze rejection, tamper detection,
safe public projection, authenticated API, zero authoritative mutations,
conservative readiness, frontend rendering, and horizontal overflow.

## T15 Implementation Summary

Implemented the v5.42 evaluator/CLI, fixed five-strategy protocol, evidence
profiles and drift diagnosis, immutable diagnostic seal, aggregate status API,
React AI Governance panel, and focused backend/browser regressions.

## T16 Tests Run / Evidence

The custody preflight passed all eight boundary checks with 1,467 development
rows and zero protected/blind modeling rows. The measured five-strategy run
selected hierarchical two-stage only as the best diagnostic ranking, passed
`0/3` folds, and froze no candidate. Focused backend/API tests pass `17/17`;
the full backend/release suite passes `953 passed, 1 skipped`; Alembic reports
no drift; React lint/build pass; Playwright passes `35 passed, 1 skipped`;
controlled source validation, layered validation `288/288`, Assistant QA
`20/20`, v5.41 custody preflight, replay dry-run, warning-free performance,
and the release gate all pass. Full evidence is recorded in the v5.42 status
and taskboard.

## T17 PRD / Docs Updated

v5.42 status, this change record, AI training runbook, current AI/ML status,
PRD, requirement traceability, university compliance checklist, taskboard
Markdown/HTML, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Evidence remains one-source, short-window, duplicate-concentrated, partly
assisted, temporally unstable, and poorly calibrated. Suspicious/malicious
recall collapses in at least one fold. No gates were relaxed; no candidate was
frozen. Independent devices/windows and genuine blind review remain external.

## T19 Release / Rollback

No commit or push is authorized. Release requires separate approval of the
exact allowlist. Rollback removes the v5.42 module/CLI/API/UI/tests/docs; there
is no database, label, active-model, alert, or response rollback.

## T20 Final Handoff

Keep lifecycle at `shadow_observation`. Use v5.42 as the only development
candidate-freeze gate. Do not open v5.41 predictions/review or reconsider
authority until one strategy passes every fixed fold and the separate external
evidence requirements are genuinely completed.
