# T1-T20: v5.49a Supplemental Threat Anchor Recovery

## T1 Change Title

v5.49a Supplemental Threat Anchor Recovery.

## T2 Requirement

Recover genuine suspicious and malicious development evidence through a
separate prediction-blind protected review without modifying the completed
v5.48 review or consuming v5.49.

## T3 Source Evidence

The closed v5.48 sealed pack, working copy, state, fixed protocol, absent
execution claim/result, v5.43-v5.47 governed development evidence, private
PAN-OS source supplied only at runtime, and current database/model authority
counts.

## T4 Current Behavior

The original review is valid at `120/120`, invalid `0`, and closed. Aggregate
support is `92/9/0`, so the suspicious and malicious preconditions do not pass.
v5.49 remains unexecuted with no claim or result.

## T5 Impacted Areas / Agents

Detection/ML Governance, Evidence Review, Backend/API, Frontend/Dashboard,
Security/Privacy, QA, Release/Ops, and one genuine authenticated reviewer.

## T6 Scope

Disposable threat-enriched acquisition, separate owner-isolated review,
post-closure aggregate support, proposed v5.49b protocol, tests, governance,
verification, and hygiene. Model evaluation and activation are out of scope.

## T7 Functional Requirements

- Preserve and continuously validate original review custody.
- Select `40-60` unique development rows using deterministic evidence only.
- Exclude original anchors, prior manual families, duplicates, quarantine, and
  locked temporal/future/external roles.
- Withhold predictions, hidden labels, reviewer targets, raw logs, identifiers,
  paths, and fingerprints.
- Require authenticated owner-isolated independent human decisions.
- Make closed supplemental decisions immutable.
- Reveal combined aggregate support only after closure.
- Create only a proposed relocked protocol when support passes.

## T8 Acceptance Criteria

The private acquisition passes coverage and custody; the dashboard supports
safe review; all required tests and verification pass; zero authoritative
writes occur; v5.49 execution remains zero; no private evidence is tracked.

## T9 API Contract

Authenticated analyst/admin routes:

- `GET /api/evidence-review/supplemental-threat-anchors/acquisition-status`
- `GET /api/evidence-review/supplemental-threat-anchors/status`
- `POST /api/evidence-review/supplemental-threat-anchors/start`
- `GET /api/evidence-review/supplemental-threat-anchors/items`
- `GET /api/evidence-review/supplemental-threat-anchors/items/{row_index}`
- `POST /api/evidence-review/supplemental-threat-anchors/items/{row_index}`
- `POST /api/evidence-review/supplemental-threat-anchors/close`

Only approved normalized evidence and explicit false-valued safety fields are
returned. Non-owners cannot open row-level evidence.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Sealed packs, working decisions, state, and a
possible protocol proposal remain ignored private files.

## T11 Backend Plan / Changes

Add deterministic acquisition, custody validation, safe status/CLI, protected
review service, API routes, revision-safe writes, immutable closure, and
post-closure support/proposal logic.

## T12 Frontend Plan / Changes

Add **Supplemental Threat Anchors** under Evidence Review with custody metrics,
progress, safe filters, deterministic evidence, prediction-withheld status,
independent decision controls, and post-closure aggregate readiness.

## T13 Security / Response / AI Safety

No prediction drives selection or display. No raw log, IP, source identity,
private path, fingerprint, review token, secret, or public reviewer identity is
returned. Rules remain alert-authoritative. Model activation, automatic
response, and real blocking remain disabled.

## T14 Test Plan

Cover original custody, exclusion and duplicate isolation, locked roles,
prediction blindness, redaction, authentication, owner isolation, auditing,
validation, immutable closure, sufficient and insufficient support, no
protocol on failure, and zero authoritative writes.

## T15 Implementation Summary

The backend acquisition/service/routes/CLI, React workspace, API types/hooks,
focused backend tests, and Playwright workflow are implemented. The measured
60-row protected pack was genuinely reviewed and closed immutably.

## T16 Tests Run / Evidence

Focused backend tests pass `5/5`; frontend lint/build pass; the focused
supplemental Playwright workflow passes. The disposable source pass parsed
`773,551` rows, selected `60` unique rows (`57` threat-enriched and `3` hard
negatives), represented nine strata, and changed no governed authority state.
Full backend tests pass `1021` with one intentional live-environment skip;
Alembic reports no drift; full Playwright passes `37` with one intentional
live-source skip; controlled source acceptance passes; layered detection passes
`288/288`; Assistant QA passes `20/20`; replay remains dry-run; performance
meets every budget without warnings; and the release gate returns `ok: true`.

## T17 PRD / Docs Updated

The v5.49a status, current AI/ML status, AI runbook, PRD, traceability,
compliance checklist, taskboard, and exact cumulative allowlist are updated.

## T18 Risks / Blockers / Assumptions / Decisions

Threat enrichment is not ground truth. A genuine reviewer must decide every
row without forcing class quotas. One physical source cannot establish
generalization. v5.49b remains conditional on honest support and later requires
independent untouched evidence.

## T19 Release / Rollback

No commit or push is authorized. Runtime rollback removes the v5.49a routes,
service, acquisition/CLI, UI/API bindings, tests, and docs. Private evidence can
be removed independently without database rollback; the original review is not
modified.

## T20 Final Handoff

The workspace is closed at `60/60`, invalid `0`, with supplemental support
`3/30/27` and combined support `95/39/27`. Preserve it unchanged. The separate
v5.49b protocol and one-shot decision are documented independently.
