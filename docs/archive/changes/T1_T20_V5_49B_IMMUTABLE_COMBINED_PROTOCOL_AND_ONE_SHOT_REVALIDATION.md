# T1-T20: v5.49b Immutable Combined Protocol And One-Shot Revalidation

## T1 Change Title

v5.49b Immutable Combined Protocol And One-Shot Diagnostic Revalidation.

## T2 Requirement

Bind the completed original and supplemental human reviews to one new fixed
protocol, consume it no more than once, and make an honest aggregate diagnostic
candidate decision without changing runtime authority.

## T3 Source Evidence

The immutable v5.48 `120`-row review, immutable v5.49a `60`-row review, private
custody files and proposal, unchanged v5.48 feature/strategy/threshold/gate
contracts, current configured-database aggregate counts, and v5.47-v5.49 tests.

## T4 Current Behavior

Combined support is `95/39/27` and passes the precondition. The v5.49b protocol
is locked and valid. Its atomic claim and result exist, execution count is `1`,
and all eight strategies have stored aggregate results. No candidate passed.

## T5 Impacted Areas / Agents

Detection/ML Governance, Evidence Review aggregate API, AI Governance UI,
Security/Privacy, QA, Release/Ops, and governance documentation.

## T6 Scope

Immutable protocol custody, atomic one-shot execution, eight-strategy fixed
comparison, aggregate decision/status projection, read-only UI, tests,
verification, hygiene, and documentation. Activation and model repair are out
of scope.

## T7 Functional Requirements

- Require both reviews to be complete, valid, closed, and immutable.
- Require combined support `>=20/15/10` before protocol lock.
- Preserve the original v5.48 protocol unchanged.
- Bind every evidence and proposal input privately before execution.
- Create the claim atomically before evaluation-label access.
- Refuse retries after any claim, interruption, completion, or tamper.
- Evaluate exactly the eight unchanged strategies and fixed gates.
- Select at most one candidate, and only if every fixed gate passes.
- Expose aggregate status only and make no authoritative writes.

## T8 Acceptance Criteria

Custody and support pass; the protocol is immutable; execution count is exactly
one; eight results exist; a conservative decision is recorded; no protected
data leaks; no label/model/alert/detection/response state changes; complete
verification and hygiene pass.

## T9 API Contract

Authenticated analyst/admin status endpoint:

- `GET /api/evidence-review/combined-manual-anchors/revalidation-status`

It returns aggregate custody, protocol, metrics, decision, and explicit safety
flags. It has no execution or mutation method.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. The protocol, claim, result, and companion
diagnostics are ignored private files outside the configured database.

## T11 Backend Plan / Changes

Add the v5.49b custody/evaluation module, safe CLI, aggregate schema and route,
atomic claim, stored-result reuse, post-execution aggregate diagnostics, and
tests for tamper, ordering, at-most-once execution, metrics, privacy, and zero
authority mutation.

## T12 Frontend Plan / Changes

Add a compact **Combined Fixed Revalidation** panel to AI Governance showing
review/support counts, one-shot state, strategy result, candidate decision,
selection-bias notice, and safety authority without private details.

## T13 Security / Response / AI Safety

No raw logs, IPs, source identities, private paths, row fingerprints, reviewer
identities, predictions, digests, or secrets are public. Rules remain
alert-authoritative. Lifecycle stays `shadow_observation`; activation,
promotion, automatic response, and real blocking remain disabled.

## T14 Test Plan

Cover protocol lock, custody tamper, claim-before-label access, at-most-once
execution, interruption lockout, all-eight evaluation, exact metric/gate
projection, authenticated redacted API access, and zero authoritative writes.

## T15 Implementation Summary

The immutable protocol/evaluator, CLI, aggregate API/schema, AI Governance
panel, focused backend/Playwright coverage, status record, taskboard, and
governance updates are implemented. The real fixed evaluation was run once.

## T16 Tests Run / Evidence

Focused v5.49b tests pass `6/6`; v5.47-v5.49b regressions pass `36/36`; full
backend passes `1027` with one intentional skip; Alembic has no drift; frontend
lint/build pass; Playwright passes `37` with one intentional skip; controlled
source, layered `288/288`, Assistant `20/20`, replay, warning-free performance,
and release `ok: true` pass. The first full test command used a disallowed
repository-local temp root; the backup guard correctly rejected it, then the
failed subset passed `29/29` and the authoritative full rerun passed under
`.tmp`. The one-shot run evaluated `8/8` strategies and left configured counts
unchanged.

## T17 PRD / Docs Updated

The v5.49b status, v5.49a closure record, AI/ML status, training runbook, PRD,
traceability, compliance checklist, taskboard/HTML, and cumulative exact
allowlist are updated.

## T18 Risks / Blockers / Assumptions / Decisions

The fixed evaluation slice contains `0` suspicious and only `2` malicious rows.
Threat enrichment also prevents field-prevalence claims. Every candidate fails
at least suspicious support/recall and confidence-gap gates. Consumed evidence
cannot be retuned or repartitioned. A second source and untouched future window
remain external requirements.

## T19 Release / Rollback

No commit or push is authorized. Runtime rollback can remove the aggregate
route/UI and v5.49b source, but the private claim/result remain an immutable
audit fact and must not be deleted to manufacture another attempt.

## T20 Final Handoff

Preserve the stored negative decision. Do not rerun v5.49b. Start a separately
versioned development-evidence acquisition phase only; require fresh untouched
and second-source evidence before any activation review.
