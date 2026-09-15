# T1-T20: v5.39 Independent Evidence And Frozen Activation Decision

## T1 Change Title

v5.39 Independent Evidence Completion and Frozen Activation Decision.

## T2 Requirement

Connect the protected human-review workspace to exactly one governed,
read-only activation evaluation without fabricating reviewer decisions,
exposing private evidence, or changing model, alert, label, or response state.

## T3 Source Evidence

The v5.26 prediction lock; v5.28 detection working copy; v5.33 Assistant
acceptance pack; v5.36 activation audit; v5.37 authenticated review service,
API, dashboard, and tests; current model/response safety services; current
private aggregate preflight state.

## T4 Current Behavior

The v5.37 workspace safely accepted immutable human decisions, but it did not
record completed-decision digests or provide an at-most-once bridge to v5.36.
The old v5.36 CLI also remained a separately executable evaluation path. At
phase start genuine review progress was `0/40` detection and `0/8` Assistant;
both workspaces are now complete and closed.

## T5 Impacted Areas / Agents

AI/ML governance, Assistant acceptance, backend API, React Evidence Review,
security/privacy, QA, Release/Ops, documentation, and human reviewer handoff.

## T6 Scope

Aggregate status, formal closure visibility, private evidence freeze,
at-most-once evaluation claim, fail-closed side-effect checks, legacy CLI
retirement, UI status, tests, governance, taskboard, and exact allowlist.

Training, tuning, human decision creation, model activation/promotion, rule
changes, external LLM calls, response automation, real blocking, and database
schema changes are out of scope.

## T7 Functional Requirements

- Require exactly 40 valid detection and eight valid Assistant decisions.
- Require both reviewer-owned workspaces to be formally closed.
- Freeze protected packs, completed decisions, and workspace state privately.
- Require an exact operator confirmation for the single evaluation attempt.
- Atomically claim the attempt across processes before evaluation and fail
  closed after interruption.
- Return a stored sanitized result instead of recalculating a completed run.
- Reject evidence tampering and any authoritative side effect.
- Expose only safe aggregate status through API and dashboard.

## T8 Acceptance Criteria

Preflight writes no state; incomplete reviews withhold metrics; only a closed,
contract-valid review can freeze; evaluator call count is at most one; changed
evidence is rejected; failed claims cannot retry automatically; model, label,
detection, alert, provider, and response mutation counts remain zero; no
protected field appears in public output.

## T9 API Contract

Adds authenticated read-only
`GET /api/evidence-review/evaluation-status`. Existing progress responses add
the boolean `closed` field. No mutation or evaluator API is exposed.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Freeze state and optional reports
are local ignored files under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add a v5.39 decision service and CLI, derive readiness from v5.37 contracts,
freeze private digests atomically, claim one attempt, call v5.36 internally
without provider/report writes, compare database authority counts, sanitize
results, and retire direct v5.36 CLI evaluation.

## T12 Frontend Plan / Changes

Add a compact frozen-evaluation status panel, distinguish rows complete from
formally closed, keep review controls unchanged, and expose no evaluation
execution button or protected evidence.

## T13 Security / Response / AI Safety

No AI-generated human decisions. No raw logs, IPs, paths, fingerprints,
digests, reviewer identities, hidden predictions, provider payloads, or
secrets in public output. Rules remain alert-authoritative. The Assistant is
read-only. Model activation/promotion, automatic response, and real firewall
blocking remain disabled.

## T14 Test Plan

Test preflight non-mutation, closure enforcement, one-shot execution, private
digest storage, tamper rejection, failed-claim lockout, legacy CLI retirement,
API authentication/redaction, frontend status/closure behavior, no evaluator
control, and complete repository regression.

## T15 Implementation Summary

Implemented the v5.39 private freeze/decision service, confirmed CLI, safe
status route/schema/query/UI, formal closure reporting, legacy v5.36 CLI
retirement, explicit two-workspace progress/auto-advance/closure ergonomics,
and focused backend/Playwright regressions. A genuine reviewer completed and
closed `40/40` detection and `8/8` Assistant items. The frozen evaluator ran
exactly once and later preflight reused the stored result.

## T16 Tests Run / Evidence

Focused v5.37/v5.39 backend tests pass `17/17` and targeted Evidence Review
Playwright passes `3/3`. Taskboard checks, Ruff, compileall, backend/release
`927 passed, 1 skipped`, Alembic no drift, React lint/build, Playwright
`35 passed, 1 skipped`, controlled source acceptance, layered `288/288`,
Assistant `20/20`, v5.38 `11/11`, replay dry-run, warning-free performance,
and release `ok: true` pass after the frozen result. The final
protected run records `40/40`, `8/8`, one completed execution, stored-result
reuse, no authoritative writes/provider call, and `shadow_observation`.

## T17 PRD / Docs Updated

v5.39 status, this T1-T20 record, AI training and lab runbooks, current AI/ML
status, requirement traceability, university compliance checklist, taskboard
Markdown/HTML, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The fixed protected exercise is complete, but its 40 rows are insufficient for
activation evidence. The frozen decision fails comparable-row, class, source,
time-window, training-overlap, queue-F1, threat-recall, false-positive, and
calibration gates. Those consumed rows cannot be used for further tuning.
Independent development evidence and a future untouched validation set are
required for repair and revalidation.

## T19 Release / Rollback

No commit or push is authorized. Release requires separate approval of the
exact allowlist. Rollback removes the v5.39 service/CLI/status UI/tests and
restores v5.36 CLI documentation. There is no database, label, or model
rollback because none is changed.

## T20 Final Handoff

Preserve the consumed evidence and stored decision. Do not rerun or tune
against it, activate the failed candidate, or enable response automation.
Repair supervised quality only with separate development evidence, acquire
independent source/time-window support, and reserve a new untouched set for a
future governed decision.
