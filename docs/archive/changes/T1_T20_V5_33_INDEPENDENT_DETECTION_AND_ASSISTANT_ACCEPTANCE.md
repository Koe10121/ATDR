# T1-T20: v5.33 Independent Detection And Assistant Acceptance

## T1 Change Title

v5.33 Independent Detection Evidence and Assistant Human Acceptance.

## T2 Requirement

Prepare the strongest honest independent validation possible for deterministic
detection, the supervised shadow model, and the Gemini SOC Assistant without
fabricating human labels, source independence, model quality, or human
approval.

## T3 Source Evidence

The source truth is the v5.19-v5.30 evidence locks, sealed native blind pack,
frozen prediction lock, review contracts, supervised closure, bounded Gemini
snapshot/evaluator, Assistant response contracts, current database aggregates,
tests, PRD, traceability, runbooks, and taskboard. Private rows, paths, IPs,
fingerprints, and secrets are not returned or copied into tracked files.

## T4 Current Behavior

ATDR already held a valid 40-row prediction-blind native review pack, fixed
promotion gates, a bounded redacted Gemini evaluator, deterministic fallback,
and zero-authority Assistant contracts. Human review remained incomplete. The
optional blind-review status command crashed when its working copy had not yet
been prepared, and no separate integrity-protected Assistant human worksheet
existed.

## T5 Impacted Areas / Agents

Detection evidence governance, blind review tooling, Assistant evaluation,
Gemini operations, QA, documentation, and release review. Detection rules,
model fitting, alert authority, response authority, IAM, schema, and startup
commands are unchanged.

## T6 Scope

In scope: safe review status, frozen-gate projection, evidence inventory,
blinded review validation, bounded Assistant worksheet generation, human-score
validation, provider/fallback measurement, privacy checks, zero-write checks,
tests, governance, and exact allowlist.

Out of scope: automatic labels, AI-as-human review, retraining, tuning on the
blind set, model activation/promotion, automatic response, real blocking,
fabricated devices, and institutional provider approval.

## T7 Functional Requirements

- Reuse existing sealed evidence and prediction locks.
- Report review totals, valid/incomplete/invalid rows, class/source/window
  coverage, duplicates, leakage, and evaluation permission.
- Withhold final metrics until every blind-review requirement passes.
- Create a sanitized Assistant worksheet with blank human fields.
- Separate automated checks from human acceptance.
- Record Gemini versus fallback, bounded usage, privacy, citations, context,
  concision, and zero authoritative mutations.
- Preserve all detection, ML, Assistant, and response authority boundaries.

## T8 Acceptance Criteria

Missing review files fail closed without exceptions; blind metrics remain
withheld at zero human decisions; protected worksheet content cannot be
silently changed; AI reviewers are rejected; raw logs, IPs, private paths, and
secrets remain absent; source database counts remain unchanged; focused and
complete verification pass.

## T9 API Contract

No HTTP API change. v5.33 adds the CLI
`python -m atdr.scripts.run_v533_independent_detection_assistant_acceptance`.
Its public output is aggregate and omits answers, reviewer identities, private
paths, fingerprints, IPs, raw logs, and secrets.

## T10 Data Model / Migration

No schema or migration change. Human worksheets and diagnostics remain ignored
local evidence. The configured database is read-only for v5.33.

## T11 Backend Plan / Changes

Repair missing-working-copy status, compose v5.27/v5.28/v5.30 evidence
contracts, generate a bounded Assistant worksheet in disposable storage,
protect non-human fields with a private manifest, validate genuine reviewer
provenance and fixed scores, and report provider operations safely.

## T12 Frontend Plan / Changes

No frontend behavior change. Existing Assistant read-only badges, provider
truth, evidence citations, and response-safety UI remain the product surface.

## T13 Security / Response / AI Safety

Rules remain alert-authoritative. IsolationForest and supervised ML remain
advisory. Gemini receives no raw logs and cannot execute actions. No label,
model, alert, detection, user, deletion, or response mutation is permitted.
Automatic response and real blocking remain disabled.

## T14 Test Plan

Test missing-review status, blank human fields, protected-content integrity,
AI-reviewer rejection, complete human-score validation, Assistant privacy,
context coverage, deterministic/provider fallback, and configured-database
zero writes. Run the complete repository verification and hygiene matrix.

## T15 Implementation Summary

Added the v5.33 coordinator/CLI, Assistant human worksheet and manifest,
human-score validator, fixed-gate detection summary, provider-operations
summary, and focused tests. Fixed v5.28 status behavior when the working copy
does not exist.

## T16 Tests Run / Evidence

Focused v5.33 and reused regression tests pass `22/22`. Full backend and
official release suites pass `879 passed, 1 skipped`; Alembic has no drift;
React lint/build, npm audit, and Playwright `31 passed, 1 skipped` pass;
controlled scenarios pass `24/24`; layered detection passes `288/288`;
Assistant QA passes `20/20`; replay and the warning-free performance rerun
pass; the release gate returns `ok: true`. The bounded real-provider probe
accepted Gemini on seven of eight questions, safely fell back once, exposed
no raw/IP/secret data, and changed no configured authoritative count. Human
acceptance remains incomplete and detection metrics remain withheld.

## T17 PRD / Docs Updated

Added v5.33 status, this T1-T20 record, and the exact allowlist. Updated the
PRD, traceability, AI/ML status, lab and AI runbooks, compliance checklist, and
taskboard.

## T18 Risks / Blockers / Assumptions / Decisions

The blind pack has zero legitimate human decisions and only one verified
source context. Human Assistant scores and institutional Gemini approval are
also absent. These external gaps cannot be closed by automation. One Gemini
investigation brief exceeded the acceptance concision rule, while the ML-
governance case safely fell back and passed its automated contract; these
remain visible quality evidence.

## T19 Release / Rollback

No commit or push is authorized. Rollback is source/document-only over the
exact allowlist; no migration or data rollback is required. Ignored human
worksheets and reports are never staged.

## T20 Final Handoff

Use the safe status command first. A genuine human reviewer may complete the
prediction-blind detection copy and Assistant worksheet without seeing model
predictions or changing protected answer content. Run the frozen evaluation
once only after validation permits it. Keep lifecycle `shadow_observation`
until every predeclared gate and independent-evidence requirement passes.
