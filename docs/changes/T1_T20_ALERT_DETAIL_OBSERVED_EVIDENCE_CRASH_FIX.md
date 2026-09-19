# T1-T20: Alert Detail "Observed Evidence" Crash Fix

## T1 Change Title

- Title: Fix a full-page white-screen crash that fired on every single alert
  when opened in the Alerts tab
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; production-affecting bug fix.

## T2 Requirement

Project owner reported: "when I click something in the alert tab my screen
went white." Reproduced via the browser's actual console output (the user
pasted it after being asked): `Uncaught Error: Objects are not valid as a
React child (found: object with keys {field, value})`, thrown inside
`DetailDrawer` while rendering `AlertsTriage`, with an accompanying
duplicate-key warning (`key`, \`[object Object]\`) on the same array.

## T3 Source Evidence

Local login is deliberately disabled on this environment
(`"Local login is disabled. Sign in through the MFU application shell."`
from `/api/auth/login`), so the bug could not be scripted/reproduced via an
automated browser session against the live system; the project owner's
pasted console output was the actual evidence. Once the error was in hand,
traced it to `frontend/src/pages/AlertsTriage.tsx:439-440`, where
`observedEvidence.slice(0, 4).map((point) => <div key={point}>{point}</div>)`
renders `point` directly. Cross-referenced `detectionSummary.observed_evidence`
against its real backend producer, `atdr/app/detection/explanations.py:516-523`
(`build_alert_detection_summary`), which builds it as
`[{"field": key, "value": value}, ...]` from `normalized_fields_used` — never
a list of strings. Confirmed by calling `build_alert_detection_summary`
directly against three real alerts in the live local database: all three
returned the `{field, value}` shape. `frontend/src/types/api.ts` declared
`observed_evidence?: string[]`, which is why `tsc` never caught this: the
type was wrong, not just the code.

## T4 Current Behavior (before this change)

Opening any alert's detail panel called
`detectionSummary?.observed_evidence ?? detectionSummary?.top_evidence_points ?? []`,
which -- because every real alert's `normalized_fields_used` is non-empty --
always picked `observed_evidence` (never the correctly-typed
`top_evidence_points` fallback), then rendered each `{field, value}` object
as a raw React child. React throws on that, and with no error boundary in
the tree, the entire page unmounted to a blank white screen. This affected
every alert with any normalized fields recorded, i.e. effectively every
alert.

## T5 Impacted Areas / Agents

`frontend/src/pages/AlertsTriage.tsx`, `frontend/src/types/api.ts`,
`frontend/tests/smoke.spec.ts` (fixture + new assertions),
`atdr/tests/test_v531_detection_explainability_adversarial_reliability.py`
(new backend contract test). No backend detection/explanation logic changed
-- its output was correct; only the frontend's type declaration and render
code were wrong.

## T6 Scope

In scope: make the frontend consume `observed_evidence` in its real,
already-correct backend shape, and add regression coverage on both sides so
a future contract drift is caught by tests rather than by a live white
screen. Out of scope: changing `build_alert_detection_summary`'s output
shape (it was already right and nothing else consumes it incorrectly);
adding a React error boundary (would have prevented the white-screen
symptom but not the underlying broken display, and was not asked for).

## T7 Functional Requirements

- The alert detail panel must render each observed-evidence point as
  readable `field: value` text, using the field name as a stable React key
  (unique per alert since it comes from a dict's keys).
- Must not regress the existing fallback to `top_evidence_points` for any
  future case where `observed_evidence` is absent or empty.
- No change to what data is computed or sent by the backend.

## T8 Acceptance Criteria

Backend: a new test asserts `observed_evidence` items are exactly
`{field, value}` dicts with a non-empty string field and a non-empty value,
documenting the contract the frontend now relies on. Frontend: the existing
`smoke.spec.ts` fixture was extended with a real `observed_evidence` sample,
and the "deep-linked alert and log drawers render" test (which deep-links
straight to an alert's detail panel, the exact crash path) now asserts the
formatted `field: value` text is visible. `tsc --noEmit` and `eslint` both
pass with zero errors/warnings.

## T9 API Contract

No backend API or schema change. Frontend `DetectionSummary.observed_evidence`
type corrected from `string[]` to `Array<{ field: string; value: unknown }>`
to match what the backend has always sent.

## T10 Data Model / Migration

None.

## T11 Backend Plan / Changes

None -- `build_alert_detection_summary` was already correct. Added one
regression test (`test_v531_observed_evidence_is_a_stable_field_value_pair_contract`)
locking in the shape it has always produced.

## T12 Frontend Plan / Changes

`types/api.ts`: corrected the `observed_evidence` field type.
`AlertsTriage.tsx`: normalize `observed_evidence` into display strings at
the point of computation (`` `${point.field}: ${String(point.value)}` ``)
so the existing render/key code downstream needs no change and keeps
working for both the `observed_evidence` and `top_evidence_points` cases
uniformly as a `string[]`.

## T13 Security / Response / AI Safety

None of this touches detection, response, or Assistant authority. This is
a display-only fix; no evidence content, privacy redaction, or authority
boundary changed.

## T14 Test Plan

`atdr/tests/test_v531_detection_explainability_adversarial_reliability.py`:
`11 passed` (1 new). Frontend: `npx tsc --noEmit` clean; `npm run lint`
clean; `npx playwright test -g "deep-linked alert and log drawers render"`
passed in isolation, then the full suite: `46 passed, 1 skipped` (up from
`45 passed, 1 skipped`). Full backend suite re-run: `1192 passed, 1 skipped`
(from the `1191` prior confirmed baseline: +1 new test). `ruff check .` and
`compileall` clean across the repository.

## T15 Implementation Summary

Two small frontend edits (one type correction, one three-line
normalization) plus two regression tests (one backend, one Playwright). No
backend logic changed.

## T16 Tests Run / Evidence

See T14. Verified against real data first: queried the live local database
directly and called `build_alert_detection_summary` against three real
alert IDs, confirming all three produced the `{field, value}` shape (i.e.
this crash was not an edge case -- it fired on effectively every alert with
recorded normalized-field evidence).

## T17 PRD / Docs Updated

This change record only.

## T18 Risks / Blockers / Assumptions / Decisions

Chose to normalize at the point of consumption (turn both possible sources
into a `string[]` immediately) rather than changing the render/key logic
downstream, to keep the fix minimal and contained to the exact place the
contract was violated. Did not add a React error boundary around
`AlertsTriage`/`DetailDrawer`; that would reduce the blast radius of a
*future* similar bug (a caught error instead of a blank page) but wasn't
part of what was asked, and is a reasonable follow-up if the project owner
wants defense in depth here.

## T19 Release / Rollback

Fully reversible: revert the two source edits and the two test additions.
No migration, no database write, no runtime config change.

## T20 Final Handoff

Shipped and verified against real data and the full test suite (backend +
Playwright). The project owner should confirm in their own browser that
opening any alert's detail panel now works; the system is already running
locally for them to check.
