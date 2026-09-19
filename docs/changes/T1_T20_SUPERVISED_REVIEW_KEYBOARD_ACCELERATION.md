# T1-T20: Supervised Qualification Review Keyboard Acceleration

## T1 Change Title

- Title: Keyboard-accelerated independent-decision review form, shared
  across the 300-row and 700-row supervised qualification workspaces
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; frontend-only, no backend/data change.

## T2 Requirement

The project owner asked to work toward supervised ML qualification. The
qualification protocol's two hard gates are (1) 1,000 rows of genuine,
prediction-blind human review (0/1,000 complete) and (2) a second physical
log source (a candidate file the owner supplied was verified, via the
project's own second-source preflight tool, to be the *existing* single
source — not independent; see the corresponding no-second-source finding
recorded in this session's conversation, not a separate change record since
nothing was changed as a result). Of the two, only the review gate is
something this session's work can meaningfully accelerate, and only its
*mechanics* — the judgment itself must remain genuinely human and
independent.

## T3 Source Evidence

Direct reading of `frontend/src/components/SupervisedQualificationReviewPanel.tsx`
and `frontend/src/components/SupervisedEvidenceExpansionPanel.tsx` (the
actual UI a human uses for all 1,000 rows), `frontend/src/components/SafeSelect.tsx`,
and `atdr/app/services/v562_supervised_qualification_review_service.py`
(server-side review contract: single-owner assignment, optimistic-concurrency
revision checks, atomic writes with rollback on integrity failure,
prediction-blind evidence projection). The backend service was already
solid; the finding was entirely in the frontend's interaction cost.

## T4 Current Behavior (before this change)

Both review workspaces required a full mouse-only interaction per row: click
a custom dropdown to open it, click an option, click into two text inputs
and a textarea to type, click a checkbox, click a submit button. No keyboard
path existed for any of it. The two forms
(`ReviewForm` in the qualification panel, `BatchReviewForm` in the expansion
panel) were also near-byte-identical duplicates of each other — same fields,
same validation, same layout — differing only in which mutation hook they
called.

## T5 Impacted Areas / Agents

New `frontend/src/components/IndependentDecisionForm.tsx` (shared);
`SupervisedQualificationReviewPanel.tsx` and
`SupervisedEvidenceExpansionPanel.tsx` (both now thin wrappers around it);
`frontend/tests/smoke.spec.ts`.

## T6 Scope

In scope: keyboard shortcuts for the mechanical parts of review (selecting a
decision, toggling confirmation, submitting), auto-focus on item load, and
eliminating the duplicate form implementation. Explicitly out of scope, by
design: anything that would speed up or soften the *judgment* itself —
confidence and rationale still require actual typed input every time, and
the confirmation checkbox still requires its own distinct keystroke/click
rather than being folded into the submit shortcut, so a reviewer can never
rubber-stamp a row via a single keychord.

## T7 Functional Requirements

- Digit keys `1`-`5` select the corresponding decision option, but only when
  focus is not inside a text-entry field (so typing "5900" in a rationale
  never gets misread as a shortcut).
- `Ctrl+Enter`/`Cmd+Enter` submits from anywhere in the form, including from
  inside a text field, but only when the existing validation (including the
  confirmation checkbox) already passes — the shortcut cannot bypass any
  existing validation rule.
- `C` toggles the confirmation checkbox as its own explicit action, never
  bundled into the submit shortcut.
- The form auto-focuses itself when a new item loads, so shortcuts work
  immediately without an extra click.
- A visible one-line legend documents the shortcuts on the form itself.
- Both the 300-row and 700-row review workspaces get this identically, from
  one shared implementation.

## T8 Acceptance Criteria

A new Playwright test proves: the shortcut selects a decision without a
dropdown click; typing digits in the rationale textarea types normally
without retriggering the shortcut; `Ctrl+Enter` while unconfirmed does not
submit (the review-progress counter does not advance and the checkbox stays
unchecked); `C` toggles confirmation as a distinct action; `Ctrl+Enter` after
confirming does submit. All pre-existing Playwright coverage for both
workspaces (which exercises the exact same field labels, placeholder text,
and confirmation copy, now emitted by the shared component instead of two
duplicates) passes unchanged.

## T9 API Contract

None. Frontend-only; no request/response shape changed.

## T10 Data Model / Migration

None.

## T11 Backend Plan / Changes

None. This change does not touch `v562_supervised_qualification_review_service.py`,
`v563_supervised_expansion_review_service.py`, or any other backend code —
the existing review contract (single-owner assignment, revision-based
optimistic concurrency, atomic-write rollback, prediction-blind evidence
projection) was already correct and is unchanged.

## T12 Frontend Plan / Changes

Added `IndependentDecisionForm.tsx`, a generic component parameterized over
the item shape and a `onSubmit` callback so each panel supplies its own
mutation call (`{rowIndex, payload}` for the 300-row campaign vs.
`{batchId, rowIndex, payload}` for the 700-row expansion) while sharing
every UI/keyboard concern. Removed the ~90-line duplicate form from each of
the two panel files.

## T13 Security / Response / AI Safety

No change to detection, response, or Assistant authority. The review
contract's integrity guarantees (single assigned human reviewer, immutable
once closed, prediction-blind evidence, no automatic import/activation) are
entirely unchanged — this only changes how fast a human can drive the
mouse-equivalent inputs, never what evidence is shown or what counts as a
valid decision.

## T14 Test Plan

New Playwright test
`supervised qualification review form supports keyboard shortcuts without
shortcutting confirmation`. Full existing Playwright suite re-run in full
(both before and after adding the new test) to confirm the refactor changed
no observable behavior for any pre-existing test. Frontend lint and
`tsc --noEmit` build re-run clean, including verifying the generic
component's TypeScript types resolve correctly against both concrete item
types via structural typing.

## T15 Implementation Summary

One new ~220-line shared component, two panel files reduced by removing
their duplicated forms (net line count for the review-panel pair decreased
despite the added shortcut logic, since the duplication removed was larger
than the new hook logic added), one new end-to-end test.

## T16 Tests Run / Evidence

New keyboard-shortcut test: `1 passed` in isolation, confirming the decision
shortcut, the digit-typed-into-rationale non-interference, the
Ctrl+Enter-cannot-bypass-confirmation guarantee, the `C` toggle, and a
successful confirmed submission via `Ctrl+Enter`. Full Playwright suite:
`45 passed, 1 skipped` both immediately after the refactor (before the new
test existed) and again after adding it. Frontend lint: zero warnings.
Frontend build (`tsc --noEmit` + `vite build`): clean; `EvidenceReviewPage`
bundle size decreased slightly (72.25 kB -> 70.41 kB) despite the added
functionality, consistent with the net duplication removal.

## T17 PRD / Docs Updated

This change record only. No product-behavior or governance claim changed —
the qualification protocol, its fixed gates, and its `0/1,000` reviewed
count are exactly as documented; this only makes the mechanical act of
recording each of those 1,000 decisions faster.

## T18 Risks / Blockers / Assumptions / Decisions

Deliberately did not touch `ManualAnchorReviewForm` or
`SupplementalThreatAnchorReviewForm` in `EvidenceReviewPage.tsx`, which share
the same structural pattern — those workspaces' review protocols are already
closed (immutable), so accelerating them would have zero practical benefit
and would only add regression-testing surface for no gain. If a future
workspace needs the same pattern, `IndependentDecisionForm` is now the
correct place to add it rather than a fifth copy-paste.

The confirmation checkbox and the `Ctrl+Enter` submit shortcut were
deliberately kept as two distinct actions rather than one, even though this
means the fastest possible chord is two keystrokes instead of one, because
collapsing them would remove the one part of this workflow whose entire
purpose is to force a separate, deliberate affirmative action per row.

## T19 Release / Rollback

Fully reversible: revert the three changed frontend files and the test
addition. No migration, no data written.

## T20 Final Handoff

This does not itself move the `0/1,000` counter — only the project owner's
actual review work does that, and only a genuinely independent second
physical log source (not the file checked during this session, which was
confirmed to be the existing primary source) closes the other gate. Handed
off ready for the project owner to begin reviewing with the accelerated
workflow.
