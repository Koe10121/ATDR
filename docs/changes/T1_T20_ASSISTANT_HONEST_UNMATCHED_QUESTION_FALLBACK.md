# T1-T20: Assistant Honest Unmatched-Question Fallback

## T1 Change Title

- Title: The SOC Assistant's fallback for questions that match no keyword
  route now says so, instead of answering with an unrelated system-summary
  paragraph as if it had addressed the question
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; correctness/UX fix, not a new feature.

## T2 Requirement

Project owner asked for the Assistant to "give only necessary info," to be
able to field a wider range of questions, and for its answers to be small
and useful. Investigation found the Assistant is already tightly
budget-controlled (55-120 words per response mode, truncation, LLM-oversize
rejection), so the concrete, verifiable defect was the fallback path:
`answer_assistant_question` (`assistant_service.py`) routes on ~25 keyword
groups, and anything matching none of them fell through to
`_answer_general_question`, which returned a fixed system-summary paragraph
(log/alert counts, recent alerts) regardless of what was actually asked.

## T3 Source Evidence

Direct reading of `assistant_service.py` (routing chain,
`answer_assistant_question` and `_answer_general_question`),
`assistant_llm.py` (`SAFE_SYSTEM_PROMPT`, per-mode word budgets, oversize
rejection), and `assistant_response_contracts.py` (`RESPONSE_CONTRACTS`
word limits 55-120). Grepped `atdr/tests/test_assistant.py` (2099 lines) and
confirmed no test pinned the old generic-fallback wording, so changing it
carried no risk of contradicting an existing contract.

## T4 Current Behavior (before this change)

Asking the Assistant something outside its keyword vocabulary (e.g. "what
does the app_risk field mean?") produced an answer about alert/log counts
and recent alerts -- correct-looking prose that had nothing to do with the
question asked, with no signal to the analyst that their actual question
went unanswered.

## T5 Impacted Areas / Agents

`atdr/app/services/assistant_service.py` only (`answer_assistant_question`
call site and `_answer_general_question`). New test in
`atdr/tests/test_assistant.py`.

## T6 Scope

In scope: make the true fallback path honest about not having a dedicated
handler, while still surfacing the same safe system-state context it
already had. Explicitly out of scope, per project owner's own choice when
asked ("Both" -> broaden coverage now, defer the bigger item): a
clarifying-questions-back-to-the-analyst feature (the Assistant has no such
mechanism today and adding one is new multi-turn UX, not a tuning fix), and
blind keyword-list expansion (no concrete list of missed question types was
available to route confidently without risking hijacking already-correct
routes).

## T7 Functional Requirements

- The deterministic fallback answer must state plainly that no dedicated
  handler matched, and must include the analyst's own question text so the
  gap is visible rather than silently papered over.
- It must not stop surfacing the safe system-state context (log/alert
  counts, recent alerts) -- that's still useful, just no longer presented
  as if it were a direct answer.
- No change to any keyword-routed branch's behavior; only the unmatched
  path changes.

## T8 Acceptance Criteria

A new API-level test confirms: a question matching no keyword route returns
`unmatched_question` in `context_used`, includes the phrase indicating no
built-in answer exists, and echoes the analyst's literal question text back
in the answer. All 56 pre-existing Assistant tests continue to pass
unmodified.

## T9 API Contract

No endpoint or schema change. `POST /api/assistant/chat` response shape is
unchanged; only the fallback answer's content and its `context_used` label
(`unmatched_question` added) differ.

## T10 Data Model / Migration

None.

## T11 Backend Plan / Changes

`_answer_general_question` gained a required `question` parameter and now
composes its answer as an explicit non-match statement (quoting the
question) followed by the same safe system-state summary it always
computed. The single call site in `answer_assistant_question`'s `else`
branch was updated to pass `question=clean_question`. No other branch,
helper, or the LLM rewrite prompt was touched -- the LLM layer already
treats the deterministic answer as ground truth to rephrase, so an honest
deterministic fallback automatically produces an honest LLM-rewritten one
too.

## T12 Frontend Plan / Changes

None. The chat UI already renders whatever `answer` string the backend
returns; no shape change was needed.

## T13 Security / Response / AI Safety

No safety-relevant behavior changed. The fallback still never invents
facts, still only surfaces already-computed safe aggregate counts and
already-redacted recent-alert summaries, and still carries the same
citations. Echoing the analyst's own question text back to them is not a
new exposure surface (it's their own input, already accepted and processed
by every other branch of this same function).

## T14 Test Plan

New: `test_assistant_chat_admits_when_no_keyword_route_matches_instead_of_a_generic_summary`
in `atdr/tests/test_assistant.py`, asserting on `context_used`, the
honesty-marker phrase, and question echo. Existing:
`atdr/tests/test_assistant.py` full suite (57 passed, 1 new). Full backend
suite re-run afterward.

## T15 Implementation Summary

One function signature change, one call-site update, one new test. No new
files.

## T16 Tests Run / Evidence

`test_assistant.py`: `57 passed` (1 new). `ruff check` on both changed
files: `All checks passed!`. `compileall`: exit 0. Full backend suite:
`1191 passed, 1 skipped` (up from the `1190` prior confirmed baseline: +1
new assistant test).

## T17 PRD / Docs Updated

This change record only.

## T18 Risks / Blockers / Assumptions / Decisions

Assumed the project owner's actual complaint was specifically this
unrelated-answer behavior (a concrete, reproducible defect matching "give
only necessary info"), rather than the already-tight word-budget system,
which was investigated and found to already be reasonably mature. Broader
keyword-coverage expansion and the clarifying-questions feature remain
explicitly deferred, per the project owner's own stated preference, until
either concrete failing examples or a decision to build the larger
multi-turn UX feature are available.

## T19 Release / Rollback

Fully reversible: revert the two edits in `assistant_service.py` and the
one new test. No migration, no database write, no runtime config change.

## T20 Final Handoff

Shipped and verified. Follow-up items, not started: (1) keyword-coverage
broadening once concrete missed-question examples are supplied; (2) a
clarifying-questions-back-to-the-analyst feature, if the project owner
decides the added multi-turn UX complexity is worth it.
