# ATDR Deep System Analysis — Round 2

Date: 2026-09-23. HEAD at time of writing: `d216d22`.

**Status: Tier 0 complete** (commits `75a8b2e`, `d309563`, `ea51bcd`) — all
3 items fixed, tested, and committed. Tier 1 in progress.

## Why a second full audit, and why it matters

The first deep analysis (`docs/SYSTEM_DEEP_ANALYSIS_2026-09-22.md`) closed
out its entire punch list, plus an Assistant upgrade and two Stage-2
security fixes, all verified green across 1219 backend + 48 frontend
tests. This round exists because "tests pass" and "actually correct" are
not the same claim, and this project's own history says so: 4 separate
times, a duplicated-logic bug was found and "fixed," only for the same bug
class to resurface somewhere else. So instead of trusting the prior
round's fixes, 5 independent audits were run against current source with
one instruction in common: **verify, don't trust — including everything
claimed fixed by this project's own prior sessions.**

That instruction paid off immediately. Two of the fixes from the previous
21 hours of work are **not actually complete**, and one brand-new feature
shipped **with a real, user-visible regression that directly contradicts
what it was built to do.** All three were caught by having a fresh agent
re-derive the answer from scratch rather than re-reading the old
conclusion. Details below, then a complete prioritized plan.

## Method

5 parallel audits, each with full read access and no obligation to agree
with prior findings: frontend UI/UX, backend architecture + data model,
security/auth, an Assistant-feature deep-dive, and a test-suite quality
meta-audit (hunting specifically for tests that pass without proving what
they claim — the exact failure mode that let two real bugs hide earlier
this session). The single most consequential finding was independently
re-verified a third time, directly, by running the actual code myself
against a real in-memory database with the LLM explicitly disabled —
not trusting the audit's report either.

---

## Tier 0 — Confirmed critical, fix before anything else

### 1. The Assistant's fallback answer is garbled and self-duplicating for every unmatched question, by default — FIXED (`75a8b2e`)

**Directly verified — this is not a report, it's a reproduction.** Asking
anything outside the ~24 keyword intents, with the LLM disabled (the
default `ASSISTANT_LLM_ENABLED=false`), returns as the literal on-screen
answer:

```
I don't have a specific built-in answer for "What does the app_risk field
mean?". Ask about a specific alert, log, source, or case (by ID), or about
ML governance, operations, or the... - I don't have a specific built-in
answer for "What does the app_risk field mean?". - Ask about a specific
alert, log, source, or case (by ID), or about ML governance, operations,
or the ATDR workflow. - Current state: 0 normalized logs, 1...
```

This is the exact opposite of "give only necessary info" — the thing this
session's own Assistant upgrade was built to achieve. It ships to every
default deployment, not an edge case.

**Root cause, traced across 4 functions:**
1. `_answer_general_question` (`atdr/app/services/assistant_service.py:3353-3359`)
   builds its answer as one unbroken paragraph — every other handler in
   this file uses `\n`-separated sections.
2. This session's own change mapped `unmatched_question` → `"list_summary"`
   mode (`atdr/app/services/assistant_response_contracts.py:68-73`), specifically
   to give the LLM more room.
3. `_ensure_answer_sections` (`assistant_service.py:1740-1752`) auto-derives
   a "summary" by splitting **only on `\n`** — since there are none, the
   entire paragraph becomes one giant "summary line."
4. `list_summary`'s presentation branch (`assistant_response_contracts.py:441-457`)
   truncates that summary to 32 words **and separately** re-splits the
   *same original paragraph* by sentence (`_fallback_lines`,
   `:209-216`), then bullet-lists those sentences too, then the whole
   assembled result gets truncated a **second** time at 75 words. Two
   independent truncation passes over one paragraph never designed for
   either produces exactly the duplicated, cut-off text above.

**Fix**: give `_answer_general_question`'s answer real `\n`-separated
structure like every other handler (cheapest, most consistent fix), or
have it set `details["answer_sections"]` explicitly instead of relying on
auto-derivation. Do **not** just remap the mode back to `direct_fact` as a
shortcut — that avoids the bullet-relisting but was already ruled out
because it removes the extra word budget the LLM synthesis path needs;
fix the actual paragraph-vs-sections mismatch instead.

**Why no test caught it**: the only test on this text
(`test_assistant_chat_admits_when_no_keyword_route_matches_instead_of_a_generic_summary`)
asserts two substrings are present — both survive the duplication intact,
so the test passes on garbled output. Neither of the two new tests added
alongside this feature check the answer's structure at all.

**Effort: 2-3h** including a new test that asserts the answer has no
duplicated sentences.

### 2. The AI-reviewer-identity consolidation from earlier this session is incomplete — 3 more independent copies exist, one is a hub — FIXED (`d309563`)

The commit that unified `_AI_REVIEWER_PATTERN` (`024ce19`) said it fixed 3
files. Two independent audits (security + backend) each found **3 more**,
overlapping on one (`v547`) and each adding others the other missed:

| File | Pattern name | What it misses vs. canonical | Live? |
|---|---|---|---|
| `atdr/app/detection/v527_blind_review_evaluation.py:25-37` | `AUTOMATED_REVIEWER_MARKERS` | bot, llm, "language model" | Yes |
| `atdr/app/detection/v547_manual_anchor_acquisition.py:112-115` | own `AI_REVIEWER_PATTERN` | bot, heuristic, "language model", openai, synthetic | Yes — **hub, 8 more files import it directly** |
| `atdr/app/services/v533_independent_acceptance_service.py:114-123` | `AI_REVIEWER_MARKERS` | bot, heuristic, model, openai, synthetic | Yes |

The `v547` hub is consumed directly by `v549a_supplemental_threat_anchor_acquisition.py`,
`v562_supervised_qualification_campaign.py`, `v563_fresh_evidence_expansion.py`,
`v548_manual_anchor_review_service.py`, `v549a_supplemental_threat_anchor_review_service.py`,
`v562_supervised_qualification_review_service.py`,
`v563_supervised_expansion_review_service.py`, plus 2 historical files —
**11 live code paths total** in the evidence-review/supervised-ML pipeline
where a reviewer string containing only "bot", "heuristic", "openai",
"synthetic", or "language model" silently passes as a genuine human
reviewer, depending on which of the 3 copies gates that path.

The damning detail: `024ce19` **already touched** `v533_independent_acceptance_service.py`
(to fix its `IP_PATTERN` import) and left this file's own
`AI_REVIEWER_MARKERS` — ~90 lines below the line it edited — completely
untouched. The fix's own test suite (`test_redaction.py`) only unit-tests
the canonical module in isolation; it never asserts anything about *other*
files importing it instead of redefining it.

**Fix**: replace all 3 local definitions with imports from
`core.redaction.AI_REVIEWER_PATTERN`. Then — this is the part that
actually prevents a 6th recurrence — **add an automated guard**, not just
another manual fix: a test that greps/AST-scans the whole `atdr/app` tree
and fails if any file outside `core/redaction.py` defines a
reviewer-marker regex/constant. This bug class has now recurred 5 times;
the fix has to be structural, not another one-off.

**Effort: 3-4h** (the fixes themselves are small; most of the time is the
guard test and verifying all 11 dependent files still behave correctly).

### 3. Password reset and password change don't revoke existing sessions — FIXED (`ea51bcd`)

This session's own session-revocation feature correctly covers `logout`
and `disable_user`, but **not** `reset_user_password`
(`atdr/app/services/user_service.py:236-252`, admin-only) or
`change_own_password` (`user_service.py:275-289`). Default token lifetime
is 8 hours. If an admin resets a compromised account's password
specifically to lock out an attacker, or a user changes their password
after suspecting compromise, any token the attacker already holds stays
valid regardless — the exact scenario this feature exists to prevent, and
arguably more security-critical than the `disable_user` case that *was*
covered.

**Fix**: set `sessions_revoked_at` in both functions, mirroring
`disable_user`. **Effort: 1h**, plus 2 new tests mirroring the existing
`test_logout_revokes_*` pattern.

**Tier 0 subtotal: 6-9 hours.**

---

## Tier 1 — High-value, real gaps

### 4. No cookie-`Secure` validation for `local_recovery` mode

`validate_runtime_settings` checks that `mfu_iam_handoff_cookie_secure` is
true in production — but only inside the `template_shell` auth-mode
branch (`atdr/app/core/config.py:676,693`). There is no equivalent check
for `local_recovery` mode, which is a real, documented recovery path
(referenced in `docs/OPERATIONS_RUNBOOK.md`, `docs/QUICKSTART_FOR_TEAM.md`),
not just a test fixture. `ATDR_AUTH_MODE=local_recovery` +
`ENVIRONMENT=production` + the default `MFU_IAM_HANDOFF_COOKIE_SECURE=false`
passes validation with zero complaints, yet `/api/auth/login` now sets a
load-bearing session cookie without `Secure` — sendable over plain HTTP,
during what's likely already a stressful ad-hoc recovery event.
**Effort: 1h.**

### 5. AssistantPage can silently answer the wrong question after navigating between prompt-only links

`restoredSessionMatchesRoute` (`frontend/src/pages/AssistantPage.tsx:487-494`)
compares 4 context ID fields but never compares `promptParam`, even though
it's part of the same `routeDirectiveKey`. Several real in-app links carry
only a `prompt` with no IDs (`ExecutiveOverview.tsx:603`,
`MLGovernance.tsx:465`). Once a context-free session is cached, visiting a
*different* prompt-only link matches as "same route," so the old cached
Q&A silently persists — nothing on screen looks broken, since there's no
context badge either way, so a user would only notice if the textarea
text doesn't match the button they clicked. **Effort: ~1h** (add the
prompt to the comparison), plus a regression test.

### 6. Session revocation has zero test coverage for the MFU-shell handoff (cookie) login path

All revocation tests authenticate via `/api/auth/login`. The handoff flow
(`/api/auth/mfu-iam/handoff/consume`) mints and cookie-sets tokens through
a completely different code path, and nothing exercises "handoff login →
logout → same cookie should now 401." The implementation is verified sound
(both paths converge on the same `get_current_user` check), but this is
exactly the shape of the two bugs already found this session: a code path
that shares implementation with a tested one but was never independently
exercised. **Effort: 1-2h.**

### 7. The frontend logout test doesn't verify logout actually happens

`useAuth.tsx`'s `logout()` calls `api.logout()` fire-and-forget
(`.catch(() => undefined)`) and clears local state unconditionally. The
one test on this (`"SOC assistant session storage is resilient and clears
on logout"`) never mocks or asserts a request to `/api/auth/logout` was
made — it would still pass if that network call were deleted from the
code entirely, which means a regression that silently breaks real
server-side session revocation (Tier 0 item 3's whole point) would ship
undetected. **Effort: 30min-1h** — add a route assertion.

### 8. A second, unconfirmed instance of the same "citation heuristic over authoritative null" bug class, in the outbound direction

The fixed bug was in the *inbound* response-sync effect. `askQuestion`'s
outbound request-building (`AssistantPage.tsx:678-681`) has the identical
shape: `lastContext.alertId ?? citationNumber(...)` cannot distinguish
"authoritatively none" from "not yet known" once `lastContext.alertId` is
`null` — which is exactly what the *fixed* code now correctly stores. A
concrete trigger exists (`_answer_log_triage_question`'s "Linked alert"
citation) but this wasn't reproduced live, only traced by reading code.
**Recommend investigating and fixing if confirmed — effort 2-3h**
including writing the reproduction first.

**Tier 1 subtotal: 6-9 hours.**

---

## Tier 2 — Real, medium-value fixes

### 9. The Assistant's fallback context always claims job/ML data even when there is none

`if job_summary:` and `if ml or supervised:` (`assistant_service.py:3409,3433`)
can never evaluate false — `build_job_summary`/`evaluation_report`/`supervised_model_report`
always return fully-populated dicts even on an empty system (zero jobs
ever run, no model trained). The parallel `sources`/`cases` guards are
correctly gated on actual row presence; these two aren't. A brand-new
system gets citations for "Job summary API" and "ML report API" on every
unmatched question regardless of whether either has ever had any data —
another direct hit against "only necessary info." **Effort: ~1h** — gate
on an actual "has real data" check instead of dict truthiness.

### 10. The Assistant's job-summary context is uncurated and can push the LLM prompt past its size limit

Unlike the hand-picked `sources`/`cases` fields, `job_summary` is embedded
whole (`assistant_service.py:3410`). Measured directly: with a modest
seeded scenario (5 sources, 5 alerts, 2 jobs), `job_summary` alone was
**64% of a 7.1KB context block**, and the full prompt reached **82% of
the 12,000-char limit** — driven by `job_to_dict`'s unbounded
`error_summary`/`result_summary_json` fields (unlike `details_json`, which
is capped). On a system with meaningfully more data, this risks exceeding
the limit — and since evidence comes *before* the safety/quality
instructions in the prompt template, overflow truncates the safety
instructions, not the evidence. **Effort: 1-2h** — curate to the same
handful of fields the other sections use.

### 11. Stale mutation errors leak across unrelated targets

`UserFieldDrawer` (`UserAdmin.tsx:607-624`) and the LogExplorer ML-label
editor (`LogExplorer.tsx:441-443`) both do `error={mutationA.error ??
mutationB.error}` — React Query only clears `.error` on the next `mutate()`
call on that *same* mutation object. Fail an email edit, cancel, open
"reset password" for the same or a different user — the old email-edit
error is still shown next to the unrelated password form. **Effort: ~1h**
— call `.reset()` on target/selection change.

### 12. ResponseCenter bypasses the shared error formatter and the shared dropdown component

`ResponseCenter.tsx:132` renders `String(blockIp.error.message)` directly
instead of `<ErrorBanner>`, so a structured 422 validation error shows a
useless generic message here while every other form in the app shows the
real detail. Same file also uses a raw native `<select>`
(`ResponseCenter.tsx:102-114`) where every other dropdown in the app uses
`SafeSelect`. **Effort: 30min-1h**, both trivial swaps.

**Tier 2 subtotal: 4-6 hours.**

---

## Tier 3 — Confirmed, low-value cleanup

- `formatName`/`formatFieldName` is now **triplicated** (`SupervisedEvidenceExpansionPanel.tsx`,
  `SupervisedQualificationReviewPanel.tsx`, `EvidenceReviewPage.tsx`) —
  consolidate into one shared export. **~30min.**
- `POST /api/auth/login`'s response body still returns the raw
  `access_token` even though the frontend never uses it anymore (the
  cookie is the real credential) — a narrow residual XSS-exfiltration
  window. Consider dropping it from the body. **~30min.**
- Dead `token`/`authMode:"bearer"` code remains in `session.ts`/`api.ts`,
  unreachable via any real login now — recommend deleting outright now
  that it's confirmed unused by any real flow (only reachable via the
  `seedSession` test bypass, which constructs the object directly and
  doesn't call the removed function). **~30min**, verify the ~40
  `seedSession`-based tests still pass.
- `v560_clean_machine_acceptance_service.py:42` has the same IPv4-only
  regex bug — but this file is confirmed **historical** (dead code, no
  live importer), so this is optional. **~15min if done at all.**
- Missing confirmation on `TableToolbar`'s "Delete last" (saved view) and
  `UserAdmin`'s "Mark unverified" toggle — inconsistent with every other
  destructive/security-relevant action in the app. **~30min.**
- Viewport-fit test only covers 8 of 12 routes (missing `audit`,
  `controls`, `tuning`, `demo`) — the WCAG sweep already covers all 12;
  this one just wasn't updated to match. **~15min.**
- Minor N+1: the Assistant fallback's `source_to_dict(..., include_quality=True)`
  computes and discards quality/run-history data it doesn't use — pass
  `include_quality=False`. **~15min.**
- `_parse_timestamp` is independently (but currently consistently)
  redefined in `v541`/`v547`/`v551` — latent duplication risk, not a live
  bug today. Consolidate opportunistically. **~30min-1h, not urgent.**

**Tier 3 subtotal: ~2-4 hours.**

---

## Confirmed clean — no action needed

Both agents cross-checked and confirmed sound, not just "not found time to
look": `MODULE_INDEX.md` (re-derived from scratch, zero drift, 130
live/47 historical unchanged), the session-revocation implementation
itself (no bypass path — single issuance, single decode site, fail-closed
on missing `iat`), the RBAC guard sweep (60+ endpoints sampled against the
matrix, no gaps), audit-logging conventions, secrets handling (no leakage
through any path touched this session), the migration chain (an actual
`alembic check` run, not just visual inspection — schema matches
`models.py` exactly), the `config.py` comment-only claim (diffed the
actual commit, 32 insertions, 0 deletions, all comments), CSRF exposure
(zero state-changing GET endpoints exist anywhere in the app, so
`SameSite=Lax` fully covers the real mutation surface — one minor residual
note: the new `/login` cookie-set path lacks the Origin check its sibling
handoff flow has, gated behind `local_recovery` mode being enabled at
all), and the `_answer_general_question` rewrite's bounds/redaction/raw-log
exposure (all correctly bounded and redacted).

Also worth stating plainly, since it was asked directly: **"answer any
question" remains a hard architectural limit, not a bug.** For a question
genuinely outside both the ~24 keyword intents and the newly-added
sources/jobs/cases/ML context, the system still says so explicitly rather
than guessing — the safety-first "stay inside supplied evidence" design
this project has maintained throughout is working as intended. Closing
that gap further would mean relaxing that constraint, which is a real
tradeoff decision, not a fix.

---

## Complete plan, in order

1. **Tier 0 first, no exceptions** (6-9h): the garbled Assistant answer,
   the AI-reviewer-pattern consolidation (done properly this time, with a
   structural guard against a 6th recurrence), and the password-reset
   revocation gap. All three are confirmed, all three are real regressions
   or incomplete fixes from this session's own recent work, not
   theoretical.
2. **Tier 1** (6-9h): the cookie-secure validation gap, the
   AssistantPage prompt-link bug, the handoff revocation test gap, the
   logout-test fix, and investigating the suspected outbound citation bug.
3. **Tier 2** (4-6h): the dead-context-guard fix, prompt-size curation,
   stale-mutation-error fix, ResponseCenter consistency fixes.
4. **Tier 3** (2-4h): cleanup — do opportunistically, not urgent.

**Total: 18-28 hours** to genuinely close out everything this round found,
across all 4 tiers. Tier 0 alone (6-9h) is the part that actually matters
most: it's the difference between "the Assistant upgrade works" and "the
Assistant upgrade ships broken by default," and between "the reviewer
gate is fixed" and "the reviewer gate is fixed in 3 of 6 places."

**What this round changes about "how far are we"**: the honest answer is
that "all tests green" was true and is no longer sufficient evidence of
"done" — this project's tests, however extensive, did not (and by
construction could not) catch a regression in output *quality* (the
garbled answer) or a *structural* duplication pattern (the reviewer-gate
drift) that spans files no single change touched. That's not a reason to
distrust the test suite; it's a reason this second audit round was worth
doing, and probably a reason to build the structural guard in Tier 0 item
2 rather than treat this as one more one-off fix.
