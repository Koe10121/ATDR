# T1-T20: Assistant IPv6 Redaction Gap Fix

## T1 Change Title

- Title: Fix IPv4-only IP redaction pattern (real IPv6 addresses could reach
  the external LLM provider and could pass privacy-verification acceptance
  gates)
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; a version number is for the project owner to
  assign alongside the other uncommitted work in this tree.

## T2 Requirement

`ASSISTANT_REDACT_IPS=true` (the required setting whenever
`ASSISTANT_LLM_ENABLED=true`, enforced by `validate_runtime_settings`) and
the "raw logs excluded, IP redaction enabled" claim repeated throughout the
active docs must hold for any IP address the system might redact, not only
IPv4.

## T3 Source Evidence

Direct reading of `atdr/app/services/assistant_llm.py` and
`atdr/app/services/assistant_service.py`'s redaction functions, then a
repository-wide search for every independent copy of the same pattern.

## T4 Current Behavior (before fix)

`IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")` — IPv4 dotted-decimal
only — was independently duplicated in six places:
`assistant_llm.py` (used for direct provider-request-body redaction),
`assistant_service.py` (used for LLM context redaction; separate duplicate
definition), `v524_investigation_gemini_quality_service.py` (used inside a
`privacy_passed` quality-gate check — i.e. an IPv6 leak would have been
silently certified as privacy-passing), `v525_integrated_acceptance_service.py`
(an `output_private` acceptance check with the same blind spot),
`v551_field_qualification_service.py` (a field-qualification privacy check,
though this one already had a *partial* IPv6 pattern — see T18). Two further
modules (`v527_gemini_real_alert_quality_service.py`,
`v533_independent_acceptance_service.py`) import `IP_PATTERN` from v524 and
so shared its gap transitively. `response_service.py`'s
`PROTECTED_RESPONSE_NETWORKS` already explicitly protects IPv6 ranges
(`::1/128`, `fc00::/7`, `fe80::/10`), confirming IPv6 traffic is an
anticipated real case for this system, not a hypothetical.

No existing test exercised an IPv6 address anywhere in the assistant/quality/
acceptance suites, so the gap was undetected.

## T5 Impacted Areas / Agents

`atdr/app/services/assistant_llm.py` (now the single canonical definition),
`atdr/app/services/assistant_service.py`,
`atdr/app/services/v524_investigation_gemini_quality_service.py`,
`atdr/app/services/v525_integrated_acceptance_service.py`,
`atdr/app/services/v551_field_qualification_service.py`,
`atdr/tests/test_assistant.py`.

## T6 Scope

In scope: making every IP-redaction/IP-leak-detection call site in the
repository correctly match IPv6 as well as IPv4, and removing the
duplication so future changes only need to happen once. Out of scope:
`v514_large_file_runtime_service.py`'s independent pattern, which already has
non-trivial (if slightly less complete) IPv6 coverage and is a lower-risk,
different-purpose check — left as-is rather than touched speculatively.

## T7 Functional Requirements

- One canonical `IP_PATTERN` in `assistant_llm.py` matches IPv4 and the
  common IPv6 literal forms (full, compressed `::`, with a `%zone` suffix),
  with lookaround guards so it does not false-positive on MAC addresses,
  hex hashes, timestamps, or ID-like tokens (`alert #1234`, `case ABCD-1234`).
- Every other module either imports this pattern or (for `v551`, which has no
  existing dependency on the assistant services) carries an equivalent
  IPv4+IPv6 pattern inline.
- No change to redaction being enabled/disabled by configuration — only to
  what counts as "an IP" once redaction runs.

## T8 Acceptance Criteria

A parametrized test proves the pattern matches seven representative IPv4/
IPv6 forms and does not match four representative non-IP strings. An
end-to-end prompt-contract test proves a real IPv6 address (including a
zone-qualified link-local address) is absent from the built LLM prompt and
replaced with `[redacted-ip]`. All five touched modules' existing test
suites and the full backend suite pass unchanged otherwise.

## T9 API Contract

None. Internal redaction/verification logic only.

## T10 Data Model / Migration

None.

## T11 Backend Plan / Changes

Added a combined IPv4/IPv6 regex (`_IPV6_CORE` alternation plus the existing
IPv4 pattern) as the canonical `assistant_llm.IP_PATTERN`. Removed the
duplicate definition in `assistant_service.py` in favor of importing it.
Removed the duplicate in `v524_investigation_gemini_quality_service.py` in
favor of importing it from `assistant_llm` (its own re-export then keeps
`v525`'s and `v527`'s existing `from ...v524... import IP_PATTERN` working
unchanged). Added `IP_PATTERN` to `v525`'s import from `v524` and removed its
local duplicate. Extended `v551`'s local pattern inline with the same IPv6
alternation, kept local since that module has no existing dependency on the
assistant services.

## T12 Frontend Plan / Changes

None.

## T13 Security / Response / AI Safety

This directly strengthens an existing privacy invariant (IP redaction before
external LLM context) rather than changing what is allowed. No detection,
alert, or response authority is touched.

## T14 Test Plan

`atdr/tests/test_assistant.py`: new parametrized regex test (11 cases) and a
new end-to-end IPv6 prompt-redaction test. Existing test suites for all five
touched modules (`test_assistant.py`, `test_v524_investigation_gemini_quality.py`,
`test_v525_integrated_acceptance.py`, `test_v527_blind_review_and_gemini_quality.py`,
`test_v533_independent_acceptance.py`, `test_v551_field_qualification.py`) run
in full. Full backend suite re-run afterward.

## T15 Implementation Summary

One new shared regex, five files updated (two net-new duplicate removals),
one file's inline pattern extended. No behavior change for any existing IPv4
test case.

## T16 Tests Run / Evidence

`test_assistant.py`: `56 passed`. Combined v524/v525/v527/v533/v551 suites:
`35 passed`. Full backend suite result recorded in
`docs/tasks/tasklist-progress.md` after the final full-matrix run.

## T17 PRD / Docs Updated

This change record only. No active document claimed IPv4-specific redaction
or made a now-false statement — "IP redaction is enabled" remains accurate
language; this fix makes that existing claim completely true rather than
correcting a false one.

## T18 Risks / Blockers / Assumptions / Decisions

`v514_large_file_runtime_service.py` has its own independent IP-matching
pattern with partial (not fully general) IPv6 coverage; it was deliberately
left untouched in this pass rather than speculatively changed, since it is a
different-purpose check (large-file runtime acceptance, not the LLM
redaction path) and its existing coverage is already meaningfully better
than pure IPv4-only. The combined regex is a practical, redaction-safety-net
pattern (verified against representative real-world IPv6 forms including
`::`-compression and `%zone` suffixes), not a formal RFC 4291 validator; an
exotic literal form could in principle still slip through, same class of
residual risk the project already accepts for its zone-name and other
heuristic matches elsewhere in the codebase.

## T19 Release / Rollback

Fully reversible: revert the six changed files. No migration, no data
written, no configuration default changed.

## T20 Final Handoff

Awaiting project-owner review and a separately approved commit/push decision
alongside the other work in this tree (v5.64, the rule-engine zone fix, and
the real response-enforcement feature).
