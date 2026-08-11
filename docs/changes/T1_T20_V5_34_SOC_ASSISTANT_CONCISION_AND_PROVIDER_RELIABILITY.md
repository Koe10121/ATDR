# T1-T20: v5.34 SOC Assistant Concision And Provider Reliability

## T1 Change Title

v5.34 SOC Assistant Concision and Provider Reliability Closure.

## T2 Requirement

Make deterministic and Gemini-assisted answers consistently concise,
evidence-grounded, citation-correct, context-aware, and resilient while
preserving read-only authority and honest human-acceptance boundaries.

## T3 Source Evidence

The source truth is the Assistant service, LLM adapters, response contracts,
schemas, React session/answer components, v5.24/v5.27 quality evaluators, v5.33
eight-case pack, focused tests, PRD, traceability, and taskboard. Provider
payloads, secrets, raw logs, IPs, and private paths are excluded.

## T4 Current Behavior

v5.33 passed seven of eight automated contracts. One investigation brief
exposed verbose provider detail sections despite a bounded answer. One
provider fallback lacked a retained failure category. Conversation context,
citations, privacy, and zero-authority-mutation behavior otherwise passed.

## T5 Impacted Areas / Agents

Assistant response contracts, provider adapter, deterministic brief builder,
API schema, React answer/session display, Assistant evaluation, QA,
documentation, and release review. Detection rules, thresholds, alert
authority, model lifecycle, database schema, response authority, IAM, and
startup commands are unchanged.

## T6 Scope

In scope: shared compaction, semantic deduplication, case-handoff mode,
provider failure classification, safe telemetry, acceptance separation,
tests, governance, and exact allowlist. Out of scope: model changes, human
scores, raw-log sharing, provider approval, action execution, and automatic
response.

## T7 Functional Requirements

- Apply one presentation contract to local and provider answers.
- Enforce direct `80`, alert `<=120`, and investigation `<=160` word budgets.
- Keep evidence/recommendations compact and citations intact.
- Classify timeout, quota, malformed output, citation failure, safety
  rejection, and availability without retaining payloads.
- Preserve contextual follow-ups, explicit-ID replacement, clear-context, and
  frontend session persistence.
- Keep deterministic fallback and all authority boundaries.
- Keep human acceptance fields unchanged and blank unless a genuine reviewer
  completes them.

## T8 Acceptance Criteria

Eight of eight content contracts pass; every mode remains within budget;
provider availability is reported separately; raw logs/IPs/secrets are
absent; citations and bound IDs remain correct; fallbacks are classified;
authoritative mutations are zero; complete verification passes.

## T9 API Contract

`POST /api/assistant/chat` adds `case_handoff` as a response mode and safe
`details.llm.failure_category` metadata. No secret, provider payload, or raw
context is added. Existing clients remain compatible with the string-based
mode and details objects.

## T10 Data Model / Migration

No database or migration change. The v5.33 ignored worksheet gains protected
diagnostic columns for response mode, word count/limit, provider contract, and
safe failure category. Human fields are unchanged.

## T11 Backend Plan / Changes

Reduce the investigation contract to 160 words, compact its source sections,
add semantic evidence deduplication, add case-handoff mode, re-render provider
sections through the shared presentation builder, classify failures, and
separate answer quality from provider availability in the evaluator.

## T12 Frontend Plan / Changes

Recognize and label case handoffs, persist the new mode safely, and show a
human-readable fallback class in the provider detail panel. Existing route,
session persistence, citations, and no-action UI remain intact.

## T13 Security / Response / AI Safety

Gemini receives bounded redacted context only. Raw logs remain disabled.
Secrets and payloads are never returned. The Assistant cannot mutate alerts,
detections, labels, models, users, data, or responses. Rules remain
alert-authoritative; automation and real blocking remain disabled.

## T14 Test Plan

Test mode budgets, semantic deduplication, citations, failure categories,
malformed fallback, unsupported IDs, contextual follow-ups, session
persistence, IP/raw-log/secret exclusion, and zero authoritative side effects.
Run the complete backend/frontend/detection/release matrix.

## T15 Implementation Summary

Implemented shared provider/local presentation, compact investigation briefs,
deduplication, case-handoff mode, payload-free failure categories, aggregate
failure telemetry, evaluator contract separation, frontend status display,
and v5.34 focused regressions.

## T16 Tests Run / Evidence

Focused Assistant reliability tests pass `21/21`; the full existing Assistant
suite passes `42/42`; repaired v5.24/v5.25 compatibility checks pass `13/13`.
Full backend and release-gate runs each pass `890 passed, 1 skipped`. Ruff,
source compile, Alembic no-drift, npm audit, React lint/build, Playwright
`31 passed, 1 skipped`, controlled detection `24/24`, layered detection
`288/288`, Assistant QA `20/20`, replay, and the official release gate pass.
The refreshed eight-case pack passes `8/8` answer contracts with zero
authoritative mutations and no raw/IP/secret exposure. Provider quota
degradation and the existing cold-SQLite Overview warning remain explicit.

## T17 PRD / Docs Updated

Added v5.34 status and this change record. Updated current AI/ML status,
traceability, PRD, taskboard/HTML, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The current Gemini project exhausted quota during bounded runs, so universal
provider availability is not claimed. Human Assistant acceptance remains
`0/8`. Provider privacy/retention/quota/key governance and detection human
review remain external. Deterministic fallback is treated as a valid safe
answer path, not as proof that provider operations passed.

## T19 Release / Rollback

No commit or push is authorized. Rollback is source/document-only over the
exact allowlist; no migration or data rollback is required. Ignored worksheets
and reports remain untracked.

## T20 Final Handoff

Review the v5.34 status, inspect the Assistant manually across alert/log/source
and case follow-ups, and resolve provider quota with the provider owner before
expecting continuous Gemini use. A genuine reviewer must still complete the
human worksheet. Keep every authority boundary unchanged.
