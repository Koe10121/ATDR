# T1-T20: v5.24 Investigation and Gemini Quality Lock

## T1 Change Title

v5.24 Investigation and Gemini Quality Lock.

## T2 Requirement

Make alert/log investigation concise and evidence-first, remove classroom
wording from runtime surfaces, and evaluate Gemini on bounded ATDR record and
follow-up questions without granting action authority.

## T3 Source Evidence

`assistant_service.py`, `assistant_llm.py`, alert/log explanation services,
Assistant/Alerts/Investigation React pages, existing assistant tests, and the
v5.20-v5.23 evidence contracts.

## T4 Current Behavior

The assistant was already read-only, redacted, structured, citation-aware, and
conversation-capable. It had only a single live provider probe, alert details
placed technical layers before missing context, and a few runtime demo or
presentation labels remained.

## T5 Impacted Areas/Agents

Backend assistant and explanation services, React investigation surfaces,
AI/privacy governance, QA, documentation, and release operations.

## T6 Scope

Bounded synthetic quality evaluation, trusted citation completion, concise
visible evidence contracts, runtime wording cleanup, tests, and governance.
Detection thresholds, alert authority, model lifecycle, response behavior,
database schema, and startup commands are out of scope.

## T7 Functional Requirements

Evaluate alert/log/source/case and follow-up questions; measure grounding,
citations, unsupported IDs, concision, latency, tokens, fallback, context
retention, privacy, and mutations; display what happened, why flagged,
evidence strength, missing context, and analyst checks.

## T8 Acceptance Criteria

All fixed quality/safety gates pass; provider calls use bounded redacted
context; every record question retains its primary context and citation; no
raw evidence, secret, unsupported ID, action claim, or authoritative write is
observed; frontend has no horizontal overflow.

## T9 API Contract

No route or request-schema change. `/api/assistant/chat` retains its existing
response contract. Server-side structured answers now guarantee that the
trusted primary citation is attached when citations exist.

## T10 Data Model / Migration

No schema or migration change. Evaluation uses disposable in-memory SQLite and
creates only expected assistant audit rows inside that disposable database.

## T11 Backend Plan / Changes

Add the v5.24 evaluator/CLI; extend answer sections with explicit limitations;
add log evidence-strength/missing-context fields; strengthen the structured
citation contract; preserve safe provider fallback.

## T12 Frontend Plan / Changes

Lead Assistant/Alerts/Investigation with bounded evidence sections, collapse
technical detection layers, rename runtime validation controls, retain
responsive and SafeSelect behavior.

## T13 Security / Response / AI Safety

Raw logs disabled, IP redaction enabled, secrets excluded, deterministic rules
authoritative, supervised lifecycle unchanged, Assistant read-only, response
automation and real blocking disabled.

## T14 Test Plan

Focused assistant/evaluator tests, Ruff, compileall, full backend tests,
Alembic, React lint/build, Playwright, controlled/layered detection,
deterministic Assistant QA, bounded live Gemini evaluation, replay,
performance, release gate, taskboard, diff, privacy, and hygiene checks.

## T15 Implementation Summary

Implemented a six-question/11-gate quality lock, deterministic provider-failure
probe, server-enforced trusted primary citation, explicit investigation
evidence sections, and professional runtime terminology.

## T16 Tests Run / Evidence

Focused Assistant/v5.24 tests pass `46/46`; new v5.24 tests pass `5/5`;
frontend lint/build pass; Playwright passes `27`, with one live scenario test
intentionally skipped; live Gemini quality passes `11/11` over six calls with
3,125 ms median, 3,731 ms p95, and 18,675 tokens. Ruff/compileall pass; full
backend and release verification pass `817 passed, 1 skipped`; Alembic has no
drift; controlled detection passes `24/24`; layered detection passes `288/288`;
Assistant QA passes `20/20`; replay writes zero; warning-free performance
records Overview `0.1653s`, cached Overview `0.0102s`, Alerts `0.0315s`, Cases
`0.0212s`, and AI Governance `0.3250s`; the official release gate returns
`ok: true`. One stale RBAC assertion for the intentional `Validation Controls`
rename was corrected before the successful full release rerun.

## T17 PRD / Docs Updated

v5.24 status, this record, PRD, traceability, compliance, runbook, system
state, docs index, taskboard/HTML, and exact cumulative allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The result is a bounded synthetic contract, not universal Gemini correctness.
Provider drift, cost/quota controls, approved real-traffic evaluation, v5.23
non-loopback transport, real-device evidence, and independent native human
labels remain open.

## T19 Release / Rollback

No commit/push is authorized. Rollback removes the evaluator/CLI/tests/docs and
reverts additive explanation/UI/citation changes; no database rollback is
required.

## T20 Final Handoff

Run v5.25 Integrated Acceptance. Keep v5.23 deferred rather than passed and
preserve all model/response authority constraints.
