# T1-T20: v5.52 Analyst Experience And SOC Assistant Closure

## T1 Change Title

v5.52 Analyst Experience And SOC Assistant Closure.

## T2 Requirement

Close locally controllable alert investigation and Assistant defects with
concise, grounded, persistent, provider-truthful, read-only behavior.

## T3 Source Evidence

Assistant router/schema/service/LLM/response contracts, React Assistant page,
sanitized session store, answer renderer, API types, backend tests, Playwright,
Assistant QA evaluator, and safe provider probes. Protected v5.49b evidence was
not opened.

## T4 Current Behavior

ATDR builds deterministic bounded evidence first and optionally lets Gemini
synthesize it. Previous context could be contaminated by generic IDs, related
citations, reset history, and one-response browser persistence.

## T5 Impacted Areas / Agents

Backend Assistant, schemas, provider adapter, React analyst workflow,
accessibility, privacy, QA, governance, and documentation.

## T6 Scope

Repair context ownership, add bounded tab persistence and explicit provenance,
tighten response limits, improve UI states, expand tests, and verify Gemini.
No detection, model, database-schema, IAM, or response-authority change.

## T7 Functional Requirements

- Parse IDs only with explicit entity context.
- Preserve one primary entity for ordinary follow-ups.
- Start a clean thread for reset prompts and explicit entity switches.
- Persist at most four sanitized tab-scoped turns.
- Show answer origin, evidence scopes, citation count, and authority boundary.
- Keep intent answers within fixed 55-120 word budgets and two follow-ups.
- Keep deterministic fallback and zero mutation behavior.

## T8 Acceptance Criteria

Alert follow-ups retain the intended record across navigation; source IDs do
not become alerts; reset calls use no provider history; provenance is visible;
Assistant QA, real provider probes, backend tests, React build, and Playwright
pass; privacy and side-effect checks remain zero.

## T9 API Contract

`POST /api/assistant/chat` adds a required `provenance` object. History rows add
safe `answer_origin` and `evidence_scope` fields. No mutation API is added.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Conversation turns use sanitized
browser `sessionStorage` only and are cleared on logout/context clear.

## T11 Backend Plan / Changes

Tighten ID extraction, isolate reset history, keep only the primary cited
entity active, compute response provenance, audit safe provenance summaries,
and reduce response budgets.

## T12 Frontend Plan / Changes

Rotate conversations on context switch, remove stale route directives, retain
four sanitized turns, add provenance and prior-turn disclosure, keyboard submit,
live-region/loading semantics, wrapping, and focused browser regressions.

## T13 Security / Response / AI Safety

Raw logs stay excluded; IP redaction stays enabled; secrets/provider payloads
stay private. Rules remain authoritative, ML advisory, Assistant read-only,
response simulated, automatic response off, and real blocking off.

## T14 Test Plan

Run focused and full backend tests, Ruff, compileall, Alembic, React lint/build,
Assistant-focused and full Playwright, Assistant QA, minimal/full Gemini probes,
controlled/layered detection, replay dry-run, performance, release, taskboard,
privacy, staging, diff, and exact-path checks.

## T15 Implementation Summary

Context ownership, history isolation, bounded persistence, explicit provenance,
concision v5 contracts, professional UI disclosure, and tests are implemented.

## T16 Tests Run / Evidence

Assistant QA passes `20/20` with `1.0000` citation pass rate, `60.9` average
words, `110` maximum, and all budgets passing. Real Gemini minimal and synthetic
full-chat probes pass with raw logs absent, redaction enabled, secrets hidden,
and zero authoritative side effects. Ruff and compileall pass; the complete
backend suite and release-gate rerun each pass `1040 passed, 1 skipped`;
Alembic reports no drift; React lint/build pass; Playwright passes `38 passed,
1 skipped`; controlled source, controlled detection, and layered detection pass
`4/4`, `24/24`, and `288/288`; replay remains zero-write; all performance
budgets pass; and the release gate returns `ok: true`.

## T17 PRD / Docs Updated

README, AI docs index, PRD, traceability, compliance, current system/AI status,
finish line, v5.52 status, T1-T20, taskboard/HTML, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Provider privacy approval, quota/billing, key rotation, real-traffic evaluation,
formal accessibility/usability acceptance, MFU preproduction, and deployment
remain external. Passing controlled QA is not universal accuracy.

## T19 Release / Rollback

No commit or push is authorized. The exact cumulative v5.50-v5.52 proposal is
42 paths in `docs/V5_52_COMMIT_ALLOWLIST.md`, with zero staged paths. Rollback
affects only v5.52 Assistant/runtime, tests, and docs; no database rollback is
required. Preserve all v5.50-v5.51 local work and private evidence.

## T20 Final Handoff

After full verification and separate publication approval, proceed to v5.53
MFU IAM And Shared Deployment Acceptance. Two substantial phases remain, with
v5.51 field evidence continuing in parallel when external resources exist.
