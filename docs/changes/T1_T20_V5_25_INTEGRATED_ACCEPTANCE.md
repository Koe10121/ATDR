# T1-T20: v5.25 Integrated Acceptance

## T1 Change Title

v5.25 Integrated Acceptance.

## T2 Requirement

Validate the complete professor-focused ATDR workflow from collection through
audited analyst-controlled simulated response, while preserving every
detection, ML, privacy, database, and response-safety boundary.

## T3 Source Evidence

v4.8 disposable product acceptance, v5.23 live-source acceptance, v5.24 Gemini
quality lock, controlled end-to-end workflow validation, lifecycle scripts,
RBAC tests, React smoke/E2E tests, release gate, and v5.20-v5.24 governance.

## T4 Current Behavior

Each workflow layer was validated separately, but no one privacy-safe runner
composed ingestion/recovery, local transport, rule detection, ML advisory use,
investigation, Gemini evidence, simulated response, audit, repository startup,
RBAC, and responsive-UI contracts.

## T5 Impacted Areas/Agents

Orchestrator, ingestion, detection, AI/ML governance, Assistant, response
safety, frontend QA, release/operations, security, and documentation.

## T6 Scope

Disposable orchestration, aggregate reporting, locked Gemini evidence reuse,
quota-aware fresh-provider option, tests, governance, and final external-gate
disclosure. Detection logic, thresholds, model artifacts, schema, startup
commands, and real response are out of scope.

## T7 Functional Requirements

Exercise collection, parsing, normalization, recovery/backpressure, local UDP,
rules, advisory ML, deduplication, cases, explanations, Gemini assistance,
simulated response, audits, startup/setup/RBAC/UI contracts, privacy, and
configured-database preservation.

## T8 Acceptance Criteria

All fixed local gates pass; fresh or validated locked Gemini evidence passes
the full v5.24 contract; configured data remains unchanged; output is aggregate
and private; no model/label authority change or real response occurs; all
external gates remain explicit.

## T9 API Contract

No API route or schema change. The new CLI composes existing public service
contracts and emits a bounded aggregate acceptance document.

## T10 Data Model / Migration

No schema or migration change. All executable acceptance paths use disposable
SQLite storage; generated reports remain ignored.

## T11 Backend Plan / Changes

Add v5.25 orchestration, CLI, aggregate projections, external-gate ledger,
privacy validation, and validated v5.24 lock loading. Add optional pacing for
fresh bounded Gemini quality runs.

## T12 Frontend Plan / Changes

No additional runtime change. v5.24 evidence-first UI is accepted through the
existing responsive, role, navigation, interaction, and overflow suites.

## T13 Security / Response / AI Safety

Rules stay authoritative; supervised ML stays shadow-only; raw Assistant
context stays disabled; IP redaction stays enabled; missing justification and
protected targets are denied; approved actions remain simulated; no real
blocking or automatic response is enabled.

## T14 Test Plan

Focused v5.24/v5.25 tests, integrated 5,000-row run, taskboard, Ruff,
compileall, full backend, Alembic, React lint/build/Playwright, controlled and
layered detection, Assistant QA, replay, performance, release, privacy,
hygiene, and exact-boundary checks.

## T15 Implementation Summary

Implemented one safe integrated acceptance runner with 14 fixed local gates,
explicit external-gate accounting, fresh-or-locked Gemini evidence policy,
and aggregate-only output.

## T16 Tests Run / Evidence

Focused v5.24/v5.25 tests pass `12/12`. The measured 5,000-row run passes
`14/14`, including exact raw/normalized counts, recovery, file/API/local UDP,
rule authority, ML advisory use, traceable alert/case explanation, locked
Gemini `11/11`, simulated response/audit, configured-DB preservation, and
privacy. Taskboard/Ruff/compileall pass; backend and release suites pass `824
passed, 1 skipped`; Alembic reports no drift; React lint/build pass; Playwright
passes `27 passed, 1 skipped`; controlled detection passes `24/24`; layered
detection passes `288/288`; Assistant QA passes `20/20`; replay dry-run writes
zero; performance smoke has no warnings; and the official release gate returns
`ok: true`. The exact cumulative boundary reconciles `75/75` paths; diff,
privacy, ignored-path, staging, and tracked-hygiene checks pass. The browser
skip is the owner-deferred external live-source gate.

## T17 PRD / Docs Updated

v5.25 status, this T1-T20 record, PRD, traceability, compliance, runbook,
current state, AI/ML status, docs index, final checklist, taskboard/HTML, and
exact cumulative allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Provider throttling can prevent fresh repeat evaluation, so v5.25 validates an
immutable passed v5.24 lock instead of treating fallback as provider evidence.
Non-loopback transport, real device, independent labels, MFU preproduction,
approved host, and provider governance remain external gates.

## T19 Release / Rollback

No commit/push is authorized. Rollback removes the v5.25 service, CLI, tests,
and docs and reverts the optional evaluator pacing; no database rollback is
required.

## T20 Final Handoff

Preserve the v5.20-v5.25 evidence locks and complete the external gates when
their owners/resources are available. Do not describe local roadmap closure as
production readiness.
