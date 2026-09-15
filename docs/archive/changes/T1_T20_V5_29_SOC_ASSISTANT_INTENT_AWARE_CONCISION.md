# T1-T20: v5.29 SOC Assistant Intent-Aware Concision

## T1 Change Title

v5.29 SOC Assistant Intent-Aware Concision and Response Quality Lock.

## T2 Requirement

Make each Assistant answer direct, short, and appropriate to the requested
intent while preserving record context, citations, privacy, deterministic
fallback, and read-only safety.

## T3 Source Evidence

Source truth is `assistant_service.py`, `assistant_llm.py`, Assistant schemas,
the React Assistant page/session code, Assistant tests, the 20-question QA
evaluator, the bounded configured-Gemini evaluator, and existing v5.24-v5.28
privacy and authority contracts. No private prompt, answer, key, raw record,
or provider secret is tracked.

## T4 Current Behavior

Before v5.29, deterministic and provider responses were normalized into the
same universal report sections. A length-based guard rejected accurate short
provider answers when local context was long. The UI expanded evidence,
citations, telemetry, and repeated safety information for routine questions.

## T5 Impacted Areas/Agents

Backend Assistant, provider adapter, frontend dashboard, security/privacy,
QA/UAT, AI governance, documentation, and release operations.

## T6 Scope

In scope: response-mode inference, dynamic word budgets, mode-specific
sections, evidence-aware provider guards, context-bound follow-ups, concise
React rendering, collapsed detail, evaluators, tests, and governance records.

Out of scope: detection changes, model training/activation/promotion, label
creation, external-provider default changes, raw-log context, response
execution, real blocking, database migration, or human blind review.

## T7 Functional Requirements

- Support nine explicit response modes with hard word limits.
- Return only sections relevant to the current question.
- Preserve the active alert/log/source/case for follow-ups.
- Reject unsupported IDs, invented facts, unsafe action claims, missing
  requested coverage, lost primary citations, secrets, and over-budget output.
- Accept accurate short answers based on coverage rather than source length.
- Put the direct answer first and collapse detailed evidence/citations.
- Preserve read-only, redaction, raw-context, and zero-side-effect controls.

## T8 Acceptance Criteria

Different intents produce different structures; routine answers remain within
their budgets; follow-ups retain the record without repeating the whole prior
answer; unsupported IDs fail closed; Gemini failure returns concise local
fallback; navigation persistence works; no horizontal overflow occurs; and no
authoritative state changes.

## T9 API Contract

`POST /api/assistant/chat` remains compatible and adds `response_mode` with
one of the nine documented values. `details.answer_sections` becomes
mode-specific, while `details.evidence_detail` retains bounded technical
evidence for expandable UI use. No mutation endpoint is added.

## T10 Data Model / Migration

No database model or migration changed. Conversation persistence remains
bounded browser session storage; Assistant question auditing remains unchanged.

## T11 Backend Plan / Changes

Add a shared response-contract module, infer intent after deterministic context
collection, shape local/provider answers to the selected mode, replace the
minimum-length guard with coverage/entity/citation/safety checks, and generate
record-bound follow-ups.

## T12 Frontend Plan / Changes

Render the direct answer first, show only three compact safety badges, collapse
evidence and provider/citation details, preserve response mode in session
storage, use mode-aware copy wording, and keep overflow protections.

## T13 Security / Response / AI Safety

Provider context excludes raw logs by default and applies IP redaction. Keys
and secrets are never returned. The Assistant cannot create responses,
detections, labels, models, users, or deletions. Rules remain authoritative;
automation and real blocking remain disabled.

## T14 Test Plan

Test mode inference and shapes, every budget, contextual follow-ups,
unsupported-ID rejection, concise Gemini use/fallback, zero mutations,
session persistence, collapsed details, safety badges, copy status, citations,
provider telemetry, and horizontal overflow.

## T15 Implementation Summary

Implemented nine response contracts, removed universal section injection,
repaired the answer guard, added context-aware follow-ups, changed Gemini to
the v4 concise schema, redesigned the response panel, and strengthened backend,
evaluator, and Playwright coverage.

## T16 Tests Run / Evidence

Focused evidence passes: Assistant backend `59 passed`; deterministic QA
`20/20`; configured Gemini `12/12` over six calls; React lint/build; and
Assistant Playwright `6 passed`. Deterministic average/max answer length fell
from 283.8/697 words to 73.1/184. Gemini returned no raw logs, IPs, private
paths, or secrets and created zero authoritative mutations.

Complete repository evidence passes: Ruff; compileall; backend
`852 passed, 1 skipped`; Alembic no drift; React lint/build; Playwright
`27 passed, 1 skipped`; replay dry-run with zero writes; warning-free
performance smoke; and official release gate `ok: true`. The browser skip
remains the external live-source gate. An
initial in-repository pytest temp root was rejected by the backup containment
policy; the approved ignored `.tmp/` boundary passed without changing runtime
safety behavior.

## T17 PRD / Docs Updated

v5.29 status, this change record, PRD, traceability, compliance checklist, AI
runbook/current status, lab runbook, docs index, taskboard/rendered HTML, and
exact cumulative commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Automated quality suites cannot replace qualified human semantic and privacy
review. Provider-host privacy approval, quota/cost monitoring, key rotation,
and operational acceptance remain external. Human blind supervised review is
still deferred and unrelated to this Assistant behavior change.

## T19 Release / Rollback

No staging, commit, or push is authorized. Rollback removes the response
contract module and reverts Assistant service/provider/schema/UI/test/docs
changes. No data or migration rollback is required.

## T20 Final Handoff

Use routine questions for concise triage and request an investigation brief
only when a full report is needed. Keep the Assistant read-only and preserve
the configured provider privacy controls. Complete human Assistant evaluation
and approved-host provider governance before deployment-quality claims.
