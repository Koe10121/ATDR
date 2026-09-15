# T1-T20: v5.56 SOC Assistant Operational Reliability And Analyst Quality Lock

## T1 Change Title

v5.56 SOC Assistant Operational Reliability And Analyst Quality Lock.

## T2 Requirement

Improve concise intent-specific answers, guarded Gemini reliability,
payload-free operational telemetry, deterministic fallback, and representative
Assistant QA without expanding authority.

## T3 Source Evidence

Assistant configuration, schema, service, response contracts, provider
adapters, evaluator, React Assistant page and API types, existing v5.52
persistence/provenance behavior, focused tests, synthetic v5.56 corpus, and
secret-safe private provider probes.

## T4 Current Behavior

The v5.52 Assistant was safe and concise overall, but related-log identity,
alert-specific checks, source/governance focus, provider output ceilings,
citation formatting, and aggregate provider-health visibility had remaining
reliability defects.

## T5 Impacted Areas / Agents

Backend Assistant, external-provider adapter, configuration, API schema,
response contracts, React status UI, QA corpus, security/privacy, tests, and
governance documentation.

## T6 Scope

Repair the evidence-to-answer and provider-validation paths, add aggregate
telemetry and a warning threshold, expand deterministic QA, and expose compact
provider health. No detection, ML lifecycle, IAM, database schema, alert
authority, response, firewall, or startup behavior changes.

## T7 Functional Requirements

- Preserve distinct related evidence records and active follow-up context.
- Give direct intent-specific answers with at most three findings/checks.
- Separate the 40-100-word target from the 120-word provider hard ceiling.
- Constrain Gemini citations to the request-specific ATDR allowlist.
- Fail every malformed, unsafe, ungrounded, or unavailable provider result to
  deterministic output.
- Expose only aggregate provider counters, latency, failure types, circuit
  state, token usage, and warning state.
- Retain zero authoritative side effects.

## T8 Acceptance Criteria

The 30-case corpus and four-turn sequence pass relevance, grounding,
citations, concision, differentiation, continuity, privacy, and no-side-effect
checks. Gemini minimal and full synthetic probes pass without raw logs or
secrets. Focused and complete backend/frontend/release verification pass.

## T9 API Contract

`GET /api/assistant/status` adds a safe token-warning setting and aggregate
operational fields. `POST /api/assistant/chat` keeps its existing read-only
contract. No mutation route is added.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Operational counters are process-
local and reset on backend restart. Conversation persistence remains bounded
browser `sessionStorage` plus actor-scoped server context.

## T11 Backend Plan / Changes

Refine answer-source selection, preserve explicit record IDs during semantic
deduplication, use explanation-derived checks, centralize provider rendering,
add guarded failure categories and aggregate telemetry, require redaction, and
bind Gemini structured citations with a dynamic enum.

## T12 Frontend Plan / Changes

Show provider health, success/failure/fallback counts, average latency, total
tokens, and a compact token-threshold warning outside the main answer. Preserve
provenance, citations, tab persistence, safety badges, MFU styling, and
overflow behavior.

## T13 Security / Response / AI Safety

Keys, prompts, provider responses, identities, raw logs, numeric IPs, private
paths, and protected evidence remain absent from telemetry and Git. Rules stay
alert-authoritative, ML stays advisory, the Assistant stays read-only, and
automatic response and real blocking stay disabled.

## T14 Test Plan

Test telemetry aggregation, threshold warnings, named provider failures,
circuit/fallback behavior, redaction preconditions, unsafe/IP/citation guards,
provider hard limits, related-log identity, intent-specific answers, React
health rendering, complete Assistant QA, full backend/frontend suites,
provider probes, detection regressions, security, performance, release, and
repository hygiene.

## T15 Implementation Summary

Intent-specific response selection, evidence-aware checks, record-preserving
deduplication, central bounded provider rendering, dynamic Gemini citation
schema, aggregate operational telemetry, warning UI, explicit governance
decision-support wording, synthetic corpus, and regression tests are
implemented.

## T16 Tests Run / Evidence

Deterministic QA passes `30/30`, the four-turn sequence passes `4/4`, citation
rate is `1.0000`, and average/max length is `56.0/110`. Focused
Assistant/provider tests pass `76/76`; an additional provider-schema subset
passes `62/62`. The complete release rerun passes `1062` backend tests with
`1` external/live skip; React lint/build and Playwright pass `39/1`.
Controlled source `4/4`, deterministic detection `24/24`, layered detection
`288/288`, Alembic, security, replay, performance, deployment operations,
private Gemini probes, and release checks pass.

## T17 PRD / Docs Updated

Current AI/ML status, PRD, traceability, compliance, AI docs index, real-LLM
plan, lab runbook, v5.56 status, T1-T20 record, taskboard/HTML, and exact
allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Telemetry is process-local, provider costs are estimates, and synthetic probes
do not establish representative field quality. Institutional privacy, quota,
billing, key rotation, persistent monitoring, and independent usability remain
external.

## T19 Release / Rollback

No commit or push is authorized. Rollback affects Assistant configuration,
provider validation, response presentation, aggregate status UI, QA/tests, and
docs only. No database or model rollback is required. Preserve the two prior
runbook corrections and all v5.54 release-candidate controls.

## T20 Final Handoff

Keep the five v5.54 external owner tracks open. Additional local work should be
limited to proven defects or separately approved accessibility/startup polish;
do not reinterpret local Gemini connectivity as institutional acceptance.
