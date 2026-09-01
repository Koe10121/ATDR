# T1-T20: v5.51 Detection Pipeline Field Qualification And Fresh Evidence

## T1 Change Title

v5.51 Detection Pipeline Field Qualification And Fresh Evidence.

## T2 Requirement

Close locally implementable detection-pipeline qualification work and provide
one privacy-safe, fail-closed path for real transport, parser-field accuracy,
rule FP/FN review, and fresh evidence without touching consumed v5.49b evidence.

## T3 Source Evidence

Published v5.49b commit `1866086e6ba9d0e6ac752e4b44e2b54a2acd6fb0`,
v5.50 truth lock, PAN-OS parser/contract source, deterministic rule and grouping
services, v5.23 live-source acceptance, v5.41/v5.44 evidence custody patterns,
Evidence Review API, AI Governance UI, and existing tests. Protected v5.49b
rows and private generated evidence were not opened.

## T4 Current Behavior

Local file/API/loopback transport, parsing, rules, source health, and safety
contracts are controlled-validated. Real non-loopback firewall/router
acceptance, field accuracy, reviewed rule metrics, a second source, and fresh
future windows remain external. Rules are authoritative; ML is advisory.

## T5 Impacted Areas / Agents

Ingestion, Parser, Detection Rules, Evidence Governance, Backend API, React AI
Governance, Security/Privacy, QA, Release/Ops, and Documentation.

## T6 Scope

Add a disposable qualification service/CLI, versioned private input contracts,
prediction-blind rule review packaging, fresh evidence roles, aggregate status
API/UI, tests, governance, and exact allowlist. No training, activation,
response, database schema, or alert-authority change is in scope.

## T7 Functional Requirements

- Require explicit disposable storage and preserve the configured database.
- Distinguish loopback, second-laptop, and physical-device evidence.
- Validate supported PAN-OS layouts and aggregate field accuracy.
- Reuse production deterministic rule/grouping logic for diagnostics.
- Withhold rule metrics until a complete prediction-blind human review exists.
- Require an attack type for suspicious/malicious review decisions.
- Create fixed duplicate-contained chronological evidence roles.
- Exclude all pre-boundary evidence without opening v5.49b.
- Expose only authenticated aggregate readiness.
- Keep all authority and safety boundaries unchanged.

## T8 Acceptance Criteria

Local preflight and controlled full pass succeed; known/extended/partial/
unsupported parser fixtures behave deterministically; private source and review
contracts fail closed; duplicate families do not cross roles; API requires
authentication and returns no private data; UI is concise and overflow-free;
complete verification and hygiene pass.

## T9 API Contract

Adds authenticated read-only
`GET /api/evidence-review/field-qualification/status`. The response contains
the fixed readiness enum, aggregate gates, transport/parser/review/fresh counts,
blockers, and false safety flags. It contains no mutation endpoint.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Private manifests/reviews/seals are
generated only under ignored evidence storage. No configured database write is
allowed.

## T11 Backend Plan / Changes

Add the v5.51 service and CLI, schema and route, privacy validation, source and
field attestation validators, prediction-blind metrics, duplicate-contained
role assignment, and focused tests.

## T12 Frontend Plan / Changes

Add typed API/query support and a compact AI Governance qualification panel
showing device transport, parser contract, rule review, fresh evidence, and
authority badges. Do not expose raw JSON or private input.

## T13 Security / Response / AI Safety

Private paths, rows, addresses, identities, fingerprints, seals, and secrets
remain absent from public output and Git. AI/assisted identities cannot attest
human evidence. No label/model/alert/detection/response write is performed.
Rules remain alert-authoritative; model lifecycle stays `shadow_observation`;
automatic response and real blocking stay disabled.

## T14 Test Plan

Run focused parser/attestation/field/review/role/privacy tests, authenticated
route tests, React lint/build and focused Playwright, then taskboard checks,
Ruff, compileall, full backend, Alembic, full Playwright, controlled source,
24-scenario and 288-layer validation, Assistant QA, replay, performance,
release, privacy, ignored-output, diff, staging, and allowlist checks.

## T15 Implementation Summary

The v5.51 qualification service, operator CLI, authenticated aggregate status,
AI Governance panel, source/field/review contracts, fresh evidence protocol,
tests, status record, and governance updates are implemented. Local status is
honestly `hardware_required`.

## T16 Tests Run / Evidence

Focused v5.51 service/API tests pass `11/11`. The full backend suite and release
gate pass `1037` tests with `1` intentional skip. Alembic reports no drift;
React lint/build pass; Playwright passes `37` tests with `1` intentional
live-source skip; controlled and layered detection pass `24/24` and `288/288`
with zero controlled FP/FN; Assistant QA passes `20/20`; replay remains
dry-run; and performance budgets pass. Local preflight/full runs account for
`5/5` datagrams, parse `2/2` rows, record zero loss/parse failures, and write no
authoritative state. Privacy, staging, and exact-path reconciliation pass.

## T17 PRD / Docs Updated

README, current system/AI status, AI runbook/index, PRD, traceability,
compliance checklist, taskboard/HTML, v5.51 status, field contract, evidence
protocol, T1-T20 record, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The local harness cannot create physical forwarding or human truth. Two real
devices, four fresh windows, independent field/rule review, and untouched
future support remain required. v5.49b is immutable and inaccessible. Fixed
minimums are qualification gates, not production claims.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes only v5.51 runtime/docs/test
paths while preserving all v5.50 documentation and every private/protected
workspace. No migration or database rollback is needed.

## T20 Final Handoff

After full verification and separate publication approval, proceed to v5.52
Analyst Experience And Assistant Closure while field evidence is collected by
the required external owners. Three substantial shared-lab phases remain.
