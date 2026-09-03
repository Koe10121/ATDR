# T1-T20: v5.54 Release Candidate Truth Lock And Operator Handoff

## T1 Change Title

v5.54 Release Candidate Truth Lock And Operator Handoff.

## T2 Requirement

Finish all locally controllable release-candidate work, freeze supported
profiles and honest claims, and hand external acceptance to named owners.

## T3 Source Evidence

Runtime/configuration source, lifecycle scripts, CI, migrations, React routes,
current readiness services, deployment assets, security controls, current-state
documents, and the published v5.53 baseline.

## T4 Current Behavior

Local functionality was broad and verified, but the Windows disposable runner
could hang on inherited capture handles, lifecycle acceptance omitted restart
and recovery, readiness labels conflated local and external state, and active
status documents accumulated stale historical claims.

## T5 Impacted Areas / Agents

Team setup, startup/recovery, readiness API/schema/UI, operator documentation,
release governance, QA, security, and external-owner handoff.

## T6 Scope

Fix proven release-blocking lifecycle/readiness defects and consolidate current
truth. Do not add speculative product features or change detector, model,
Assistant, identity, database, or response authority.

## T7 Functional Requirements

- Verify shell-first local SQLite and explicit local recovery.
- Exercise setup, start, health, handoff, stop, restart, and recovery.
- Distinguish local verification from external accepted/pending/unavailable/
  failed states.
- Publish concise operator and owner handoffs.
- Preserve all privacy, ML, detection, and response boundaries.

## T8 Acceptance Criteria

The clean disposable lifecycle passes all 11 stages; local controls are green;
external evidence remains pending; full verification passes; private data and
secrets remain excluded; `production_ready=false`.

## T9 API Contract

The existing admin-only release-readiness response adds typed
`readiness_states` and per-track `acceptance_state`. No endpoint gains mutation
authority.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration.

## T11 Backend Plan / Changes

Repair Windows lifecycle process handling, add bounded health/handoff checks
and disposable recovery authentication, and classify readiness with explicit
local/external states.

## T12 Frontend Plan / Changes

Render explicit status badges for local verification, external acceptance,
pending evidence, unavailable resources, and failures. Never expose config
values or secrets.

## T13 Security / Response / AI Safety

Use disposable SQLite and owned child processes; generate recovery credentials
ephemerally; never expose them; preserve shell-first normal login, read-only
Assistant, rule authority, simulation-only response, and disabled blocking.

## T14 Test Plan

Lifecycle/readiness regressions; full backend; Alembic; React lint/build and
Playwright; source/detection/layered/Assistant/Gemini validation; replay;
performance; security/dependency/deployment/release gates; taskboard and repo
hygiene.

## T15 Implementation Summary

Added capture-safe long-lived process execution, 11-stage disposable lifecycle
acceptance, local-recovery smoke, login-handoff checks, explicit readiness
states, dashboard badges, concise status locks, and final operator/owner docs.

## T16 Tests Run / Evidence

Clean disposable lifecycle passes `11/11`; controlled source `4/4`; detection
`24/24`; layered detection `288/288`; Assistant QA `20/20`; private Gemini
minimal/full synthetic probes pass; performance, source scan, Python/npm audit,
and deployment validation pass. Full backend passes `1052/1`; Playwright passes
`38/1`. The independent release gate passes with `ok=true`, zero failed
required checks, Alembic at head, deployment controls valid, simulation on,
and `production_ready=false`. Final hygiene passes with exactly 27 allowlisted
paths, empty staging, clean diff check, zero tracked-source findings, and no
private/generated evidence tracked.

## T17 PRD / Docs Updated

README, current state, current AI/ML status, v5.54 truth lock, operator handoff,
external-owner checklist, PRD, traceability, compliance, runbooks, docs index,
taskboard/HTML, T1-T20, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

MFU, shared-host, provider, teammate, and independent field-evidence acceptance
remain external. The release decision is local-only and cannot be expanded by
configuration or same-machine testing.

## T19 Release / Rollback

No commit/push is authorized. No database rollback is required. Revert only
the v5.54 code/doc paths if later verification proves a regression; never
delete configured data or protected evidence.

## T20 Final Handoff

Final decision: `local_release_candidate_ready`, with
`production_ready=false`. Broad local feature development ends at v5.54. The exact 27-path allowlist
authorizes no Git action. Run the five external acceptance
tracks in parallel, record real owner evidence, and make a separate release or
model-activation decision only after its gates pass.
