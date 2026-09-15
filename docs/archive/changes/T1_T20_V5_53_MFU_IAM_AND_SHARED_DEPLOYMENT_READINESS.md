# T1-T20: v5.53 MFU IAM And Shared Deployment Readiness

## T1 Change Title

v5.53 MFU IAM And Shared Deployment Readiness.

## T2 Requirement

Complete every locally controllable IAM, deployment, provider, security, and
teammate-runtime control while failing closed on externally owned acceptance.

## T3 Source Evidence

MFU handoff/auth services, configuration validation, preproduction acceptance,
database/worker/backup/monitoring services, setup/start/check/stop scripts,
Assistant provider telemetry, deployment assets, CI, and current runbooks.

## T4 Current Behavior

The source had mature shell-first auth and deployment foundations, but no
single expiring external-evidence contract, no aggregate release-readiness API,
wildcard CORS methods/headers, no backend dependency audit/CodeQL/SBOM gate,
and no disposable team-machine acceptance CLI.

## T5 Impacted Areas / Agents

IAM, backend, frontend Admin/AI Governance, release operations, deployment,
security, provider governance, teammate onboarding, QA, and documentation.

## T6 Scope

Add fail-closed readiness aggregation, private acceptance manifests,
disposable rehearsal tooling, explicit CORS, security CI, dependency repair,
professional status surfaces, tests, runbooks, and governance. No second auth
system, model activation, response automation, or blocking.

## T7 Functional Requirements

- Preserve mandatory template-shell normal login and secure one-time handoff.
- Require analyst default and explicit group-based admin mapping.
- Distinguish local controls from external acceptance and production claims.
- Surface database, workers, backups, monitoring, TLS, secrets, Gemini, and
  external blockers without secrets or raw configuration.
- Rehearse clean-clone startup only in disposable storage with confirmation.
- Audit dependencies/secrets, generate SBOMs, and run Python/TypeScript CodeQL.

## T8 Acceptance Criteria

All new tests and the complete regression matrix pass; dependency audits have
no known high-risk blocker; readiness output exposes no secret/path; external
evidence is absent/expired/incomplete by default; zero model, detection,
response, label, or configured-database mutation occurs.

## T9 API Contract

Admin-only `GET /api/operations/release-readiness` returns aggregate v5.53
status. Existing authentication and Assistant endpoints are unchanged.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Acceptance manifests are private,
ignored, bounded JSON files outside the database.

## T11 Backend Plan / Changes

Strengthen configuration validation; add readiness/security services and CLIs;
reuse existing preproduction, IAM, database, Assistant, worker, backup, and
monitoring source truth; never infer acceptance from configuration alone.

## T12 Frontend Plan / Changes

Add compact Admin release-readiness and AI Governance provider panels with
wrapping, aggregate status, professional wording, and no secret/raw JSON.

## T13 Security / Response / AI Safety

Hashed lock, dependency audits, secret scan, SBOM, CodeQL, explicit CORS,
secure-origin checks, expiring manifests, raw-log exclusion, redaction, and
zero side effects. Rules remain authoritative; ML and Assistant remain
advisory/read-only; response simulation remains required.

## T14 Test Plan

Focused readiness/security/IAM/Assistant tests; full backend; Alembic; React
lint/build/Playwright; source/detection/layered/Assistant QA; Gemini safe
probes; replay; performance; deployment validation; release; privacy/hygiene;
taskboard; diff; staging; exact allowlist.

## T15 Implementation Summary

Implemented secret-safe readiness contracts/API/CLIs, disposable teammate
rehearsal, security CI/SBOM/CodeQL, dependency remediation, explicit CORS, UI,
tests, external-owner manifests, and governance updates.

## T16 Tests Run / Evidence

Focused v5.53 tests pass `8/8`; upgraded authentication/Assistant tests pass
`55/55`; full backend/release passes `1048 passed, 1 skipped`; Alembic reports
no drift; React lint/build pass; Playwright passes `38/1`; controlled source,
deterministic detection, layered detection, and Assistant QA pass `4/4`,
`24/24`, `288/288`, and `20/20`. Configured Gemini minimal/full synthetic
probes, replay dry-run, every performance budget, deployment validation, and
release `ok: true` pass. Python/npm audits report zero known findings, source
scan reports zero findings, and source/frontend SBOMs contain `395/276`
components. The only new dependency warning is the non-failing Starlette test-
client migration notice for future `httpx2` adoption.

## T17 PRD / Docs Updated

v5.53 status, manifest runbook, current state, current AI status, PRD,
traceability, compliance, AI docs index, team/lab/deployment/operations
runbooks, README, taskboard/HTML, T1-T20, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

MFU provider lifecycle, real admin group, approved host, institutional Gemini,
physical teammate machine, and second-source detection evidence remain
external. No acceptance is fabricated from a template, mock, or local probe.

## T19 Release / Rollback

No commit/push is authorized. Runtime changes are additive/configuration based;
no database rollback is required. Restore the prior dependency lock and remove
v5.53 routes/services/UI only if full compatibility verification fails.

## T20 Final Handoff

After complete verification and separately approved publication, proceed to
v5.54 Release Candidate Truth Lock And Operator Handoff. One local closure
phase and five external acceptance tracks remain.
