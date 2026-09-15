# T1-T20: v5.50 Current-State Truth Lock

## T1 Change Title

v5.50 Current-State Truth Lock And Finish-Line Consolidation.

## T2 Requirement

Publish one accurate, reproducible, privacy-safe description of the current
ATDR product and reduce the remaining roadmap to the shortest honest finish
line after the completed v5.49b supervised decision.

## T3 Source Evidence

Published commit `1866086e6ba9d0e6ac752e4b44e2b54a2acd6fb0`, GitHub Actions
run `33348242534`, runtime source under `atdr/app/` and `frontend/src/`, CI and
release scripts, active governance documents, and aggregate v5.49b status.
Protected rows or private generated evidence were not used.

## T4 Current Behavior

ATDR implements the controlled collection-to-audit SOC workflow. Rules are
alert-authoritative, anomaly and supervised output are advisory, the supervised
lifecycle is `shadow_observation` with no qualified candidate, the Assistant is
read-only, response is simulated, and real blocking is disabled.

## T5 Impacted Areas / Agents

Documentation, AI/ML Governance, Product/PRD, University Compliance,
Taskboard, Release/Ops, Security/Privacy, and future phase planning.

## T6 Scope

Audit runtime source, correct active documentation drift, record the aggregate
v5.49b decision, classify completion and external gates, publish a four-phase
finish line, run verification, and produce an exact allowlist. Runtime behavior
and private evidence are out of scope.

## T7 Functional Requirements

- Identify the exact published baseline and CI result.
- Distinguish controlled implementation from field/provider/deployment proof.
- State that v5.49b ran once and selected no candidate.
- Never present historical artifacts as a qualified current supervised model.
- Preserve all alert, model, Assistant, IAM, and response authority boundaries.
- Expose only aggregate supervised facts.
- Assign remaining work to Codex or the required external owner.
- Limit the roadmap to v5.51-v5.54 unless evidence requires another phase.

## T8 Acceptance Criteria

Active truth documents agree on baseline, lifecycle, authority, limitations,
and roadmap; stale current claims are corrected; protected/private data remain
absent; complete verification and hygiene pass; the exact changed-path set is
documented; no runtime or database behavior changes.

## T9 API Contract

No API change.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration change. The source audit did not use
the configured database. Later verification read only aggregate health and
performance state; it did not reset, delete, migrate, or modify configured
data.

## T11 Backend Plan / Changes

No backend runtime change. Backend source is inspected only to establish the
mounted routes, ingestion/parser/detection/ML/Assistant/IAM/operations truth.

## T12 Frontend Plan / Changes

No frontend runtime change. React source is inspected only to establish route,
workflow, RBAC, persistence, responsive, and safety behavior.

## T13 Security / Response / AI Safety

No protected row, decision, identity, path, fingerprint, prediction, claim,
digest, raw log, provider payload, credential, or secret is published. Rules
remain alert-authoritative. Supervised lifecycle remains
`shadow_observation`; the Assistant stays read-only; automatic response and
real blocking remain disabled.

## T14 Test Plan

Run taskboard render/check, Ruff, compileall, full backend tests, Alembic check,
React lint/build/Playwright, controlled source and layered detection validation,
Assistant QA, replay dry-run, performance smoke, release gate, diff check,
privacy checks, ignored-output checks, staging check, and exact allowlist
reconciliation.

## T15 Implementation Summary

The README, current system state, current AI/ML status, product finish line,
AI docs index, AI runbook, PRD, traceability, compliance checklist, and
taskboard are consolidated around the published v5.49b truth. A canonical
v5.50 lock, this T1-T20 record, and an exact allowlist are added.

## T16 Tests Run / Evidence

Taskboard render/check, Ruff, compileall, and Alembic pass. Backend passes
`1027` with one intentional skip. React lint/build pass; Playwright passes `37`
with one intentional external live-source skip. The controlled source scenario
passes, controlled detection passes `24/24`, layered validation passes
`288/288` with controlled FP/FN `0/0`, Assistant QA passes `20/20`, replay
writes zero, performance passes all budgets without warnings, and release is
`ok: true`. The first direct backend run hit a Windows global-temp ACL denial;
the authoritative ignored `.tmp` rerun and independent release-gate rerun both
pass.

## T17 PRD / Docs Updated

`README.md`, current state and AI/ML status, product finish line, AI docs index,
AI runbook, PRD, traceability, compliance checklist, taskboard/HTML, v5.50
status, change record, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Fresh independent evidence is not created by documentation. Detection field
qualification requires hardware and reviewers; MFU IAM requires university
inputs; Gemini shared use requires provider/privacy approval; deployment
acceptance requires an approved host. The consumed v5.49b result cannot be
retuned or rerun.

## T19 Release / Rollback

No commit or push is authorized. Rollback is documentation-only: revert the
v5.50 tracked paths while preserving the published v5.49b baseline and all
private evidence custody.

## T20 Final Handoff

After verification and separate publication approval, proceed to v5.51
Detection Pipeline Field Qualification And Fresh Evidence. Complete local
harness work independently, fail closed when hardware or reviewed evidence is
absent, and preserve every current authority boundary.
