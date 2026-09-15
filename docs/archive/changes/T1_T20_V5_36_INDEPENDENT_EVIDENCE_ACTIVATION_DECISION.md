# T1-T20: v5.36 Independent Evidence And Activation Decision

## T1 Change Title

v5.36 Independent Evidence Execution and Supervised Activation Decision.

## T2 Requirement

Execute all locally available frozen detection, Assistant, and Gemini
acceptance gates honestly; expose one fail-closed supervised lifecycle
decision; and provide exact human and institutional handoffs without
fabricating labels, revealing blind predictions, or changing runtime
authority.

## T3 Source Evidence

v5.26 sealed prediction lock, v5.27 blind validator/evaluator and Gemini
quality service, v5.28 review helper and readiness audit, v5.30 evidence
closure and fixed gates, v5.33 acceptance coordinator and worksheet, v5.34
Assistant response contracts, registered model metadata, AI runbook, PRD,
traceability, compliance, and current AI status.

## T4 Current Behavior

The sealed pack had 0/40 genuine human decisions and correctly withheld every
frozen metric. The Assistant worksheet had 0/8 human scores. The registered
artifact could produce non-independent configured-data diagnostics, but no
single command combined those facts into an explicit final activation matrix.

## T5 Impacted Areas / Agents

AI/ML governance, evidence custody, backend diagnostic service and CLI,
Assistant/provider quality, security/response safety, QA, documentation, and
release operations. Runtime API and frontend behavior are unchanged.

## T6 Scope

Read-only orchestration, safe aggregate projections, fixed activation gates,
human handoff, bounded Gemini audit, focused tests, governance records, and
full verification. Training, threshold selection, label creation, artifact
writes, activation, API/UI changes, and response authority are out of scope.

## T7 Functional Requirements

- Reuse existing sealed evidence and fixed gates.
- Reveal no predictions or metrics before strict human intake passes.
- Separate blind metrics from non-independent configured diagnostics.
- Compare frozen rule, IsolationForest, supervised, and hybrid layers only
  after valid human review exists.
- Require every evidence and quality gate for activation-review eligibility.
- Never activate a model; only recommend a separate explicit review.
- Audit Assistant automated/human acceptance and Gemini operations separately.
- Prove zero configured authority mutation and preserve all safety controls.

## T8 Acceptance Criteria

Current 0/40 review withholds all blind metrics, evidence locks pass, the
registered artifact is diagnostic-only, the final decision remains
`shadow_observation`, Assistant human acceptance remains 0/8, bounded Gemini
checks are privacy-safe, all mutation deltas are zero, and verification gates
pass.

## T9 API Contract

No API route, request, response, authentication, frontend, or startup contract
changes. v5.36 is a local governance CLI and service.

## T10 Data Model / Migration

No schema or migration change. The configured database is read only. Generated
JSON/Markdown reports remain ignored private diagnostics.

## T11 Backend Plan / Changes

Add one coordinator that invokes v5.33 for sealed review, Assistant, and
provider evidence and v5.30 for registered-shadow diagnostics. Project only
safe aggregates, evaluate the frozen gates, compare before/after authority
counts, and emit a conservative lifecycle decision.

## T12 Frontend Plan / Changes

No frontend source change. Existing AI Governance and Assistant behavior are
regression-verified by the full frontend suite.

## T13 Security / Response / AI Safety

No secrets, provider payloads, raw logs, IPs, absolute private paths,
fingerprints, row predictions, or reviewer identities are returned. Rules
remain alert-authoritative. ML and Gemini remain advisory/read-only. No model,
label, detection, user, response, automation, or blocking authority is added.

## T14 Test Plan

Verify early metric withholding, post-gate aggregate metric projection,
prediction/detail stripping, strict human provenance, fixed-gate behavior,
diagnostic-only shadow results, no activation, no mutation, no secret
exposure, existing detection and Assistant locks, full backend/frontend
regression, migration drift, performance, release, and repository hygiene.

## T15 Implementation Summary

Added the v5.36 read-only service, CLI, and six focused tests. The report
separates sealed blind evaluation, configured-data shadow diagnostics,
activation gates, Assistant automated/human evidence, Gemini operational
status, exact handoff, external blockers, and safety state.

## T16 Tests Run / Evidence

Focused v5.36 tests pass `6/6`. The real no-write audit reports 40 sealed
rows, 0 valid human decisions, 3/9 evidence gates, 0/7 evaluable quality gates,
zero configured mutations, and `shadow_observation`. A bounded live Gemini
run passes 12/12 automated checks across six calls with median/p95
`2,879.5/3,832 ms`, 21,572 tokens, no raw logs/IPs/secrets, and zero actions.
The complete local matrix passed: taskboard render/check, Ruff, source
compileall, focused `43 passed`, backend/release `902 passed, 1 skipped`,
Alembic no drift, npm audit `0`, React lint/build, Playwright `31 passed, 1
skipped`, controlled detection `24/24`, layered detection `288/288`, Assistant
QA `20/20`, replay dry-run, warning-free performance smoke, release gate
`ok: true`, and exact allowlist/privacy/hygiene checks.

## T17 PRD / Docs Updated

v5.36 status, this change record, exact allowlist, current AI status, AI
training runbook, lab runbook, PRD, traceability, compliance checklist, and
rendered taskboard.

## T18 Risks / Blockers / Assumptions / Decisions

No qualified human review, second verified physical source, independent
training-overlap exclusion, or institutional Gemini approval exists. The
configured shadow diagnostic misses FPR, recall, F1, and calibration gates and
is not promotion evidence. These blockers cannot be repaired honestly by code
or AI-generated labels.

## T19 Release / Rollback

No commit or push is authorized by this record. Release requires separate
approval of the exact v5.36 allowlist. Rollback removes the new read-only
service/CLI/tests/docs only; no database or model rollback is required.

## T20 Final Handoff

A genuine reviewer completes the two ignored worksheets. A second real source
and institutional provider owners supply external evidence. Rerun v5.36 after
those inputs. A future all-green result still requires a separate explicit
activation change; response automation and real blocking stay disabled.
