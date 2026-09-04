# T1-T20: v5.57 End-to-End Analyst Workflow, Accessibility, And Startup Reliability Lock

## T1 Change Title

v5.57 End-to-End Analyst Workflow, Accessibility, And Startup Reliability
Lock.

## T2 Requirement

Verify and repair the local analyst journey from MFU-shell entry through
investigation, Assistant follow-up, simulated response, and audit while making
startup and the primary React surfaces accessible and predictable.

## T3 Source Evidence

MFU-shell launcher scripts, authentication contracts, React application shell
and SOC pages, deterministic ingestion/detection/investigation services,
Assistant response contracts, existing controlled scenarios, Playwright, and
v5.54-v5.56 release-candidate evidence.

## T4 Previous Behavior

Core workflows were individually tested, but no current disposable acceptance
joined Assistant continuity to ingestion-through-audit. Repeated healthy
startup errored, diagnostics returned local paths, and automated accessibility
testing exposed keyboard, ARIA, labelling, focus, and contrast defects.

## T5 Impacted Areas / Agents

React application shell, common controls, primary analyst pages, accessibility
tests, Assistant intent classification, disposable workflow validation,
Windows lifecycle scripts, backend tests, runbooks, and governance records.

## T6 Scope

Local workflow reliability, accessibility, responsiveness, startup diagnosis,
and controlled acceptance only. No schema, parser, rule threshold, model
lifecycle, alert authority, IAM provider, or response-authority change.

## T7 Functional Requirements

- Preserve one selected entity through Assistant follow-ups.
- Verify ingestion through audit in disposable storage.
- Support keyboard-only route, select, and drawer workflows.
- Expose valid landmarks, labels, focus, status, and progress semantics.
- Preserve five target viewport layouts without page overflow.
- Make healthy repeated startup idempotent and partial state actionable.
- Return no machine paths or secrets from status diagnostics.

## T8 Acceptance Criteria

Integrated acceptance, focused regressions, full backend/frontend suites,
automated WCAG checks, five viewport checks, real local start/restart-status/
stop evidence, controlled detection validations, Assistant QA, security,
performance, release, and hygiene checks pass without protected-data access.

## T9 API Contract

No product API route changes. The launcher JSON status removes absolute roots
and adds configuration booleans, a sanitized template error, and an actionable
next command. Assistant chat keeps its existing read-only API contract.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. The acceptance runner uses temporary
in-memory SQLite. No configured-data reset, protected evidence access, label
write, or model artifact write occurs.

## T11 Backend Plan / Changes

Extend controlled workflow validation with three contextual Assistant turns,
case handoff, privacy checks, auditing, and authoritative-row delta checks.
Add a privacy-safe v5.57 acceptance CLI and repair the related-log intent
phrase uncovered by that sequence.

## T12 Frontend Plan / Changes

Add skip and main landmarks, route focus/announcement, accessible loading,
dialog focus management, keyboard-complete selects, valid progress semantics,
labels, focus visibility, reduced motion, contrast repair, axe coverage, and
five-viewport regression.

## T13 Security / Response / AI Safety

No secrets, paths, private logs, numeric addresses, raw provider content, or
protected decisions enter acceptance output. Rules remain alert-authoritative,
ML remains advisory, Assistant calls remain deterministic and read-only, and
response remains simulated.

## T14 Test Plan

Test Assistant mode continuity and zero side effects; privacy-safe acceptance
output; runtime state classification and sanitized diagnostics; login and core
route axe scans; skip-link, route-focus, select, and dialog keyboards; desktop,
tablet, and mobile layout; complete backend/frontend and release matrices.

## T15 Implementation Summary

An integrated disposable workflow, related-log intent repair, idempotent
launcher, safe diagnostics, consistent wrapper guidance, accessible common UI
contracts, MFU-compatible contrast values, automated axe checks, keyboard
regressions, five-viewport coverage, and the affected legacy source-contract
acceptance check are implemented.

## T16 Tests Run / Evidence

Focused backend tests pass `34/34`; repaired v5.38 regressions pass `8/8`;
direct and release-gate backend runs each pass `1067/1`; integrated workflow
passes `24/24`; Ruff, compileall, Alembic, React lint/build, Playwright `42/1`,
controlled source `4/4`, deterministic `24/24`, layered `288/288`, Assistant
QA `30/30`, replay, security, dependency audits, performance, deployment
operations, release, exact `61/61` reconciliation, empty staging, and hygiene
checks pass. Performance retains one soft cold-Overview warning.

## T17 PRD / Docs Updated

v5.57 status and T1-T20 records, current system state, PRD, traceability,
compliance, AI docs index, lab/team startup guidance, taskboard/HTML, and exact
cumulative allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Automated accessibility is not certification; controlled evidence is not
field accuracy; local shell startup is not teammate or MFU acceptance. Physical
machine, provider, university, field-source, shared-host, and independent
usability gates remain external.

## T19 Release / Rollback

No commit or push is authorized. Rollback is limited to common UI semantics,
Playwright dependency/tests, workflow validation, Assistant phrase matching,
startup scripts/tests, and docs. No database or model rollback is required.

## T20 Final Handoff

Keep v5.54 `local_release_candidate_ready` and `production_ready=false`.
Complete external owner evidence instead of inventing additional local
readiness. Preserve all v5.56 Assistant reliability changes.
