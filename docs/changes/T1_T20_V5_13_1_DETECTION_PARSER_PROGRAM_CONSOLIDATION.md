# T1-T20: v5.13.1 Detection/Parser Program Consolidation And Repository Closure

Date: 2026-07-28

## T1 Change Title

v5.13.1 Detection/Parser Program Consolidation And Repository Closure.

## T2 Requirement

Reconcile the complete uncommitted v4.9-v5.13 program into one source-backed
current-state record and exact review boundary before new feature work.

## T3 Source Evidence

- `git status --short --untracked-files=all`
- `git diff`, `git diff --check`, `git ls-files`, and `git check-ignore`
- v4.9-v5.13 status, T1-T20, and allowlist documents
- `atdr/app/main.py`, backend routers/schemas/services, and migrations
- `frontend/src/lib/api.ts`, hooks, types, pages, and Playwright tests
- `atdr/tests/*` and `atdr/scripts/verify_release.py`
- the successful published CI run for commit `e05032a`

## T4 Current Behavior

Published `main` is clean and CI-green at `e05032a`. The local tree contains a
cumulative 177-path v4.9-v5.13 implementation with no staged files. Fourteen
phase allowlists cover 174 paths; three implementation paths were omitted from
phase documentation. No current path is authorized for staging or deletion.

## T5 Impacted Areas/Agents

- Orchestrator and Product Owner: scope reconciliation and handoff
- Detection/Parser/ML: authority and lifecycle truth
- Backend/Database: services, API contracts, and migration chain
- Frontend: TypeScript/API/UI compatibility
- Security/Response Safety: protected-path and no-action boundaries
- QA/Release: complete verification and exact allowlist
- Documentation: current state, taskboard, and change record

## T6 Scope

In scope: audit, path classification, phase reconciliation, documentation
freshness, exact allowlist, verification, hygiene, and next-phase decision.

Out of scope: runtime feature changes, model tuning/activation, label changes,
historical reparse, database migration/reset, provider configuration, response
automation, real blocking, staging, commit, push, or file deletion.

## T7 Functional Requirements

1. Account for every changed path.
2. Resolve all paths missing from phase allowlists.
3. Prove the migration chain and frontend/backend contracts are coherent.
4. Refresh the current-state source of truth through v5.13.
5. Produce one exact approval-gated master allowlist.
6. Run the complete local verification and hygiene matrix.

## T8 Acceptance Criteria

- Every starting path is classified and retained or separately proposed.
- No protected/private/generated evidence enters the allowlist.
- All phase records and paths are present.
- The migration chain has one head and no model/data reset.
- Backend, frontend, scenario, assistant, performance, and release checks pass.
- Staged path count remains zero.
- No commit or push occurs.

## T9 API Contract

No API behavior changes. The audit confirms React calls correspond to mounted
authenticated FastAPI endpoints and current response fields.

## T10 Data Model / Migration

No new migration is introduced. Existing cumulative migrations form the
additive chain `b4c5d6e7f8a9 -> c5d6e7f8a9b0 -> d6e7f8a9b0c1 ->
e7f8a9b0c1d2`.

## T11 Backend Plan / Changes

No backend source change is made by v5.13.1. Existing service changes are
classified, tested, and included in the review boundary.

## T12 Frontend Plan / Changes

No frontend behavior change is made by v5.13.1. Existing API, hook, type, page,
and test changes are contract-checked and included in the review boundary.

## T13 Security / Response / AI Safety

- Rules remain alert-authoritative.
- ML remains advisory in `shadow_observation`.
- No label, activation, promotion, response, firewall, user, or data mutation.
- No secret, `.env`, database, private log, review output, or model artifact.
- Private-path and raw-evidence redaction remain mandatory.

## T14 Test Plan

Run taskboard checks, Ruff, compileall, full backend tests, Alembic check, React
lint/build, Playwright, controlled scenarios, layered detection validation,
assistant QA, replay dry-run, performance smoke, release gate, diff check, and
repository hygiene.

## T15 Implementation Summary

- Reconciled 14 phase status records, 14 T1-T20 records, and 14 allowlists.
- Classified all starting paths by subsystem.
- Included three source-evidenced paths omitted from phase allowlists.
- Found no exact duplicate, oversized, orphaned, or safe deletion candidate.
- Refreshed the current-state lock and taskboard.
- Added this status/change record and an exact master allowlist.

## T16 Tests Run / Evidence

The complete closure matrix passed:

- taskboard render and standards check
- Ruff and compileall
- full backend `741 passed, 1 skipped`
- Alembic current/head `e7f8a9b0c1d2` with no drift
- React lint/build and Playwright `26 passed, 1 skipped`
- controlled scenarios `24/24` with 15 expected alerts and zero response
  actions
- layered validation `288/288` with zero controlled false positives or false
  negatives
- deterministic assistant QA `20/20`, full required citations, and zero
  authoritative side effects
- replay dry-run with two rows parsed and zero writes
- warning-free performance smoke on 145,232 rows
- official release gate `ok: true` with zero failed required checks
- exact allowlist, diff, privacy, ignored-file, staging, and tracked hygiene

An initial full-test run encountered four Windows path-length failures because
its temporary fixture root was too long. A short external temporary-root rerun
and the official release-gate run both passed all 741 runnable tests.

## T17 PRD / Docs Updated

- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/AI-DOCS-INDEX.md`
- `README.md`
- `docs/V5_13_1_DETECTION_PARSER_PROGRAM_CONSOLIDATION.md`
- this T1-T20 record
- `docs/tasks/tasklist-progress.md`
- generated taskboard HTML
- `docs/V5_13_1_COMMIT_ALLOWLIST.md`

The PRD, requirement traceability, compliance checklist, AI runbook, and
current AI/ML status already contain the cumulative v4.9-v5.13 behavior and
remain in the exact review boundary.

## T18 Risks / Blockers / Assumptions / Decisions

- Shared files contain cumulative cross-phase diffs, so phase-by-phase staging
  would be misleading.
- Independent multi-device labels, real SYSTEM logs, provider-backed IAM, and
  approved-host operations remain external gates.
- The closure records scope; it does not make the product or model production
  ready.
- No file removal is justified by current evidence.

## T19 Release / Rollback

No release action is authorized. After successful verification, the owner may
separately approve staging exactly the master allowlist. Rollback for this
closure would remove only the v5.13.1 documents and restore documentation
wording; runtime/data rollback is unnecessary.

## T20 Final Handoff

Review the final verification evidence and exact allowlist. If accepted, obtain
separate explicit approval to stage, commit, and push without force. Monitor
every CI job and make only narrowly scoped fixes if required.
