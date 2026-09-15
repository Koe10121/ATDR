# T1-T20: v4.8.1 Repository Consolidation

## T1 Change Title

v4.8.1 NewSystem Reference Archival And Repository Consolidation.

## T2 Requirement

Remove the unused tracked NewSystem runtime copy without losing university
workflow/IAM evidence, touching protected local material, or changing ATDR
behavior.

## T3 Source Evidence

`git ls-files`, `git status --short --untracked-files=all`, `.gitignore`,
runtime/test/script/CI reference searches, `docs/ATDR_REPO_CLEANUP_PLAN.md`,
`docs/AI-DOCS-INDEX.md`, `docs/CURRENT_SYSTEM_STATE_LOCK.md`, the versioned MFU
shell contract, and current ATDR source/tests.

## T4 Current Behavior

ATDR ran independently of a 526-file tracked Node/Vue/Mongo template copy. The
copy duplicated reference material, included unrelated runtime/assets, and made
repository ownership and hygiene harder to understand.

## T5 Impacted Areas / Agents

Orchestrator, Product/Requirements, Security/IAM, QA/UAT, Release/Ops, and
Documentation. Runtime feature agents are verification-only.

## T6 Scope

Archive selected non-secret references, relocate NewSystem-specific workflow
examples, remove the unused tracked runtime copy, update active documentation,
record current AI/ML truth, and create an exact approval-gated allowlist.

## T7 Functional Requirements

- Prove no active runtime/test/script/CI dependency.
- Preserve required template/IAM/workflow evidence.
- Keep the approved companion-shell distribution contract unchanged.
- Keep protected and generated material untouched.
- Update active links and source-truth boundaries.
- Do not commit or push without a separate explicit approval.

## T8 Acceptance Criteria

Zero tracked `NewSystem/` runtime files remain; 24 existing references are
preserved or relocated plus one new archive-scope document (25 files total);
active links resolve; secret-pattern and hygiene checks pass; all runtime gates
pass; no protected file is staged; and the changed-path set exactly equals the
cleanup allowlist.

## T9 API Contract

No API route, payload, status code, or authorization behavior changes.

## T10 Data Model / Migration

No model or migration change. The configured database is not reset, migrated,
or written by this cleanup.

## T11 Backend Plan / Changes

No backend behavior change. Verify FastAPI source, tests, release gate, and
Alembic state after removing the unrelated template runtime.

## T12 Frontend Plan / Changes

No React behavior change. Verify lint, build, and Playwright after removing the
unrelated Vue template runtime.

## T13 Security / Response / AI Safety

Do not read or stage private environments. Sanitize archived legacy identifiers.
Keep Gemini raw-log exclusion/redaction, supervised candidate-only status,
response automation disabled, and real blocking disabled.

## T14 Test Plan

Task-board render/check, Ruff, compileall, backend tests, Alembic check, React
lint/build/Playwright, replay dry-run, performance smoke, release gate,
runtime-reference search, broken-link check, secret-pattern scan, diff check,
tracked hygiene scan, and exact allowlist comparison.

## T15 Implementation Summary

Nine selected files were preserved from the 526-file template copy, 15 original
workflow/history files were relocated to the same archive, and 517 unrelated
tracked runtime files were removed. Active docs now distinguish archived
reference material from the versioned MFU companion shell and ATDR runtime. The
root ignore policy now excludes private `.env.*` files while allowing committed
`.example` templates.

## T16 Tests Run / Evidence

The published v4.8 baseline commit `15e43c8` passed GitHub Actions run
`29640334774` in all three jobs. For this cleanup proposal, task-board
render/standards, Ruff, compileall, Alembic no-drift, React lint/build,
Playwright (`25 passed, 1 skipped`), replay dry-run, read-only performance smoke,
and release gate all passed. The direct backend suite and the release-gate suite
each passed `612 passed, 1 skipped`. Assistant QA passed `20/20`; the bounded
Gemini probe used redacted, non-raw context and exposed no secret. Runtime
dependency, link, secret-pattern, tracked-hygiene, diff, and exact-allowlist
checks passed. The initial direct pytest attempt used a disallowed repository
temp root; the six affected persistence cases and then the complete suite passed
under ATDR's approved ignored `.tmp/` root without weakening the safeguard.

## T17 PRD / Docs Updated

README, current state lock, AI docs index, PRD, requirement traceability,
compliance checklist, cleanup plan/report, template alignment/manifest, task
board, reference scope, and current AI/ML product status.

## T18 Risks / Blockers / Assumptions / Decisions

Private old-directory environment files remain locally and ignored. Historical
docs may mention NewSystem as past evidence; active docs must make their
reference-only status clear. External IAM, deployment, real-source, and model
promotion gates remain open.

## T19 Release / Rollback

No cleanup commit or push is authorized by this record. A future approval must
name `docs/V4_8_1_COMMIT_ALLOWLIST.md`. Rollback is a normal Git restore/revert;
there is no data or migration rollback.

## T20 Final Handoff

Review the consolidation report and exact allowlist, confirm protected-file
exclusions, then provide separate explicit commit/push approval if the cleanup
should be published.
