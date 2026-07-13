# T1-T20 Change Document: v3.88 Product Baseline Consolidation And Release Checkpoint

## T1 Change Title

- Title: v3.88 Product Baseline Consolidation And Release Checkpoint
- Date: 2026-07-12
- Owner / acting agent: Codex
- Related version: v3.88

## T2 Requirement

Consolidate the heavily modified but verified v3.78-v3.87 worktree into a coherent, secure, reproducible, documented commit set before adding PostgreSQL, workers, observability, or further ML work.

## T3 Source Evidence

| Area | Source Evidence |
| --- | --- |
| Git/worktree | `git status`, `git diff --stat`, `git diff --check`, `.gitignore` |
| Runtime | `atdr/app/main.py`, routers, services, schemas, models |
| Template handoff | `atdr/app/services/mfu_iam_service.py`, `frontend/src/pages/LoginPage.tsx`, v3.78-v3.86 docs/tests |
| Assistant | `atdr/app/services/assistant_llm.py`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, v3.87 docs/tests |
| CI | `.github/workflows/ci.yml`, `atdr/scripts/verify_release.py`, `frontend/package.json` |
| External template | Advisor template `frontend-vue/src/views/Dashboard.vue` launcher markers |

## T4 Current Behavior

- FastAPI/React/SQLAlchemy/Alembic remain the ATDR runtime.
- SQLite remains local default.
- Template shell is optional; local login is fallback.
- Gemini is optional; deterministic assistant fallback remains.
- Response automation, real blocking, and model promotion remain disabled.
- The visible worktree contains intended implementation/tests/docs plus ignored private/runtime state.

## T5 Impacted Areas / Agents

Orchestrator, Product, Security/IAM, Backend, Frontend, Assistant/AI Governance, QA, Documentation, and Release/Ops are impacted. Data model and detection runtime behavior are not changed by v3.88.

## T6 Scope

In scope: audit, classification, source/doc reconciliation, CI/clean-config validation, safety/hygiene audit, checkpoint docs, exact staging plan, and full verification.

Out of scope: schema migration, PostgreSQL cutover, worker queue, new detection/ML behavior, response enforcement, raw-log LLM context, or production claim.

## T7 Functional Requirements

1. Preserve all user data and unrelated changes.
2. Classify every visible change and private ignored category.
3. Make docs match source truth for template handoff and Gemini assistant.
4. Prove CI/clean configuration does not require private secrets or current DB.
5. Produce an exact non-wildcard staging manifest.
6. Preserve all response/ML/assistant safety invariants.

## T8 Acceptance Criteria

- No private/generated artifact is tracked or recommended for staging.
- README, frontend README, state lock, roadmap, traceability, compliance, runbook, PRD, index, and tasklist agree with current source.
- Clean-config backend and frontend checks pass without private `.env` or current DB.
- Full required verification and release gate pass.
- Exact staging/rollback commands exist and no commit/push occurs automatically.

## T9 API Contract

No new v3.88 API contract. This checkpoint consolidates the already implemented optional IAM and assistant contracts.

## T10 Data Model / Migration

No schema change and no migration. Existing database is not reset, copied into a clean test, or modified by checkpoint documentation/audit.

## T11 Backend Plan / Changes

Audit existing v3.78-v3.87 backend changes, run safety tests, reconcile docs, and fix only proven inconsistencies.

## T12 Frontend Plan / Changes

Audit handoff/fallback and assistant context/provider UI behavior, update frontend documentation, and run full Playwright coverage.

## T13 Security / Response / AI Safety

- Secrets and private `.env` values remain outside Git.
- Local login fallback remains.
- Raw logs remain excluded from external LLM context.
- Assistant remains read-only.
- Response automation and real blocking remain disabled.
- ML remains candidate-only decision support.

## T14 Test Plan

Tasklist render/check, Ruff, compileall, full backend tests, Alembic check, React lint/build/Playwright, safe provider status probes, replay dry-run, performance smoke, release gate, clean-config simulation, and secret/path hygiene scans.

## T15 Implementation Summary

- Reconciled stale documentation with implemented template-session handoff and v3.87 Gemini behavior.
- Added v3.88 checkpoint and exact changeset manifest.
- Classified ignored/private/external state and rollback behavior.
- Replaced the identifiable student test email in trackable docs/tests with a synthetic domain-valid fixture.
- Added Node `>=20.19.0` compatibility metadata and non-breaking frontend lock updates that reduce npm audit findings from five to zero.
- Selected PostgreSQL/shared-lab persistence as the next product phase.

## T16 Tests Run / Evidence

| Check | Result |
| --- | --- |
| Tasklist render/standard | passed |
| Ruff / compileall | passed |
| Backend tests | `473 passed, 1 skipped` |
| Alembic check | no drift |
| Clean-config simulation | no private `.env`/current DB; `89 passed`; clean frontend build passed |
| npm install/audit | passed; zero vulnerabilities |
| React lint/build | passed |
| Playwright | `19 passed, 1 skipped` |
| Template static contract/readiness | passed; no secrets exposed |
| Provider status probes | passed without real call; no secrets/raw logs |
| Replay dry-run | passed; no writes |
| Performance repeat | no warnings; Overview `0.3794s`, cached `0.0057s`, ML Governance `1.1196s` |
| Release gate | `ok: true` |

## T17 PRD / Docs Updated

README, frontend README, state lock, roadmap, PRD, traceability, compliance checklist, docs index, lab runbook, tasklist/HTML, v3.88 checkpoint, manifest, and this T1-T20 record.

## T18 Risks / Blockers / Assumptions / Decisions

- No current code blocker identified.
- External template folder is not version controlled and currently has no discoverable launcher backup.
- Clean advisor archive is the external rollback source.
- Private provider/IAM configuration remains local and uncommitted.
- The next phase will not begin until this checkpoint is staged/committed deliberately.

## T19 Release / Rollback

No automatic commit or push. Disable optional provider/handoff flags for immediate runtime rollback. Revert the future checkpoint commit for source rollback. No data rollback is required.

## T20 Final Handoff

- Status: completed.
- Commit set: `docs/V3_88_CHANGESET_MANIFEST.md`.
- Verification: all required checks passed; source ready for exact-path staging.
- Next phase: PostgreSQL/shared-lab persistence and backup/restore validation after checkpoint commit/CI.
