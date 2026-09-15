# T1-T20: v3.67 CI And Assistant Stability

## T1 Change Title

v3.67 CI And Assistant Stability

## T2 Requirement

Make GitHub CI more representative of ATDR's verified backend and React dashboard gates while preserving safe defaults and no-secret behavior.

## T3 Source Evidence

- `.github/workflows/ci.yml`
- `atdr/app/core/config.py`
- `atdr/scripts/config_doctor.py`
- `frontend/package.json`
- `frontend/playwright.config.ts`
- `docs/V3_66_SOC_ASSISTANT_CONTEXT_HARDENING.md`

## T4 Current Behavior

The local release gate passed after v3.66, but the GitHub workflow only checked backend Python gates. A clean-copy no-`.env` local check also showed that pytest can fail on this Windows machine if it uses the default locked temp root.

## T5 Impacted Areas / Agents

- Release/Ops
- QA
- Frontend / Dashboard
- Backend / API
- Security / Response Safety

## T6 Scope

In scope:
- CI workflow hardening.
- Explicit safe CI environment defaults.
- Frontend dashboard CI job.
- Progress and traceability docs.

Out of scope:
- Runtime startup command changes.
- Schema changes.
- Detection/ML logic changes.
- IAM activation.
- Real external LLM execution.
- Response automation.

## T7 Functional Requirements

- Backend CI must run without private `.env`.
- CI must keep response simulation and assistant raw-log restrictions safe.
- CI must run React lint/build/e2e checks.
- CI must avoid relying on machine-global pytest temp directories.

## T8 Acceptance Criteria

- `.github/workflows/ci.yml` has backend and frontend jobs.
- Backend CI sets safe SQLite and assistant/response defaults.
- Backend pytest uses workspace-local `.tmp` temp/cache paths.
- Frontend CI uses Node.js 20 and runs lint, build, and Playwright.
- Local no-`.env` backend checks pass in a clean copy.

## T9 API Contract

No API contract changes.

## T10 Data Model / Migration

No data model or migration changes.

## T11 Backend Plan / Changes

No backend code changes for v3.67. Backend CI environment values are made explicit in workflow YAML.

## T12 Frontend Plan / Changes

No frontend code changes for v3.67. The existing React dashboard checks are added to CI.

## T13 Security / Response / AI Safety

- `RESPONSE_SIMULATION=true` in CI.
- `ASSISTANT_LLM_ENABLED=false` in CI.
- `ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false` in CI.
- No secrets are configured in CI workflow.

## T14 Test Plan

- Run clean-copy backend CI-equivalent checks without `.env`.
- Run local release gate.
- Continue using existing frontend lint/build/e2e checks.

## T15 Implementation Summary

Updated `.github/workflows/ci.yml` with:
- `backend-release-gate`
- safe backend env defaults
- workspace-local pytest temp/cache paths
- `frontend-dashboard` job using Node.js 20 and Playwright.

## T16 Tests Run / Evidence

- Clean-copy `config_doctor`: pass.
- Clean-copy backend tests with explicit basetemp: `431 passed, 1 skipped`.
- Clean-copy Alembic upgrade/check: pass.
- Clean-copy Ruff: pass.
- Local release gate: `ok: true`.

## T17 PRD / Docs Updated

- `docs/V3_67_CI_AND_ASSISTANT_STABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`
- `docs/AI-DOCS-INDEX.md`

## T18 Risks / Blockers / Assumptions / Decisions

- GitHub runtime may still differ in package install time and Playwright browser setup, but the workflow now explicitly installs Chromium dependencies.
- Performance smoke remains outside CI because it depends on local large SQLite data and is not deterministic across machines.

## T19 Release / Rollback

Rollback is limited to reverting `.github/workflows/ci.yml` and the v3.67 docs. No runtime data or schema rollback is needed.

## T20 Final Handoff

v3.67 makes CI more representative and safer. If GitHub still fails, inspect the failing job log and compare it against the local clean-copy evidence.
