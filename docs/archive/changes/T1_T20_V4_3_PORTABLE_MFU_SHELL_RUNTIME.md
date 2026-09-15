# T1-T20: v4.3 Portable MFU Shell Runtime

## T1 Change Title

- Title: Portable MFU Outer-Shell Runtime And One-Command Team Startup
- Date: 2026-07-15
- Owner / acting agent: Codex
- Related version: v4.3

## T2 Requirement

- Make the approved MFU shell the normal entry point on every teammate machine.
- Replace machine-specific setup with one setup command and one start command.
- Preserve ATDR's FastAPI/React/SQL architecture and all response/ML safety rules.
- Do not copy the external shell or any private environment file into Git.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| ATDR configuration/auth | `atdr/app/core/config.py`, `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` |
| ATDR frontend entry | `frontend/src/pages/LoginPage.tsx`, `frontend/src/hooks/useAuth.tsx` |
| Secure handoff tests | `atdr/tests/test_mfu_iam_handoff.py`, `atdr/tests/test_template_shell_runtime.py`, `frontend/tests/smoke.spec.ts` |
| Approved shell contract | `<MFU_SHELL_ROOT>/backend-node/server/Project/atdr/*`, `<MFU_SHELL_ROOT>/frontend-vue/src/projects/utils/atdr-handoff.js` |
| Operations | `scripts/system_common.ps1`, setup/start/check/stop scripts |

## T4 Current Behavior

Before v4.3, ATDR and the shell required multiple terminals, private machine paths appeared in active guidance, direct local login could look like the normal path, and a missing configuration could produce confusing startup output. The secure one-time handoff already existed, but team lifecycle orchestration was not portable.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Backend/Auth | Auth profile enforcement and clean configuration failure |
| Frontend | Fail-closed shell login presentation |
| Release/Ops | Portable setup, preflight, start, stop, and process tracking |
| Security | Secret-safe shell integration and recovery isolation |
| QA/Docs | Clean-path tests and teammate runbook |

## T6 Scope

In scope: local Windows lifecycle, separate approved shell discovery, secure handoff profile, safe configuration, docs, and tests.

Out of scope: copying the shell into ATDR, production hosting, provider credential issuance, real firewall response, automatic response, model promotion, and database reset.

## T7 Functional Requirements

| ID | Requirement |
| --- | --- |
| FR-V43-01 | Setup and start must work from arbitrary paths, including spaces. |
| FR-V43-02 | Normal entry must open the MFU shell, not direct ATDR login. |
| FR-V43-03 | Local login must require explicit `local_recovery`. |
| FR-V43-04 | Existing database and private configuration must be preserved safely. |
| FR-V43-05 | Diagnostics must list field names/status only and never secrets. |
| FR-V43-06 | Stop must affect only launcher-owned processes. |

## T8 Acceptance Criteria

- Fresh-path setup dry-run succeeds without file or database mutation.
- Setup/start contain no hardcoded developer path.
- Shell profile rejects local login and exposes no secret.
- One-time handoff tests reject replay and unsafe identity/role mappings.
- All four services have explicit readiness checks.
- Response automation and real blocking remain disabled.

## T9 API Contract

Existing auth routes remain. `POST /api/auth/login` returns 403 in shell mode. `GET /api/auth/mfu-iam/public-status` safely reports auth profile/readiness. The hidden form-post handoff receiver and HttpOnly cookie contract remain unchanged.

## T10 Data Model / Migration

No v4.3 schema change. Setup runs existing additive Alembic migrations only after backing up an existing SQLite database. It never resets or seeds data.

## T11 Backend Plan / Changes

Add explicit auth profiles, validate shell mode without unrelated B2B requirements, reject direct login in normal mode, expose safe mode status, remove machine-path defaults, and return concise configuration-unavailable responses.

## T12 Frontend Plan / Changes

Fetch public auth status, hide local credentials in shell mode, provide only the MFU return path, retain an explicit recovery form in `local_recovery`, and update regression tests.

## T13 Security / Response / AI Safety

- One-time opaque code and server-side exchange retained.
- Secrets generated/stored only in ignored private files or process environment.
- Admin mapping still requires approved groups.
- Response remains simulated; assistant remains read-only; raw-log assistant context remains disabled; models are not activated.

## T14 Test Plan

- PowerShell parser and lifecycle dry-runs.
- Portable-path/backend targeted tests.
- Shell Node contract tests.
- Ruff, compileall, backend suite, Alembic check.
- React lint/build/Playwright.
- Replay dry-run, performance smoke, and release gate.

## T15 Implementation Summary

| Area | Files |
| --- | --- |
| Auth/config | `atdr/app/core/config.py`, `atdr/app/routers/auth.py`, auth schemas/services |
| Startup guard | `atdr/app/main.py` |
| Frontend | `frontend/src/pages/LoginPage.tsx`, API types/tests |
| Lifecycle | `scripts/*_system.ps1`, `scripts/setup_team.ps1`, `.cmd` wrappers |
| Configuration | `.env.shell.example`, `.env.example`, `.env.lab.example`, `.gitignore` |
| Tests/docs | v4.3 tests and team runtime docs |

## T16 Tests Run / Evidence

Final command evidence is recorded in `docs/tasks/tasklist-progress.md`. Clean-path readiness passed `4/4`; focused ATDR tests passed `14`; backend passed `577` with `1` hardware skip; Playwright passed `23` with `1` live-scenario skip; supervisor shell service/IAM SDK/contracts passed `37`/`15`/`12`; disposable Alembic upgrade/check, replay dry-run, and release gate passed. No provider secret value or private environment file is part of the evidence.

## T17 PRD / Docs Updated

README, frontend README, team quickstart, lab runbook, PRD, traceability, compliance checklist, current-state lock, task board, v4.3 guide, and this change record are updated.

## T18 Risks / Blockers / Assumptions / Decisions

- Teammates still need an approved separate shell copy and its private configuration.
- The shell requires MongoDB even though ATDR uses SQLAlchemy/SQLite locally.
- Real provider-backed MFU authentication remains subject to university configuration and acceptance.
- Direct local login is retained only as explicit recovery rather than removed.

## T19 Release / Rollback

Release requires private setup per machine. Roll back by stopping launcher-owned processes and selecting `local_recovery` only for an authorized recovery event. No data rollback is required because v4.3 adds no schema.

## T20 Final Handoff

- Status: repository/local-runtime scope complete; provider-backed MFU acceptance remains an external environment gate.
- Normal commands: `setup_team.cmd`, then `start_system.cmd`.
- Normal URL: `http://127.0.0.1:8080/#/pages/login`.
- Remaining external gate: approved provider-backed MFU login and group/2FA lifecycle evidence.
