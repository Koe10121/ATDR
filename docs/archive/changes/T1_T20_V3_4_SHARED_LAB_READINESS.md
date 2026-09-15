# T1-T20: v3.4 Shared-Lab Production-Readiness Foundation

## T1 Change Title

| Field | Value |
| --- | --- |
| Change ID | T1_T20_V3_4_SHARED_LAB_READINESS |
| Module | Production-readiness foundation / shared-lab validation |
| Date | 2026-06-19 |
| Owner / Agent | Codex / Orchestrator + Release-Ops + Backend + QA |
| Status | Done |
| Active Tasklist | `docs/tasks/tasklist-progress.md` |

## T2 Requirement

Implement v3.4 Shared-Lab Production-Readiness Foundation while preserving ATDR's current stack and workflow.

Required outcomes:

- non-destructive PostgreSQL/shared-lab readiness reporting;
- safe backup/restore drill;
- cold dashboard summary performance profiling;
- real-source pilot checklist/reporting;
- operations readiness snapshot;
- config/security warning improvements;
- docs, traceability, tasklist, and tests.

## T3 Source Evidence

| Area | Source path / route / command | What was verified |
| --- | --- | --- |
| Runtime app | `atdr/app/main.py` | FastAPI app, health route, response simulation health check, router mounting. |
| Runtime config | `atdr/app/core/config.py`, `atdr/scripts/config_doctor.py`, `atdr/scripts/production_readiness_doctor.py` | Existing safety settings, production blockers, OIDC placeholders, response simulation. |
| Database/session | `atdr/app/db/database.py`, `atdr/app/db/models.py` | SQLAlchemy/Alembic model truth and tables for logs, sources, runs, response, audit, labels. |
| PostgreSQL readiness | `atdr/scripts/run_postgres_lab_validation.py`, `docs/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md` | Existing validator was extended, not replaced. |
| Backup helpers | `atdr/scripts/backup_demo.py`, `atdr/scripts/backup_postgres.py` | Existing backup helpers informed the safe drill design. |
| Performance | `atdr/scripts/performance_smoke.py`, `atdr/app/services/dashboard_service.py` | Cold Overview path, cache behavior, and performance warning source. |
| Real-source pilot | `atdr/scripts/run_v30_real_source_pilot_validation.py`, `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md` | Existing source pilot validator and checklist scope. |
| Workflow/docs | `docs/ATDR_AI_WORKFLOW.md`, `docs/tasks/tasklist-progress.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Required tasklist, PRD, traceability, and T1-T20 updates. |

## T4 Current Behavior

- Normal backend command unchanged.
- Normal frontend command unchanged.
- SQLite remains the normal local database.
- PostgreSQL remains optional shared-lab validation.
- Response remains simulated and analyst-approved.
- ML remains decision support and is not production-promoted.
- Existing v3 docs identify real-device syslog, PostgreSQL validation, backup/restore, IAM, observability, and performance as remaining blockers.

## T5 Impacted Areas / Agents

| Agent | Required? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Owns tasklist, T1-T20, scope, and handoff. |
| Backend/API | yes | Adds scripts that import backend settings/models/services. |
| Data Model | no schema change | Reads DB counts only; no migration. |
| Frontend | no runtime change | Frontend verification still required. |
| Security / Response Safety | yes | Confirms response automation remains disabled. |
| QA/UAT | yes | Adds v3.4 tests and runs release gates. |
| Release/Ops | yes | Owns readiness report, backup/restore drill, performance profiling, repo hygiene. |

## T6 Scope

In scope:

- `run_backup_restore_drill`
- `profile_dashboard_summary`
- `run_v34_shared_lab_readiness`
- config doctor and PostgreSQL reporting improvements
- v3.4 tests
- v3.4 docs, PRD, traceability, tasklist

Out of scope:

- no database reset;
- no schema migration;
- no Docker/PostgreSQL requirement for local use;
- no real firewall blocking;
- no automatic response;
- no ML activation or promotion;
- no production-readiness claim.

## T7 Functional Requirements

| FR ID | Requirement | Status |
| --- | --- | --- |
| FR-V34-001 | Report PostgreSQL configured/not-configured state without mutating SQLite | Implemented |
| FR-V34-002 | Create an ignored SQLite backup copy and verify row counts from the copy | Implemented |
| FR-V34-003 | Profile dashboard summary timing read-only | Implemented |
| FR-V34-004 | Provide real-source pilot checklist and conservative status | Implemented |
| FR-V34-005 | Provide operations readiness snapshot | Implemented |
| FR-V34-006 | Warn on demo passwords, partial OIDC config, and TLS/API concerns | Implemented |

## T8 Acceptance Criteria

| AC ID | Given | When | Then |
| --- | --- | --- | --- |
| AC-V34-001 | Local SQLite config | PostgreSQL validator runs | It reports SQLite local mode and PostgreSQL pending without modifying DB. |
| AC-V34-002 | SQLite DB file | Backup drill runs | It writes an ignored copy, verifies row counts, and never overwrites live DB. |
| AC-V34-003 | Dashboard DB | Profiler runs | It reports slowest read-only steps and cache timing. |
| AC-V34-004 | Real-source pilot not complete | v3.4 report runs | It warns honestly and keeps production flags false. |
| AC-V34-005 | Response simulation setting | v3.4 report runs | It does not enable automatic response or real firewall blocking. |

## T9 API Contract

No API contract changes.

## T10 Data Model / Migration

| Item | Decision |
| --- | --- |
| Schema change | none |
| Alembic migration | none |
| Data reset/backfill | none |
| Live DB write | none, except optional ignored backup copy under `.tmp` |

## T11 Backend Plan / Changes

- Add script-level shared-lab readiness tools.
- Extend config doctor warnings.
- Extend PostgreSQL validation output with local SQLite, migration, seed, backup, and response simulation status.
- Preserve existing services and routers.

## T12 Frontend Plan / Changes

No frontend code changes.

## T13 Security / Response / AI Safety

| Concern | Decision |
| --- | --- |
| Secrets | Scripts hide DB passwords and do not render OIDC client secret. |
| Response | Response automation remains false; real firewall blocking remains false. |
| ML | No model is activated or production-promoted. |
| Backup | Backup drill writes only ignored validation copies and never restores over live DB. |
| IAM | No OAuth/OIDC flow added; disabled groundwork remains future work. |
| Production claim | All reports keep `production_ready=false`. |

## T14 Test Plan

| Test | Expected |
| --- | --- |
| v3.4 unit tests | Backup drill, config warnings, PostgreSQL blocked state, profiler read-only behavior, and conservative readiness pass. |
| Full backend tests | Existing runtime safety remains intact. |
| Alembic check | No schema drift. |
| Frontend lint/build/e2e | UI behavior remains intact. |
| Replay dry-run | No DB mutation. |
| Performance smoke | Completes and records warnings if any. |
| Release gate | Passes. |

## T15 Implementation Summary

| File | Change |
| --- | --- |
| `atdr/scripts/run_backup_restore_drill.py` | Added safe backup/restore readiness drill. |
| `atdr/scripts/profile_dashboard_summary.py` | Added read-only dashboard summary profiler. |
| `atdr/scripts/run_v34_shared_lab_readiness.py` | Added combined v3.4 shared-lab readiness report. |
| `atdr/scripts/config_doctor.py` | Added demo password, partial OIDC, and TLS/API warnings. |
| `atdr/scripts/run_postgres_lab_validation.py` | Added local SQLite, backup, migration, seed, and response simulation readiness fields. |
| `atdr/tests/test_v34_shared_lab_readiness.py` | Added v3.4 safety and readiness tests. |
| `docs/V3_4_SHARED_LAB_READINESS.md` | Added v3.4 readiness doc. |
| `docs/LAB_RUNBOOK.md` | Added v3.4 commands and guidance. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added v3.4 traceability row. |
| `docs/prd/PRD-ATDR.md` | Added v3.4 shared-lab readiness requirement. |
| `README.md` | Linked v3.4 doc and commands. |
| `docs/tasks/tasklist-progress.md` | Added active v3.4 task. |

Tasklist progress:

| Task ID | Status | Progress % |
| --- | --- | ---: |
| ATDR-V34-001 | done | 100 |

## T16 Tests Run / Evidence

| Command | Result | Evidence / Notes |
| --- | --- | --- |
| Targeted compileall | pass | New scripts/tests compile. |
| Targeted Ruff | pass | New/changed files passed Ruff. |
| `pytest atdr\tests\test_v34_shared_lab_readiness.py` | pass | `6 passed`. |
| `node scripts/render-tasklist-progress-html.js .` | pass | Regenerated `docs/tasks/tasklist-progress.html`. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Tasklist standard passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Full compile check passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v34-full -p no:cacheprovider` | pass | `252 passed, 1 skipped`. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `cd frontend; npm.cmd run lint` | pass | ESLint passed. |
| `cd frontend; npm.cmd run build` | pass | TypeScript/Vite build passed. |
| `cd frontend; npm.cmd run test:e2e` | pass | Playwright `13 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | pass | Dry-run parsed safe sample, imported 0 rows. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass | Overview `0.4511s`; cached hit `0.006s`; ML Governance `1.2837s`; no warnings. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate `ok: true`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --pretty` | pass | SQLite backup/restore drill passed; row counts matched; live DB unchanged. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/prd/PRD-ATDR.md` | yes | New shared-lab readiness requirement. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | New v3.4 traceability row. |
| `docs/LAB_RUNBOOK.md` | yes | New v3.4 commands. |
| `README.md` | yes | New v3.4 doc/command links. |
| `docs/tasks/tasklist-progress.md` | yes | Active progress-board entry. |
| `docs/V3_4_SHARED_LAB_READINESS.md` | created | New phase status/runbook. |

## T18 Risks / Blockers / Assumptions / Decisions

| ID | Type | Description | Status |
| --- | --- | --- | --- |
| R-001 | Risk | PostgreSQL validation requires a PostgreSQL-capable host. | open |
| R-002 | Risk | Real device syslog forwarding remains unvalidated. | open |
| R-003 | Risk | Cold large-SQLite Overview query can still exceed budget. | open |
| D-001 | Decision | Keep v3.4 non-destructive and conservative. | closed |
| D-002 | Decision | Keep production-ready flags false. | closed |

## T19 Release / Rollback

- Release steps: commit scripts/tests/docs after verification.
- Rollback trigger: new scripts fail release gate or create false production claims.
- Rollback steps: revert v3.4 scripts/tests/docs and restore prior tasklist.
- Runtime rollback: none; no runtime behavior/schema change.

## T20 Final Handoff

```text
Feature: v3.4 Shared-Lab Production-Readiness Foundation
Status: done
Routes: none
UI routes: none
Schema: none
Data reset: none
Response automation: disabled
Real firewall blocking: disabled
ML activation/promotion: none
Tests: full verification passed
Docs: v3.4 doc, runbook, PRD, traceability, tasklist updated
Open blockers: PostgreSQL host validation, real-device syslog pilot, TLS/reverse proxy, external IAM callback, observability stack
Next owner: Release/Ops for controlled real-device/syslog pilot and PostgreSQL shared-lab validation
```
