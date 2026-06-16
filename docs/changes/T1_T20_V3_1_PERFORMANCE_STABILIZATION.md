# T1-T20: v3.1 Performance Stabilization And PostgreSQL Lab Path

## T1 Change Title

- Title: v3.1 Performance Stabilization and PostgreSQL Lab Path
- Date: 2026-06-16
- Owner / acting agent: Codex
- Related version or sprint: v3.1 Production-Readiness Track

## T2 Requirement

- User request: investigate large-SQLite performance warnings, improve safe performance where useful, document PostgreSQL lab validation, and preserve all safety boundaries.
- Business / lab goal: improve credibility for production-readiness planning without claiming production readiness.
- Success outcome: performance smoke is clean or warnings are explained honestly; PostgreSQL path is documented; tests protect cache behavior.
- Explicit non-goals: no DB reset, no stack migration, no model activation, no automatic response, no real firewall blocking.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Performance smoke | `atdr/scripts/performance_smoke.py` | Measures Overview, ML Governance, alert list, case summary, run history, and feature generation. |
| Overview summary | `atdr/app/services/dashboard_service.py` | Uses aggregate queries plus summary cache with invalidation signature. |
| ML Governance summary | `atdr/app/services/ml_service.py` | Builds dataset profile, data quality, drift, score stats, and anomaly samples. |
| Index migration | `migrations/versions/a7c9d2e4f6b1_add_summary_performance_indexes.py` | Existing indexes cover alert status/severity, anomaly, ML labels, and model runs. |
| Production doctor | `atdr/scripts/production_readiness_doctor.py` | Reports readiness blockers and warnings without exposing secrets. |
| PostgreSQL validator | `atdr/scripts/run_postgres_lab_validation.py` | Cleanly blocks when SQLite is configured. |

## T4 Current Behavior

- Current backend behavior: normal SQLite workflow remains supported; summary cache is enabled.
- Current frontend behavior: React dashboard shows cached summary status and production-readiness track.
- Current data model behavior: no new schema change needed for v3.1.
- Current AI/ML behavior: decision support only; no activation or production promotion.
- Current response/audit behavior: simulated and analyst-approved only.
- Current known limitation: cold SQLite reads can occasionally produce performance smoke warnings after heavy test/load activity.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Coordinates v3.1 stabilization. |
| Product Owner / Requirement Planner | yes | Documents production-readiness limits. |
| Data Model / Database | no | No migration added. |
| Backend / API | yes | Production doctor guidance and tests. |
| Frontend / Dashboard | no | No UI behavior change in this pass. |
| AI/ML Governance | yes | ML summary performance is monitored. |
| Security / Response Safety | yes | Safety status remains explicitly disabled. |
| QA/UAT | yes | Cache regression and verification commands. |
| Release/Ops / Lab Validation | yes | PostgreSQL validation path clarified. |

## T6 Scope

### In Scope

- Performance root-cause assessment.
- Production-readiness doctor guidance.
- Performance/cache regression test.
- v3.1 performance and PostgreSQL docs.

### Out Of Scope

- No real firewall blocking.
- No automatic response.
- No production-readiness claim.
- No reset/delete of current data.
- No PostgreSQL requirement for normal local development.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V31-001 | Document root cause and stabilization plan. | Must | User prompt |
| FR-V31-002 | Keep performance smoke honest; do not hide warnings by threshold changes only. | Must | User prompt |
| FR-V31-003 | Preserve summary cache correctness after ingestion. | Must | `dashboard_service.py` |
| FR-V31-004 | PostgreSQL validation must cleanly block on SQLite. | Must | `run_postgres_lab_validation.py` |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | v3.1 plan exists with source evidence and root-cause analysis. | Read `docs/V3_1_PERFORMANCE_STABILIZATION_PLAN.md`. |
| AC-002 | Cache path hits and invalidates after ingestion. | Backend test. |
| AC-003 | Production doctor recommends performance smoke/PostgreSQL validation. | Backend test and command output. |
| AC-004 | Performance smoke has no warnings on focused rerun or documents warnings honestly. | `performance_smoke --pretty`. |

## T9 API Contract

- New endpoints: none.
- Changed endpoints: none.
- Unchanged endpoints: `/api/dashboard/summary`, `/api/dashboard/validation-summary`.
- Auth/RBAC: unchanged.
- Backward compatibility: preserved.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.
- Index changes: none in v3.1.
- Existing data compatibility: current database is not reset or modified by validation.
- Rollback strategy: revert docs/test/doctor guidance changes.
- No migration needed because focused profiling did not identify a missing-index bottleneck.

## T11 Backend Plan / Changes

- Scripts: update `production_readiness_doctor` recommendations.
- Services: no query behavior changed.
- Tests: add cache hit/invalidation assertion and doctor recommendation assertion.

## T12 Frontend Plan / Changes

- No frontend change required.

## T13 Security / Response / AI Safety

- Response mode remains simulation: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Audit impact: none.
- ML decision-support status: unchanged.
- Data privacy/repo hygiene: generated reports and real logs remain ignored.
- Security reviewer decision: pass with known performance follow-up.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Ruff | `.\.venv\Scripts\python.exe -m ruff check .` | yes | Code style. |
| Compile | `.\.venv\Scripts\python.exe -m compileall atdr` | yes | Python syntax. |
| Backend tests | `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp atdr\data\processed\pytest-v31-full` | yes | Full backend test suite. |
| Alembic | `.\.venv\Scripts\alembic.exe check` | yes | No drift. |
| Performance smoke | `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | yes | Budget check. |
| Production doctor | `.\.venv\Scripts\python.exe -m atdr.scripts.production_readiness_doctor --pretty` | yes | Readiness guidance. |
| PostgreSQL validator | `.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty` | yes | Expected SQLite blocker locally. |
| Release gate | `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release --pretty` | yes | Final gate. |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `atdr/scripts/production_readiness_doctor.py` | Added performance-smoke/PostgreSQL validation guidance. |
| `atdr/tests/test_replay_and_dedup.py` | Added Overview cache hit and invalidation regression test. |
| `atdr/tests/test_v30_production_readiness.py` | Added doctor recommendation assertion. |
| `docs/V3_1_PERFORMANCE_STABILIZATION_PLAN.md` | Added performance analysis and stabilization plan. |
| `docs/V3_1_POSTGRESQL_PERFORMANCE_VALIDATION_PLAN.md` | Added PostgreSQL performance validation path. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| Focused profiling | passed | Overview about `0.37s`, ML Governance about `1.07s` on rerun. |
| Performance smoke | pending final run | To be recorded in final handoff. |
| Release gate | pending final run | To be recorded in final handoff. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/V3_1_PERFORMANCE_STABILIZATION_PLAN.md` | yes | New stabilization plan. |
| `docs/V3_1_POSTGRESQL_PERFORMANCE_VALIDATION_PLAN.md` | yes | New PostgreSQL validation plan. |
| README | no | Existing v3.0 docs remain enough for main entry point. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- SQLite cold-cache timings may vary after heavy tests or large imports.
- PostgreSQL validation is still pending on a suitable host.

### Blockers

- None for local lab workflow.

### Assumptions

- SQLite remains normal local database.
- PostgreSQL validation will be run separately.

### Decisions

- No new index migration in v3.1 because focused profiling did not reproduce the slow path.
- Keep warnings honest in `performance_smoke`.

## T19 Release / Rollback

- Release impact: docs/test/script guidance only.
- Deployment notes: no startup command changes.
- Local workflow impact: unchanged.
- Rollback plan: revert modified files.
- Data rollback: not applicable.
- Monitoring/checks after release: run performance smoke after large imports.

## T20 Final Handoff

- Status: completed pending final verification.
- Files changed: doctor, tests, v3.1 docs.
- Behavior changed: production doctor now explicitly recommends performance smoke/PostgreSQL validation.
- Verification result: see final response.
- Remaining risks: PostgreSQL lab validation still environment-blocked locally.
- Exact next command for user: see final response.

