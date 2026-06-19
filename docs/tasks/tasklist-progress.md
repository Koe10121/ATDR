# Tasklist: ATDR System Progress And Readiness

| Field | Value |
| --- | --- |
| Date | 2026-06-19 |
| Project | MFU AI-Driven Log-Based Threat Detection and Response System |
| Module / Feature | v3.5 controlled real-source/syslog pilot |
| Requirement | Add read-only source/syslog pilot checking, safe evidence export, dashboard validation checklist, and source-pipeline-vs-real-device wording |
| Active Change Record | `docs/changes/T1_T20_V3_5_REAL_SOURCE_SYSLOG_PILOT.md` |
| Overall Status | done |
| Overall Progress | 100% |
| Progress Type | Evidence-backed real-source pilot readiness progress, not production readiness |

## T1. Source Evidence

| Area | Source Evidence |
| --- | --- |
| ATDR runtime source truth | `atdr/app/main.py`, `atdr/app/core/config.py`, `atdr/app/db/database.py`, `atdr/app/db/models.py`, `atdr/app/routers/*.py`, `frontend/src/App.tsx`, `frontend/src/lib/api.ts`, `frontend/src/pages/*` |
| Existing production-readiness docs | `docs/FINAL_SYSTEM_STATUS.md`, `docs/V3_0_PRODUCTION_READINESS_GAP_ASSESSMENT.md`, `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md`, `docs/V3_0_OBSERVABILITY_AND_OPERATIONS_PLAN.md`, `docs/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md` |
| ATDR workflow / PRD / traceability | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md`, `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` |
| Tasklist/progress-board workflow | `docs/tasks/README.md`, `docs/tasks/tasklist-progress.md`, `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| Existing readiness scripts | `atdr/scripts/production_readiness_doctor.py`, `atdr/scripts/run_postgres_lab_validation.py`, `atdr/scripts/performance_smoke.py`, `atdr/scripts/run_v30_real_source_pilot_validation.py`, `atdr/scripts/verify_release.py` |
| v3.4 source evidence | `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/profile_dashboard_summary.py`, `atdr/tests/test_v34_shared_lab_readiness.py`, `docs/V3_4_SHARED_LAB_READINESS.md` |
| New v3.5 source evidence | `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/scripts/export_real_source_pilot_evidence.py`, `atdr/tests/test_v35_real_source_pilot.py`, `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md` |

## T2. Progress Calculation

| Readiness Area | Weight | Earned | Basis |
| --- | ---: | ---: | --- |
| Source discovery completed | 15 | 15 | Existing v3 docs, source/runtime files, syslog/replay scripts, source services, v3.4 readiness, PRD, and traceability were read. |
| Safe v3.5 scripts added | 25 | 25 | Read-only pilot checker and evidence exporter were added without schema, detection, ML, response, or startup changes. |
| Tests added | 15 | 15 | `atdr/tests/test_v35_real_source_pilot.py` covers missing source, source counts, parser failures, simulated-source honesty, evidence export privacy, and response safety. |
| Docs/traceability updated | 20 | 20 | v3.5 doc, LAB_RUNBOOK, README, PRD, traceability, compliance checklist, docs index, tasklist, and T1-T20 record updated. |
| Verification completed | 20 | 20 | Tasklist scripts, Ruff, compileall, backend tests, Alembic check, React lint/build/e2e, replay dry-run, performance smoke, v3.4 readiness, v3.5 checker/exporter, and release gate passed. |
| Handoff completed | 5 | 5 | Final handoff is documented in this progress board and T1-T20 change record. |
| **Total** | **100** | **100** | v3.5 controlled real-source/syslog pilot readiness is complete; production readiness remains explicitly out of scope. |

## T3. Active Tasklist

| Task ID | Task | Agent | Owner | Depends On | Status | Progress % | Progress Basis | Source Evidence | Tests Evidence | Blocker | Next Action | Output |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ATDR-V35-001 | v3.5 Controlled Real-Source / Syslog Pilot | Orchestrator / Release-Ops / Backend / QA | Codex | v3.4 shared-lab readiness, source management, tasklist workflow | done | 100 | Read-only checker/exporter/tests/docs added; v3.4 source-pilot reporting now uses stricter v3.5 result; full verification passed | `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/scripts/export_real_source_pilot_evidence.py`, `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md` | Full backend tests `258 passed, 1 skipped`; frontend e2e `13 passed, 1 skipped`; release gate `ok: true`; performance smoke no warnings | Real device and PostgreSQL host still unavailable | Run approved real-device syslog pilot when hardware is available | v3.5 scripts, tests, readiness docs, progress board |
| ATDR-V34-001 | v3.4 Shared-Lab Production-Readiness Foundation | Orchestrator / Release-Ops / Backend / QA | Codex | v3.3 shared-lab readiness, tasklist workflow | done | 100 | Scripts/docs/tests added; backup drill, profiling, v3.4 report, and full verification completed | `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/profile_dashboard_summary.py`, `docs/V3_4_SHARED_LAB_READINESS.md` | Full backend tests `252 passed, 1 skipped`; frontend e2e `13 passed, 1 skipped`; release gate `ok: true`; performance smoke no warnings | Real device and PostgreSQL host still unavailable | Continue to controlled real-device/syslog pilot and PostgreSQL shared-lab validation | v3.4 scripts, tests, readiness docs, progress board |
| ATDR-TASKLIST-001 | ATDR university-template tasklist/progress-board compliance | Orchestrator / Release-Ops | Codex | none | done | 100 | Process compliance completed in previous phase | `docs/changes/T1_T20_TASKLIST_PROGRESS_COMPLIANCE.md` | Release gate passed in previous phase | none | Keep tasklist current for future work | `docs/tasks/`, progress scripts, docs index |

## T4. Verification Log

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `.\.venv\Scripts\python.exe -m compileall -q atdr\scripts\run_backup_restore_drill.py atdr\scripts\profile_dashboard_summary.py atdr\scripts\run_v34_shared_lab_readiness.py atdr\tests\test_v34_shared_lab_readiness.py` | pass | Targeted compile check passed. |
| `.\.venv\Scripts\ruff.exe check atdr\scripts\run_backup_restore_drill.py atdr\scripts\profile_dashboard_summary.py atdr\scripts\run_v34_shared_lab_readiness.py atdr\scripts\config_doctor.py atdr\scripts\run_postgres_lab_validation.py atdr\tests\test_v34_shared_lab_readiness.py` | pass | Ruff reported all checks passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v34_shared_lab_readiness.py -q --basetemp .pytest_tmp\v34-targeted -p no:cacheprovider` | pass | `6 passed`. |
| `node scripts/render-tasklist-progress-html.js .` | pass | Regenerated `docs/tasks/tasklist-progress.html`. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Validated tasklist/progress-board standard. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Full compile gate passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v34-full -p no:cacheprovider` | pass | `252 passed, 1 skipped`. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e` | pass | Lint/build passed; Playwright `13 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | pass | Safe sample dry-run parsed 2 rows and wrote no DB rows. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass | Overview `0.4511s`, cached hit `0.006s`, ML Governance `1.2837s`, no warnings. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --pretty` | pass | SQLite backup/restore drill passed, verified row counts from ignored `.tmp` backup copy, live DB unchanged. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v35_real_source_pilot.py -q --basetemp .pytest_tmp\v35-targeted -p no:cacheprovider` | pass | `6 passed`. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v34_shared_lab_readiness.py atdr\tests\test_v35_real_source_pilot.py -q --basetemp .pytest_tmp\v35-v34-targeted -p no:cacheprovider` | pass | `12 passed`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.run_v35_real_source_pilot_check --pretty` | pass | Latest local source reported `simulated_source_pipeline_validated`; `real_device_forwarding_validated=false`; no response actions created. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --pretty` | pass | Printed safe evidence JSON; no file written; full raw private log contents excluded by default. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v35-final -p no:cacheprovider` | pass | `258 passed, 1 skipped`. |
| `npm.cmd run test:e2e` | pass | Playwright `13 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass | Overview `0.4426s`, cached hit `0.0061s`, ML Governance `1.2293s`, no warnings. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty` | pass | Reports `shared_lab_foundation_ready_with_warnings`; source pilot warning is now `simulated_source_pipeline_validated`, not real-device validation. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`; backend tests `258 passed, 1 skipped`; Alembic check passed. |

## T5. Blockers And Risks

| ID | Type | Status | Evidence | Impact | Next Action |
| --- | --- | --- | --- | --- | --- |
| R-001 | risk | open | Current environment may be SQLite, not PostgreSQL. | PostgreSQL shared-lab validation can only report `blocked_by_environment` locally. | Validate on a PostgreSQL/Docker-capable shared-lab host later. |
| R-002 | risk | open | Real router/firewall forwarding is not currently validated. | Cannot claim production-like source reliability. | Run controlled real-device syslog pilot. |
| R-003 | risk | open | Large local SQLite cold Overview/ingestion summary can exceed budget before cache. | Dashboard may be slow after cache invalidation with large local DB. | Use v3.4 profiler and consider targeted query/index/cache work or PostgreSQL validation. |
| R-004 | risk | open | OIDC provider details are not supplied. | External school-email IAM remains future work. | Keep local JWT login and disabled OIDC groundwork. |
| B-001 | blocker | closed | No runtime blocker found; full verification passed. | None. | Continue to approved real-device syslog pilot when hardware/network are available. |

## T6. Decision

ATDR v3.5 adds a controlled real-source/syslog pilot checker and safe evidence export. ATDR remains FastAPI + React + SQLAlchemy/Alembic, with SQLite for local development, optional PostgreSQL validation later, local JWT/RBAC, simulated response, and ML decision support only. The v3.5 pilot-readiness task is complete; production readiness is still not claimed.
