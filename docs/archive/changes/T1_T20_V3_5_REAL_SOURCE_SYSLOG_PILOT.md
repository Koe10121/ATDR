# T1-T20: v3.5 Controlled Real-Source / Syslog Pilot

## T1. Change Title

v3.5 Controlled Real-Source / Syslog Pilot Checker, Safe Evidence Export, and Runbook.

## T2. Requirement

Implement a non-destructive real-source/syslog pilot workflow that can verify source health, parser quality, source-scoped detection, alert/case traceability, and response-safety state without resetting data, changing startup commands, activating models, enabling automatic response, or claiming production readiness.

## T3. Source Evidence

| Area | Source Evidence |
| --- | --- |
| User prompt | `<USER_REQUEST_ATTACHMENT>` |
| Runtime app | `atdr/app/main.py`, `atdr/app/core/config.py` |
| Data model | `atdr/app/db/models.py` |
| Source management | `atdr/app/routers/sources.py`, `atdr/app/services/source_service.py` |
| Ingestion/parser | `atdr/app/services/log_service.py`, `atdr/app/parsers/paloalto_parser.py` |
| Detection/run history | `atdr/app/services/detection_service.py`, `atdr/app/services/operation_run_service.py` |
| Existing syslog/replay | `atdr/scripts/run_syslog_receiver.py`, `atdr/scripts/send_sample_syslog.py`, `atdr/scripts/register_log_source.py`, `atdr/scripts/replay_logs.py` |
| Existing readiness | `atdr/scripts/run_v30_real_source_pilot_validation.py`, `atdr/scripts/run_v34_shared_lab_readiness.py`, `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md`, `docs/V3_4_SHARED_LAB_READINESS.md` |
| Tasklist/PRD/traceability | `docs/tasks/tasklist-progress.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

## T4. Current Behavior

Before v3.5, ATDR had source management, syslog/replay support, v3.0 pilot validation, and v3.4 shared-lab readiness reporting. It did not yet have a stricter v3.5 read-only pilot checker that clearly separated source-pipeline validation from real-device forwarding validation, nor a safe evidence export command that avoids full raw private log contents by default.

## T5. Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Backend / scripts | New read-only checker and safe evidence exporter. |
| QA | New tests for read-only behavior, evidence privacy, parser failure reporting, and response safety. |
| Release/Ops | Updated lab runbook and v3.5 pilot checklist. |
| Product/docs | PRD, traceability, compliance checklist, tasklist, and README links updated. |
| ML / Response | No behavior changes; model activation and automatic response remain disabled. |

## T6. Scope

In scope:

- Add `atdr/scripts/run_v35_real_source_pilot_check.py`.
- Add `atdr/scripts/export_real_source_pilot_evidence.py`.
- Add backend tests for the v3.5 workflow.
- Add v3.5 runbook/status documentation and tasklist evidence.

Out of scope:

- Real firewall blocking.
- Automatic response.
- ML retraining, tuning, activation, or promotion.
- Database reset or schema changes.
- PostgreSQL requirement.
- Full external IAM/OIDC callback implementation.

## T7. Functional Requirements

| ID | Requirement | Status |
| --- | --- | --- |
| FR-V35-001 | Report source existence, enabled state, parser profile, host/port, last seen, and last log received | Implemented |
| FR-V35-002 | Report source-linked raw/normalized logs, parse failures, unknown app rate, parser errors, latest ingestion/detection runs, alerts, and cases | Implemented |
| FR-V35-003 | Verify response automation remains disabled and checker creates no response actions | Implemented |
| FR-V35-004 | Distinguish simulated/replay pipeline validation from real-device forwarding validation | Implemented |
| FR-V35-005 | Export safe evidence with IDs/counts and no full raw private log contents by default | Implemented |

## T8. Acceptance Criteria

| Criteria | Evidence |
| --- | --- |
| Missing source reports not validated without failing destructively | `atdr/tests/test_v35_real_source_pilot.py` |
| Source with logs reports counts and detection run status | `atdr/tests/test_v35_real_source_pilot.py` |
| Parser failure rate and parser errors appear | `atdr/tests/test_v35_real_source_pilot.py` |
| Simulated/source scenario is not marked as real-device forwarding | `atdr/tests/test_v35_real_source_pilot.py` |
| Evidence export does not include full raw private logs by default | `atdr/tests/test_v35_real_source_pilot.py` |
| No response action is created by checker/exporter | `atdr/tests/test_v35_real_source_pilot.py` |

## T9. API Contract

No API contract changed.

New CLI commands:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v35_real_source_pilot_check --source-name <source> --expected-min-logs 100 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --source-name <source> --expected-min-logs 100 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --source-name <source> --expected-min-logs 100 --write --pretty
```

## T10. Data Model / Migration

No database schema changes and no Alembic migration.

## T11. Backend Plan / Changes

- Add read-only checker using existing source, run history, alert, case, and response-action tables.
- Add safe evidence exporter that prints by default and writes only when `--write` is passed.
- Keep generated evidence under ignored `demo_exports/real_source_pilot/`.

## T12. Frontend Plan / Changes

No frontend code changes. Dashboard verification remains documented:

- Overview source panel.
- Source detail drawer.
- Investigation source filter.
- Alerts source filter.
- Alert detail "Why flagged?"
- Case/source traceability.
- Response & Audit no automatic response.

## T13. Security / Response / AI Safety

- Response mode remains simulation.
- No automatic response action is created.
- Real firewall blocking remains disabled.
- ML remains decision support only.
- Evidence export avoids full private raw log contents by default.
- Simulated/replay sources are not presented as real-device forwarding validation.

## T14. Test Plan

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v35_real_source_pilot.py -q
```

Then full verification:

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr\tests -q
.\.venv\Scripts\alembic.exe check
cd frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
cd ..
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

## T15. Implementation Summary

Added:

- `atdr/scripts/run_v35_real_source_pilot_check.py`
- `atdr/scripts/export_real_source_pilot_evidence.py`
- `atdr/tests/test_v35_real_source_pilot.py`
- `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`

Updated:

- `docs/LAB_RUNBOOK.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`
- `README.md`

## T16. Tests Run / Evidence

Initial targeted evidence:

| Command | Result |
| --- | --- |
| `.\.venv\Scripts\python.exe -m compileall -q atdr\scripts\run_v35_real_source_pilot_check.py atdr\scripts\export_real_source_pilot_evidence.py atdr\tests\test_v35_real_source_pilot.py` | pass |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v35_real_source_pilot.py -q --basetemp .pytest_tmp\v35-targeted -p no:cacheprovider` | `6 passed` |

Full verification:

| Command | Result | Evidence |
| --- | --- | --- |
| `node scripts/render-tasklist-progress-html.js .` | pass | Regenerated progress HTML. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Tasklist standard passed. |
| `.\.venv\Scripts\ruff.exe check atdr` | pass | Ruff reported all checks passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Compile gate passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v35-final -p no:cacheprovider` | pass | `258 passed, 1 skipped`. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `npm.cmd run lint` | pass | React lint passed. |
| `npm.cmd run build` | pass | React build passed. |
| `npm.cmd run test:e2e` | pass | Playwright `13 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | pass | Safe sample dry-run parsed 2 rows and wrote no DB rows. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass | Overview `0.4426s`, cached hit `0.0061s`, ML Governance `1.2293s`, no warnings. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty` | pass | `shared_lab_foundation_ready_with_warnings`; v3.5 source-pilot warning correctly states simulated source pipeline validation. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.run_v35_real_source_pilot_check --pretty` | pass | Latest local source reported `simulated_source_pipeline_validated`; `real_device_forwarding_validated=false`; no response actions created. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --pretty` | pass | Printed safe evidence JSON; no file written by default. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`. |

## T17. PRD / Docs Updated

Updated:

- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/LAB_RUNBOOK.md`
- `docs/tasks/tasklist-progress.md`
- `README.md`

## T18. Risks / Blockers / Assumptions / Decisions

| ID | Type | Status | Note |
| --- | --- | --- | --- |
| R-V35-001 | Risk | open | No approved real hardware source is available in this coding environment. |
| R-V35-002 | Risk | open | UDP syslog may be blocked by host firewall or wrong interface binding during real pilot. |
| R-V35-003 | Risk | open | Generic syslog and raw fallback preserve evidence but may have limited normalized fields. |
| D-V35-001 | Decision | closed | Keep v3.5 read-only and non-destructive. |
| D-V35-002 | Decision | closed | Treat replay/sample/scenario sources as source-pipeline validation only, not real-device forwarding validation. |

## T19. Release / Rollback

Release:

- Commit the v3.5 scripts, tests, docs, tasklist, and regenerated tasklist HTML after verification.

Rollback:

- Revert the v3.5 script/test/doc files and restore tasklist/README/PRD/traceability edits.
- No migration rollback is needed.
- No database data rollback is needed because the checker/exporter are read-only by default.

## T20. Final Handoff

ATDR v3.5 adds a controlled source/syslog pilot workflow without changing runtime behavior or safety posture. The system still does not claim production readiness, does not activate ML, does not automate response, and does not perform real firewall blocking. The next practical step is to run the v3.5 check against an approved lab firewall/router source after sustained syslog forwarding is configured.
