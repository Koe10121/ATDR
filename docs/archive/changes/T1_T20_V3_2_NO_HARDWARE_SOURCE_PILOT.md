# T1-T20: v3.2 No-Hardware Source Pilot

## T1 Change Title

- Title: v3.2 No-Hardware Real-Source Pilot Simulator and Syslog Readiness
- Date: 2026-06-16
- Owner / acting agent: Codex
- Related version or sprint: v3.2 Production-Readiness Track

## T2 Requirement

- User request: create a no-hardware pilot workflow that simulates a real firewall/syslog source over time and prepares ATDR for future real-device validation.
- Business / lab goal: validate source pipeline readiness without requiring router/firewall hardware.
- Success outcome: source registration, ingestion, parser quality, source health, detection, alerts, cases, and response-safety checks pass with safe synthetic logs.
- Explicit non-goals: no production-readiness claim, no automatic response, no real firewall blocking, no model activation, no DB reset.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Source registration | `atdr/scripts/register_log_source.py` | Existing idempotent helper creates/updates sources. |
| Parser/import services | `atdr/app/services/log_service.py`, `atdr/app/parsers/paloalto_parser.py` | Raw evidence is preserved; parser failures are counted for malformed wrappers. |
| Source health | `atdr/app/services/source_service.py` | Health becomes healthy/warning/error/idle/disabled based on activity and parser quality. |
| Source-scoped detection | `atdr/app/services/detection_service.py` | Detection supports `source_id` and records source-linked run details. |
| v30 validator | `atdr/scripts/run_v30_real_source_pilot_validation.py` | Read-only source pipeline validator can be reused by v3.2. |
| Dashboard status | `atdr/app/routers/dashboard.py`, `frontend/src/pages/MLGovernance.tsx` | Production Readiness Track panel exists. |

## T4 Current Behavior

- Current backend behavior: real-source validator reports no source when hardware/source is absent.
- Current frontend behavior: AI Governance shows production-readiness status.
- Current data model behavior: source_id is optional and source health exists.
- Current AI/ML behavior: decision support only.
- Current response/audit behavior: simulated and analyst-approved only.
- Current known limitation: no real router/firewall is available for forwarding validation.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Coordinates safe no-hardware pilot. |
| Product Owner / Requirement Planner | yes | Clarifies simulated vs real-device validation. |
| Data Model / Database | no | No schema change. |
| Backend / API | yes | New scripts and dashboard summary fields. |
| Frontend / Dashboard | yes | Small readiness-panel wording update. |
| AI/ML Governance | yes | Production-readiness panel shows simulated source status. |
| Security / Response Safety | yes | Verifies no automatic response or real blocking. |
| QA/UAT | yes | Adds v3.2 tests. |
| Release/Ops / Lab Validation | yes | Adds no-hardware pilot workflow. |

## T6 Scope

### In Scope

- Source simulator using safe synthetic scenario rows.
- Full no-hardware source pilot runner.
- Source lifecycle and parser quality checks.
- Dashboard readiness status for simulated source.
- Documentation and tests.

### Out Of Scope

- No real firewall blocking.
- No automatic response.
- No production-readiness claim.
- No database reset/delete.
- No hardware-specific syslog instructions beyond future replacement guidance.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V32-001 | Simulator must not require hardware. | Must | User prompt |
| FR-V32-002 | Simulator must label real-device forwarding as false. | Must | User prompt |
| FR-V32-003 | Pilot must import 100 safe mixed rows and count parser quality. | Must | User prompt |
| FR-V32-004 | Pilot must run source-scoped detection and trace alerts/cases to source. | Must | User prompt |
| FR-V32-005 | No response action may be created automatically. | Must | Safety constraint |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Dry-run is non-mutating. | `test_v32_syslog_source_simulator_dry_run_is_non_mutating` |
| AC-002 | Temp pilot imports 100 rows with parser successes/failures. | `test_v32_no_hardware_pilot_validates_source_pipeline_in_temp_db` |
| AC-003 | Detection run is source-linked and creates port-scan result. | Backend test and command output |
| AC-004 | Dashboard distinguishes simulated source from real forwarding. | Playwright smoke |

## T9 API Contract

- New endpoints: none.
- Changed endpoints: `/api/dashboard/validation-summary` includes additional v3.2 status fields under `v30_production_readiness`.
- Auth/RBAC: unchanged; endpoint remains analyst/admin protected.
- Backward compatibility: existing fields preserved.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.
- Index changes: none.
- Existing data compatibility: current DB is not reset or deleted.
- Rollback strategy: remove scripts/docs/frontend labels if needed.

## T11 Backend Plan / Changes

- Add `atdr/scripts/run_v32_syslog_source_simulator.py`.
- Add `atdr/scripts/run_v32_no_hardware_source_pilot.py`.
- Allow v30 validator to accept a provided session factory for temp-DB validation.
- Add v3.2 fields to dashboard validation summary.
- Add backend tests.

## T12 Frontend Plan / Changes

- Add compact labels to AI Governance Production Readiness Track:
  - Simulated source
  - Real device forwarding
- Keep UI concise.
- Update Playwright smoke mock/assertions.

## T13 Security / Response / AI Safety

- Response mode remains simulation: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Audit impact: only normal import/detection audit behavior if current DB pilot is intentionally run.
- ML decision-support status: unchanged.
- Data privacy/repo hygiene: safe synthetic logs only; no generated report committed.
- Security reviewer decision: pass for lab simulation.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Ruff | `.\.venv\Scripts\python.exe -m ruff check .` | yes | Code style |
| Compile | `.\.venv\Scripts\python.exe -m compileall atdr` | yes | Python syntax |
| Backend tests | `.\.venv\Scripts\python.exe -m pytest atdr\tests -q` | yes | Full suite |
| Alembic | `.\.venv\Scripts\alembic.exe check` | yes | No drift |
| React lint/build | `cd frontend; npm.cmd run lint; npm.cmd run build` | yes | UI status fields |
| Playwright | `cd frontend; npm.cmd run test:e2e` | yes | Readiness panel |
| v3.2 pilot | `.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --use-temp-db --pretty` | yes | Safe validation |
| Release gate | `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release --pretty` | yes | Final gate |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `atdr/scripts/run_v32_syslog_source_simulator.py` | New safe simulated source import workflow. |
| `atdr/scripts/run_v32_no_hardware_source_pilot.py` | New no-hardware source pilot runner. |
| `atdr/scripts/run_v30_real_source_pilot_validation.py` | Accepts optional session factory for safe temp validation. |
| `atdr/app/routers/dashboard.py` | Adds simulated-source readiness status. |
| `frontend/src/pages/MLGovernance.tsx` | Shows simulated source and real-device forwarding status. |
| `docs/V3_2_NO_HARDWARE_SOURCE_PILOT.md` | New runbook. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| Temp v3.2 pilot | passed | 100 rows, 97 parsed, 3 failures, 1 alert/case, no response. |
| Full verification | pending final run | See final response. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/V3_2_NO_HARDWARE_SOURCE_PILOT.md` | yes | New v3.2 runbook. |
| `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md` | yes | Adds no-hardware bridge. |
| `docs/V3_0_PRODUCTION_READINESS_TRACK.md` | yes | Adds v3.2 step. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Adds v3.2 row. |
| README | yes | Links v3.2 docs/command. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Simulated source does not prove network forwarding or UDP reliability.
- Current DB pilot intentionally adds safe synthetic rows if run without `--use-temp-db`.

### Blockers

- Real firewall/router hardware remains unavailable.

### Assumptions

- Safe synthetic samples are acceptable for no-hardware readiness.
- Real-device forwarding will be validated later.

### Decisions

- Use in-process `simulated_source_import` mode for reliability.
- Keep real-device forwarding explicitly false.

## T19 Release / Rollback

- Release impact: optional scripts/docs plus small dashboard status labels.
- Deployment notes: no startup command changes.
- Local workflow impact: unchanged.
- Rollback plan: revert v3.2 scripts/docs/UI fields.
- Data rollback: not applicable unless user intentionally runs current-DB pilot; then rows are normal lab evidence.

## T20 Final Handoff

- Status: completed pending final verification.
- Files changed: v3.2 scripts, tests, docs, dashboard summary/UI.
- Behavior changed: optional no-hardware source pilot now available.
- Verification result: see final response.
- Remaining risks: real-device forwarding and PostgreSQL lab validation remain future work.
- Exact next command for user: see final response.

