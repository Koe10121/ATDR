# T1-T20 Change Document: v3.21 SOC Assistant Demo-Quality Upgrade

## T1 Change Title

- Title: v3.21 SOC Assistant Demo-Quality Upgrade
- Date: 2026-06-21
- Owner / acting agent: Codex
- Related version or sprint: v3.21

## T2 Requirement

- User request: Improve the ATDR SOC Assistant for advisor demonstration while keeping it read-only and safe.
- Business / lab goal: Make the chatbot useful for explaining alerts, source health, detection runs, ML governance, and safe analyst workflows.
- Success outcome: Assistant answers are clearer, preset prompts are demo-friendly, unsafe action requests are refused, and verification passes.
- Explicit non-goals:
  - No external IAM/OIDC/Google/MFU login changes.
  - No real SMTP.
  - No external LLM calls by default.
  - No raw log context by default.
  - No response execution, detection execution, label changes, model activation, model promotion, or data deletion from assistant.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Assistant router | `atdr/app/routers/assistant.py` | Authenticated status/chat/history endpoints already exist. |
| Assistant service | `atdr/app/services/assistant_service.py` | Deterministic local answer engine, redaction, context builders, and audit logging. |
| Assistant schema | `atdr/app/schemas/assistant.py` | Chat/status/history response contracts. |
| Assistant page | `frontend/src/pages/AssistantPage.tsx` | React chat UI, presets, status cards, history, citations, collapsible technical context. |
| API hooks | `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts` | Assistant API client and query/mutation hooks. |
| Source APIs | `atdr/app/routers/alerts.py`, `atdr/app/routers/logs.py`, `atdr/app/routers/sources.py`, `atdr/app/routers/ml.py`, `atdr/app/routers/jobs.py` | Existing read-only context sources. |
| Existing assistant docs | `docs/V3_8_ANALYST_ASSISTANT_MVP.md`, `docs/V3_9_ASSISTANT_HARDENING.md`, `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md` | Prior assistant scope, safety, and explainer behavior. |

## T4 Current Behavior

- Current backend behavior: Assistant is authenticated and deterministic. It can summarize alerts, source health, jobs, ML, and lab workflow.
- Current frontend behavior: Assistant page exists with safety badges, prompt groups, response panel, citations, and history.
- Current data model behavior: No schema changes.
- Current AI/ML behavior: ML remains decision support; assistant does not activate/promote/train.
- Current response/audit behavior: Assistant questions are audited; no response actions are created.
- Current known limitation: Command-like unsafe requests needed clearer refusal handling.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Coordinates source-backed assistant hardening. |
| Product Owner / Requirement Planner | yes | Defines advisor-demo question coverage. |
| Data Model / Database | no | No schema changes. |
| Backend / API | yes | Assistant deterministic intents and guardrails improved. |
| Frontend / Dashboard | yes | Assistant preset labels and safety badges improved. |
| AI/ML Governance | yes | Assistant explains model status without changing it. |
| Security / Response Safety | yes | Unsafe commands are refused. |
| QA/UAT | yes | Backend and frontend tests updated. |
| Release/Ops / Lab Validation | yes | Full verification required. |

## T6 Scope

### In Scope

- Improve assistant deterministic answer routing.
- Add unsafe action refusal.
- Add detection-run summary.
- Add import-log help.
- Improve frontend preset names and safety badge visibility.
- Update docs/governance/tests.

### Out Of Scope

- No external LLM integration.
- No runtime provider calls.
- No response execution.
- No model activation/promotion.
- No database reset or migration.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V321-001 | Assistant answers critical-alert, alert-explanation, source, detection-run, job, ML, and how-to questions. | Must | User request |
| FR-V321-002 | Assistant refuses unsafe command-like requests. | Must | Safety constraint |
| FR-V321-003 | Assistant frontend presets are demo-friendly and professional. | Must | User request |
| FR-V321-004 | Assistant remains read-only, deterministic local by default, with raw log context disabled. | Must | Safety constraint |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Unsafe action requests return a refusal and create no response/model/detection side effects. | `atdr/tests/test_assistant.py` |
| AC-002 | Detection-run, import-log, reviewed-label, scenario, source, alert, and ML questions return useful answers. | `atdr/tests/test_assistant.py` |
| AC-003 | Assistant page shows safety badges and demo prompt presets. | `frontend/tests/smoke.spec.ts` |
| AC-004 | Long response/details remain bounded. | `frontend/tests/smoke.spec.ts` |

## T9 API Contract

- New endpoints: none.
- Changed endpoints: none.
- Unchanged endpoints: `GET /api/assistant/status`, `POST /api/assistant/chat`, `GET /api/assistant/history`.
- Auth/RBAC: unchanged; analyst/admin required.
- Backward compatibility: response shape unchanged.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.
- Existing data compatibility: unchanged.
- No migration needed because this is service/UI/docs/test hardening only.

## T11 Backend Plan / Changes

- `assistant_service.py`: add unsafe action guardrail, detection-run answer, import-log answer, Simulation Mode safety note, and better latest-alert routing.
- Tests: extend assistant tests for guardrails and new intents.

## T12 Frontend Plan / Changes

- `AssistantPage.tsx`: add Simulation Mode badge and advisor-friendly preset button labels.
- `frontend/tests/smoke.spec.ts`: update assistant UI expectations.

## T13 Security / Response / AI Safety

- Response mode remains simulation: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Protected IP handling: unchanged.
- Audit impact: assistant questions continue to be audited.
- ML decision-support status: unchanged.
- Raw log context: disabled by default.
- External LLM: disabled by default.
- Security reviewer decision: pass.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Tasklist render/check | `node scripts/render-tasklist-progress-html.js .` and `node scripts/check-tasklist-progress-standard.js .` | yes | Governance |
| Ruff | `.\.venv\Scripts\ruff.exe check .` | yes | Code style |
| Compile | `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | yes | Python compile |
| Backend tests | `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v321-full -p no:cacheprovider` | yes | Full backend regression |
| Alembic | `.\.venv\Scripts\alembic.exe check` | yes | No schema drift |
| Frontend | `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e` | yes | UI regression |
| Replay dry-run | `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | yes | Safety smoke |
| Performance smoke | `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | yes | Local performance |
| Release gate | `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | yes | Release evidence |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `atdr/app/services/assistant_service.py` | Added guardrail refusal, detection-run summary, import-log help, Simulation Mode safety, and plural/singular latest alert routing. |
| `frontend/src/pages/AssistantPage.tsx` | Added Simulation Mode badge and demo-friendly preset labels. |
| `atdr/tests/test_assistant.py` | Added detection-run fixture, new intent assertions, and unsafe action refusal tests. |
| `frontend/tests/smoke.spec.ts` | Added preset and Simulation Mode UI checks. |
| `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md` | Added assistant demo-quality documentation. |
| `docs/tasks/tasklist-progress.md` | Updated progress board. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added v3.21 traceability row. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | Added v3.21 compliance evidence. |
| `docs/prd/PRD-ATDR.md` | Updated current stage/source evidence/assistant capability notes. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `node scripts/render-tasklist-progress-html.js .` | pass | Regenerated the ATDR tasklist progress board. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Tasklist/progress-board standard check passed. |
| `.\.venv\Scripts\ruff.exe check .` | pass | Ruff reported all checks passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Backend and migration compile check passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py -q --basetemp .pytest_tmp\v321-assistant -p no:cacheprovider` | pass | `8 passed`; assistant intent coverage and unsafe-action refusal tests passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v321-full -p no:cacheprovider` | pass | `305 passed, 1 skipped`; warnings are existing sklearn/joblib warnings. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e` | pass | Frontend lint/build passed; Playwright `14 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | pass | Safe sample dry-run parsed 2 rows and wrote no DB rows. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass | `ok: true`; Overview `0.4347s`, cached Overview `0.0076s`, ML Governance `1.2783s`, alert list `0.0364s`, case summary `0.0425s`, no warnings. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`; backend tests `305 passed, 1 skipped`; Alembic check passed. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/prd/PRD-ATDR.md` | yes | Assistant capability changed. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Added v3.21 row. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | yes | Added v3.21 evidence. |
| `docs/tasks/tasklist-progress.md` | yes | Updated active progress board. |
| `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md` | yes | New status/runbook doc. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Deterministic answer routing may not understand every phrasing.
- External LLM integration remains future work and requires privacy/security review.

### Blockers

- None for the local deterministic assistant upgrade.

### Assumptions

- Advisor demo should show safe assistant explanations, not autonomous actions.
- Current local JWT/IAM state remains unchanged.

### Decisions

- Add guardrail refusal instead of adding any command execution ability.
- Keep raw logs and external LLM disabled by default.

## T19 Release / Rollback

- Release impact: backend assistant service, React assistant page, tests, docs.
- Deployment notes: no startup command change.
- Local workflow impact: unchanged.
- Rollback plan: revert changed service/UI/docs/tests.
- Data rollback: not applicable.

## T20 Final Handoff

- Status: completed.
- Files changed: assistant service/page/tests/docs/governance.
- Behavior changed: assistant answer quality and refusal behavior improved.
- Verification result: passed; release gate returned `ok: true`.
- Remaining risks: deterministic wording limits; external LLM remains future work.
- Exact next command for user: start backend and frontend, then open `/assistant` and ask the demo questions in `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`.
