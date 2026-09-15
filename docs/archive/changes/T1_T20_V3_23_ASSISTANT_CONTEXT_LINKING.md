# T1-T20 Change Document: v3.23 Assistant Context Linking And Dashboard Handoff

## T1 Change Title

v3.23 Assistant Context Linking And Dashboard Handoff Polish

## T2 Requirement

Make SOC Assistant citations and follow-up context easier to use by linking safe source references to the appropriate dashboard pages while preserving read-only behavior.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/pages/ExecutiveOverview.tsx`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/tests/smoke.spec.ts`
- `atdr/tests/test_assistant.py`
- `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`

## T4 Current Behavior

Before v3.23, assistant citations were visible as text but did not provide dashboard navigation. Alert detail already supported a route-level assistant handoff through `/assistant?alert=<id>`.

## T5 Impacted Areas / Agents

- Frontend / Dashboard
- Backend / API test validation
- Security / Response Safety
- QA / UAT
- Documentation / Governance

## T6 Scope

In scope:

- Link assistant citation rows to safe dashboard routes.
- Preserve alert/source context when asking follow-up questions.
- Add small `Ask Assistant` dashboard links where useful.
- Add tests and docs.

Out of scope:

- External LLM enablement.
- Raw log sharing.
- Response execution.
- Detection execution.
- Label/model/data mutation.
- Dedicated run-history detail pages.

## T7 Functional Requirements

- Citations for alert, log, source, detection run, job, and ML report references must be displayed clearly.
- API-backed citations that map to current dashboard routes should expose an `Open` link.
- Documentation/code citations should remain text references.
- Source context must be accepted through `/assistant?source=<id>`.
- Overview should open source detail when loaded with `?source=<id>`.

## T8 Acceptance Criteria

- Clicking an alert citation navigates to `/alerts?alert=<id>`.
- Clicking a log citation navigates to `/logs?log=<id>`.
- Clicking a source citation navigates to `/?source=<id>` and opens source detail.
- ML report citations navigate to `/ml`.
- Assistant safety badges remain visible.
- Assistant cannot execute response actions.
- No raw log context or external provider is used by default.

## T9 API Contract

No API contract change. Existing assistant response citations remain:

```json
{ "label": "Alert detail", "source": "/api/alerts/{alert_id}", "reference_id": "1" }
```

The frontend maps known citation sources to dashboard routes.

## T10 Data Model / Migration

No schema or migration changes.

## T11 Backend Plan / Changes

No backend behavior changes. Backend tests verify that assistant citations remain safe, source-backed, and non-mutating.

## T12 Frontend Plan / Changes

- Add citation-to-route mapping in `AssistantPage.tsx`.
- Render citations as compact rows with optional `Open` links.
- Add source query context support to Assistant.
- Add source query handling in Overview.
- Add read-only `Ask Assistant` links in source detail, operations health, and AI Governance.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Response automation remains disabled.
- No real firewall blocking is enabled.
- No model activation or promotion is added.
- No external LLM call is enabled.
- Raw log context remains disabled by default.

## T14 Test Plan

- Backend assistant tests for safe citation coverage and no mutation.
- Playwright smoke test for citation route mapping and source context.
- Existing assistant safety and dashboard smoke coverage.
- Full release verification gates.

## T15 Implementation Summary

Assistant citations now provide dashboard handoffs for alert, log, source, operation, detection, and ML context. The handoffs are navigation-only and do not add mutation capabilities.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py -q --basetemp .pytest_tmp\v323-assistant -p no:cacheprovider`: pass, `9 passed`.
- `cd frontend; npm.cmd run lint`: pass.
- `node scripts/render-tasklist-progress-html.js .`: pass.
- `node scripts/check-tasklist-progress-standard.js .`: pass.
- `node -c scripts/render-tasklist-progress-html.js; node -c scripts/check-tasklist-progress-standard.js`: pass.
- `.\.venv\Scripts\ruff.exe check .`: pass.
- `.\.venv\Scripts\python.exe -m compileall -q atdr migrations`: pass.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v323-full -p no:cacheprovider`: pass, `306 passed, 1 skipped`.
- `.\.venv\Scripts\alembic.exe check`: pass, no new upgrade operations detected.
- `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e`: pass, Playwright `14 passed, 1 skipped`.
- `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty`: pass, dry-run wrote no DB rows.
- `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty`: pass, no warnings; Overview `0.4197s`, cached `0.0066s`, ML Governance `1.1286s`.
- `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release`: pass, `ok: true`.

## T17 PRD / Docs Updated

- `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md`
- `docs/changes/T1_T20_V3_23_ASSISTANT_CONTEXT_LINKING.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Run/job citations currently open Overview Operations Health because no dedicated run detail route exists.
- Documentation citations remain text-only.
- Assistant remains deterministic local decision support.

## T19 Release / Rollback

Rollback is limited to reverting the frontend citation rendering and documentation/test changes. No database rollback is needed.

## T20 Final Handoff

Manual testers should open `/assistant`, ask alert/source/ML questions, click citation links, and confirm navigation is correct while no response or detection action is executed.
