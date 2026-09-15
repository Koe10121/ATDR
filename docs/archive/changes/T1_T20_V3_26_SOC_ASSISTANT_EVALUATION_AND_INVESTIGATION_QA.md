# T1-T20 Change Document: v3.26 SOC Assistant Evaluation And End-To-End Investigation QA

## T1 Change Title

v3.26 SOC Assistant Evaluation And End-To-End Investigation QA

## T2 Requirement

Add a controlled, repeatable QA evaluator that proves the read-only SOC Assistant can answer key investigation questions with citations and no side effects.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `atdr/app/services/log_service.py`
- `atdr/app/services/detection_service.py`
- `atdr/scripts/evaluate_assistant_qa.py`
- `data/samples/scenarios/port_scan_like_traffic.txt`
- `atdr/tests/test_assistant.py`
- `atdr/tests/test_assistant_qa_evaluator.py`
- `frontend/src/pages/AssistantPage.tsx`
- `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`

## T4 Current Behavior

Before v3.26, the assistant could answer alert, log, source, case, and brief questions. The project did not yet have one repeatable evaluator that ran those questions end to end against a controlled detection fixture and checked for unwanted side effects.

## T5 Impacted Areas / Agents

- Backend / Assistant Service
- Detection / Scenario Fixture
- Security / Response Safety
- QA / UAT
- Documentation / Governance

## T6 Scope

In scope:

- Add a deterministic assistant QA question set.
- Add an evaluator script that uses a temporary in-memory DB.
- Import a safe scenario, run rule detection, and ask assistant questions against generated context.
- Verify citations, safety wording, and no-side-effect behavior.
- Add backend regression test coverage.
- Update PRD, traceability, compliance, docs index, tasklist, and T1-T20 records.

Out of scope:

- Persisted investigation notebooks.
- Persisted incidents beyond existing computed case/group behavior.
- External LLM enablement.
- Raw log sharing by default.
- Response action execution.
- Detection execution from chat.
- Label/model/user/source mutation from chat.
- ML model activation or promotion.

## T7 Functional Requirements

- Evaluator must cover alert, log, source, job, ML, safe next-step, brief, and unsafe-request questions.
- Evaluator must create its own temporary scenario fixture.
- Evaluator must verify no response actions, detection runs, model runs, labels, alerts, or logs are created by assistant answers.
- Evaluator must verify external provider and raw-log context are disabled by default.
- Evaluator must verify assistant questions are audited.

## T8 Acceptance Criteria

- `python -m atdr.scripts.evaluate_assistant_qa --pretty` returns `ok: true`.
- At least 15 controlled assistant questions pass.
- End-to-end scenario checks pass.
- Side-effect checks pass.
- Backend tests include the evaluator.
- No database migration is required.

## T9 API Contract

No public API contract change. Existing endpoint remains:

```json
POST /api/assistant/chat
{
  "question": "Why was alert 1 flagged?",
  "alert_id": 1,
  "log_id": null,
  "source_id": null,
  "case_id": null,
  "include_recent_context": true
}
```

The evaluator calls the assistant service directly with controlled in-memory data.

## T10 Data Model / Migration

No schema or migration changes.

## T11 Backend Plan / Changes

- Add `atdr/scripts/evaluate_assistant_qa.py`.
- Build an in-memory SQLite fixture using current SQLAlchemy models.
- Import safe port-scan scenario logs through the existing import service.
- Run existing detection service with ML disabled.
- Ask assistant questions through existing assistant service.
- Validate output, citations, safety, audit, and side effects.

## T12 Frontend Plan / Changes

No frontend behavior change was required. Existing SOC Assistant UI from v3.21-v3.25 remains the manual test surface.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- No external LLM call is enabled.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Assistant cannot execute response, detection, model, label, source, user, email, or data actions.

## T14 Test Plan

- Run the new evaluator script.
- Run assistant-focused backend tests.
- Run full backend tests, Alembic check, frontend lint/build/e2e, replay dry-run, performance smoke, and release gate.

## T15 Implementation Summary

v3.26 adds a repeatable QA harness for the SOC Assistant. It validates the assistant against a realistic investigation path while preserving all read-only and safety constraints.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\ruff.exe check atdr\scripts\evaluate_assistant_qa.py atdr\tests\test_assistant.py atdr\tests\test_assistant_qa_evaluator.py`: pass.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py atdr\tests\test_assistant_qa_evaluator.py -q --basetemp .pytest_tmp\v326-assistant -p no:cacheprovider`: pass, `16 passed`.
- `.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa`: pass, `15` question cases, `0` failed questions, all side-effect checks true.

Full verification evidence is recorded in the final v3.26 handoff.

## T17 PRD / Docs Updated

- `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`
- `docs/V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`
- `docs/changes/T1_T20_V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Controlled scenario QA is not production accuracy validation.
- The assistant remains deterministic and local by default.
- Persisted investigation notebook design is intentionally skipped for now.
- Real external LLM use requires future privacy, security, and provider review.

## T19 Release / Rollback

Rollback is limited to reverting the evaluator script, evaluator test, and v3.26 documentation. No database rollback is needed.

## T20 Final Handoff

Manual testers should run the evaluator, then open `/assistant` and ask the v3.26 question-set prompts. Confirm answers include citations, safety wording, and no action controls. Response automation, real firewall blocking, external LLM use, and raw-log sharing remain disabled.
