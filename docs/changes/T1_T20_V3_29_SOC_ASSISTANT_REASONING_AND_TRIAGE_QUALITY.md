# T1-T20 Change Document: v3.29 SOC Assistant Reasoning And Triage Quality

## T1 Change Title

v3.29 SOC Assistant Reasoning And Triage Quality

## T2 Requirement

Improve the SOC Assistant's professional triage usefulness by adding stronger answer structure, false-positive awareness, missing-evidence handling, source/case risk summaries, and concrete investigation guidance while preserving read-only behavior.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/scripts/evaluate_assistant_qa.py`
- `atdr/tests/test_assistant.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md`
- `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`

## T4 Current Behavior

Before v3.29, the assistant could answer alert, log, source, case, operations, ML, and workflow questions with citations and safety boundaries. It was safe, but some answers were still closer to evidence summaries than professional SOC triage guidance.

## T5 Impacted Areas / Agents

- Backend / Assistant service
- Frontend / SOC Assistant page
- Security / Response safety
- QA / Assistant evaluator
- Documentation / Governance

## T6 Scope

In scope:

- Add deterministic evidence-strength language.
- Add false-positive/noise caveats.
- Add missing-evidence notes.
- Add source risk/noise reasoning.
- Add case handoff risk interpretation.
- Improve preset grouping in the Assistant page.
- Expand assistant QA evaluator and tests.
- Update PRD, traceability, compliance, docs index, tasklist, and T1-T20 evidence.

Out of scope:

- External LLM enablement.
- Raw-log context sharing.
- Automatic assistant tuning.
- Feedback status lifecycle.
- Response action execution.
- Detection execution from chat.
- Label/model/data mutation from chat.

## T7 Functional Requirements

- Alert answers use Summary, Evidence, Risk interpretation, What to check next, Safety note, and Citations.
- False-positive questions return cautious review guidance rather than final dismissal.
- Missing-evidence questions identify gaps in compact ATDR context.
- Source questions explain health/noise/risk using source quality fields.
- Case handoff questions summarize computed groups without creating incidents.
- All answers remain read-only and cited where possible.

## T8 Acceptance Criteria

- Assistant QA evaluator passes expanded controlled question set.
- Backend tests cover false-positive reasoning, missing evidence, source risk, case handoff, and supervisor summaries.
- Frontend shows professional preset groups and section rendering.
- Assistant does not create response actions, detection runs, labels, ML model runs, logs, alerts, or feedback rows during evaluator runs.
- External provider and raw-log context remain disabled by default.

## T9 API Contract

No endpoint changes. Existing assistant endpoint continues to be used:

```text
POST /api/assistant/chat
```

Response `details.answer_sections` may now include:

- `risk_interpretation`
- `what_to_check_next`
- `safety_note`

Existing fields remain compatible.

## T10 Data Model / Migration

No database schema change.

## T11 Backend Plan / Changes

- Add deterministic reasoning helpers for evidence strength, false positives, and missing evidence.
- Enrich alert/log/source/case answer sections.
- Expand assistant QA evaluator with additional professional triage questions.
- Keep all assistant behavior non-mutating.

## T12 Frontend Plan / Changes

- Group Assistant presets by professional SOC workflows.
- Render Risk interpretation and What to check next sections before legacy fallback fields.
- Preserve technical context behind collapsed details.
- Keep safety badges visible.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Response automation remains disabled.
- Real firewall blocking is not implemented.
- External LLM remains disabled by default.
- Raw-log context remains disabled by default.
- Assistant cannot execute response, detection, label, model, source, user, email, or data actions.

## T14 Test Plan

- Backend tests for structured SOC answer sections, false-positive reasoning, missing evidence, source risk, case handoff, supervisor summary, and no side effects.
- Frontend smoke tests for preset groups, answer sections, safety badges, and no action controls.
- Assistant QA evaluator with 20 controlled questions.
- Full release verification.

## T15 Implementation Summary

v3.29 upgrades the assistant from a safe evidence explainer into a more professional read-only triage helper. It improves how answers discuss confidence, uncertainty, false positives, missing evidence, and next analyst checks while preserving ATDR's strict safety boundaries.

## T16 Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`
- `docs/changes/T1_T20_V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`
- `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Reasoning remains deterministic and evidence-template based.
- False-positive guidance is cautious and does not override analyst judgment.
- External LLM, raw logs, persisted notebooks, automatic tuning, and action execution remain future reviewed work.

## T19 Release / Rollback

Rollback can remove v3.29 helper logic, preset grouping, evaluator cases, docs, and tests. No database rollback is required.

## T20 Final Handoff

Manual testers should open `/assistant` and ask alert, false-positive, missing-evidence, source-risk, and case-handoff questions. Answers should include risk interpretation, concrete checks, citations, and safety notes while creating no actions or mutations.
