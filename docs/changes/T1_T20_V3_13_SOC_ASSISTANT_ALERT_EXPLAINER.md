# T1-T20 Change Document: v3.13 SOC Assistant Alert Explainer

## T1. Change Title

v3.13 SOC Assistant Alert Explainer Upgrade

## T2. Requirement

Improve the read-only ATDR SOC Assistant so analysts can ask alert-specific questions and receive structured explanations that summarize why an alert was flagged, what evidence supports it, what ATT&CK-style mapping applies, and what an analyst should check next.

## T3. Source Evidence

| Area | Source |
| --- | --- |
| Assistant route | `atdr/app/routers/assistant.py` |
| Assistant service | `atdr/app/services/assistant_service.py` |
| Alert explanation builder | `atdr/app/detection/explanations.py` |
| Alert router | `atdr/app/routers/alerts.py` |
| Alerts dashboard | `frontend/src/pages/AlertsTriage.tsx` |
| Assistant dashboard | `frontend/src/pages/AssistantPage.tsx` |
| API client/types | `frontend/src/lib/api.ts`, `frontend/src/types/api.ts` |
| Prior detection docs | `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md`, `docs/V3_12_DETECTION_RULE_QUALITY.md`, `docs/DETECTION_RULE_CATALOG.md` |

## T4. Current Behavior

Before v3.13, the assistant could answer alert questions, but alert explanations were compact paragraph-style summaries. The Alerts page did not provide a direct assistant handoff from the alert detail drawer.

## T5. Impacted Areas / Agents

- Backend / API
- Frontend / Dashboard
- Security / Response Safety
- AI/ML Governance
- QA/UAT
- Documentation / Release-Ops

## T6. Scope

In scope:

- deterministic alert explainer intent improvements
- safe alert context building
- structured assistant answer format
- dashboard `Ask Assistant` handoff from alert detail
- backend/frontend tests
- docs and progress-board updates

Out of scope:

- external LLM calls
- raw log context sharing
- response action execution
- detection threshold changes
- ML retraining, activation, or promotion
- database schema changes
- real firewall blocking

## T7. Functional Requirements

- Assistant answers alert questions with clear sections.
- Assistant includes safe alert evidence context without full raw logs by default.
- Assistant cites alert/source/rule references when available.
- Alert detail drawer can prefill the assistant with the selected alert ID.
- Assistant remains read-only and audited.

## T8. Acceptance Criteria

- Alert explainer answer includes Summary, Why flagged, Evidence, ATT&CK mapping, Analyst next steps, Safety note, and References.
- Assistant response has `external_provider_used=false`.
- Assistant response has `raw_log_context_included=false`.
- Response actions are not created by assistant questions.
- Model runs are not created or activated by assistant questions.
- Alert detail shows `Ask Assistant`.
- Assistant long responses do not overflow.

## T9. API Contract

Existing API is preserved:

- `GET /api/assistant/status`
- `POST /api/assistant/chat`
- `GET /api/assistant/history`

No new API route is required. `POST /api/assistant/chat` continues to accept optional `alert_id`.

## T10. Data Model / Migration

No schema change and no Alembic migration.

## T11. Backend Plan / Changes

- Reuse `build_alert_detection_summary()` in assistant alert answers.
- Add safe helper logic for source rows, parser notes, grouped alert metadata, response history summary, rule names, and markdown-style sections.
- Expand intent routing for alert explanation, evidence, ATT&CK mapping, rule/model contribution, and response-safety questions.
- Preserve audit logging for every assistant question.

## T12. Frontend Plan / Changes

- Add `Ask Assistant` link in alert detail.
- Use query parameters to prefill the Assistant page with alert context.
- Keep safety badges visible.
- Keep technical context collapsed.

## T13. Security / Response / AI Safety

- Assistant is read-only.
- Assistant cannot execute response actions.
- Assistant cannot mutate alerts, labels, logs, users, models, or sources.
- Assistant cannot run detection.
- Assistant cannot retrain, activate, or promote ML models.
- External LLM remains disabled by default.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Real firewall blocking remains disabled/unimplemented.

## T14. Test Plan

Backend:

- authenticated assistant alert explanation
- latest critical alert explanation
- alert/source/rule citations
- redaction and raw-log exclusion
- no response action creation
- no model run creation
- unauthenticated rejection

Frontend:

- alert detail shows `Ask Assistant`
- click opens Assistant page with alert context
- assistant presets still work
- structured long response does not overflow
- response action controls are absent from assistant

## T15. Implementation Summary

- Updated `atdr/app/services/assistant_service.py`.
- Updated `frontend/src/pages/AssistantPage.tsx`.
- Updated `frontend/src/pages/AlertsTriage.tsx`.
- Updated backend and Playwright tests.
- Added v3.13 docs and change record.

## T16. Tests Run / Evidence

Targeted checks:

- `.\.venv\Scripts\ruff.exe check atdr\app\services\assistant_service.py atdr\tests\test_assistant.py`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py -q`
- `npm.cmd run lint`

Full verification is recorded in `docs/tasks/tasklist-progress.md` after final handoff.

## T17. PRD / Docs Updated

- `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- External LLM provider integration remains future work.
- Real-source traffic may require more assistant wording improvements.
- Assistant output remains decision support, not final incident classification.
- No blocker found during targeted testing.

## T19. Release / Rollback

Rollback:

- revert assistant service alert-answer changes
- remove `Ask Assistant` link/query handling
- revert tests/docs for v3.13

No data migration rollback is needed.

## T20. Final Handoff

v3.13 improves analyst usability by letting a user move directly from an alert to a read-only assistant explanation. It preserves response safety, ML decision-support boundaries, raw-log privacy defaults, and local deterministic behavior.
