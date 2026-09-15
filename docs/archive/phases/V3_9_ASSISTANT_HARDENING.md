# v3.9 Analyst Assistant Hardening

## Status

v3.9 improves the ATDR SOC Assistant without changing its safety boundary. The assistant remains local, deterministic, read-only, and decision-support only by default. It can summarize more ATDR context, provide prompt presets in the React dashboard, show recent assistant questions from audit records, and cite the ATDR sources used for each answer.

ATDR remains a controlled lab prototype. This phase does not add production promotion, automatic response, real firewall blocking, raw-log sharing, or external LLM calls by default.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Assistant API | `atdr/app/routers/assistant.py` |
| Assistant service | `atdr/app/services/assistant_service.py` |
| Assistant schemas | `atdr/app/schemas/assistant.py` |
| Audit model | `atdr/app/db/models.py` |
| React page | `frontend/src/pages/AssistantPage.tsx` |
| Frontend API/hooks/types | `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts`, `frontend/src/types/api.ts` |
| Backend tests | `atdr/tests/test_assistant.py` |
| Frontend tests | `frontend/tests/smoke.spec.ts` |

## What The Assistant Can Answer

- Latest critical or open alerts.
- Why an alert was flagged.
- Safe next analyst steps for an alert.
- Source health and sources with warning/error conditions.
- Recent ATDR activity from audit and operation job summaries.
- Failed operation jobs.
- Current ML Governance status and why the model is not production promoted.
- How to import reviewed labels.
- How to run safe source scenarios.
- Normal local startup and replay workflow.

## What The Assistant Cannot Do

- Execute block, unblock, containment, or any other response action.
- Enable automatic response.
- Perform real firewall blocking.
- Run detection or ingestion jobs.
- Change alert status, notes, labels, users, sources, or settings.
- Activate or promote any ML model.
- Delete, reset, or mutate ATDR data.
- Send raw logs to an external LLM by default.

## Privacy Rules

| Rule | v3.9 Behavior |
| --- | --- |
| External provider | Disabled by default. `external_provider_used` remains `false` in normal local mode. |
| API key exposure | Status and history endpoints never return `ASSISTANT_API_KEY`. |
| Raw logs | `raw_log_context_included=false` by default. |
| IP redaction | Enabled by default through `ASSISTANT_REDACT_IPS=true`. |
| Audit logging | Assistant questions are audited as summaries. Secrets and raw logs are not written to assistant history responses. |
| Context limit | `ASSISTANT_MAX_CONTEXT_ROWS` caps assistant context size. |

## External LLM Future Requirements

Before enabling an external LLM provider, ATDR needs a separate reviewed change with:

- approved provider and data-processing policy
- school or lab account ownership
- `.env` secret management
- allowed context policy
- raw-log sharing review
- prompt injection and data exfiltration tests
- audit retention decision
- explicit confirmation that response automation remains disabled

## Response Safety Rules

- The assistant is read-only.
- Response actions remain simulated.
- Response actions require authorized analyst/admin confirmation and justification outside the assistant.
- Protected IP safeguards remain enforced by response services.
- ML output and assistant output cannot trigger containment.

## Known Limitations

- Answers are deterministic summaries, not a general-purpose SOC copilot.
- The assistant may miss context if data is absent or outside the capped context size.
- External LLM integration is intentionally future work.
- Raw evidence remains available in ATDR investigation pages, not in assistant context by default.
- Assistant history is based on audit log summaries, not full transcripts.
