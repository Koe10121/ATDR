# v3.8 Analyst Assistant MVP

## Status

v3.8 adds a safe read-only SOC assistant MVP to ATDR. The assistant helps analysts understand alerts, sources, operations, ML governance, and lab workflow. It does not execute response actions, run detection, activate models, change labels, or modify source data.

ATDR remains a controlled lab prototype. It does not claim production readiness, real firewall blocking, or automatic response.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Assistant config | `atdr/app/core/config.py`, `.env.example`, `.env.lab.example` |
| Assistant schemas | `atdr/app/schemas/assistant.py` |
| Assistant service | `atdr/app/services/assistant_service.py` |
| Assistant API | `atdr/app/routers/assistant.py`, `atdr/app/main.py` |
| Frontend page | `frontend/src/pages/AssistantPage.tsx`, `frontend/src/App.tsx`, `frontend/src/components/AppShell.tsx` |
| Frontend API/hooks | `frontend/src/types/api.ts`, `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts` |
| Tests | `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |

## Behavior

- `GET /api/assistant/status` returns safe assistant configuration status.
- `POST /api/assistant/chat` answers read-only analyst questions.
- External LLM use is disabled by default.
- Deterministic local fallback answers common questions without external network calls.
- Raw log context is disabled by default.
- IP redaction is enabled by default.
- Questions are audited as `assistant_question`.
- API secrets are never returned.

## Supported Questions

Examples:

- What is the latest critical alert?
- Why was alert X flagged?
- Summarize source health.
- Summarize recent operation jobs.
- Explain current ML model status.
- What should an analyst check next?
- How do I run replay or detection?

## Safety Controls

| Control | v3.8 Behavior |
| --- | --- |
| Response actions | Not exposed or executable through assistant |
| Automatic response | Disabled |
| Real firewall blocking | Not implemented |
| Model activation | Not performed |
| Raw logs | Not included by default |
| IPs | Redacted by default |
| External provider | Disabled unless explicitly configured in `.env` |
| Audit | Assistant questions are recorded without secrets |

## Configuration

Default values:

```text
ASSISTANT_ENABLED=false
ASSISTANT_PROVIDER=disabled
ASSISTANT_MODEL=
ASSISTANT_API_KEY=
ASSISTANT_MAX_CONTEXT_ROWS=20
ASSISTANT_REDACT_IPS=true
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
```

Do not commit `.env` files or API keys. Full external LLM integration remains future work and requires privacy/security review.

## Remaining Gaps

- No external LLM provider is wired by default.
- No OAuth/OIDC chat identity delegation beyond existing local JWT auth.
- No raw-log sharing until privacy review approves it.
- No response/action execution through the assistant.
- Assistant answers are decision support and should be verified by analysts.
