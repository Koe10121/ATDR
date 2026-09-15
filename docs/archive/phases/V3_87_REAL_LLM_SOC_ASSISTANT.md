# v3.87 Real LLM SOC Assistant Integration And Reliability

Date: 2026-07-12

## Summary

v3.87 completes the guarded real-provider path for the ATDR SOC Assistant. The assistant can use a privately configured Gemini provider to improve evidence-grounded analyst summaries while ATDR retains control of context retrieval, authorization, redaction, citations, conversation scope, and all safety boundaries.

External-provider mode remains opt-in. With no valid provider configuration, the existing deterministic assistant continues to work.

## Implemented Behavior

- Authenticated admin and analyst users can ask read-only SOC questions.
- ATDR retrieves bounded alert, related-log summary, source-health, case, job/run, and ML-governance context.
- Raw log lines, secrets, tokens, passwords, private paths, and model paths are excluded from provider context.
- IP addresses are redacted when `ASSISTANT_REDACT_IPS=true`.
- Server-owned conversation context keeps follow-up questions attached to the correct alert, log, source, or case.
- Explicit IDs and global prompts override or clear stale context.
- Provider output must match a structured JSON contract before it can replace the deterministic presentation sections.
- Provider failures, malformed output, unsafe wording, and timeouts fall back to deterministic answers.
- Per-user rate limiting and bounded retries reduce accidental provider abuse.
- Audit rows record safe metadata only; prompts, raw logs, secrets, and credentials are not recorded.

## Structured Answer Contract

The provider returns these fields:

- `summary`
- `evidence`
- `risk_interpretation`
- `analyst_checks`
- `missing_information`
- `safety_notice`
- `suggested_followups`
- `citation_references`

ATDR filters citation references against citations supplied by the application. Log evidence is treated as untrusted data, so instructions embedded in log content cannot override the system policy.

## Real Provider Validation

The private local configuration was exercised through both provider and full assistant probes:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --execute --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --execute --pretty
```

The successful full-path probe reported:

- provider: Gemini
- external provider answer used: true
- structured output valid: true
- raw log context included: false
- IP redaction enabled: true
- secrets exposed: false
- response actions created: 0
- detection runs created: 0
- labels changed: 0
- model runs created: 0
- assistant audit created: true

The probe uses a synthetic temporary database and does not modify the current ATDR database.

## Reliability Finding

Gemini 2.5 Flash initially consumed its output budget with internal thinking and returned truncated JSON. ATDR now requests a zero thinking budget for that model family while retaining JSON response mode. A regression test protects this provider-specific behavior.

## Safety Boundary

The assistant cannot execute response actions, run detection, change labels, activate or promote models, administer users or sources, delete data, send email, or change firewall state. It is AI-assisted decision support only. Response automation and real firewall blocking remain disabled.

## Known Limitations

- Provider quality and availability depend on the configured external service.
- The assistant is not an autonomous SOC agent and does not replace analyst judgment.
- Raw logs remain unavailable to the external provider by default.
- Conversation memory is deliberately bounded and audit-backed rather than a full transcript store.
- Real-provider privacy, cost, quota, and organizational approval remain deployment responsibilities.

