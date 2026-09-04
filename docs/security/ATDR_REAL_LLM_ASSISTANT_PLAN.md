# ATDR Real LLM Assistant Plan

## Status

The SOC Assistant normally runs in deterministic local mode. It is read-only, audited, and cannot execute response actions, run detection, mutate labels, activate models, change accounts, or expose raw logs by default.

v3.63 added provider adapters for Gemini, OpenAI-compatible APIs, Claude/Anthropic, and a mock provider. v3.65 added a command-line provider probe. v3.87 completes validated structured answers, bounded conversation context, retries, rate limiting, privacy filtering, safe audit telemetry, and full-service real-provider validation. v5.56 adds request-bound Gemini citations, a provider hard ceiling, aggregate operational telemetry, usage warnings, and expanded deterministic QA. External LLM calls remain disabled by default and require explicit private `.env` configuration.

## Recommended Provider Strategy

| Priority | Provider | Why |
| --- | --- | --- |
| 1 | Gemini | Best fit if MFU school accounts or Google Workspace access are approved. |
| 2 | OpenAI-compatible API | Strong general SOC reasoning and flexible provider abstraction if a managed key is available. |
| 3 | Claude / Anthropic | Good fallback for long-context policy or investigation summaries if approved. |

Do not hard-code a vendor into the assistant logic. Add a provider adapter so ATDR can switch providers by `.env` only after security review.

## Safe Config Placeholders

```env
ASSISTANT_LLM_ENABLED=false
ASSISTANT_LLM_PROVIDER=""
ASSISTANT_LLM_MODEL=""
ASSISTANT_LLM_API_KEY=""
ASSISTANT_LLM_BASE_URL=""
ASSISTANT_LLM_TIMEOUT_SECONDS=15
ASSISTANT_LLM_USAGE_WARNING_TOKENS=100000
```

These are separate from the existing deterministic assistant settings. Keep them disabled unless a provider, key handling policy, and data-sharing review are approved.

Existing safety settings still apply:

```env
ASSISTANT_REDACT_IPS=true
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
ASSISTANT_MAX_CONTEXT_ROWS=20
```

## Required Safety Contract

The external LLM adapter must:

- stay disabled unless `ASSISTANT_LLM_ENABLED=true`;
- never return or expose API keys;
- redact IPs when `ASSISTANT_REDACT_IPS=true`;
- not include raw logs unless a future privacy review explicitly allows it;
- send only bounded, summarized context;
- include citations/source references in the response;
- refuse requests to execute response, detection, label, user, source, model, email, or data-changing actions;
- audit every question with provider-used status and context type;
- fail closed to deterministic local help if the provider is unavailable;
- avoid claiming production accuracy or autonomous incident authority.

## Allowed Assistant Use Cases

- Explain why an alert was flagged.
- Summarize related logs without sending raw log lines by default.
- Summarize source health and parser warnings.
- Explain operations/job failures.
- Explain AI Governance status.
- Generate an investigation brief.
- Suggest analyst next checks before any simulated response.
- Explain safe lab commands and runbooks.

## Disallowed Assistant Use Cases

- Block or unblock an IP.
- Run detection.
- Import or delete logs.
- Change labels.
- Train, activate, promote, or roll back a model.
- Create users or change roles.
- Send email or verification codes.
- Export raw private evidence to an external provider by default.
- Give production-readiness claims.

## Implementation Phases

1. Status-only placeholders and documentation. Done.
2. Provider abstraction interface with a mock provider in tests. Done in v3.63.
3. Gemini adapter if school/Google provider access is approved. Adapter exists; disabled until configured.
4. OpenAI-compatible and Claude adapters only if API keys and data-sharing rules are approved. Adapters exist; disabled until configured.
5. Prompt-injection and privacy tests with redacted context.
6. Dashboard provider-status display and clear fallback behavior. Done for safe provider readiness.
7. Optional per-question "use external LLM" control after audit/privacy review.

## Current Decision

Gemini is the validated local provider candidate. ATDR must still keep deterministic behavior as the default for unconfigured environments and must obtain organizational approval for provider data sharing, key custody, quotas, and deployment use.

## v3.87 Implemented Contract

- ATDR retrieves evidence and sends only bounded, sanitized structured context.
- Raw log lines remain excluded by default.
- IP redaction remains enabled by default.
- Provider output must pass the current `soc_intent_aware_concise_v5` JSON contract.
- Citations are limited to references supplied by ATDR.
- Actor-scoped conversation context supports follow-ups without trusting client-only state.
- Explicit global prompts clear stale alert/log/source/case context.
- Transient provider failures are retried within configured limits; failures fall back deterministically.
- Per-actor rate limiting protects provider quota and the API.
- Prompt-injection, secret, and action requests stay local and are refused.
- The provider cannot execute ATDR actions or mutate data.

## Safe Provider Probe

Run status-only provider readiness:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
```

Run one minimal provider call only after configuring a private `.env` and setting `ASSISTANT_LLM_ENABLED=true`:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --execute --pretty
```

The probe reports whether a provider/model/key are configured, but never prints API keys. It sends only bounded safety-policy context and does not include raw logs.

## v5.56 Operational Reliability Addendum

- Gemini receives a response schema whose citation enum contains only the
  canonical ATDR citations supplied for that request.
- A post-response guard still rejects unknown or ambiguous citations.
- Provider content over 120 words, over the visible-character limit, malformed,
  unsafe, unredacted, or ungrounded falls back to deterministic output.
- Valid provider content is centrally rendered to the narrower intent budget.
- Authenticated status exposes aggregate counts, latency, named failure events,
  circuit state, token totals, threshold state, and optional configured-rate
  cost estimates only.
- Prompts, responses, identities, keys, provider payloads, and raw evidence are
  never included in operational status.
- Process-local counters reset on backend restart. Persistent monitoring,
  billing, retention, and quota governance remain external acceptance work.

The synthetic v5.56 corpus passes `30/30` independent questions and one
four-turn follow-up sequence with citation rate `1.0000`, average/max response
length `56.0/110` words, and zero authoritative side effects. Private minimal
and full-chat Gemini probes pass with raw logs excluded, redaction enabled,
secrets hidden, and no detection, label, model, or response mutations.
