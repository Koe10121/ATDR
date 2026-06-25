# v3.63 Real LLM Assistant Adapter

## Status

Implemented as a disabled-by-default provider adapter for the SOC Assistant.

ATDR now has a safe adapter layer for:

- Gemini
- OpenAI-compatible chat completions
- Claude / Anthropic messages
- mock provider for tests

The default behavior remains deterministic local assistant answers. External LLM calls happen only when `ASSISTANT_LLM_ENABLED=true`, a supported provider is configured, and the provider has the required configuration.

## What Changed

- Added `atdr/app/services/assistant_llm.py` with provider-specific adapters and a shared safe prompt contract.
- Wired the assistant response path so ATDR first builds the existing deterministic answer, then optionally asks the configured LLM to improve wording using bounded, redacted context.
- Added safe status fields for LLM base URL and timeout configuration without exposing values.
- Added `.env.example` and `.env.lab.example` placeholders:
  - `ASSISTANT_LLM_BASE_URL`
  - `ASSISTANT_LLM_TIMEOUT_SECONDS`
- Updated the React Assistant status cards to show configured provider readiness without exposing keys or endpoint details.
- Added tests for mock-provider usage, redaction, provider-used audit, and no response action creation.

## Safety Contract

The adapter must remain:

- disabled by default;
- read-only;
- deterministic-fallback safe;
- raw-log-context disabled by default;
- IP-redaction aware;
- secret-hiding in status and errors;
- unable to execute response actions, detection runs, label changes, user changes, model activation, model promotion, data deletion, or firewall changes.

The provider receives only a bounded prompt built from:

- analyst question;
- deterministic assistant answer;
- context labels;
- citations;
- suggested follow-ups;
- safety rules.

Raw log lines are not included by default.

## Configuration

Default safe local configuration:

```env
ASSISTANT_LLM_ENABLED=false
ASSISTANT_LLM_PROVIDER=""
ASSISTANT_LLM_MODEL=""
ASSISTANT_LLM_API_KEY=""
ASSISTANT_LLM_BASE_URL=""
ASSISTANT_LLM_TIMEOUT_SECONDS=15
ASSISTANT_REDACT_IPS=true
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
```

Supported provider values:

- `gemini`
- `openai`
- `openai_compatible`
- `claude`
- `anthropic`
- `mock` for tests only

## Current Limitations

- No API key is committed.
- No provider is enabled by default.
- No per-question provider toggle exists yet.
- No production data-sharing approval is assumed.
- Prompt-injection testing should continue before using real private data.
- Real school/MFU provider approval is still needed before using school-managed LLM access.

## Manual Test

1. Start backend and frontend normally.
2. Open `http://127.0.0.1:5173`.
3. Open `SOC Assistant`.
4. Confirm status shows local/deterministic mode unless `.env` explicitly enables an LLM provider.
5. Ask an alert question and confirm:
   - answer is read-only;
   - citations remain visible;
   - raw logs are not shown;
   - no response action is created.

For real provider testing later, set provider values only in local `.env` and never commit the file.
