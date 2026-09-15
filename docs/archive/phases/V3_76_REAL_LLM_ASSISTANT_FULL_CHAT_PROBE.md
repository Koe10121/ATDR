# v3.76 Real LLM Assistant Full Chat Probe

Date: 2026-06-27

## Summary

v3.76 adds a safe command-line probe for the full SOC Assistant chat path with a configured external LLM provider. Unlike the lower-level provider probe, this script exercises the same assistant service used by the dashboard while using a synthetic temporary database so the current ATDR database is not modified.

The probe is intended for real-provider validation after a private `.env` config is added.

## New Command

Status-only check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --pretty
```

Full synthetic assistant chat check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --execute --pretty
```

## What It Validates

- Whether external LLM settings are enabled/configured.
- Whether the full assistant service can call the configured provider.
- Whether the provider answer passes existing assistant guardrails.
- Whether raw log context stays disabled.
- Whether the synthetic raw line is not exposed.
- Whether API keys/secrets are not exposed.
- Whether the assistant creates only an audit row in the temporary database.
- Whether response actions, detection runs, labels, and model runs remain unchanged.

## Current Local Result

With the user's private `.env` configuration, the probe reported:

- Provider: Gemini
- Provider call executed: true
- Provider answer used: true
- Raw log context included: false
- Raw synthetic line exposed: false
- Secrets exposed: false
- Response actions created: 0
- Detection runs created: 0
- Labels changed: 0
- Model runs created: 0
- Temporary audit row created: true

No real database rows were modified because the probe uses an in-memory synthetic database.

## Safety Boundaries

- The command does not print API keys.
- The command does not read or print `.env`.
- The command does not send raw logs by default.
- The command does not modify the current ATDR database.
- The assistant remains read-only.
- Response automation and real firewall blocking remain disabled.

## Remaining Work

- Manually test the dashboard Assistant page with the same private provider configuration.
- Continue refining provider answer quality if real outputs are too verbose, too terse, or miss important citations.
- Keep deterministic fallback and provider-output guardrails enabled for all future assistant work.
