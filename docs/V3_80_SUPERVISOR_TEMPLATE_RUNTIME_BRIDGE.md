# v3.80 Supervisor Template Runtime Bridge Validation

Date: 2026-07-11

## Summary

v3.80 adds a safe, repeatable validation command for the official supervisor template outer-shell integration.

The goal is to prove the template has the expected school-login/IAM shell contract before wiring live provider behavior into ATDR. This phase does not migrate ATDR to Node/Vue/MongoDB, does not enable real firewall blocking, and does not change detection or ML behavior.

## What The Template Provides

The official supervisor template at:

```text
C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response
```

contains the expected IAM/login building blocks:

- IAM system docs and recommendations
- IAM SDK adapter
- B2B bearer-token middleware
- token introspection and client-profile calls
- Vue login flow
- 2FA/OTP flow
- `x-access-token` session storage
- security permission matrix modules
- project IAM env variable names

The important runtime finding is that the template completes login/2FA and stores a template session token as `x-access-token`.

## ATDR Bridge Contract

ATDR now has the receiving side from v3.79:

```text
GET /login?mfu_token=<token-or-code>&next=/assistant&source=template-shell
```

The login page accepts these token/code parameter names:

- `mfu_token`
- `iam_token`
- `handoff_token`
- `atdr_handoff_token`
- `x_access_token`
- `access_token`
- `token`
- `handoff_code`
- `atdr_handoff_code`
- `code`

ATDR then clears token-like values from the URL and uses:

```text
POST /api/auth/mfu-iam/token-login
```

to validate the token/code through the configured MFU IAM path.

## New Validation Command

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_bridge_contract --pretty
```

The command checks:

- supervisor template path exists
- expected IAM/login/security files exist
- template login markers are present
- template uses `x-access-token`
- template has IAM SDK env variable names
- ATDR handoff receiver exists
- ATDR accepts token/code-like handoff params
- ATDR clears URL handoff values
- ATDR has the backend token-login validation path

The command only reports env variable names and readiness booleans. It does not print env values, API keys, client secrets, tokens, or passwords.

## Current Result

Current local validation result:

```text
ok: true
template_contract_detected: true
atdr_receiver_detected: true
secrets_exposed: false
```

This means the source-level bridge contract is present. It does not mean live school-email login is fully verified yet.

## Recommended Local Flow

For local validation, after the supervisor template finishes login and 2FA, the template shell can open ATDR with a handoff URL:

```text
http://127.0.0.1:5173/login?mfu_token=<template_x_access_token_or_short_handoff_code>&next=/assistant&source=template-shell
```

ATDR should then:

1. detect the handoff value
2. clear it from the URL
3. call the token-login endpoint only if MFU IAM is ready
4. create or update the local ATDR user for the verified school email
5. default new school users to analyst unless admin mapping is configured
6. open the requested ATDR route

## Recommended Production-Like Flow

For production-like deployment, prefer a short-lived server-side handoff code instead of a long bearer token in a URL.

Recommended sequence:

1. user logs into the supervisor template shell
2. template backend confirms login, 2FA, and permissions
3. template backend creates a short-lived handoff code
4. browser redirects to ATDR with the code
5. ATDR backend exchanges the code with the template/IAM backend
6. ATDR issues its own local JWT session

This requires a provider/template endpoint that can exchange a handoff code. If the official template cannot provide that yet, the `x-access-token` handoff remains the practical local bridge for controlled testing.

## What Still Requires Input

Live completion still requires private/provider details:

- approved local/preprod/prod callback URLs
- whether ATDR should receive `x-access-token`, IAM access token, Google token, or short-lived handoff code
- allowed school email domains
- admin/analyst role mapping
- whether provider-managed 2FA proof is included in the token/profile
- whether template backend can create a short-lived handoff code
- whether ATDR and template will run behind the same domain/reverse proxy

## Safety Boundaries

- Do not commit `.env` files or copied template secrets.
- Do not print client secrets, API keys, or tokens.
- Do not hard-code one student email as the only user.
- Keep local ATDR username/password fallback.
- Keep response automation disabled.
- Keep real firewall blocking disabled.
- Keep the SOC Assistant read-only.
- Keep raw logs out of external LLM context by default.

## Verification

This phase added:

- `atdr/app/services/template_bridge_contract.py`
- `atdr/scripts/validate_template_bridge_contract.py`
- `atdr/tests/test_template_bridge_contract.py`

Verification commands:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_bridge_contract --pretty
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_template_bridge_contract.py -q --basetemp .pytest_tmp\template-bridge -p no:cacheprovider
.\.venv\Scripts\ruff.exe check atdr\app\services\template_bridge_contract.py atdr\scripts\validate_template_bridge_contract.py atdr\tests\test_template_bridge_contract.py
.\.venv\Scripts\python.exe -m compileall -q atdr\app\services\template_bridge_contract.py atdr\scripts\validate_template_bridge_contract.py atdr\tests\test_template_bridge_contract.py
```

All focused checks passed.
