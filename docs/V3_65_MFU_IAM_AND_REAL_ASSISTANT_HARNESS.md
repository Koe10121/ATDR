# v3.65 MFU IAM And Real Assistant Harness

## Status

v3.65 adds a safe bridge from the supervisor MFU IAM template into ATDR without changing ATDR's stack or normal startup flow. Local username/password login remains the default. MFU school-email token login is disabled unless explicitly configured in a private `.env`.

The SOC Assistant real-LLM path remains disabled by default. A command-line provider probe was added so an operator can check configured Gemini/OpenAI-compatible/Claude/mock provider readiness without exposing API keys.

## What Changed

| Area | Result | Evidence |
| --- | --- | --- |
| MFU IAM public readiness | Added safe unauthenticated login-page status | `GET /api/auth/mfu-iam/public-status` |
| MFU IAM token login | Added disabled-by-default external token handoff | `POST /api/auth/mfu-iam/token-login` |
| Local user mapping | Verified school-email identities map to local ATDR users | `atdr/app/services/mfu_iam_service.py` |
| Role mapping | New external users default to analyst unless explicitly allowlisted | `MFU_IAM_ADMIN_EMAILS` |
| Audit | Success, failure, and denied-domain events are audited | `mfu_iam_login_success`, `mfu_iam_login_failed` |
| Frontend login | School email token login panel appears only when ready | `frontend/src/pages/LoginPage.tsx` |
| Admin status | Token login, test harness, and admin mapping readiness are visible | `frontend/src/pages/UserAdmin.tsx` |
| LLM provider probe | Added explicit CLI probe; no provider call unless requested | `python -m atdr.scripts.test_assistant_llm_provider --pretty` |

## MFU IAM Safety Model

- `MFU_IAM_ENABLED=false` by default.
- `MFU_IAM_MOCK_ENABLED=false` by default.
- `MFU_IAM_ALLOWED_DOMAINS` must be configured before token login is accepted.
- Newly provisioned external users become `analyst` by default.
- Admin external login requires explicit `MFU_IAM_ADMIN_EMAILS`.
- No client secret, API key, or `.env` value is returned by status endpoints.
- Local username/password login stays available.
- No response action, model activation, data deletion, or firewall operation is connected to IAM login.

## Real Provider Readiness

The supervisor template provides MFU IAM B2B variables, token/introspection/profile paths, Google client ID placeholders, 2FA/OTP UI references, and permission bootstrap concepts. ATDR now understands those values through ATDR-specific settings and aliases, but real provider operation still requires private `.env` configuration and provider reachability.

The test school email `6631501139@lamduan.mfu.ac.th` can be used as a local test account, but it is not hard-coded as the only allowed user. Allowed users are controlled by domain and optional role mapping.

## Real LLM Assistant Harness

Use:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
```

This reports provider readiness only. To run one minimal external call, configure `ASSISTANT_LLM_ENABLED=true`, provider/model/key fields in private `.env`, then run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --execute --pretty
```

The probe sends only bounded safety-policy context. It does not send raw logs and does not expose the API key.

## Manual Test Notes

For local mock IAM testing only:

```env
MFU_IAM_ENABLED=true
MFU_IAM_MOCK_ENABLED=true
MFU_IAM_ALLOWED_DOMAINS="lamduan.mfu.ac.th"
MFU_IAM_ADMIN_EMAILS="6631501139@lamduan.mfu.ac.th"
```

Then start the normal backend/frontend and use token:

```text
mock:6631501139@lamduan.mfu.ac.th
```

Do not commit `.env`.

## Remaining Work

- Validate real MFU IAM token introspection against provider service.
- Confirm final Google/MFU Mail browser login flow if required.
- Confirm provider-managed 2FA behavior.
- Decide whether admin mapping should come from IAM groups instead of explicit email allowlist.
- Get approval before using any real external LLM provider with school data.

## Safety Decision

ATDR remains a controlled lab prototype. MFU IAM and real LLM support are configuration-gated integration harnesses. Response automation remains disabled, real firewall blocking remains disabled, and ML remains decision support only.
