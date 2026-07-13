# v3.83 Template Shell Session Adapter

Date: 2026-07-11

## Summary

ATDR now supports a safer supervisor-template outer-shell handoff mode. Instead of assuming the template `x-access-token` is directly introspectable by MFU IAM, ATDR can validate the template session through the template backend profile endpoint and then map the verified school email into an ATDR user.

This keeps the advisor-provided template responsible for login, account lifecycle, and 2FA/OTP behavior while ATDR remains the SOC module for ingestion, parsing, detection, AI assistance, simulated response, and audit.

## What Changed

- Added disabled-by-default template shell session settings:
  - `MFU_IAM_TEMPLATE_SHELL_ENABLED`
  - `MFU_IAM_TEMPLATE_SHELL_BASE_URL`
  - `MFU_IAM_TEMPLATE_SHELL_ME_PATH`
  - `MFU_IAM_TEMPLATE_SHELL_HEADER`
- Added a template-shell identity validation path in `atdr/app/services/mfu_iam_service.py`.
- Added non-secret readiness fields to MFU IAM status responses.
- Updated the Admin / Settings dashboard to show template shell handoff readiness.
- Added backend tests for template-shell status, successful school-email mapping, and failure safety.

## Intended Local Configuration

Use private `.env` only. Do not commit real secrets.

```env
MFU_IAM_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_BASE_URL=http://127.0.0.1:8214
MFU_IAM_TEMPLATE_SHELL_ME_PATH=/api/v1/auth/me
MFU_IAM_TEMPLATE_SHELL_HEADER=x-access-token
MFU_IAM_ALLOWED_DOMAINS=lamduan.mfu.ac.th
MFU_IAM_DEFAULT_ROLE=analyst
```

Admin role mapping must be explicit:

```env
MFU_IAM_ADMIN_EMAILS=
```

Do not hard-code one school email as the only accepted user. A school email may be configured as a local test/admin mapping only when approved.

## Runtime Flow

1. User signs in through the supervisor template shell.
2. Template shell completes its login and 2FA flow.
3. User clicks `Open ATDR SOC Dashboard`.
4. Template launches ATDR with a session handoff value.
5. ATDR React login receiver immediately clears token-like URL data.
6. ATDR backend calls the template backend profile endpoint using the configured session header.
7. Template backend verifies the session and returns the current profile.
8. ATDR extracts the verified school email, checks allowed domains, maps the user to `analyst` by default, and issues an ATDR JWT.
9. ATDR audits success or failure without storing the handoff token.

## Safety Behavior

- Local username/password login remains available.
- Template-shell IAM remains disabled unless explicitly configured.
- Secrets are never returned by status endpoints.
- Handoff tokens are not written to audit details.
- Admin role requires an explicit allowlist.
- No response automation is enabled.
- No real firewall blocking is enabled.
- The SOC Assistant remains read-only.

## What Still Requires Live Validation

- Start the template backend and frontend.
- Sign in with a school account through the template.
- Click the ATDR launcher.
- Confirm ATDR maps the school email correctly.
- Confirm failed/expired template sessions are rejected cleanly.
- Confirm production/preprod URL and HTTPS routing with advisor-approved deployment settings.

## Verification

Targeted backend verification passed after implementation:

```powershell
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_api.py -q --basetemp .pytest_tmp\template-shell-api -p no:cacheprovider
.\.venv\Scripts\ruff.exe check atdr\app\core\config.py atdr\app\services\mfu_iam_service.py atdr\app\schemas\auth.py atdr\tests\test_api.py
.\.venv\Scripts\python.exe -m compileall -q atdr\app\core\config.py atdr\app\services\mfu_iam_service.py atdr\app\schemas\auth.py atdr\tests\test_api.py
```

Result:

- Backend focused tests: `38 passed`
- Ruff: passed
- Compileall: passed

