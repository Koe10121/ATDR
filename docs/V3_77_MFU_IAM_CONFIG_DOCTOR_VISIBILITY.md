# v3.77 MFU IAM Config Doctor Visibility

Date: 2026-06-27

## Summary

v3.77 adds MFU IAM readiness visibility to `config_doctor` so operators can quickly see whether ATDR is running in local-login mode, mock mode, or ready for a private MFU IAM provider probe.

This does not enable external IAM login. It only reports safe non-secret readiness booleans.

## What Changed

`python -m atdr.scripts.config_doctor --pretty` now includes an `mfu_iam` block:

- `enabled`
- `mode`
- `token_login_ready`
- `b2b_ready`
- `admin_api_ready`
- `permission_bootstrap_ready`
- `mock_enabled`
- `google_sso_enabled`
- `allowed_domains`
- `domain_hints`
- `default_role`
- `auth_require_2fa`
- `secrets_exposed`

It also warns when:

- MFU IAM fields are configured while `MFU_IAM_ENABLED=false`.
- MFU IAM is enabled but token login is not ready.
- MFU IAM is enabled without allowed domains.
- MFU IAM mock mode is enabled in production-like configuration.

## Current Local Result

Current local config reports:

- Mode: `local_login_only`
- MFU IAM enabled: false
- Token login ready: false
- B2B ready: false
- Admin API ready: false
- Permission bootstrap ready: false
- Secrets exposed: false

This means the school-email IAM path is implemented as disabled-by-default groundwork, but the current `.env` is not configured for live MFU IAM validation yet.

## What To Configure Privately

To move from local-login mode to live MFU IAM validation, configure these in private `.env` only:

- `MFU_IAM_ENABLED=true`
- `IAM_SDK_BASE_URL` or `MFU_IAM_BASE_URL`
- `IAM_SDK_CLIENT_ID` or `MFU_IAM_CLIENT_ID`
- `IAM_SDK_CLIENT_SECRET` or `MFU_IAM_CLIENT_SECRET`
- `IAM_SDK_AUDIENCE` or `MFU_IAM_AUDIENCE`
- `IAM_SDK_SCOPE` or `MFU_IAM_SCOPE`
- `IAM_SDK_TOKEN_PATH` or `MFU_IAM_TOKEN_PATH`
- `IAM_SDK_INTROSPECT_PATH` or `MFU_IAM_INTROSPECT_PATH`
- `IAM_SDK_PROFILE_PATH` or `MFU_IAM_PROFILE_PATH`
- `MFU_IAM_ALLOWED_DOMAINS=lamduan.mfu.ac.th`
- Optional explicit admin mapping: `MFU_IAM_ADMIN_EMAILS=<approved-school-email>`

Do not commit `.env` or any secret values.

## Validation Commands

Status only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty
```

Live provider probe after private config:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --execute --pretty
```

## Safety Boundaries

- Local username/password login remains available.
- External IAM login remains disabled until `MFU_IAM_ENABLED=true`.
- No secrets are returned by config doctor or IAM status APIs.
- No response automation or real firewall blocking is affected.
