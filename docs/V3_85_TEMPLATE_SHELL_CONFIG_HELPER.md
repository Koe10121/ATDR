# v3.85 Template Shell Config Helper

Date: 2026-07-11

## Summary

ATDR now includes a dry-run-first helper for preparing private `.env` values needed by the supervisor-template shell handoff flow:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_template_shell_config --dry-run --pretty
```

The helper can write changes only when explicitly run with `--write`; when writing, it creates a backup under `.tmp/env-backups/`.

## What It Sets

The helper sets only non-secret template-shell values:

- `MFU_IAM_ENABLED=true`
- `MFU_IAM_TEMPLATE_SHELL_ENABLED=true`
- `MFU_IAM_TEMPLATE_SHELL_BASE_URL`
- `MFU_IAM_TEMPLATE_SHELL_ME_PATH`
- `MFU_IAM_TEMPLATE_SHELL_HEADER`
- `MFU_IAM_ALLOWED_DOMAINS`
- `MFU_IAM_DEFAULT_ROLE`

Default local values:

```env
MFU_IAM_TEMPLATE_SHELL_BASE_URL=http://127.0.0.1:8214
MFU_IAM_TEMPLATE_SHELL_ME_PATH=/api/v1/auth/me
MFU_IAM_TEMPLATE_SHELL_HEADER=x-access-token
MFU_IAM_ALLOWED_DOMAINS=lamduan.mfu.ac.th
MFU_IAM_DEFAULT_ROLE=analyst
```

## What It Does Not Set

- No API keys.
- No client secrets.
- No session tokens.
- No `.env` commit.
- No admin allowlist.
- No database mutation.
- No login attempt.
- No response automation.

`MFU_IAM_ADMIN_EMAILS` remains manual on purpose. Admin access must be explicitly approved and configured.

## Commands

Preview:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m atdr.scripts.use_template_shell_config --dry-run --pretty
```

Write with backup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_template_shell_config --write --pretty
```

Validate after writing and starting services:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

## Safety

The command output reports changed keys, not secret values. Existing secret-like `.env` content is not returned in the JSON result.

