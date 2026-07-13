# v3.84 Template Shell Runtime Validation

Date: 2026-07-11

## Summary

ATDR now includes a non-mutating runtime validator for the supervisor-template outer-shell handoff path:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

The validator checks the static source contract, ATDR MFU/template-shell configuration, and optionally live ATDR/template service reachability without printing secrets or session tokens.

## Why This Exists

The advisor direction is to use the official supervisor template as the outer login/account shell, then open ATDR as the SOC module after school-email login. The static source bridge exists, but operators need a safe way to answer:

- Is the official template still present?
- Is the ATDR handoff receiver present?
- Is template-shell IAM enabled in private `.env`?
- Is the template profile endpoint configured?
- Is ATDR running?
- Is the template backend reachable?
- Does the profile endpoint look protected?
- If a manual session token is supplied privately, does the template return a profile with an email?

## Current Local Status

On the current local machine, the static bridge is present:

- official template detected
- ATDR receiver detected
- template launcher expected
- secrets exposed: false

Live handoff is not ready until private `.env` is configured:

- `MFU_IAM_ENABLED=false`
- `MFU_IAM_TEMPLATE_SHELL_ENABLED=false`
- `MFU_IAM_TEMPLATE_SHELL_BASE_URL` not configured
- `MFU_IAM_ALLOWED_DOMAINS` not configured

This is not a code failure. It means local ATDR is still running in safe local-login mode.

## Private Config Needed For Live Template-Shell Handoff

Use private `.env` only:

```env
MFU_IAM_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_BASE_URL=http://127.0.0.1:8214
MFU_IAM_TEMPLATE_SHELL_ME_PATH=/api/v1/auth/me
MFU_IAM_TEMPLATE_SHELL_HEADER=x-access-token
MFU_IAM_ALLOWED_DOMAINS=lamduan.mfu.ac.th
MFU_IAM_DEFAULT_ROLE=analyst
```

Do not commit `.env`. Do not hard-code a single school email as the only accepted user.

## Safe Config Helper

ATDR includes a dry-run-first helper that prepares the non-secret template-shell handoff values in private `.env`:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m atdr.scripts.use_template_shell_config --dry-run --pretty
```

If the preview looks correct, write it with a backup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_template_shell_config --write --pretty
```

The helper sets:

- `MFU_IAM_ENABLED`
- `MFU_IAM_TEMPLATE_SHELL_ENABLED`
- `MFU_IAM_TEMPLATE_SHELL_BASE_URL`
- `MFU_IAM_TEMPLATE_SHELL_ME_PATH`
- `MFU_IAM_TEMPLATE_SHELL_HEADER`
- `MFU_IAM_ALLOWED_DOMAINS`
- `MFU_IAM_DEFAULT_ROLE`

It does not set or print client secrets, API keys, session tokens, or `MFU_IAM_ADMIN_EMAILS`. Admin mapping remains an explicit manual decision.

## Live Validation Steps

Start ATDR backend:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start ATDR frontend:

```powershell
cd C:\Users\User\Desktop\ATDR\frontend
npm.cmd run dev
```

Start template backend:

```powershell
cd C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node
npm.cmd install
npm.cmd run start:local
```

Start template frontend:

```powershell
cd C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue
npm.cmd install
npm.cmd run serve:local
```

Run the runtime check:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

Expected result after config and services are ready:

- `static_contract_ok: true`
- `template_contract_detected: true`
- `atdr_receiver_detected: true`
- `mfu_iam.mode: template_shell_session_handoff`
- `mfu_iam.template_shell_ready: true`
- `atdr_runtime.public_status_reachable: true`
- `template_runtime.reachable: true`
- `secrets_exposed: false`

If the template profile endpoint returns `401` or `403` without a token, that is acceptable and means the endpoint is reachable and protected.

## Optional Manual Session Probe

Only for local validation, after logging into the template shell, a session token can be placed in a temporary environment variable and never printed:

```powershell
$env:ATDR_TEMPLATE_SESSION_TOKEN = "<paste-template-session-value-for-this-terminal-only>"
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --session-token-env ATDR_TEMPLATE_SESSION_TOKEN --pretty
Remove-Item Env:\ATDR_TEMPLATE_SESSION_TOKEN
```

The command reports whether a profile email was present, but it does not print the token or email value.

## Safety

- No database mutation.
- No user creation.
- No login attempt unless the operator manually uses the actual launcher/login flow.
- No response action.
- No model activation.
- No raw log sharing.
- Secrets and session tokens are not printed.
