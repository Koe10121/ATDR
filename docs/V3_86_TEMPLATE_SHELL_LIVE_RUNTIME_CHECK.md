# v3.86 Template Shell Live Runtime Check

Date: 2026-07-11

## Summary

The supervisor-template outer-shell path was validated at runtime on the local machine up to the point that does not require a real logged-in browser session.

Validated:

- ATDR backend reachable on `http://127.0.0.1:8000`
- ATDR React dashboard reachable on `http://127.0.0.1:5173`
- Supervisor template backend reachable on `http://127.0.0.1:8214`
- Supervisor template frontend reachable on `http://localhost:8080`
- ATDR private config is in `template_shell_session_handoff` mode
- ATDR public MFU IAM status reports token login ready
- Template profile endpoint `/api/v1/auth/me` is reachable and protected
- Static source contract remains present
- Secrets exposed: false

Not yet validated:

- A real logged-in template session token
- End-to-end click from template shell into ATDR after school-email login

## Commands Used

ATDR private `.env` was prepared with the dry-run-first helper:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_template_shell_config --write --pretty
```

The command created a private `.env` backup under `.tmp/env-backups/`.

ATDR backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

ATDR frontend:

```powershell
npm.cmd run dev
```

Template backend:

```powershell
set DOTENV_CONFIG_PATH=.env.local&& node -r dotenv/config server.js
```

Note: the template's `npm run start:local` script uses Unix-style environment-variable syntax, so the Windows-safe command above was used.

Template frontend:

```powershell
npm.cmd run serve:local
```

Runtime validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

## Runtime Result

The validator returned:

- `ok: true`
- `static_contract_ok: true`
- `template_contract_detected: true`
- `atdr_receiver_detected: true`
- `mfu_iam.mode: template_shell_session_handoff`
- `mfu_iam.template_shell_ready: true`
- `atdr_runtime.health_reachable: true`
- `atdr_runtime.public_status_reachable: true`
- `template_runtime.reachable: true`
- `template_runtime.protected_endpoint_detected: true`
- `template_runtime.status_code: 401`
- `secrets_exposed: false`

The template profile endpoint returning `401` without a session token is expected. It proves the endpoint is reachable and protected.

## Template Runtime Notes

Template backend:

- MongoDB connection reported connected.
- Redis connection was refused on `127.0.0.1:6379`.

Redis refusal did not prevent the template backend from binding to port `8214`, but template features that depend on Redis may need a Redis service or template configuration review.

Template frontend:

- Compiled successfully.
- Local URL: `http://localhost:8080/`

## Next Manual Validation

1. Open the template frontend:

   ```text
   http://localhost:8080/
   ```

2. Log in through the supervisor template using the approved school-email flow.
3. Click `Open ATDR SOC Dashboard`.
4. Confirm ATDR opens and the URL token-like values are cleared.
5. Confirm ATDR dashboard shows the mapped school user as analyst unless an explicit admin mapping was configured.
6. Confirm local ATDR login remains available as fallback.

Optional manual token probe, only for local validation:

```powershell
$env:ATDR_TEMPLATE_SESSION_TOKEN = "<paste-template-session-value-for-this-terminal-only>"
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --session-token-env ATDR_TEMPLATE_SESSION_TOKEN --pretty
Remove-Item Env:\ATDR_TEMPLATE_SESSION_TOKEN
```

The command reports whether a profile email was present, but it does not print the token or email value.

## Safety

- No response automation was enabled.
- No real firewall blocking was enabled.
- No model activation or promotion occurred.
- No raw logs were shared.
- No secrets or session tokens were printed.
- No database reset or deletion occurred.

