# ATDR Team Startup

ATDR uses the approved MFU application as its mandatory outer shell. A normal user starts at the MFU sign-in page and enters the React SOC console only through the secure one-time handoff.

## What A Teammate Needs

- Windows 10 or 11 with PowerShell.
- Python 3.11.
- Node.js `20.19.0` or newer with npm.
- MongoDB Community Server running on `127.0.0.1:27017` for the MFU shell.
- A clone or zip of this ATDR repository.
- A separate approved copy of the supervisor MFU shell.
- The shell's private backend/frontend environment files, obtained through the approved channel.
- One university-approved Google OAuth Web client ID configured identically as `VUE_APP_CLIENTID` and `GOOGLE_CLIENT_ID` before normal startup.

The supervisor shell is not copied into ATDR and its private environment file is never committed.

## First Setup

Open PowerShell in the ATDR repository and run one command. The shell can be in any folder, including a path containing spaces.

```powershell
.\scripts\setup_team.cmd -TemplateRoot "D:\Approved Projects\mfu-ai-driven-log-based-threat-detection-and-response"
```

The setup command:

- discovers the ATDR root from the script location;
- validates the approved shell structure without printing secrets;
- creates `.venv` and installs missing dependencies;
- creates ignored private ATDR configuration with random local secrets;
- records the shell location in ignored `.atdr_runtime/team-config.json`;
- backs up an existing SQLite database before migrations;
- applies additive Alembic migrations without resetting or seeding data.

Setup also checks whether the private shell profile contains the required MongoDB, IAM proxy, admin-scope, permission-group, and 2FA field names with non-placeholder values. It never prints or copies those values. Missing provider settings do not block dependency installation or Alembic migration; they are reported as a separate provider-readiness blocker, and normal startup remains fail-closed.

When matching Google frontend/backend client configuration is present, setup also removes the old source fallback with an ignored backup. Diagnose without displaying the value:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.template_auth_doctor --template-root "D:\Approved Projects\mfu-ai-driven-log-based-threat-detection-and-response" --pretty
```

For an existing private `.env` that must be converted to shell mode, review it first and use:

```powershell
.\scripts\setup_team.cmd -TemplateRoot "D:\Approved Projects\mfu-ai-driven-log-based-threat-detection-and-response" -UpdateExistingConfig
```

The previous `.env` is copied to ignored `.atdr_runtime/config-backups/` before updates.

To inspect setup without changing files or the database:

```powershell
.\scripts\setup_team.cmd -TemplateRoot "D:\Approved Projects\mfu-ai-driven-log-based-threat-detection-and-response" -DryRun
```

## Start, Check, And Stop

After setup, start the whole system with:

```powershell
.\scripts\start_system.cmd
```

The launcher starts and checks all four components:

1. ATDR FastAPI on port `8000`.
2. ATDR React on port `5173`.
3. MFU shell backend on port `8214`.
4. MFU shell frontend on port `8080`.

It then opens the normal entry point:

```text
http://localhost:8080/#/pages/login
```

The first shell launch can take two to four minutes while the legacy Vue/Webpack application performs a cold compile. The launcher waits for readiness and keeps progress logs under ignored `.atdr_runtime/logs/`.

Check configuration and service state without exposing secret values:

```powershell
.\scripts\check_system.cmd
```

The report deliberately separates:

- **Installation ready:** Python/pip, Node 20.19+, npm, shell structure, private ATDR configuration, SQLite/Alembic, and response simulation are usable;

- **IAM proxy configured:** required private shell fields appear usable;
- **Google authentication ready:** both private client fields are configured identically and no source fallback exists;
- **MFU account acceptance:** remains `not validated` until an authorized user completes a real provider sign-in and passes the project-scope check.

v4.4 removed the legacy Google client fallback. Preflight now stops normal startup when the approved client is missing or mismatched.

Stop only processes recorded by the launcher:

```powershell
.\scripts\stop_system.cmd
```

## Authentication Contract

- `template_shell` is the normal profile and fails closed if the shell handoff is incomplete.
- Direct ATDR username/password login is hidden and rejected in this profile.
- The shell issues a short-lived, single-use opaque code after its own authenticated session.
- ATDR exchanges the code server-to-server and sets its own HttpOnly session cookie.
- School credentials, OTP values, bearer tokens, and bridge secrets are never placed in the handoff URL.
- New external users default to `analyst`; `admin` requires an approved IAM group mapping.
- `local_recovery` is an explicit recovery/development profile, not the normal user path.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Script execution is blocked | Use the `.cmd` launchers above; they apply process-only PowerShell bypass and do not change machine policy. |
| Node version is rejected | Install Node.js 20.19 or newer and rerun setup. |
| Shell path missing | Rerun setup with `-TemplateRoot`; no username-specific path is built into ATDR. |
| MongoDB unavailable | Start MongoDB, then run `check_system.cmd`. MongoDB is required by the MFU shell, not by ATDR's SQL database. |
| Port already occupied | Run `stop_system.cmd`; if the process was not launcher-owned, stop the owning application and rerun. |
| Configuration incomplete | Run `check_system.cmd`; it lists missing field names only. |
| Google configuration diagnosis | Run `template_auth_doctor`; set matching private frontend/backend client IDs through the approved channel. |
| Google `400 invalid_request` | Use exactly `http://localhost:8080` and ask the university administrator to authorize that JavaScript origin and the school domain/account policy. |
| MFU sign-in returns `account_not_in_..._scope` | The provider recognized the identity, but IAM has not assigned it to this project's approved group/scope. Ask the MFU IAM owner to add the account; do not bypass the check. |
| MFU sign-in fails before scope checking | Check the shell's private provider configuration, approved Google client ID, and MongoDB. Do not paste credentials into logs, issues, or chat. |
| Handoff fails | Confirm both services use the same private handoff secret and the exact local origins; rerun setup if needed. |
| Backend shows a configuration traceback | Current startup returns a concise 503 instead; run the preflight and correct the reported field names. |

## Honest Scope

The local shell-to-ATDR contract is testable and portable. Real MFU provider authentication, provider-managed 2FA, approved group mapping, recovery, and deprovisioning still require authorized university environment validation. Response automation and real firewall blocking remain disabled.
