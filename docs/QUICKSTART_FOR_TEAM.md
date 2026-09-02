# ATDR Quickstart For Team Members

This is the Windows quickstart for a fresh clone or zip. ATDR's normal entry is the approved MFU application shell; direct React login is not the normal user workflow.

## Architecture You Will Run

| Component | Stack | Local port |
| --- | --- | ---: |
| MFU outer-shell frontend | Vue | 8080 |
| MFU outer-shell backend | Node/Express/MongoDB | 8214 |
| ATDR API | FastAPI/SQLAlchemy | 8000 |
| ATDR SOC console | React/Vite | 5173 |

ATDR continues to use SQLite by default. MongoDB is required only by the separately supplied MFU shell.

## Requirements

- Windows 10/11 and PowerShell.
- Python 3.11.
- Node.js `20.19.0` or newer and npm. Node 16 and Node 20 releases below 20.19 are unsupported by the current Vite/Playwright toolchain.
- MongoDB Community Server for the shell.
- Git, or a GitHub zip download.
- The approved `mfu-atdr-shell-1.4.0-atdr.1.zip` companion archive and separately controlled private backend/frontend environment files.
- One approved Google OAuth Web client ID supplied through the university channel.

Never commit the shell's `.env.local`, ATDR `.env`, API keys, DB files, real logs, model artifacts, `ml_baseline_reviews/`, `demo_exports/`, or generated reports.

ATDR configuration references are `.env.example` for explicit local recovery/development, `.env.shell.example` for the normal MFU-shell profile, `.env.lab.example` for optional PostgreSQL lab work, and `frontend/.env.example` for direct React component development. Never commit the private files created from them.

## 1. Get ATDR And The Shell Release

Clone or extract ATDR into any folder:

```powershell
git clone <ATDR_REPOSITORY_URL> ATDR
Set-Location .\ATDR
```

Obtain the approved MFU shell archive separately from the supervisor/team channel. Do not extract it manually or place it in tracked ATDR source; setup verifies and installs it. Obtain its private environment through the approved channel.

Provider configuration may be added before or after installation. Normal startup requires the same approved Google OAuth Web client ID in these ignored shell files:

```text
frontend-vue/.env.localdev: VUE_APP_CLIENTID=<approved client ID>
backend-node/.env.local:    GOOGLE_CLIENT_ID=<the same client ID>
```

The local authorized JavaScript origin is exactly `http://localhost:8080`. Do not use the machine IP or `127.0.0.1` for the Google login page, and do not put the client value in ATDR source or documentation.

The private configuration directory supplied to setup must contain these relative files:

```text
backend-node/.env.local
frontend-vue/.env.localdev
```

## 2. Start MongoDB

Start the local MongoDB service used by the shell. The setup preflight checks `127.0.0.1:27017` but does not install or reset MongoDB.

## 3. Run Setup Once

From the ATDR root:

```powershell
.\scripts\setup_team.cmd -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip"
```

This verifies the package checksum and source manifest, installs it under ignored runtime storage, installs pinned Python dependencies from `requirements.lock.txt` plus lockfile-backed JavaScript dependencies, creates ignored private configuration, generates local secrets, records non-secret release metadata, backs up an existing SQLite database, and runs additive migrations. It does not reset or seed data. Installation can complete when private MFU/Google settings are unavailable; setup reports provider readiness separately, and startup stays blocked until the approved provider profile is installed.

With approved private provider configuration:

```powershell
.\scripts\setup_team.cmd `
  -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  -ShellPrivateConfigRoot "D:\Private MFU Configuration"
```

Preview the operation without changes:

```powershell
.\scripts\setup_team.cmd -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" -DryRun
```

For an existing ATDR `.env`, use `-UpdateExistingConfig` only after reviewing the change. Setup creates an ignored backup first.

## 4. Start The Whole System

```powershell
.\scripts\start_system.cmd
```

The launcher checks configuration and ports, starts all four services, waits for readiness, and opens:

```text
http://localhost:8080/#/pages/login
```

Sign in through the MFU shell. After authentication, choose **Open ATDR SOC Dashboard**. The shell issues a short-lived one-time code, ATDR exchanges it server-to-server, and the browser receives an HttpOnly ATDR session cookie.

## 5. Check Or Stop

```powershell
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

The check command reports readiness and missing field names without secret values. The stop command acts only on launcher-recorded processes.

## First Safe Validation

After entering ATDR, confirm Overview, Alerts, Investigation, SOC Assistant, AI Governance, and Response & Audit load. Response must show simulation/automation-disabled status.

Safe CLI validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

No log is written during this dry run.

Run the bounded end-to-end reliability lock only against disposable storage:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v538_product_reliability_acceptance --use-temp-db --pretty
```

Expected result is `11/11` gates, `configured_database_unchanged: true`, zero
real response actions, and no model activation. The command refuses to run
without `--use-temp-db` and does not return raw evidence, private paths, IPs,
or secrets.

Preview the idempotent bundled dashboard scenario:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_safe_demo --pretty
```

The preview writes nothing. Intentional execution requires `--execute --confirm SAFE_SYNTHETIC_DEMO`, uses synthetic evidence only, never resets data, and never creates response actions.

## Component Development And Recovery

The shell-first launcher is the normal user workflow. For an authorized recovery event or focused component development, the established commands remain available after selecting `ATDR_AUTH_MODE=local_recovery` privately:

```powershell
python -m atdr.scripts.check_dev_environment
python -m atdr.scripts.seed_users
cd frontend
npm.cmd run dev
```

The direct React component URL is `http://127.0.0.1:5173`. It is not the normal authentication entry in `template_shell` mode.

The safe two-line sample is `data/samples/paloalto-demo.txt`. Keep large or real logs outside Git and provide their private path only at runtime.

## Database Choice

- **SQLite** remains the default ATDR database for one-machine local use.
- **PostgreSQL** is the optional shared-lab/deployment database and is configured through `.env.lab.example`; it is not required for normal local startup.
- **MongoDB is not used currently by ATDR**; it belongs only to the separate supervisor MFU shell. ATDR has not migrated to MongoDB and keeps its relational SQLAlchemy/Alembic data model.

Do not migrate ATDR to MongoDB as part of teammate setup; the shell and ATDR intentionally retain separate persistence architectures.

## Recovery Profile

`ATDR_AUTH_MODE=local_recovery` exposes local username/password login for an authorized development or recovery event. It is not the standard teammate workflow and is not selected by the team launcher.

## Common Problems

| Problem | Resolution |
| --- | --- |
| `.ps1` scripts are blocked | Use the documented `.cmd` launchers; they do not change permanent execution policy. |
| Node version is rejected | Install Node.js 20.19 or newer. `node --version` must report at least `v20.19.0`. |
| Shell package not found or rejected | Obtain the approved archive and use `-ShellPackage`. Do not rename, edit, or re-zip it. |
| Windows extraction reports a long path | Move the clone to a shorter location such as `C:\ATDR Team\ATDR`; spaces are supported. |
| MongoDB unavailable | Start the MongoDB service, then run `check_system.cmd`. |
| Port 8000/5173/8214/8080 busy | Run `stop_system.cmd`; stop any non-launcher process using the reported port. |
| Configuration incomplete | Run `check_system.cmd` and correct only the named fields in private configuration. |
| `frontend_client_not_configured` | Set `VUE_APP_CLIENTID` in ignored `frontend-vue/.env.localdev`. |
| `backend_client_not_configured` | Set matching `GOOGLE_CLIENT_ID` in ignored `backend-node/.env.local`. |
| `client_id_mismatch` | Make the two private client IDs identical; do not print them while diagnosing. |
| Google `400 invalid_request` | Use `http://localhost:8080`; ask the MFU/Google administrator to authorize that exact JavaScript origin and school account/domain for the approved OAuth client. |
| MFU sign-in fails | Run `template_auth_doctor`; never paste tokens, client values, or private environment files into support messages. |
| Handoff fails | Confirm the shell is started by the team launcher and both services share the generated private bridge secret. |
| Large log is outside the repo | This is correct. Pass its private absolute path through the dashboard or CLI; never copy it into Git. |
| Safe sample imports only a few rows | The bundled sample is intentionally small. Use an external synthetic/private file for larger tests. |

## More Detail

- Full lifecycle: `docs/TEAM_ONE_COMMAND_START.md`
- Lab operations: `docs/LAB_RUNBOOK.md`
- v4.6 distribution and acceptance: `docs/V4_6_VERSIONED_MFU_SHELL_DISTRIBUTION.md`
- v4.4 authentication stabilization: `docs/V4_4_MFU_AUTH_STABILIZATION.md`
- v4.5 reproducible baseline: `docs/V4_5_REPRODUCIBLE_PRODUCT_BASELINE.md`
- IAM acceptance boundary: `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`
- v5.38 reliability lock: `docs/V5_38_PRODUCT_RELIABILITY_AND_FAILURE_MODE_LOCK.md`
- v5.53 release-readiness status: `docs/V5_53_MFU_IAM_AND_SHARED_DEPLOYMENT_READINESS.md`

## Physical Teammate Acceptance

After the repository baseline is committed and clean, a teammate can run a
read-only source preflight from their clone:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_team_runtime_acceptance `
  --template-root "C:\Path\To\Approved-MFU-Shell" `
  --pretty
```

The disposable full exercise requires the exact confirmation printed by the
CLI. It copies into temporary storage, starts and checks the shell-first stack,
stops only processes it owns, and cleans up. It deliberately does not mark the
physical-machine acceptance contract as passed; the teammate must retain the
real, private evidence and follow the v5.53 manifest guide.
