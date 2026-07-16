# v4.4 MFU Authentication And Shell Integration Stabilization

## Status

ATDR uses the separately supplied MFU Vue/Node application as its normal authentication shell. ATDR remains FastAPI, React, SQLAlchemy/Alembic, and SQLite for local use. The shell-to-ATDR transition uses a short-lived one-time code, a server-to-server exchange, and an HttpOnly ATDR session cookie.

Local implementation hardening is complete. Real Google/MFU account acceptance is **not yet validated** because the approved shell's private Google client fields are currently unconfigured. No provider credential was invented, copied into Git, or displayed by the diagnostics.

## Confirmed Root Cause

The July 2026 Google `400 invalid_request` behavior was not an ATDR parser, database, or handoff failure. Source and private-configuration inspection established that:

- `frontend-vue/.env.localdev` did not configure `VUE_APP_CLIENTID`.
- `backend-node/.env.local` did not configure `GOOGLE_CLIENT_ID`.
- The frontend and backend source used an old hardcoded Google client fallback.
- Google rejected the MFU account for that legacy client/origin policy.

The fallback has been removed from the authorized local shell copy. Startup now fails clearly until matching approved client IDs are supplied privately.

## Implemented Controls

- `template_auth_doctor` checks frontend/backend configuration agreement without returning either value.
- `setup_team` and `start_system` fail closed for missing, mismatched, or legacy Google client configuration.
- `check_system` reports only booleans, a diagnosis code, and the approved local origin.
- The static bridge validator verifies the Express `/atdr/handoff` mount and `/start` action separately, so it now checks the real composed route instead of relying on a concatenated source literal.
- The shell backend returns a safe `AUTH_GOOGLE_NOT_CONFIGURED` response when its audience is absent.
- The shell frontend maps common cancellation, access-denied, and configuration failures to concise messages without showing provider payloads.
- ATDR maps expired, replayed, unavailable, invalid-response, disabled-account, identity-conflict, and disallowed-domain handoff failures to safe UI messages.
- External identities default to `analyst`; only configured approved groups can produce `admin`.
- Local username/password login remains available only through the explicit `local_recovery` profile.
- Response automation and real firewall blocking remain disabled.

## Private Configuration Required

The approved Google OAuth **Web application** client identifier must be placed in both ignored shell files:

```text
frontend-vue/.env.localdev: VUE_APP_CLIENTID=<approved OAuth Web client ID>
backend-node/.env.local:    GOOGLE_CLIENT_ID=<the same client ID>
```

Do not put the value in ATDR source, documentation, support messages, screenshots, or committed example files. This popup/ID-token flow does not require ATDR to receive a Google client secret.

Validate safely:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.template_auth_doctor `
  --template-root "D:\Path To\mfu-ai-driven-log-based-threat-detection-and-response" `
  --pretty
```

The result must show `ready: true`, matching IDs, no legacy fallback, and `secrets_exposed: false`.

## Exact University Administrator Action

An authorized MFU/Google Workspace administrator must provide or approve one OAuth 2.0 Web application client for this application and configure:

- Local authorized JavaScript origin: `http://localhost:8080`
- Preproduction origin: `https://preprod-mfu-ai-driven-log-based-threat-detection-and-response.mfu.ac.th`
- Production origin: `https://mfu-ai-driven-log-based-threat-detection-and-response.mfu.ac.th`
- Approved Workspace domain/account policy for `lamduan.mfu.ac.th`
- Internal consent-screen access or explicit test-user access, as required by the university policy
- Secure delivery of the approved client ID to the project team
- Revocation and rotation of any IAM administrator credential that was ever shared outside the approved university secret channel

The administrator should also confirm the approved IAM group identifier that maps to ATDR `admin`. Without that written mapping, school users remain analysts.

Do not add redirect URIs by guesswork. The current shell uses a Google popup/ID-token flow; any redirect URI must come from the approved provider/client design.

## Normal Operation

After the private client ID is configured:

```powershell
cd C:\Path\To\ATDR
.\scripts\setup_team.cmd -TemplateRoot "D:\Path To\mfu-ai-driven-log-based-threat-detection-and-response" -UpdateExistingConfig
.\scripts\start_system.cmd
.\scripts\check_system.cmd -RequireReady
```

Open only:

```text
http://localhost:8080/#/pages/login
```

Acceptance requires a real approved school account to sign in, reach React `/overview`, receive an external ATDR user mapping, and leave no token or one-time code in the URL or logs.

## Recovery And Rollback

Run `scripts/stop_system.cmd` to stop launcher-owned services. For an authorized recovery event, set `ATDR_AUTH_MODE=local_recovery` privately and start the ATDR backend/frontend directly. Recovery mode must never be selected automatically after an MFU provider failure.

The hardening tool stores source backups only under ignored `.atdr_runtime/template-backups/`. It does not modify either private client-ID value or the ATDR database.

## Remaining Evidence

- Successful Google/MFU login using the approved client
- Successful one-time handoff to `/overview`
- Provider-managed 2FA/session evidence
- Approved analyst/admin group mapping evidence
- Preproduction HTTPS, logout, recovery, and deprovisioning acceptance

Until those items exist, MFU authentication is locally hardened but not provider-accepted or production-ready.

## Local Verification Result

- Task-board render/check, Ruff, compileall, and Alembic drift check passed.
- Focused v4.4/MFU/handoff tests passed `19`; corrected bridge/runtime contract tests passed `10`.
- Full backend passed `584`, with one hardware-dependent skip. The release gate repeated the same result and returned `ok: true` with no failed required checks.
- React lint/build passed; Playwright passed `24`, with one hardware-dependent skip.
- The external Vue production build passed and its Node one-time handoff tests passed `3/3`.
- Replay dry-run parsed two safe rows and wrote zero.
- Read-only performance smoke returned `ok: true`; cached Overview was `0.0093s`. Cold large-SQLite Overview (`11.806s`) and ML Governance (`2.7463s`) remain documented capacity warnings unrelated to authentication.
- Setup/start/check correctly fail closed with `frontend_client_not_configured`; stop remains safe and idempotent.
