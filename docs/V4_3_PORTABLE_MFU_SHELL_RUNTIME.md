# v4.3 Portable MFU Shell Runtime

Date: 2026-07-15

## Outcome

v4.3 makes the supervisor MFU application shell the normal ATDR entry point and adds a portable Windows team lifecycle. ATDR remains FastAPI, React, SQLAlchemy/Alembic, and SQLite locally; the external shell remains Node, Vue, and MongoDB.

## Runtime Topology

```text
Browser
  -> MFU shell frontend :8080
  -> MFU shell backend :8214
  -> one-time opaque handoff code
  -> ATDR FastAPI :8000
  -> HttpOnly ATDR session
  -> ATDR React :5173
```

The repositories remain separate. The shell path is supplied at setup time and stored only in ignored runtime configuration. No developer username, Desktop path, Downloads path, private shell file, or secret is committed.

## Delivered Controls

- `ATDR_AUTH_MODE=template_shell` is the fail-closed runtime default.
- `local_recovery` is the only profile that permits direct local login.
- Public auth status reports mode/readiness without secret material.
- Invalid startup configuration produces a concise operational 503 while liveness and safe public auth status remain available.
- Setup generates private JWT, handoff, and shell session secrets.
- Existing `.env` files are preserved unless `-UpdateExistingConfig` is explicit.
- Existing SQLite data is backed up before Alembic migration and is never reset or seeded automatically.
- Launcher PIDs, logs, private paths, and backups live only in ignored locations.
- Startup checks Python, Node, npm, MongoDB, shell structure, configuration field names, ports, dependencies, and four service readiness endpoints.
- The launcher allows up to four minutes for the supervisor shell's first cold Vue/Webpack compile while retaining concise failure guidance.
- Provider preflight distinguishes private IAM proxy readiness, environment-specific Google client configuration, and real account/scope acceptance.
- Shutdown acts only on PIDs and start times recorded by the launcher.
- `.cmd` entry points avoid permanent PowerShell execution-policy changes.

## Secure Handoff

The shell stores only a SHA-256 hash of a random short-lived code. The browser form-posts the opaque code without putting it in a URL. ATDR exchanges it with the shell backend using a private shared secret, consumes it once, maps the verified identity, and sets an HttpOnly cookie. Reuse, expiry, invalid origin, invalid domain, disabled accounts, subject mismatch, and unapproved admin mapping fail closed.

## Commands

```powershell
.\scripts\setup_team.cmd -TemplateRoot "<MFU_SHELL_ROOT>"
.\scripts\start_system.cmd
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

## Validation Boundary

Source contracts, one-time exchange behavior, login fail-closed behavior, portable paths, dry-run database preservation, stale PID safety, frontend shell mode, and component builds are covered locally. The approved private local shell currently has the required IAM proxy field names configured, but `VUE_APP_CLIENTID` is not environment-configured and the source uses a legacy fallback. A true provider-backed MFU sign-in and project-scope assignment remain environment acceptance activities and must not be inferred from configuration, mock, source-contract, or local shell tests.

## Final Local Acceptance Evidence

- A disposable project copy under a Windows path containing spaces completed setup against its own SQLite database.
- FastAPI, React, the MFU shell backend, and the MFU shell frontend reached readiness `4/4`.
- The shell page returned HTTP 200; shell mode rejected direct local login with HTTP 403.
- Stop affected exactly the four processes recorded by the launcher.
- Focused ATDR shell/auth tests passed `14`; the full backend passed `577` with `1` hardware-dependent skip.
- Supervisor shell service tests passed `37`, IAM SDK tests passed `15`, and handoff/IAM contracts passed `12`.
- React lint/build passed; Playwright passed `23` with `1` live-scenario skip.
- Replay dry-run wrote zero rows. The release gate returned `ok: true` with no failed required check.
- The configured `.env` and `atdr.db` hashes remained unchanged.
- Read-only performance smoke retained a known large-SQLite warning: cold Overview `9.7888s` and ML Governance `2.2851s`; cached Overview was `0.0075s`.

The supervisor shell's upstream aggregate npm test command uses Unix-style inline environment syntax. On Windows, the equivalent test sets were run with process-local PowerShell environment variables; the runtime lifecycle scripts do not depend on that upstream test wrapper.

## Unchanged Safety

- No automatic response.
- No real firewall blocking.
- No automatic model activation or promotion.
- No raw logs sent to an external assistant by default.
- No database reset or destructive migration.
- No production-readiness claim.
