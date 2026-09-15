# v4.6 Versioned MFU Shell Distribution

## Decision

ATDR now treats the MFU outer shell as a separately distributed, sanitized companion release. The normal teammate input is the approved archive `mfu-atdr-shell-1.4.0-atdr.1.zip`, not a machine-specific supervisor download directory. ATDR remains FastAPI, React, SQLAlchemy/Alembic, and SQLite by default.

This is a controlled deployment-readiness improvement. It does not prove production readiness or university-provider acceptance.

## Release Contract

`config/mfu-shell-contract.json` locks:

- contract version `2`;
- shell release `1.4.0-atdr.1`;
- archive SHA-256 `ce327eb315eac0591026e68eb416ba8415c0d3f2e6e6b371c2671f1ac2c72d3a`;
- source fingerprint `cd6ce0de6824b6d1749f7c937d63b0d6a4e7b8df565e3f353ae0d6f2eded1201`;
- allowed source roots and required runtime files;
- excluded private, generated, test, upload, model, backup, and environment paths.

The archive contains 454 source files and a self-describing `mfu-shell-release.json` manifest. It is generated deterministically and remains outside Git.

## Safety Boundary

The package builder rejects private `.env` files, credentials, assigned secrets, hard-coded Google client identifiers, private keys, unsafe links, and archive traversal paths. It excludes `node_modules`, builds, logs, uploads, model binaries, backup files, and generated artifacts.

Private provider files remain separately controlled:

- `backend-node/.env.local`
- `frontend-vue/.env.localdev`

They may be copied only from an approved private configuration directory during setup. No secret value is printed, returned, or stored in the repository.

## Teammate Workflow

Use a reasonably short Windows path; spaces are supported.

```powershell
cd "C:\ATDR Team\ATDR"
.\scripts\setup_team.cmd -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip"
.\scripts\check_system.cmd
.\scripts\start_system.cmd
```

When authorized private provider configuration is supplied:

```powershell
.\scripts\setup_team.cmd `
  -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  -ShellPrivateConfigRoot "D:\Private MFU Configuration"
```

The setup command verifies the archive against the contract, installs it under ignored `.atdr_runtime/shell/<release>`, records only non-secret metadata, installs dependencies, and applies migrations without resetting data. Re-running setup reuses a verified release.

## Acceptance Evidence

A disposable clean clone in a normal desktop path containing spaces began without a virtual environment, dependencies, database, private provider files, or generated data.

- first setup: passed in `554.8s`;
- Python environment and all three JavaScript dependency trees installed;
- disposable SQLite migrated from empty state to Alembic head;
- installation readiness: `true`;
- package integrity: `verified`;
- provider readiness: `false`;
- secrets exposed: `false`;
- repeat setup with dependencies skipped: passed in `3.2s` and reused the release;
- start dry-run: failed closed with one private-provider configuration blocker;
- stop: passed twice with no process metadata.

Provider readiness is intentionally independent of installation readiness. A successful university sign-in still requires an approved OAuth Web client, matching private frontend/backend client configuration, authorized domains/groups, provider-managed 2FA policy, and a real account acceptance run.

## Verification

- taskboard render/standard check: passed;
- Ruff and compileall: passed;
- package/auth/portability tests: `23 passed`;
- full backend: `595 passed, 1 skipped`;
- Alembic: no drift;
- React lint/build: passed;
- Playwright: `25 passed, 1 skipped`;
- replay dry-run: parsed 2, wrote 0;
- performance smoke: `ok: true`, with the inherited cold large-SQLite warning retained;
- release gate: `ok: true`, no failed required checks.

## Unchanged Safety Controls

- MFU shell remains the normal entry path.
- Local credentials remain an explicit recovery profile only.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- No model is activated or promoted.
- The current database is not copied or reset.
