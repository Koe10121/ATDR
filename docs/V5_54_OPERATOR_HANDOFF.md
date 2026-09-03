# v5.54 ATDR Operator Handoff

Date: 2026-09-02

## Product Boundary

ATDR collects firewall/syslog records, preserves raw evidence, normalizes
investigation fields, runs deterministic detection, presents explainable alerts,
and supports analyst decisions through a read-only SOC Assistant. Deterministic
rules are alert-authoritative. Supervised ML and IsolationForest are advisory.
Response is simulated and always requires an analyst action; real firewall
blocking is disabled.

This handoff describes a local release candidate. It is not a production or
university-environment acceptance claim.

## Install Once

Requirements:

- Windows 10/11 and PowerShell;
- Python 3.11;
- Node.js 20.19 or newer and npm;
- MongoDB listening on loopback for the MFU companion shell;
- the approved checksum-locked MFU shell package;
- private shell configuration and OAuth client values from the approved owner.

From the ATDR root:

```powershell
.\scripts\setup_team.cmd `
  -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  -ShellPrivateConfigRoot "D:\Private MFU Configuration"
```

Setup creates ignored runtime configuration, preserves existing data, backs up
SQLite before migration, and runs additive Alembic migrations. It does not
reset or seed the configured database.

## Normal Lifecycle

```powershell
.\scripts\start_system.cmd
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

Wait for `All components are ready`. Enter only at:

```text
http://localhost:8080/#/pages/login
```

The MFU shell owns school sign-in. ATDR consumes a short-lived, single-use
server-side handoff and creates its own HttpOnly session. Local passwords are
disabled in this profile. A real MFU account/group acceptance remains an
external university check.

To restart, stop and start again. If startup fails, run `check_system.cmd` and
correct only the reported dependency or field names. Never paste private
configuration into chat, issues, screenshots, or tracked files.

## Ingest Logs

Normal analysts use the dashboard source/import workflow. Operators may import
an external private file directly:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "D:\Private Logs\firewall.log" --limit 5000
```

For large imports, submit the durable operation from the dashboard and run an
approved worker. Check progress, cancellation, retry, staging capacity, parser
quality, and source health before detection. Private logs stay outside Git.

For live lab traffic, start the receiver on loopback unless the network owner
has approved another bind address:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

## Detect And Investigate

1. Confirm source health and parser quality.
2. Run detection from the dashboard for the intended source/window.
3. Triage rule-created alerts by severity, evidence strength, and SLA.
4. Open `Why flagged` and verify related logs, rule evidence, parser caveats,
   ATT&CK-style context, and recommended checks.
5. Assign the alert, record notes, and update status only from observed
   evidence.

No current supervised candidate qualifies for activation. The governed
v5.49b evaluation selected zero candidates, so lifecycle remains
`shadow_observation`. Do not activate historical registry rows.

## SOC Assistant And Gemini

The Assistant answers from bounded ATDR context: alerts, related logs,
source-health aggregates, operation/job summaries, ML governance, and approved
runbook guidance. Each answer identifies its source references and whether it
used deterministic synthesis or an external provider.

When privately configured, Gemini may synthesize the already-redacted bounded
context. Raw log provider context remains disabled. IP redaction remains
enabled. The Assistant cannot run detection, change labels, update users,
activate models, delete data, or create response actions. If Gemini is
unavailable, deterministic fallback remains usable.

Never treat an Assistant answer as alert authority. Open its cited ATDR record
before acting.

## Response Boundary

`RESPONSE_SIMULATION=true` and `RESPONSE_PROVIDER=simulation` are mandatory.
Dashboard response controls record an analyst-approved simulation and audit
event only. They do not change a firewall. Automatic response and real blocking
must remain disabled.

## Backup, Restore, Recovery

Preview and execute backup only to ignored or external storage:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --execute --pretty
```

Validate restore into a new empty target; never overwrite the configured
database. Use `docs/OPERATIONS_RUNBOOK.md` for the exact restore and isolated
disaster-recovery commands.

Local recovery is an explicit private profile only. Stop normal services,
back up data, select `ATDR_AUTH_MODE=local_recovery`, and start FastAPI/React
directly as documented in the operations runbook. Return to `template_shell`
before normal operation.

## Troubleshooting Order

1. `check_system.cmd` for package, dependency, configuration, and service state.
2. Ignored `.atdr_runtime/logs/` for the named component only.
3. `/health/live` and `/health` for backend liveness/readiness.
4. Operation Jobs for import/detection worker state.
5. Source Health and parser-quality panels for evidence problems.
6. AI Governance for model/Assistant state.
7. `docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md` when the blocker belongs to MFU,
   Gemini governance, a physical teammate, field hardware, or the host owner.

Redis connection warnings do not block the local shell because its rate-limit
store has an in-memory fallback. MongoDB is required by the shell. ATDR itself
uses SQLite locally or PostgreSQL on an approved shared host.

## Handoff Decision

Local setup, shell-first lifecycle, health, secure handoff configuration,
restart, and explicit local-recovery login have been exercised in disposable
storage. Final v5.54 verification remains the source of truth for the release
candidate decision. External acceptance must be recorded only by the owners in
`docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md`.
