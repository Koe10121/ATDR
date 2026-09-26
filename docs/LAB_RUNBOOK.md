# ATDR Lab Runbook

This is the active hands-on lab reference. ATDR is a controlled release
candidate: deterministic rules create alerts, ML is advisory, the Assistant is
read-only, and response is simulated by default (an operator may explicitly
opt into a real, host-scoped Windows Firewall connector; see
`README.md#response-and-containment`).

## Normal Startup

Complete first-time installation with `docs/QUICKSTART_FOR_TEAM.md`. For daily
use from the repository root:

```powershell
.\scripts\start_system.cmd
.\scripts\check_system.cmd
```

Wait for `All components are ready`, then open:

```text
http://localhost:8080/#/pages/login
```

Stop or restart only through the tracked launcher:

```powershell
.\scripts\stop_system.cmd
.\scripts\start_system.cmd
```

The normal profile starts FastAPI, React, and the approved MFU Node/Vue shell.
MongoDB belongs to the shell; ATDR itself uses SQLite locally or PostgreSQL on
an approved shared host.

## Health And Safety Check

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
```

Require database health, `RESPONSE_SIMULATION=true`, no real response provider,
and no unexpected configuration disclosure. The startup checker must fail
closed when a required shell component or provider setting is missing.

## Import And Replay

Keep private logs outside Git and pass their path only at runtime:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "D:\Private Logs\firewall.log" --limit 5000
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

The importer preserves raw evidence before parsing. Malformed rows remain
available with parser warnings. For large files, submit a durable import from
the dashboard and run one worker with SQLite:

```powershell
$env:OPERATION_WORKER_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

Review progress, staging capacity, cancellation state, and worker heartbeat in
Operations Health. Do not run multiple SQLite workers.

With `OPERATION_WORKER_ENABLED=true` in `.env`, `.\scripts\start_system.cmd`
starts this one worker for you (tracked as `atdr-worker` and stopped by
`.\scripts\stop_system.cmd`), so do not also start it by hand. Run
`.\scripts\stop_system.cmd` before the full backend test suite: six acceptance
tests (v48, v525, v538) prove a test run never changes the configured
`atdr.db` files, and the running worker's heartbeat legitimately does.

After an import, open Validation Controls and use **Check all unchecked logs**.
Each log records the detection run that checked it, so this checks every
unchecked log once, oldest first, in batches, instead of only the newest batch.

## Live Syslog Lab Flow

Loopback is the safe default:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

A non-loopback sender requires an approved interface, firewall rule, registered
source, and network owner. A loopback or replay test does not qualify a
physical firewall source.

## Detect And Investigate

1. Check source and parser health.
2. Run detection from the dashboard.
3. Open High/Critical findings and read `Why flagged`, evidence strength,
   parser caveats, related logs, and recommended checks.
4. Compare nearby source activity before assigning, labeling, or closing.
5. Record notes and ownership.
6. Use only analyst-confirmed simulated response actions.

The controlled source scenario and layered regression matrix are engineering
tests, not field-accuracy claims:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --pretty
```

## SOC Assistant

The Assistant retrieves bounded ATDR alert, normalized-log, source, operation,
ML-governance, and approved runbook context. Gemini may synthesize that context
when privately configured; deterministic fallback remains available.

Safe provider checks never print the API key:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --execute --pretty
```

Require raw-log context false, redaction true, no secret exposure, and zero
detection, label, model, user, or response side effects. Verify citations in
the dashboard before acting on an answer.

## Backup And Recovery

Preview before writing a backup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --execute --pretty
```

Restore drills must target a new empty database, never the configured database.
Follow `docs/OPERATIONS_RUNBOOK.md` for restore confirmation, shared deployment,
worker recovery, and incident troubleshooting.

## Verification

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr/tests -q
.\.venv\Scripts\alembic.exe check
Set-Location frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
```

Return to the repository root before running
`python -m atdr.scripts.verify_release --pretty`.

The complete historical lab command ledger is preserved at
`docs/archive/runbooks/LAB_RUNBOOK_THROUGH_V5_58.md`.
