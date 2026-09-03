# ATDR Operations Runbook

This is the active operations reference for ATDR. Normal users enter through
the approved MFU shell. ATDR remains a controlled release candidate: rules are
alert-authoritative, supervised ML is shadow-only, the SOC Assistant is
read-only, response is simulated, and real firewall blocking is disabled.

## Supported Profiles

| Profile | Purpose | Database | Entry |
| --- | --- | --- | --- |
| MFU shell-first local | Normal laptop and team use | SQLite | `http://localhost:8080/#/pages/login` |
| Local recovery | Authorized recovery/component diagnosis | SQLite | Direct React `http://127.0.0.1:5173` |
| Teammate distribution | Same shell-first flow from approved shell package | SQLite | MFU shell login |
| Shared deployment | Owner-approved multi-user host | PostgreSQL | HTTPS reverse proxy and MFU shell |

The Node/Vue/MongoDB companion is the authentication shell only. The ATDR
application remains FastAPI, React, SQLAlchemy/Alembic, and SQLite or
PostgreSQL.

## Start, Check, Stop, Restart

From the ATDR repository root:

```powershell
.\scripts\start_system.cmd
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

Wait for `All components are ready` before opening the login page. To restart,
run `stop_system.cmd` and then `start_system.cmd`. The launcher tracks only the
four processes it owns and keeps logs in ignored `.atdr_runtime/logs/`.

Normal startup requires the approved shell package/private profile, Python
3.11, Node.js 20.19 or newer, npm, and MongoDB on loopback for the companion
shell. Redis is optional: the shell rate limiter has an in-memory local
fallback, although a shared deployment should provide its approved cache
service.

## Daily Operator Checks

1. Run `check_system.cmd`; require installation, provider, and all service
   checks to pass.
2. Review source health, parser warnings, failed imports, and stale jobs.
3. Review new High/Critical alerts, ownership, SLA state, and related evidence.
4. Confirm `RESPONSE_SIMULATION=true`, rules remain authoritative, and no model
   has been promoted.
5. Review Assistant provider health and provenance. Raw-log provider context
   must remain disabled.
6. Review audit events for failed logins, account changes, alert actions, and
   simulated response requests.

API liveness is `GET /health/live`; operational health is `GET /health`.
Prometheus metrics are available only when the configured deployment profile
enables them.

## Log Ingestion And Detection

Prefer the dashboard for normal analyst work. For an operator-controlled file
import, keep the log outside Git and pass its private path only at runtime:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "D:\Private Logs\firewall.log" --limit 5000
```

For live lab forwarding, register the source and run the UDP receiver only on
an approved interface. Loopback is the safe default:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Raw evidence is preserved before parsing. Parser failure does not discard the
row. Run detection from the dashboard after checking source/parser quality.
Rule findings create authoritative alerts; anomaly and supervised scores add
advisory context only.

## Analyst Workflow

1. Open an alert and read `Why flagged`, evidence strength, parser caveats,
   related logs, and the recommended checks.
2. Compare nearby activity and source health before changing status or label.
3. Use the SOC Assistant for concise synthesis; verify its cited alert, log,
   source, job, or governance references in ATDR.
4. Record investigation notes and ownership.
5. Any response remains an analyst-confirmed simulation and is written to the
   audit trail. Never describe it as firewall enforcement.

## Backup And Restore

Preview a backup first, then write only to ignored or external storage:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --execute --pretty
```

Restore is deliberately restricted to a new empty target:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.restore_database `
  --backup-path "D:\Private Backups\atdr-backup" `
  --manifest-path "D:\Private Backups\manifest.json" `
  --target-database-url "sqlite:///./.tmp/restored-atdr.db" `
  --pretty
```

Execution additionally requires `--execute --confirm
RESTORE_TO_NEW_EMPTY_TARGET`. Never point a restore drill at the configured
database. Use the isolated disaster-recovery exercise for rehearsal:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --execute --confirm ISOLATED_V395_DRILL --pretty
```

## Local Recovery

Local username/password access is an explicit recovery profile, never a silent
fallback. Stop the shell-first runtime, make a private database backup, set
`ATDR_AUTH_MODE=local_recovery` only in the ignored local environment, then run
the established FastAPI and React component commands in separate terminals:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.check_dev_environment
.\.venv\Scripts\python.exe -m atdr.scripts.seed_users
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000
```

```powershell
Set-Location frontend
npm.cmd run dev -- --host 127.0.0.1
```

Return the private profile to `template_shell` before normal operation. Never
use recovery credentials as a substitute for MFU account acceptance.

## Shared Deployment

The repository contains reference Nginx, systemd, worker, monitoring, secret,
backup, and recovery assets under `deploy/`. They are not proof of a deployed
environment. Before a shared-host claim, require PostgreSQL, migrations at
head, multiworker ownership, shared storage, HTTPS, managed secrets,
monitoring/alerts, backup/restore, measured RPO/RTO, rollback, load, and
disaster-recovery evidence from the host owner.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_deployment_operations --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_release_readiness --pretty
```

## Troubleshooting

| Symptom | Safe action |
| --- | --- |
| PowerShell policy blocks `.ps1` | Use the tracked `.cmd` wrappers. |
| Startup says processes already run | Run `check_system.cmd`; use `stop_system.cmd` for launcher-owned processes. |
| A required port is occupied | Stop the owning application; do not kill unrelated processes blindly. |
| MongoDB is unavailable | Start MongoDB for the MFU shell; ATDR's SQL database is separate. |
| Shell backend briefly logs Redis timeout | Local fallback is expected; confirm `/healthz` becomes ready. |
| Google returns `400 invalid_request` | Use the exact approved origin and ask the MFU/Google owner to authorize the account/client. |
| MFU account is outside project scope | Ask the IAM owner for the approved group/scope; do not bypass it. |
| Backend reports database unavailable | Check `DATABASE_URL`; normal laptop use is `sqlite:///./atdr.db`. |
| Assistant provider fails | Confirm deterministic fallback, redaction, and raw-log exclusion; never expose the key. |
| Import stalls/fails | Inspect operation job state, worker heartbeat, staging capacity, and source/parser warnings. |

## Release Checks

Run `docs/V5_54_OPERATOR_HANDOFF.md` for the exact handoff sequence and
`docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md` for evidence that cannot be produced
locally. Configuration alone is never external acceptance, and
`production_ready` must remain false until every named owner has supplied real,
current evidence.
