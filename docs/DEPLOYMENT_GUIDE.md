# ATDR Deployment Guide

ATDR has four supported profiles. Only the first three are locally
reproducible today; the shared-host profile remains externally pending until an
authorized deployment owner supplies real acceptance evidence.

## 1. MFU Shell-First Local SQLite

This is the normal laptop workflow. Obtain the approved shell package and its
private configuration through the authorized channel, then run:

```powershell
.\scripts\setup_team.cmd `
  -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  -ShellPrivateConfigRoot "D:\Private MFU Configuration"
.\scripts\start_system.cmd
```

The only normal user entry is:

```text
http://localhost:8080/#/pages/login
```

The launcher coordinates FastAPI `8000`, React `5173`, the MFU shell backend
`8214`, and the MFU shell frontend `8080`. SQLite remains ATDR's local database;
MongoDB belongs only to the companion shell.

## 2. Explicit Local Recovery

Use local recovery only for authorized diagnosis when MFU sign-in is
unavailable. Select `ATDR_AUTH_MODE=local_recovery` in the ignored private
environment and follow the component commands in `docs/OPERATIONS_RUNBOOK.md`.
Local recovery must never activate automatically or be presented as MFU IAM.

## 3. Teammate Shell Distribution

Each teammate uses their own clone and private configuration. Do not copy
`.env`, database files, API keys, or review evidence between machines. Setup
accepts either the checksum-locked shell package or an explicitly approved
source directory:

```powershell
.\scripts\setup_team.cmd -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip"
.\scripts\check_system.cmd
.\scripts\start_system.cmd
```

The teammate must independently prove clean setup, login entry, secure handoff,
health, shutdown, restart, and private-data exclusion. A same-machine
disposable rehearsal does not replace that physical-machine acceptance.

## 4. Shared PostgreSQL Deployment

This profile keeps FastAPI/React and uses PostgreSQL, durable workers, a reverse
proxy, managed secrets, monitoring, and external backup storage. Reference
assets are under:

- `deploy/nginx/`
- `deploy/systemd/`
- `deploy/monitoring/`
- `deploy/secrets/`

Start from `.env.production.example` or `.env.lab.example` without committing
the resulting private file. Required boundaries include:

```text
ENVIRONMENT=preproduction
AUTO_CREATE_TABLES=false
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
```

The private `DATABASE_URL`, JWT secret, handoff secret, provider credentials,
hostnames, and TLS key must come from the deployment owner's managed secret
channel. Never paste them into tickets, documentation, command output, or
acceptance manifests.

Validate repository-side assets:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_deployment_operations --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_release_readiness --pretty
```

The host owner must separately prove migrations at head, PostgreSQL
connectivity, worker concurrency, shared staging/storage, HTTPS, trusted proxy
handling, managed secrets, monitoring alerts, backup/restore, measured RPO/RTO,
rollback, disaster recovery, and load behavior. Until then, shared deployment
is externally pending and `production_ready=false`.

## Live Source Boundary

UDP syslog is suitable only for an approved lab network. The safe default is
loopback:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Binding to another interface requires the network owner to approve firewall
rules, sender identity, retention, and transport risk. UDP syslog is neither
authenticated nor encrypted. Real-source acceptance still requires a physical
sender and independent field verification.

## Deployment Decision

Repository assets and local rehearsal prove implementation, not owner
acceptance. See `docs/V5_54_OPERATOR_HANDOFF.md` for operator steps and
`docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md` for the five remaining external
evidence tracks.
