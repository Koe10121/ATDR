# ATDR Deployment Guide

This guide covers two supported deployment modes for the MFU ATDR prototype.

Before choosing a mode, read `docs/ENVIRONMENT_GUIDE.md`.
Before handing off a release candidate, run the gate in `docs/RELEASE_CHECKLIST.md`.

## Mode 1: Local SQLite Demo

Use this mode for presentation, development, and quick testing.

```powershell
Copy-Item .env.example .env
python -m atdr.scripts.config_doctor --pretty
python -m atdr.scripts.verify_release --pretty
python -m atdr.scripts.seed_users
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd install
npm.cmd run dev
```

Recommended settings:

```text
ENVIRONMENT=development
DATABASE_URL=sqlite:///./atdr.db
AUTO_CREATE_TABLES=true
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
SYSLOG_HOST=127.0.0.1
SYSLOG_PORT=5514
```

## Mode 2: PostgreSQL Lab Pilot

Use this mode for a more realistic lab deployment.

```powershell
Copy-Item .env.lab.example .env
python -m atdr.scripts.config_doctor --pretty
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
python -m atdr.scripts.lab_smoke_check
python -m atdr.scripts.verify_release --include-smoke --require-docker --pretty
```

Recommended settings:

```text
ENVIRONMENT=production
DATABASE_URL=postgresql+psycopg2://atdr:<strong-password>@postgres:5432/atdr
AUTO_CREATE_TABLES=false
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
JWT_SECRET_KEY=<long-random-secret>
CORS_ALLOWED_ORIGINS=https://atdr.example.local
```

The application intentionally fails startup in production if unsafe defaults are used.

If Docker is not installed on the current Windows machine, record that as a local tooling blocker and run the same commands on a Docker-capable host. The local script reports this condition clearly:

```powershell
python -m atdr.scripts.lab_smoke_check
```

## Live Syslog Receiver

Live UDP ingestion is intended for a lab network only.

Default safe mode binds to localhost:

```powershell
python -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

To test locally, send one syslog line to UDP port `5514`. ATDR stores the raw line first, then attempts Palo Alto parsing. Malformed lines are preserved as evidence and do not crash ingestion.

Harmless local sender:

```powershell
python -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

Verification checklist:

- Confirm the receiver prints or logs accepted datagrams.
- Open React Investigation and check for new normalized rows.
- Open AI Governance and review Data Quality for latest ingestion time, parse errors, missing fields, and parser error examples.
- Run detection on new logs only after confirming raw evidence was preserved.

Do not bind the receiver to `0.0.0.0` unless the host firewall and network scope are understood.

## Production Safety Checklist

- Replace all demo passwords.
- Use a strong `JWT_SECRET_KEY`.
- Set `CORS_ALLOWED_ORIGINS` to the exact dashboard origin.
- For local React preview, include `http://127.0.0.1:5173` and `http://localhost:5173`; remove these from hardened production configs unless used behind the approved reverse proxy.
- Keep response actions simulated until firewall enforcement is approved. Disabling simulation before a connector exists records actions as `pending_connector`, not real enforcement.
- Run Alembic migrations explicitly.
- Back up PostgreSQL and model artifacts.
- Restrict API/dashboard access to trusted networks.
- Monitor structured API logs and audit logs.
- Review suppression rules regularly.
- Review watchlist matches and ownership regularly.
- Train ML only on reviewed baseline traffic.

## Backup And Cleanup Utilities

SQLite demo archive:

```powershell
python -m atdr.scripts.backup_demo --dry-run
python -m atdr.scripts.backup_demo
```

PostgreSQL logical backup:

```powershell
python -m atdr.scripts.backup_postgres --dry-run
python -m atdr.scripts.backup_postgres
```

Old demo export cleanup is dry-run by default:

```powershell
python -m atdr.scripts.cleanup_exports --older-than-days 14
python -m atdr.scripts.cleanup_exports --older-than-days 14 --execute
```

For HTTPS, reverse proxy, backup, retention, and recovery procedures, use `docs/OPERATIONS_RUNBOOK.md`.
For release candidate validation, use `docs/RELEASE_CHECKLIST.md`.

## v3.0 Production-Readiness Track

ATDR is not production ready. v3.0 adds non-destructive validation commands for the next lab-hardening track:

```powershell
python -m atdr.scripts.production_readiness_doctor --pretty
python -m atdr.scripts.run_v30_real_source_pilot_validation --pretty
python -m atdr.scripts.run_postgres_lab_validation --pretty
python -m atdr.scripts.run_real_source_ml_monitoring --pretty
```

Use:

- `docs/V3_0_PRODUCTION_READINESS_GAP_ASSESSMENT.md`
- `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md`
- `docs/V3_0_POSTGRESQL_LAB_DEPLOYMENT_VALIDATION.md`
- `docs/V3_0_PRODUCTION_READINESS_TRACK.md`

The v3.0 track keeps response simulation enabled and does not activate a model or enable real firewall blocking.
