# Operations Runbook

This runbook is for lab-pilot operation. Keep response actions simulated unless a formal firewall connector is approved.

## Daily Checks

- Confirm `/health` reports database status `ok`.
- Review critical open alerts.
- Review SLA states for overdue or unassigned High/Critical alerts.
- Review failed login audit events.
- Review response actions and blocked IP records.
- Check ML anomaly rate for sudden spikes.
- Check suppressions with `pending` or `needs_changes` review status.

## Reverse Proxy And HTTPS

For a lab deployment, place FastAPI and Streamlit behind a trusted reverse proxy such as Nginx, Caddy, or Traefik.

Minimum guidance:

- Terminate TLS at the reverse proxy.
- Restrict access to trusted campus or lab networks.
- Forward `X-Request-ID` when present.
- Set `CORS_ALLOWED_ORIGINS` to the exact dashboard origin, for example `https://atdr.example.local`.
- Do not expose the UDP syslog receiver publicly.
- Use strong secrets and `ENVIRONMENT=production`.

Example path layout:

```text
https://atdr.example.local/api/      -> FastAPI :8000
https://atdr.example.local/          -> Streamlit :8501
```

## Backup Policy

Recommended PostgreSQL backup cadence for a lab pilot:

- Daily logical backup of the ATDR database.
- Daily copy of `models/` ML artifacts.
- Retain daily backups for 14 days.
- Retain weekly backups for 8 weeks.
- Test restore at least once before supervisor evaluation.

SQLite demo mode backup is simpler: stop the services and copy `atdr.db`, `models/`, and important logs. SQLite is not recommended for shared lab operation.

Scripted backup helpers:

```powershell
python -m atdr.scripts.backup_demo --dry-run
python -m atdr.scripts.backup_demo
python -m atdr.scripts.backup_postgres --dry-run
python -m atdr.scripts.backup_postgres
```

## Retention Policy

Suggested initial retention:

- Raw logs: 90 days for lab pilot, longer if storage allows.
- Normalized logs: 180 days.
- Alerts and evidence links: 180 days.
- Audit logs: 365 days.
- ML run history: 365 days or all runs for the project period.

Do not delete raw evidence linked to active or unresolved alerts.

Clean old demo evidence exports:

```powershell
python -m atdr.scripts.cleanup_exports --older-than-days 14
python -m atdr.scripts.cleanup_exports --older-than-days 14 --execute
```

## Safe Response Procedure

1. Confirm the alert evidence.
2. Assign the alert to an analyst.
3. Add an investigation note.
4. Use simulated block only if containment is justified.
5. Verify the response appears in Audit Log.
6. Mark the alert contained or resolved only after documenting the decision.

## Recovery Checklist

- Restore PostgreSQL backup.
- Restore `models/` artifacts.
- Run `alembic upgrade head`.
- Start FastAPI and confirm `/health`.
- Start Streamlit and log in.
- Review recent audit events after recovery.

## Lab Smoke Checks

Use the lab smoke check after starting API and Streamlit:

```powershell
python -m atdr.scripts.lab_smoke_check
```

It checks API health, admin login, dashboard summary, alerts, audit, ML report, Streamlit reachability, and Docker Compose availability. If Docker is missing on the current machine, treat that as a tooling blocker and run Compose validation on a Docker-capable host.
