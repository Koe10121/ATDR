# Operations Runbook

This runbook is for lab-pilot operation. Keep response actions simulated unless a formal firewall connector is approved.

Use `docs/ENVIRONMENT_GUIDE.md` before changing `.env`. Run Config Doctor after editing configuration:

```powershell
python -m atdr.scripts.config_doctor --pretty
```

Before a handoff or release candidate, run the release gate:

```powershell
python -m atdr.scripts.verify_release --pretty
```

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
4. Use simulated block only if containment is justified and a response note explains the reason.
5. Verify the response appears in Audit Log.
6. Mark the alert contained or resolved only after documenting the decision.

ATDR denies simulated block attempts for protected internal or management IP ranges and records denied attempts in the audit log. This protects lab users from accidentally treating internal infrastructure as an external containment target.

## Alert Workflow

Alert status values are:

- `open`: new triage item.
- `investigating`: analyst is reviewing evidence.
- `needs_more_context`: analyst needs asset, owner, or network context before decision.
- `contained`: response action or containment decision has been recorded.
- `resolved`: investigation is complete.
- `false_positive`: reviewed benign or noisy finding.

Alert details should include severity, risk score, attack type, detection source, why-flagged explanation, related logs, ATT&CK-style mapping, response history, notes, and audit timeline. ML output remains decision support only.

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

For the full release process, including backup dry runs, optional Playwright smoke tests with `ATDR_RUN_PLAYWRIGHT=1`, rollback notes, and Docker/PostgreSQL validation, use `docs/RELEASE_CHECKLIST.md`.

## v5.53 Operator Readiness

Before a shared deployment claim, run the admin-only aggregate readiness check
and verify the private deployment contract is current. The operator must supply
real evidence for HTTPS, managed secrets, PostgreSQL migrations, durable worker
ownership, monitoring and alerts, load behavior, backup/restore, measured
RPO/RTO, rollback, and disaster recovery. A configured setting or successful
local SQLite test is not a substitute.

Run repository security controls before handoff:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_security_acceptance --pretty
.\.venv\Scripts\python.exe -m pip_audit -r requirements.lock.txt --no-deps
Set-Location frontend
npm.cmd audit --audit-level=moderate
```

Keep generated SBOMs and acceptance evidence in ignored temporary/private
storage. CodeQL runs only after a separately approved publication reaches
GitHub Actions.
