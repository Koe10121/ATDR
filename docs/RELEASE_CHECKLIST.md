# ATDR Release Checklist

ATDR is lab-pilot ready, not certified production software. Use this checklist before a supervisor demo, lab-pilot handoff, or release candidate tag.

## Local Pre-Demo Gate

Run these from the project root after activating the virtual environment:

```powershell
python -m atdr.scripts.config_doctor --pretty
python -m atdr.scripts.verify_release --pretty
python -m atdr.scripts.backup_demo --dry-run
python -m atdr.scripts.lab_smoke_check --skip-docker
```

Confirm:

- Config Doctor has no critical issues.
- Tests pass and Alembic reports no drift.
- API and Streamlit are reachable.
- Demo users are available only for local demo use.
- Response mode remains simulated.
- Demo evidence export still works from Demo Controls.

## Lab-Pilot Release Gate

Use `.env.lab.example` as the starting profile and replace all placeholders:

```powershell
Copy-Item .env.lab.example .env
python -m atdr.scripts.config_doctor --pretty
python -m atdr.scripts.verify_release --pretty
python -m atdr.scripts.backup_postgres --dry-run
python -m atdr.scripts.lab_smoke_check
```

Confirm:

- PostgreSQL is configured.
- `AUTO_CREATE_TABLES=false`.
- Alembic migrations are applied with `alembic upgrade head`.
- `JWT_SECRET_KEY` is long, random, and not a demo value.
- `CORS_ALLOWED_ORIGINS` lists exact dashboard origins.
- Syslog binds only to approved lab interfaces.
- Response actions are still simulated.

## Docker And PostgreSQL Validation

This is the Docker/PostgreSQL validation step for a lab-capable host.

Run this on a Docker-capable host:

```powershell
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
python -m atdr.scripts.lab_smoke_check
python -m atdr.scripts.verify_release --include-smoke --require-docker --pretty
```

If Docker is unavailable on the current Windows machine, record that as a local tooling blocker. Do not mark PostgreSQL lab validation complete until these commands pass on a Docker-capable host.

## Optional Browser Smoke Tests

Playwright checks are optional because browser dependencies are not always installed:

```powershell
$env:ATDR_RUN_PLAYWRIGHT="1"
pytest atdr/tests/test_dashboard_playwright_smoke.py -q
```

Run them only after API and Streamlit are already running.

## Backup And Retention

Before lab-pilot changes:

```powershell
python -m atdr.scripts.backup_demo --dry-run
python -m atdr.scripts.backup_postgres --dry-run
python -m atdr.scripts.cleanup_exports --older-than-days 14
```

For real lab operation, schedule PostgreSQL logical backups, copy `models/`, and retain audit logs according to `docs/OPERATIONS_RUNBOOK.md`.

## Rollback Notes

- Keep a database backup from before each release candidate.
- Keep a copy of the previous `.env`.
- Roll back code with Git, then run `alembic downgrade` only if a future migration explicitly documents a safe downgrade path.
- Restore `models/` artifacts if ML scoring behavior changes unexpectedly.
- Keep response simulation enabled while investigating any release issue.

## Known Blockers Before True Production

- Docker/PostgreSQL validation must pass on a Docker-capable host.
- HTTPS/reverse proxy setup must be validated on the target lab network.
- Backup jobs and restore drills must be scheduled and tested.
- Real firewall blocking remains unsupported until an approved connector, allowlist, dry-run preview, rollback process, and change approval flow exist.
- ML thresholds require baseline tuning with reviewed campus/lab traffic.
