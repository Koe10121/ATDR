# ATDR v3.0 PostgreSQL Lab Deployment Validation

PostgreSQL is optional for shared lab deployment. It is not required for normal local development.

## Source Evidence

- Database configuration: `atdr/app/core/config.py`, `atdr/app/db/database.py`
- Alembic migrations: `alembic/versions/`
- Environment templates: `.env.lab.example`, `.env.production.example`
- PostgreSQL validator: `atdr/scripts/run_postgres_lab_validation.py`
- Deployment guide: `docs/DEPLOYMENT_GUIDE.md`

## Current Local Default

Normal local development uses SQLite:

```text
DATABASE_URL=sqlite:///./atdr.db
AUTO_CREATE_TABLES=true
```

This must remain supported for teammates and demos.

## PostgreSQL Lab Preflight

On a Docker/PostgreSQL-capable host:

```powershell
Copy-Item .env.lab.example .env
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

If run on SQLite, the validator reports:

```text
postgres_lab_validation_blocked_by_environment
```

That is expected and non-destructive for normal local use.

## Lab Validation Criteria

- PostgreSQL connection succeeds.
- Alembic check passes with no schema drift.
- `AUTO_CREATE_TABLES=false`.
- Seed users are created idempotently.
- Import/replay works without resetting data.
- Detection, alert deduplication, source health, cases, and run history work.
- React dashboard loads from FastAPI.
- Performance smoke remains within lab budget.
- Response simulation remains enabled.

## Not Covered Yet

- Managed database backups and restore drills.
- Production retention policy.
- High availability.
- TLS/proxy hardening.
- External IAM callback flow.
- Real firewall response connector.
