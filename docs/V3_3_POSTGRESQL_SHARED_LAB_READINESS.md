# ATDR v3.3 PostgreSQL and Shared Lab Readiness

ATDR keeps SQLite as the normal local development database. v3.3 prepares the optional PostgreSQL/shared-lab path without changing the backend or frontend startup commands.

## Current Local Workflow

SQLite remains valid for local testing:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

The default local database is configured by `DATABASE_URL=sqlite:///./atdr.db`. This is easy for demos and teammate laptops, but it is not the target for shared-lab or production-like claims.

## Why PostgreSQL Matters

PostgreSQL is the next shared-lab validation target because ATDR has relational workflow data:

- users, roles, authentication, and audit events;
- raw logs, normalized logs, sources, ingestion runs, and detection runs;
- alerts, evidence, cases, labels, and response actions;
- JSON run details and timestamp-heavy SOC workflows.

PostgreSQL gives better concurrency, backup tooling, remote access control, and deployment realism than a local SQLite file.

## Already Compatible

Source evidence:

- SQLAlchemy models: `atdr/app/db/models.py`
- DB session setup: `atdr/app/db/database.py`
- Alembic migrations: `migrations/versions/`
- PostgreSQL validator: `atdr/scripts/run_postgres_lab_validation.py`
- Portability audit: `atdr/scripts/database_portability_audit.py`
- Environment examples: `.env.lab.example`, `.env.production.example`

ATDR already uses SQLAlchemy/Alembic rather than SQLite-specific raw SQL for normal app paths. SQLite support must remain intact.

## Required Environment Variables

For a PostgreSQL/shared-lab host:

```env
DATABASE_URL=postgresql+psycopg2://atdr_user:change_me@127.0.0.1:5432/atdr_lab
AUTO_CREATE_TABLES=false
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
JWT_SECRET_KEY=<long-random-secret>
DEMO_ADMIN_PASSWORD=<non-default-password>
DEMO_ANALYST_PASSWORD=<non-default-password>
```

Do not commit `.env`.

## Validation Commands

On any local machine:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.database_portability_audit --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

If SQLite is configured, PostgreSQL validation should return:

```text
postgres_lab_validation_blocked_by_environment
```

That is expected and non-destructive.

On a PostgreSQL/Docker-capable host, after configuring `.env`:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --include-smoke --include-sample-ingest --pretty
```

Only `--include-sample-ingest` writes safe synthetic rows.

## Migration Expectations

- Alembic migrations must apply cleanly.
- `AUTO_CREATE_TABLES=false` should be used for PostgreSQL/shared-lab validation.
- `alembic check` should report no drift.
- Seed users must be idempotent.

## Rollback and Safety Notes

- Do not reset the current SQLite database for PostgreSQL testing.
- Use a separate PostgreSQL database for shared-lab validation.
- Take a backup before migrations.
- Keep response mode simulated.
- Do not enable automatic response.
- Keep real firewall blocking disabled.
- Do not activate a model automatically.

## What Must Not Be Claimed Yet

v3.3 does not prove production readiness. Remaining blockers include real-device forwarding, PostgreSQL host validation, backup/restore drill, external IAM callback flow, TLS/reverse proxy hardening, monitoring, retention policy, and real response connector governance.
