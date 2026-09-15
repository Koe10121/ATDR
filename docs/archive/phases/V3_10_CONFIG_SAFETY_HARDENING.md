# v3.10 Local / Shared-Lab Configuration Safety Hardening

## Status

v3.10 makes ATDR configuration failures easier to diagnose across normal local SQLite use and optional PostgreSQL lab use. It does not change startup commands, database schema, detection behavior, ML behavior, response behavior, or dashboard routes.

ATDR remains a controlled lab prototype. Real firewall blocking, automatic response, model activation, and production readiness are still disabled/not claimed.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Settings and runtime validation | `atdr/app/core/config.py` |
| Database engine and connectivity checks | `atdr/app/db/database.py` |
| Startup and DB-unavailable response | `atdr/app/main.py` |
| Config doctor | `atdr/scripts/config_doctor.py` |
| Teammate setup checker | `atdr/scripts/check_dev_environment.py` |
| Local SQLite helper | `atdr/scripts/use_local_sqlite_config.py` |
| Docs | `README.md`, `docs/QUICKSTART_FOR_TEAM.md`, `docs/LAB_RUNBOOK.md` |
| Tests | `atdr/tests/test_api.py`, `atdr/tests/test_dev_onboarding.py`, `atdr/tests/test_hardening_and_ingestion.py` |

## What Changed

- Config doctor now identifies the normal local SQLite profile.
- Config doctor warns when `DATABASE_URL` uses PostgreSQL host `postgres` outside a container, because that hostname normally only works in Docker Compose.
- Config doctor warns if assistant external provider settings or raw-log context are enabled.
- The teammate environment checker redacts database passwords.
- The teammate environment checker gives a clear local fix when it detects Docker-style PostgreSQL host `postgres`.
- Backend database `OperationalError` responses now return a clean `503 Database unavailable` message instead of a generic traceback-style login failure.
- Added `python -m atdr.scripts.use_local_sqlite_config`, a dry-run-first helper that can preview or explicitly write the normal local SQLite `.env` values.

## Normal Local SQLite Values

For normal laptop/dashboard testing:

```env
DATABASE_URL="sqlite:///./atdr.db"
AUTO_CREATE_TABLES=true
ENVIRONMENT="development"
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER="simulation"
```

## Optional PostgreSQL Lab Values

PostgreSQL remains optional and should be used only when the Docker/PostgreSQL lab service is running. The hostname `postgres` is a Docker Compose service alias, not a normal Windows hostname.

If `.env` uses:

```env
DATABASE_URL="postgresql+psycopg2://...@postgres:5432/atdr"
```

then run PostgreSQL/Docker first or switch back to SQLite.

## Safe Recovery Helper

Preview only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_local_sqlite_config --dry-run --pretty
```

Write only when intended:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_local_sqlite_config --write --pretty
```

Write mode preserves a backup under ignored `.tmp/env-backups/`.

## Safety Controls Preserved

- `.env` is still not committed.
- No database reset or deletion.
- No schema migration.
- No real firewall blocking.
- No automatic response.
- No model activation or promotion.
- Assistant external LLM remains disabled by default.
- Assistant raw-log context remains disabled by default.

## Known Limitations

- Config doctor cannot start Docker/PostgreSQL for the user.
- PostgreSQL validation still requires a PostgreSQL-capable lab host.
- The helper edits only selected local-profile keys and does not manage every possible environment variable.
- Local SQLite is appropriate for teammate laptops and controlled labs, not a production database target.
