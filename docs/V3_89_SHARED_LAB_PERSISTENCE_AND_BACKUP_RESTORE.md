# v3.89 Shared-Lab Persistence And Backup/Restore

Date: 2026-07-13

## Purpose

v3.89 strengthens ATDR persistence operations without changing the normal local startup workflow. SQLite remains the default for a teammate laptop. PostgreSQL is an optional shared-lab path, not a requirement for local development.

This phase does not reset or overwrite the current database, enable automatic response, enable firewall blocking, activate an ML model, or change the SOC Assistant's read-only boundary.

## Source-Backed Compatibility Review

| Area | Evidence | v3.89 result |
| --- | --- | --- |
| Python database stack | `requirements.txt`, `atdr/app/db/database.py` | SQLAlchemy, Alembic, and `psycopg2-binary` support SQLite and PostgreSQL. |
| Engine behavior | `atdr/app/db/engine.py` | SQLite keeps `check_same_thread=false`; PostgreSQL alone receives bounded pool, pre-ping, connection-timeout, and statement-timeout options. |
| Migrations | `migrations/env.py`, `migrations/versions/*` | Alembic uses the same configured dialect-aware connection behavior. The `ml_labels.reviewed` migration now uses a dialect-safe boolean default. |
| Schema | `atdr/app/db/models.py` | JSON, timezone-aware timestamps, booleans, indexes, and constraints require PostgreSQL runtime validation but have no remaining known SQLite-only schema definition. |
| JSON access | `atdr/app/routers/dashboard.py`, `atdr/scripts/run_v32_no_hardware_source_pilot.py` | SQLAlchemy JSON expressions are used. PostgreSQL CI validation is required before treating source-scoped JSON queries as shared-lab proven. |
| SQLite-only SQL | `atdr/app/services/persistence_service.py` | `PRAGMA quick_check` and SQLite backup APIs are isolated to SQLite-only branches. |
| Long operations | ingestion/detection/ML services and operation-job records | Operations are still synchronous in the API process. Durable workers remain the next operational phase after persistence. |

## Configuration Profiles

Normal local profile remains unchanged:

```env
DATABASE_URL="sqlite:///./atdr.db"
AUTO_CREATE_TABLES=true
RESPONSE_SIMULATION=true
```

Optional shared-lab PostgreSQL settings are available in `.env.lab.example` and `.env.production.example`:

```env
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT_SECONDS=30
DB_CONNECT_TIMEOUT_SECONDS=10
DB_POOL_PRE_PING=true
DB_STATEMENT_TIMEOUT_MS=30000
```

The pool settings apply only to PostgreSQL. SQLite continues to use a simple local engine with a bounded connection timeout.

## Safe Diagnostics

`config_doctor`, `/health`, and `database_portability_audit` now report only safe persistence metadata:

- database dialect and connection state;
- migration state and current/head revision where available;
- PostgreSQL backup-tool availability;
- whether a host is configured, without showing it;
- `secrets_exposed=false`.

They do not return database passwords, database URLs, tokens, or private connection hostnames.

## Backup And Restore Commands

Preview a backup without writing anything:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .tmp\backup-preview --pretty
```

Create a local backup with a checksum manifest. Choose an ignored path or a directory outside the repository:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir C:\ATDR-backups --execute --pretty
```

The backup command never modifies the source database. SQLite backups use the SQLite backup API rather than copying an active database file. PostgreSQL backups use `pg_dump` only when that executable is available.

Restore validation is dry-run by default. A real restore requires a new empty target and an explicit confirmation string:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.restore_database `
  --backup-path "C:\ATDR-backups\atdr-sqlite-<timestamp>.sqlite3" `
  --target-database-url "sqlite:///C:/ATDR-restore/atdr-restored.sqlite3" `
  --execute `
  --confirm RESTORE_TO_NEW_EMPTY_TARGET `
  --pretty
```

The restore command rejects the configured active database, non-empty targets, invalid manifests, checksum mismatches, and dialect mismatches. The persistence validator also refuses either isolated validation target when it matches the configured database. Restore validation compares table counts and Alembic revision after restore.

## Isolated Persistence Validation

Run the full local SQLite drill:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_persistence_profile --pretty
```

The command creates temporary synthetic source and restore databases under ignored `.tmp/`, applies migrations, writes one synthetic user/source/raw-log row, backs up, restores, validates integrity/checksum/counts/revision, and checks that the configured current SQLite database fingerprint remains unchanged.

For an approved PostgreSQL host, create two new empty databases and set these values only in the shell or a private environment file:

```powershell
$env:ATDR_PERSISTENCE_SOURCE_DATABASE_URL = "postgresql+psycopg2://<user>:<password>@<host>:5432/<new_source_db>"
$env:ATDR_PERSISTENCE_RESTORE_DATABASE_URL = "postgresql+psycopg2://<user>:<password>@<host>:5432/<new_restore_db>"

.\.venv\Scripts\python.exe -m atdr.scripts.validate_persistence_profile `
  --include-postgres `
  --execute-postgres `
  --confirm ISOLATED_POSTGRES_DATABASES `
  --pretty
```

This requires `pg_dump` and `pg_restore`. It refuses non-empty targets. Do not point either URL at the existing local or shared ATDR database.

## CI Validation

GitHub Actions now includes a separate `postgres-persistence` job. It creates an isolated control database plus two ephemeral validation databases, applies Alembic migrations to the isolated source, creates a synthetic backup, restores it to the empty target, checks drift against the source, and runs focused persistence and API tests.

The job has no private `.env`, no external IAM/LLM provider call, and no access to a user's local database. Its remote result must be checked after the v3.89 commit is pushed; this workstation has no local PostgreSQL/Docker tooling, so it cannot make a live PostgreSQL claim.

## Validation Result And Limits

Local SQLite validation passes with:

- fresh migration to head;
- checksum manifest;
- integrity check;
- matching table counts;
- matching Alembic revision;
- zero response actions, ML labels, and model runs in synthetic data;
- current database fingerprint unchanged.

v3.89 verification also passed:

- focused persistence/API regression: `51 passed`;
- full backend suite: `486 passed, 1 skipped`;
- Ruff, compileall, and Alembic drift check;
- frontend dependency audit, lint, build, and Playwright: `19 passed, 1 skipped`;
- replay dry-run, performance smoke with no warnings, and release gate.

The local Node runtime is `20.11.1`; it passed the current frontend checks but emits an engine warning because `frontend/package.json` requires Node `20.19.0` or newer. Upgrade Node before relying on future frontend-toolchain changes.

The exact source-controlled staging allowlist and explicit private-output exclusions are in `docs/V3_89_CHANGESET_MANIFEST.md`.

Remaining limits:

- PostgreSQL runtime validation is pending the new CI job or an approved lab host.
- Backup retention, encrypted off-host storage, restore drills by an operator, and disaster recovery objectives are not complete.
- Long-running ingestion/detection/ML work still needs durable background workers.
- ATDR remains a controlled lab system, not production-certified software.

## Rollback

No schema migration is added by v3.89. To roll back the code, revert the v3.89 commit. Existing SQLite local startup remains valid. Backup files and manifests are generated in ignored or external locations and must never be committed.
