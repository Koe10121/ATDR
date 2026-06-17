# ATDR v3.3 Backup, Restore, and Retention Plan

This plan documents backup readiness for local demos and future PostgreSQL shared-lab validation. It is a plan and checklist, not a completed production disaster-recovery certification.

Automatic response remains disabled during backup/restore validation, and this plan does not claim production readiness.

## Existing Helpers

SQLite/demo backup dry run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_demo --dry-run
```

PostgreSQL logical backup dry run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_postgres --dry-run
```

The PostgreSQL helper requires `pg_dump` for real backup execution.

## SQLite Demo Backup

Use SQLite backup only for local demo continuity:

1. Stop backend and frontend.
2. Run `backup_demo --dry-run`.
3. If the dry run is correct, run `backup_demo`.
4. Store the backup outside Git.
5. Record the timestamp and ATDR commit hash.

Do not commit `atdr.db` or backup archives.

## PostgreSQL Logical Backup

For a shared-lab PostgreSQL host:

1. Confirm `DATABASE_URL` points to PostgreSQL.
2. Confirm `pg_dump` is available.
3. Run `backup_postgres --dry-run`.
4. Run `backup_postgres`.
5. Store backup output in managed storage outside Git.
6. Capture command output for evidence.

## Restore Test Checklist

- Restore into a separate test database, never over the active lab database.
- Run Alembic check after restore.
- Start backend against the restored database.
- Verify login, Overview, Alerts, Sources, AI Governance, Response & Audit, and Audit Log.
- Run `performance_smoke`.
- Confirm response automation remains disabled.

## Retention Plan

Recommended shared-lab retention:

- Raw and normalized logs: retain according to lab policy; sanitize before sharing.
- Audit logs: retain for the full project review period.
- Response actions: retain all attempted, denied, and approved simulated actions.
- Model artifacts: keep only reviewed candidate artifacts needed for evidence.
- Demo exports and review CSVs: keep outside Git.

## Never Commit

- real/private logs
- database files
- `.env`
- model artifacts
- generated CSVs/reports
- `demo_exports/`
- `ml_baseline_reviews/`
- processed logs or screenshots

## Evidence To Capture

- backup dry-run output
- real backup output on the PostgreSQL host
- restore checklist result
- performance smoke after restore
- release gate result after restore

## Current Status

Backup helpers exist, and dry-run-first usage is documented. A real PostgreSQL restore drill is still pending.
