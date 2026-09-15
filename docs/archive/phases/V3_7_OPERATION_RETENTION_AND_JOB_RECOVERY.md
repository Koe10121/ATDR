# v3.7 Operation Retention And Job Recovery

## Status

v3.7 adds safe operation-job maintenance for long-running ATDR lab use. It does not change detection logic, ML logic, response behavior, database startup behavior, or the normal local workflow.

ATDR remains a controlled lab prototype. It does not claim production readiness, real firewall blocking, or automatic response.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Job model | `atdr/app/db/models.py` |
| Job service | `atdr/app/services/job_service.py` |
| Job API | `atdr/app/routers/jobs.py` |
| Job schemas | `atdr/app/schemas/operations.py` |
| Maintenance CLI | `atdr/scripts/maintenance_jobs.py` |
| Dashboard visibility | `frontend/src/pages/ExecutiveOverview.tsx`, `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts`, `frontend/src/types/api.ts` |
| Tests | `atdr/tests/test_operation_jobs.py` |
| Config examples | `.env.example`, `.env.lab.example` |

## What Was Added

- Stale active job detection based on `JOB_STALE_AFTER_MINUTES`.
- Safe job summary API at `GET /api/jobs/summary`.
- Operations Health dashboard counts for active jobs, stale jobs, and latest failed job.
- Dry-run-first maintenance command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --dry-run --pretty
```

- Explicit stale marking:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --execute --mark-stale-jobs --pretty
```

- Explicit old terminal job cleanup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --execute --cleanup-completed-jobs --older-than-days 30 --limit 100 --pretty
```

## Retention Defaults

| Setting | Default | Behavior |
| --- | ---: | --- |
| `JOB_STALE_AFTER_MINUTES` | 60 | Active jobs older than this are reported as stale. |
| `JOB_RETENTION_DAYS` | 30 | Terminal job records older than this are cleanup candidates. |
| `RUN_HISTORY_RETENTION_DAYS` | 90 | Advisory run-history retention value; no automatic deletion is implemented. |

## Safety Rules

- Dry-run is the default.
- Maintenance does not run automatically on backend startup.
- Cleanup only targets terminal rows in `operation_jobs`.
- Raw logs, normalized logs, alerts, alert evidence, labels, audit logs, response actions, ingestion runs, and detection runs are never deleted by this command.
- Stale jobs are only marked when `--execute --mark-stale-jobs` is used.
- Cleanup is only performed when `--execute --cleanup-completed-jobs` is used.

## Remaining Gaps

- True async workers, queue-backed cancellation, retries, and distributed job ownership remain future work.
- SQLite remains acceptable for local lab use, but shared-lab operation should eventually validate PostgreSQL.
- Run-history archival is documented as a future policy; v3.7 does not delete ingestion or detection run history.
