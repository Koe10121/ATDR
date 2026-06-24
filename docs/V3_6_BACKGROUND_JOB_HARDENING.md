# v3.6 Background Job And Long-Running Operation Hardening

## Status

Implemented as a synchronous lab-safe job tracking layer. ATDR still runs the same FastAPI and React startup commands, uses SQLite locally, and does not require Celery, Redis, Docker, PostgreSQL, automatic response, or real firewall blocking.

## Source Evidence

| Area | Source |
| --- | --- |
| Job data model | `atdr/app/db/models.py`, `migrations/versions/a1b2c3d4e5f7_add_operation_jobs.py` |
| Job service | `atdr/app/services/job_service.py` |
| Job API | `atdr/app/routers/jobs.py`, `atdr/app/main.py` |
| Tracked operations | `atdr/app/routers/logs.py`, `atdr/app/routers/detection.py`, `atdr/app/routers/ml.py`, `atdr/app/routers/demo.py`, `atdr/scripts/replay_logs.py` |
| React operations visibility | `frontend/src/pages/ExecutiveOverview.tsx`, `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts`, `frontend/src/types/api.ts` |
| Tests | `atdr/tests/test_operation_jobs.py`, `frontend/tests/smoke.spec.ts` |

## What Changed

- Added `operation_jobs` for lightweight tracking of long-running dashboard and CLI operations.
- Added authenticated job-history endpoints:
  - `GET /api/jobs`
  - `GET /api/jobs/{id}`
  - `POST /api/jobs/{id}/cancel`
- Wrapped existing synchronous operations so they record completed or failed job history:
  - log import
  - demo sample import
  - detection run
  - anomaly ML train/score
  - supervised ML train
  - demo evidence export
  - direct replay when not in dry-run mode
- Added a compact **Latest Operation Job** panel to Overview / Operations Health.
- Kept dry-run replay read-only: it does not write job history unless a future explicit flag is added.

## Behavior Notes

- Jobs are not a background queue yet. Operations still complete synchronously in the request or script process.
- `cancel` is intentionally conservative. Only queued jobs can be cancelled. In v3.6, normal operations move directly to `running` and finish synchronously, so the API returns a clear `409` when cancellation would be misleading.
- Result summaries are sanitized and compact. Private full paths should not be exposed in dashboard job summaries.
- Existing ingestion and detection run history remains the detailed source of truth for parser, detection, deduplication, and runtime counts.

## Safety

- No response automation was added.
- No real firewall blocking was added.
- No ML model activation or production promotion was added.
- No database reset or data deletion is part of this change.
- Generated reports, real logs, databases, model artifacts, `.env`, `ml_baseline_reviews/`, `demo_exports/`, and processed logs remain out of Git.

## Remaining Work

- True asynchronous workers can be considered later if the lab needs multi-minute imports or ML training from the dashboard.
- Future async work should add durable cancellation semantics, worker heartbeat, retry policy, and retention cleanup.
- PostgreSQL should be used before relying on this as a shared-lab or production-style job system.
