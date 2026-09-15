# v3.90 Durable Background Jobs And Operation Reliability

Date: 2026-07-13

## Purpose

v3.90 changes ATDR operation jobs from history-only synchronous wrappers into an opt-in, database-backed work queue for controlled local and shared-lab use. It preserves the normal FastAPI and React startup commands and does not start a worker from the API process.

## What Is Implemented

- `operation_jobs` now stores a private execution payload, idempotency key, attempt count, lease owner, lease expiry, and next attempt time.
- `operation_worker_heartbeats` records safe worker availability and the current job ID.
- A separate worker command can process one job explicitly or, only when enabled by private configuration, watch a queue.
- Queued imports stage uploads below ignored `.atdr_runtime/operation-jobs/`; full source paths, staged paths, and raw upload content are never returned by the API or dashboard.
- Queued detection, anomaly training, supervised candidate training, anomaly scoring, and evidence exports use an allowlisted dispatcher.
- Supervised worker training is candidate-only. The worker does not activate or promote a model.
- Idempotency keys return the original job for the same requesting user.
- Analysts can see and manage only their own jobs. Admins can see and manage all jobs and can queue ML/export work.
- Operations Health shows queue counts, worker state, attempt counts, and safe retry/cancel controls.

## Safety Contract

- No worker starts automatically with `uvicorn`.
- No queued job type can execute a response action, firewall change, user/account change, label change, data deletion, model activation, model promotion, IAM call, SMTP action, or external LLM call.
- Cancel is allowed only before worker completion (`queued` or `retry_wait`). Running work is never force-stopped because it may be writing evidence.
- Evidence-mutating jobs fail closed after an expired worker lease. Only report exports may be automatically retried because they do not alter detection evidence.
- Import staging files are removed after a worker attempt. A failed queued import requires a deliberate re-upload rather than an unsafe replay of partial evidence work.
- Raw logs, normalized logs, alerts, labels, audit records, ingestion runs, and detection runs are never deleted by worker recovery or job cancellation.

## Worker Commands

Run a single explicit job cycle without enabling a persistent worker:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --once --pretty
```

For a deliberate shared-lab worker, set this only in a private `.env`:

```text
OPERATION_WORKER_ENABLED=true
```

Then run a separately managed watcher:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

The normal backend command remains unchanged:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

## API Surface

- `GET /api/jobs` - scoped operation history; analysts receive only their own jobs.
- `GET /api/jobs/summary` - safe queue and worker health summary.
- `GET /api/jobs/{id}` - job detail without private payload or paths.
- `POST /api/jobs/submit` - JSON queue submission for allowlisted detection/ML/export operations.
- `POST /api/jobs/import` - admin-only multipart queued import/replay upload.
- `POST /api/jobs/{id}/cancel` - cancels only queued or retry-waiting work.
- `POST /api/jobs/{id}/retry` - queues a new retry for safe retryable terminal work.

Existing actions remain synchronous unless a caller explicitly uses `enqueue=true` for detection or supported ML routes, or calls the queue API directly.

## Known Limits

- SQLite remains the normal local database and is best run with one worker due to its single-writer behavior.
- A persistent worker is an operational process that must be started separately; it is not a production process manager.
- Large-file resumability, distributed workers, worker authentication, PostgreSQL load evidence, and queue monitoring/alerting remain later shared-lab/deployment work.
- This change does not claim production readiness.

## Source Evidence

- `atdr/app/db/models.py`
- `migrations/versions/e1f2a3b4c5d6_add_durable_operation_job_fields.py`
- `atdr/app/services/job_service.py`
- `atdr/app/services/job_dispatcher.py`
- `atdr/app/services/operation_worker.py`
- `atdr/app/routers/jobs.py`
- `atdr/scripts/run_operation_worker.py`
- `frontend/src/pages/ExecutiveOverview.tsx`
- `atdr/tests/test_v390_durable_operation_jobs.py`
