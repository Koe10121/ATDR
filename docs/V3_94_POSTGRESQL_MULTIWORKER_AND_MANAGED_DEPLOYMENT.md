# v3.94 PostgreSQL Multi-Worker And Managed Deployment

## Status

v3.94 adds the runtime controls and validation harness needed to operate ATDR's durable queue with multiple PostgreSQL workers. It does not make PostgreSQL mandatory and it does not claim production readiness.

The normal local workflow remains unchanged:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

SQLite remains the default local database and permits one operation worker. PostgreSQL, shared staging, managed services, and the concurrency drills are optional deployment work.

## What Changed

- PostgreSQL queue claims and expired-lease recovery use row locking with `SKIP LOCKED`.
- Every claim receives a private lease token and incremented claim generation. A stale worker cannot renew, complete, cancel, fail, or release a job after ownership changes.
- File jobs carry a staging storage identity and relative storage key. A worker only claims an import when it can access the matching storage.
- Shared staging requires an absolute mounted path and a non-local storage ID.
- Legacy host-local staged imports remain claimable by the matching local profile but are not taken by shared workers.
- Concurrent source creation tolerates a unique-name race, and source counters are updated while the source row is locked.
- `SIGINT` or `SIGTERM` requests a graceful worker stop. A resumable import finishes its current transaction chunk, persists the checkpoint, releases its lease, and returns to the queue for another worker.
- PostgreSQL backup obtains an exclusive ATDR advisory lock. Cooperative workers pause new cycles, and backup refuses to run while a mutating operation is still active.
- Example `systemd` units run the API and worker as an unprivileged user with explicit restart and shutdown policies.
- Ephemeral PostgreSQL CI is configured to exercise migrations, concurrent workers, shared staging, backup drain protection, and isolated restore.

## Runtime Guarantees

### Job Ownership

The worker must present both its worker ID and current lease token for ownership-sensitive writes. Lease tokens are never returned by the public operation-job serializer. PostgreSQL claims and recovery skip rows locked by another transaction, so two workers cannot claim the same available row through the normal queue path.

This is lease-fenced at-least-once execution with transactional checkpoints. It is not a global exactly-once guarantee. A separate intentional import of the same file may preserve duplicate raw evidence and report duplicate counts.

### Shared Staging

All hosts in one worker deployment must mount the same storage at the configured absolute path and use the same storage ID:

```text
OPERATION_STAGING_ROOT=/srv/atdr/shared/operation-jobs
OPERATION_STAGING_SHARED=true
OPERATION_STAGING_STORAGE_ID=shared-lab-staging-v1
```

The database stores a relative key plus the storage ID, not a private host path. Path traversal, missing files, fingerprint changes, and storage-ID mismatches fail closed.

### Graceful Restart

For resumable file imports, a managed stop waits for the active chunk boundary. Committed evidence and checkpoint state remain durable, the job returns to `queued`, and a replacement worker continues from the verified checkpoint. Non-import jobs drain normally within the service manager's shutdown timeout.

If a process is killed before graceful release, the lease expires and the existing recovery policy applies. Evidence-mutating jobs still fail closed unless their workflow explicitly supports verified resume.

### Backup Coordination

ATDR workers acquire a shared PostgreSQL advisory lock around a work cycle. Backup requests the corresponding exclusive lock and refuses to proceed if workers are active or if a mutating job is still marked running. After the queue is drained, `pg_dump` runs with `--serializable-deferrable`; restore verification uses a separate empty database and compares migration revision and row counts.

This coordination covers ATDR operation workers. A full shared deployment backup must also put API-side mutating endpoints into an approved maintenance or read-only window. It is not a universal database freeze for unrelated clients.

## Configuration

Use `.env.example` for normal SQLite development. Use `.env.lab.example` only on an approved PostgreSQL/shared-storage host. Deployment-specific values and secrets belong in a private environment file or secret manager.

Required shared-worker controls include:

```text
DATABASE_URL=postgresql+psycopg2://...
AUTO_CREATE_TABLES=false
RESPONSE_SIMULATION=true
OPERATION_WORKER_ENABLED=true
OPERATION_WORKER_DEPLOYMENT_ID=shared-lab
OPERATION_WORKER_CONCURRENCY=2
OPERATION_WORKER_SHUTDOWN_GRACE_SECONDS=120
OPERATION_STAGING_ROOT=/srv/atdr/shared/operation-jobs
OPERATION_STAGING_SHARED=true
OPERATION_STAGING_STORAGE_ID=shared-lab-staging-v1
```

Do not place a database password, IAM secret, assistant key, or other credential in a service file committed to Git.

## Managed Service Example

Reference files are under `deploy/systemd/`:

- `atdr-api.service.example`
- `atdr-worker@.service.example`
- `atdr.env.example`
- `README.md`

Validate the local profile without changing data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_worker_deployment --pretty
```

On the configured Linux shared host, validate the shared profile before installing units:

```bash
python -m atdr.scripts.validate_worker_deployment --require-shared --pretty
sudo systemctl daemon-reload
sudo systemctl enable --now atdr-api.service
sudo systemctl enable --now atdr-worker@1.service atdr-worker@2.service
```

The API service never starts a worker itself. Start only the worker count approved for the configured PostgreSQL pool and host capacity.

## Isolated Validation Commands

The following execute modes are destructive only to explicitly named disposable v3.94 test databases. They refuse ordinary database names and require confirmation phrases.

Concurrent worker and shared-staging drill:

```powershell
$env:ATDR_V394_POSTGRES_DATABASE_URL="postgresql+psycopg2://.../atdr_v394_jobs"
.\.venv\Scripts\python.exe -m atdr.scripts.validate_postgres_multiworker --execute --confirm ISOLATED_V394_POSTGRES --pretty
```

Backup/drain/restore drill:

```powershell
$env:ATDR_V394_BACKUP_SOURCE_DATABASE_URL="postgresql+psycopg2://.../atdr_v394_backup_source"
$env:ATDR_V394_BACKUP_RESTORE_DATABASE_URL="postgresql+psycopg2://.../atdr_v394_backup_restore"
.\.venv\Scripts\python.exe -m atdr.scripts.validate_backup_worker_concurrency --execute --confirm ISOLATED_V394_BACKUP_DATABASES --pretty
```

Without `--execute`, both commands are non-mutating preflight reports.

## Validation Coverage

The v3.94 tests and drills cover:

- PostgreSQL claim and recovery SQL containing `FOR UPDATE SKIP LOCKED`;
- unique concurrent job claims and expired-lease recovery;
- stale lease-token rejection;
- concurrent same-name source creation;
- two imports updating one source without lost counters;
- shared storage ownership and unsafe-key rejection;
- graceful import release and replacement-worker resume;
- backup refusal while mutating work is active;
- isolated backup and restore row/revision comparison;
- unchanged response-action, label, and model-run counts.

Local source/unit tests and dry-run validators are evidence available on a SQLite workstation. Successful execution of the ephemeral PostgreSQL GitHub Actions job or the same drills on an approved PostgreSQL host is still required before claiming environment-backed multi-worker validation.

## Local Verification Result

On 2026-07-13, the repository-side v3.94 checkpoint passed:

- task-board render and standard check;
- full Ruff and Python compilation;
- backend `515 passed, 1 skipped`;
- Alembic at revision `a3b4c5d6e7f8` with no drift;
- React lint/build and Playwright `21 passed, 1 skipped`;
- replay dry-run with two safe sample rows and zero writes;
- local worker deployment validator and both non-mutating PostgreSQL preflights;
- release gate `ok: true` with no failed required checks;
- hygiene check with zero tracked private env, database, model, review, or export artifacts.

The read-only performance smoke completed successfully but reported cold large-SQLite warnings: Overview `8.9415s`, ML Governance `2.4876s`; cached Overview was `0.0070s`. This is a known local-dataset performance follow-up, not evidence of PostgreSQL multi-worker execution.

## Safety Boundaries

- Response remains simulated and analyst-approved.
- Workers and validators do not create response actions.
- No real firewall connector is enabled.
- No ML model is activated or promoted.
- The SOC Assistant remains read-only.
- Raw evidence is not deleted by worker recovery, cancellation, backup, or rollback.
- Secrets, connection strings, paths, lease tokens, and raw logs are excluded from public status output.

## Rollback

1. Stop managed workers gracefully and confirm no running jobs remain.
2. Keep the API in a controlled maintenance window.
3. Back up the database and staging metadata.
4. Roll back application services to the prior version.
5. Downgrade migration `a3b4c5d6e7f8` only when no queued/resumable job depends on lease-token or storage-identity fields.
6. Never delete raw logs as rollback cleanup.

## Remaining Gaps

- A successful remote PostgreSQL CI or approved-host run must be recorded.
- Multi-host shared-storage mount behavior and permissions need environment evidence.
- API mutation quiescing during backup needs a deployment maintenance procedure.
- External metrics persistence, alert routing, TLS/reverse proxy, secret management, and disaster recovery remain separate phases.
- Real device syslog validation remains blocked until approved hardware/network access exists.
