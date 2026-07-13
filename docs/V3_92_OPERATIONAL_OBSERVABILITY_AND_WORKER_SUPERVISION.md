# v3.92 Operational Observability And Worker Supervision

## Status

ATDR v3.92 adds a local, dependency-free observability and worker-supervision layer. It does not start a worker with the API, change detection or ML behavior, enable automatic response, or delete current data. SQLite remains the normal local database and permits one operation worker.

## Root Gaps Closed

- Incoming request IDs were accepted without a length or character boundary.
- `/health` mixed process, database, migration, model, and response checks without separate liveness/readiness semantics.
- Queue/worker state existed, but stale heartbeat, backlog, and repeated-failure warnings were not consolidated.
- Metrics were not available in a low-cardinality machine-readable format.
- Watch workers did not record a graceful stopped state, and SQLite did not reject a second fresh worker.
- Audit/job retention planning existed, but there was no explicit audit-event dry-run/apply tool with protected security-event rules.

## Request Correlation

`RequestContextMiddleware` accepts `X-Request-ID` only when it is 1-64 characters and matches the bounded set `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, and `-`. Invalid, blank, or oversized values are replaced with a UUID. The selected value is:

- returned as `X-Request-ID`;
- included in structured request and exception logs;
- never used as a metric label.

## Health Endpoints

| Endpoint | Purpose | Database work | Result |
| --- | --- | --- | --- |
| `GET /health` | Backward-compatible dashboard health | yes | `200`, with `ok` or `degraded` |
| `GET /health/live` | Process liveness | no | `200` while the API process responds |
| `GET /health/ready` | Database, Alembic, and configuration readiness | yes | `200` only when ready; otherwise safe `503` |
| `GET /api/operations/health` | Detailed safe operations status | yes | Admin only |

Readiness output does not include database credentials, URLs, model paths, tokens, or secrets. An unavailable database or migration drift fails readiness cleanly.

## Metrics

`GET /metrics` renders Prometheus text without requiring Prometheus locally. Labels are restricted to bounded HTTP method/status families, known job types/states, worker freshness state, and fixed outcome values.

Included signals:

- HTTP request count and duration by method and status family;
- operation queue depth by known type/state;
- completed, failed, and retry-wait job counts and terminal durations;
- fresh, stale, and stopped worker counts without worker IDs;
- ingestion parse successes/failures;
- detection alerts created/deduplicated;
- database metric collection readiness.

Metrics never include request IDs, paths, usernames, emails, IP addresses, file names, raw log text, job/run IDs, credentials, or secrets.

## Worker Supervision

The worker remains opt-in and separately launched:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --once --pretty
$env:OPERATION_WORKER_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

Behavior:

- default worker identity includes host and process ID;
- startup, idle/running, and stopped heartbeats are persisted;
- watch mode records `stopped` in a `finally` block on graceful exit;
- expired leases retry only explicitly safe report-export work;
- evidence-changing jobs fail closed when a lease expires;
- SQLite rejects a second fresh worker;
- PostgreSQL retains the locking design for multiple workers, but multi-worker runtime validation is still pending on an approved host;
- API startup never launches the operation worker.

## Operational Warnings

The existing Overview Operations Health panel now displays compact warnings for:

- stale jobs or worker heartbeat;
- queue backlog at the configured threshold;
- repeated recent job failures;
- database unavailability;
- Alembic migration drift;
- invalid runtime configuration;
- response simulation unexpectedly disabled.

Warnings are visibility only. They never create response actions, detection runs, labels, or model runs.

## Audit Retention Safety

Dry-run is the default:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.audit_retention --pretty
```

Applying one bounded batch requires both flags:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.audit_retention --apply --confirm APPLY-AUDIT-RETENTION --pretty
```

Safety contract:

- configured retention cannot be shorter than the minimum;
- only eligible old `audit_logs` rows are considered;
- IAM, authentication, account, email-verification, response, block/unblock, and denied events are preserved;
- raw logs, normalized logs, alerts, labels, model runs, response actions, and evidence are never deleted;
- each applied batch writes an `audit_retention_applied` event;
- v3.92 verification applies retention only to temporary test databases;
- no retention apply was run against the user's current database.

## Configuration

```dotenv
OPERATION_QUEUE_BACKLOG_WARNING=25
OPERATION_JOB_FAILURE_WARNING_COUNT=3
OPERATION_JOB_FAILURE_WARNING_WINDOW_MINUTES=60
AUDIT_RETENTION_DAYS=365
AUDIT_RETENTION_MIN_DAYS=90
AUDIT_RETENTION_BATCH_SIZE=500
```

## Known Limits

- Metrics are in-process plus database snapshots; process counters reset when the API restarts.
- No external monitoring, alert notification, or paging service is required or configured.
- SQLite remains single-worker and is not a shared high-throughput queue.
- PostgreSQL multi-worker behavior needs controlled runtime validation.
- Audit retention is operator-invoked, not a scheduler.
- Current private configuration must pass `config_doctor`; readiness intentionally fails if an enabled IAM/provider profile is incomplete.

## Next Phase

Recommended v3.93: resumable large-file ingestion and backpressure. Add chunk checkpoints, progress, cancellation boundaries, idempotent resume, size/retention policy, and failure recovery without changing parser/detection semantics or deleting evidence.
