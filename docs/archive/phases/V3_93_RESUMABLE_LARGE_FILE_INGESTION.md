# v3.93 Resumable Large-File Ingestion

## Status

Implemented and verified on 2026-07-13 as a controlled local/productization increment. ATDR is not production-ready. SQLite remains the normal local database and permits one operation worker.

## Problem Closed

Before v3.93, queued imports streamed text but committed the database only after the entire file completed. A worker crash rolled back the in-progress transaction, the lease was not renewed while parsing, and worker cleanup removed the staged input after success or failure. The duplicate counter measured previously seen raw text but did not prevent insertion, so it could not provide resume idempotency.

## Actual Processing Guarantee

For the durable `import_logs` and `replay_logs` queue path:

- the staged file has a safe display name, byte size, SHA-256 fingerprint, and nonblank-line count;
- the worker seeks to the last committed byte checkpoint;
- raw-log writes, normalized-log writes, source counters, ingestion-run counters, job progress, byte/line checkpoint, lease renewal, and worker heartbeat commit in the same database transaction for each chunk;
- a failure before a chunk commit rolls that chunk back;
- a failure after a chunk commit resumes after that committed checkpoint;
- a changed size or fingerprint blocks resume;
- completed imports delete the staged copy;
- failed or cancelled imports retain the staged copy only through the configured resume window.

This is a transactional chunk guarantee for one verified staged input. It is not a claim of global exactly-once ingestion. Re-importing the same content as a separate job still creates new raw evidence under the existing import semantics, while `duplicate_raw_logs` reports that content was seen previously.

The existing synchronous sample/file import path remains compatible and keeps its prior single-transaction behavior.

## Chunk And Checkpoint Semantics

Configuration defaults:

```env
INGESTION_CHUNK_SIZE=500
INGESTION_PROGRESS_UPDATE_INTERVAL=500
```

The effective committed chunk size is the smaller configured value. Progress is measured in committed nonblank log records. The checkpoint also stores the physical line and byte offset, so blank lines do not break resume positioning. The UI reports committed progress and never invents an ETA.

## Cancellation

`POST /api/jobs/{id}/request-cancel` supports:

- immediate cancellation for queued or retry-waiting jobs;
- `cancel_requested` for a running resumable import;
- worker acknowledgement only at the next chunk boundary;
- preservation of already committed raw and normalized evidence;
- retention of the verified staged input while resume remains eligible.

The compatibility endpoint `POST /api/jobs/{id}/cancel` uses the same safe behavior. Cancellation never creates detection runs, labels, model runs, response actions, or firewall activity.

## Resume

`POST /api/jobs/{id}/resume` is admin-only. Resume is accepted only when:

- the job is a failed or cancelled file import/replay;
- the resume window is open;
- the staged input exists under ATDR's ignored runtime root;
- size and SHA-256 fingerprint match;
- no other active resume owns the same original job;
- a committed checkpoint and ingestion-run relationship can be continued safely.

A resume creates a child operation job with `resume_of_job_id` and `original_job_id`. It continues the same ingestion run and cumulative source counters. Paths and fingerprints are not returned by the API.

## Backpressure And Staging

Defaults:

```env
OPERATION_MAX_QUEUED_IMPORTS=10
OPERATION_MAX_QUEUED_JOBS_PER_ACTOR=5
OPERATION_STAGING_MAX_TOTAL_BYTES=1073741824
OPERATION_STAGING_MIN_FREE_BYTES=268435456
OPERATION_STAGING_RETENTION_HOURS=24
```

Queue capacity returns HTTP 429. Storage pressure returns HTTP 503. Upload streaming stops before the per-file, total staging, or minimum free-space boundary is crossed. Existing synchronous small imports are not routed through these limits.

Preview staged-input cleanup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.cleanup_staged_inputs --pretty
```

Apply requires both flags:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.cleanup_staged_inputs --apply --confirm APPLY-STAGED-CLEANUP --pretty
```

Cleanup never deletes active or still-resumable staged inputs and never deletes raw logs or normalized evidence. Do not run `--apply` without reviewing the dry-run output.

## Operations Visibility

Operation job payloads now expose only safe fields:

- committed current/total and percentage;
- progress status without a fake ETA;
- checkpoint line/bytes/time;
- chunk commit count;
- cancellation-requested state;
- resume eligibility and safe reason;
- original/resume job references;
- latest heartbeat time and lease expiry.

Prometheus output adds low-cardinality totals for chunk commits, resumes, cancellation requests/completions, interrupted imports, and staging pressure. File names, paths, actors, source IDs, job IDs, IPs, and request IDs are not metric labels.

## React Workflow

Admin > Demo Controls includes a durable file upload that queues work without replacing the existing sample import. Overview > Operations Health shows stable progress bars, status badges, staging pressure, safe cancellation, admin-only resume, and collapsed checkpoint details.

The API never starts a worker. Start one separately when durable work should run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

## Failure Recovery

1. Stop or replace the failed worker process.
2. Wait for lease recovery or confirm the job is `failed`/`cancelled`.
3. Review the job's committed progress and resume eligibility in Operations Health.
4. Confirm the staged input has not been moved or changed.
5. Select Resume as an admin, or call `POST /api/jobs/{id}/resume`.
6. Start exactly one SQLite operation worker.
7. Verify the child job completes and the cumulative ingestion run/source counts match the expected file limit.

If the staged file is missing, changed, or expired, upload it as a new job. ATDR intentionally refuses an unsafe resume.

## Validation Evidence

- v3.93 focused backend and operation regressions: passed.
- Full backend: 509 passed, 1 skipped.
- Complete Alembic SQLite chain through `f2a3b4c5d6e7`: passed with no drift.
- React lint/build: passed.
- Playwright: 21 passed, 1 hardware-dependent scenario skipped; focused progress/resume/upload checks passed.
- Replay dry-run: two safe rows parsed and zero rows written.
- Performance smoke: no warnings; Overview `0.4572s`, cached Overview `0.0063s`, ML Governance `1.6617s`, operation-job summary `0.0070s`.
- Staged-input cleanup dry-run: zero candidates and zero raw evidence deleted; no apply was run.
- Release gate: `ok: true` with no failed required checks.

## Limitations And Next Phase

- SQLite supports one operation worker and is not a multi-user throughput target.
- Staged files are local to the worker host; shared workers require approved shared storage semantics.
- Separate imports may intentionally preserve duplicate raw evidence.
- No real device, PostgreSQL multi-worker, managed worker supervisor, or distributed lock was validated here.
- Detection, ML, assistant, IAM, response safety, and startup commands were not broadened.

Recommended v3.94: PostgreSQL multi-worker runtime validation, managed worker deployment, and backup/restore concurrency drills on an approved shared-lab host.
