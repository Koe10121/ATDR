# v3.97 Large-File Ingestion Reliability And Resumability

## Status

Implemented and validated on 2026-07-13 with synthetic data and disposable SQLite databases. The configured ATDR database was not migrated, reset, deleted, or written during validation. ATDR is not production-ready.

## Scope

v3.97 strengthens the v3.93 durable import path without replacing it. The following behavior remains unchanged:

- FastAPI and React startup commands;
- normal synchronous file/sample import;
- optional source selection and the `local_import` fallback;
- parser profiles and raw-evidence preservation;
- detection and ML are separate analyst operations;
- response automation and real firewall blocking remain disabled.

## Root Cause And Repair

The existing resumable worker already staged uploads, committed bounded chunks, persisted byte/line checkpoints, renewed leases, supported safe cancellation, and rejected changed inputs. Profiling found two scale costs in the hot path:

1. every row executed an unindexed full-text duplicate lookup against `raw_logs.raw_line`;
2. every parsed row forced an immediate ORM flush before its normalized row was attached.

v3.97 adds an indexed SHA-256 content fingerprint and performs bounded fingerprint lookups per chunk. Full raw text is still compared after a fingerprint match, so duplicate accounting remains exact even under a theoretical hash collision. Repeated lines inside the same chunk are also counted correctly. Duplicate rows are reported but are still stored as raw evidence, preserving existing semantics.

`persist_parsed_log` now attaches raw and normalized ORM objects by relationship and lets the chunk transaction flush them together. Raw evidence and one normalized row per input record remain intact.

## Schema Change

Alembic revision `b4c5d6e7f8a9` adds nullable, indexed `raw_logs.raw_line_hash` and backfills existing raw rows in batches of 2,000. The migration does not delete or rewrite `raw_line` evidence.

Apply it before running the updated application:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

The current database was intentionally left untouched during implementation verification. A disposable migration test confirmed that a pre-v3.97 raw row receives the expected fingerprint and index.

## Progress And Operations Visibility

Running import job details now expose cumulative safe counters:

- raw logs imported;
- parsed successfully;
- parse failures;
- duplicate raw logs;
- ingestion run ID and source ID.

Overview > Operations Health displays the four ingestion counters under committed progress. Paths, fingerprints, raw content, and secrets remain private.

Prometheus output adds low-cardinality gauges:

- `atdr_ingestion_active_jobs`;
- `atdr_ingestion_committed_rows_total`;
- `atdr_ingestion_checkpoint_age_seconds`;
- `atdr_ingestion_stalled_jobs`.

No job, source, actor, path, IP, or raw-log value is used as a metric label.

## Safe Validation Command

The validator refuses to run without the explicit temporary-database flag:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_large_ingestion --use-temp-db --lines 100000 --pretty
```

It generates synthetic generic syslog, uses ignored `.tmp` storage, creates a disposable SQLite database, forces one graceful worker handoff, resumes from the committed checkpoint, tests changed-input rejection, tests chunk-boundary cancellation, measures memory, verifies side-effect tables, and removes its temporary directory. It never accepts the configured database as a target.

## 100,000-Line Result

| Measure | Result |
| --- | --- |
| Validation | passed |
| Raw logs / normalized logs | 100,000 / 100,000 |
| Parse success / failures | 100,000 / 0 |
| Chunk commits | 200 |
| Forced handoff checkpoint | row 500 |
| Duplicate rows after resume | 0 |
| Changed staged input | rejected |
| Cooperative cancellation | cancelled after 2 committed rows; evidence retained |
| Ingestion runtime | 138.0349 seconds |
| Throughput | 724.45 rows/second |
| Peak traced Python memory | 8.71 MiB |
| Response/detection/label/model side effects | 0 / 0 / 0 / 0 |
| Configured database changed | false |

A 5,000-line synthetic validator run completed in 6.5149 seconds at 767.47 rows/second. Earlier profiling of the old hot path took 23.8615 seconds for 5,000 synthetic Palo Alto rows; the parser/input shapes differ, so that comparison is directional rather than a strict benchmark. The 100,000-line result is the canonical v3.97 acceptance measurement.

### v3.97 Closure Recheck

The v3.98 goal closure pass repeated the full 100,000-line validator on 2026-07-14. It again produced 100,000 raw and normalized rows, 200 chunk commits, one forced resume from row 500, zero resume duplicates, changed-input rejection, cooperative cancellation at a committed boundary, zero unsafe side effects, and an unchanged configured database. The repeat measured 146.1105 seconds, 684.41 rows/second, and 8.70 MiB peak traced Python memory. The original and closure measurements show local runtime variance and remain engineering observations rather than an SLA.

## Existing Large-DB Read-Only Smoke

Because the current 145,232-row database was intentionally not migrated, ATDR's safe backup utility created a disposable copy under ignored `.tmp` storage. Only that copy was upgraded to v3.97 and used for the read-only performance smoke:

| Query | Time |
| --- | ---: |
| Overview summary | 0.6656 seconds |
| Cached Overview summary | 0.0093 seconds |
| ML Governance lightweight summary | 1.8452 seconds |
| Alert list | 0.0500 seconds |
| Case summary | 0.0962 seconds |
| Operation job summary | 0.0115 seconds |
| Feature generation sample | 0.4630 seconds |

The smoke reported no warnings. These measurements are local read-only observations, not an SLA. The backup command confirmed `source_database_modified: false` before the disposable copy was migrated.

## Failure And Resume Semantics

- Progress is committed nonblank records, not records merely read into memory.
- Raw/normalized rows, source/run counters, duplicate count, checkpoint, lease, and heartbeat commit together.
- Graceful worker shutdown releases an import at a committed checkpoint and the next worker continues the same job.
- Failed or cancelled jobs may create an admin-only resume child while the verified staged input and resume window remain valid.
- A size or SHA-256 staged-file mismatch fails closed.
- Cancellation takes effect only at a committed chunk boundary and never deletes committed evidence.
- A separate re-import remains a separate evidence event; ATDR does not claim global exactly-once ingestion.

## Remaining Limits

- Local SQLite remains single-worker and is not a shared high-throughput target.
- The 100,000-line run used synthetic generic syslog, not a real device or sustained concurrent upload workload.
- Local staged storage remains host-bound unless an approved shared-storage deployment is configured.
- There is no automatic retention of raw evidence and no automatic downstream detection after import.
- PostgreSQL multi-worker, shared storage, sustained concurrency, and approved-host capacity evidence remain environment-backed work.
- These results do not establish an SLA or production readiness.
