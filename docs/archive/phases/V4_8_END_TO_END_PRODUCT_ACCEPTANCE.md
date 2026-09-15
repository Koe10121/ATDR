# v4.8 End-to-End Product Acceptance And Failure-Recovery Validation

## Decision

v4.8 adds one fail-closed acceptance runner that proves ATDR's implemented workflow against an Alembic-migrated disposable SQLite database. It exercises real application services from durable ingestion through investigation, assistant grounding, observability, and backup/restore. It never targets the configured database.

This is controlled synthetic acceptance evidence. It is not a production-readiness claim, a real-device test, an external model validation, or authorization for automatic response.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v48_product_acceptance `
  --use-temp-db `
  --log-count 50000 `
  --simulate-interruption `
  --run-detection `
  --test-assistant `
  --test-backup-restore `
  --pretty
```

`--use-temp-db` is mandatory. Without it, the runner exits with `explicit_temp_database_required`. Assistant validation requires detection so it can cite an actual scenario alert. Temporary source, staging, database, backup, restore, and generated evidence are deleted after the run.

## Acceptance Flow

1. Record a non-content marker for the configured SQLite database and sidecars.
2. Create a unique ignored temporary workspace and SQLite database.
3. Run `alembic upgrade head` against only that database.
4. Register four synthetic sources using `generic_syslog`, `palo_alto`, and `raw_fallback` profiles.
5. Queue and process synthetic bulk ingestion through the durable worker.
6. Interrupt after a committed chunk, then resume from the persisted checkpoint.
7. Cancel a second import at a committed boundary, create a verified resume job, and finish exactly once.
8. Fail an expired mutating-job lease closed with a useful diagnostic and no unsafe automatic retry.
9. Import a ten-row port-scan scenario twice and run source-scoped rule detection after each import.
10. Confirm one alert is created, the second run deduplicates into it, and its occurrence/evidence counts reach 20.
11. Trace the alert to its source, computed case, and `Why flagged?` explanation.
12. Exercise deterministic assistant explanation and follow-ups, then inject a provider failure and confirm local fallback.
13. Render low-cardinality metrics and verify no raw evidence, IP address, or secret is exposed.
14. Create, verify, and restore a backup into a second empty disposable database; refuse the active source as a restore target.
15. Measure ingestion throughput and Overview cold/warm application-cache timing.
16. Compare configured-database markers and remove all temporary artifacts.

## Measured 50,000-Log Result

The 2026-07-16 practical-scale run passed:

| Area | Result |
| --- | ---: |
| Raw logs | 50,000 |
| Normalized logs | 50,000 |
| Parse failures | 3 intentional raw-fallback rows |
| Duplicate raw observations | 19 |
| Ingestion throughput | 1,911.22 rows/second |
| Total acceptance runtime | 30.9894 seconds |
| Resume completion overhead | 25.5329 seconds |
| Source-scoped detection | 0.0360 seconds |
| Overview cold app-cache median | 0.0935 seconds |
| Overview cold app-cache p95 | 0.1162 seconds |
| Overview warm median | 0.0052 seconds |
| Overview warm p95 | 0.0052 seconds |
| Alert list | 0.0119 seconds |
| Case summary | 0.0042 seconds |
| Assistant workflow | 0.2104 seconds |
| Backup / restore | 0.2018 / 0.3923 seconds |
| Disposable DB size | 49,299,456 bytes |

The port-scan source was healthy, detection created one `possible_port_scan` alert, the repeat run performed one deduplication update, and the final alert contained 20 occurrences and 20 related logs. The computed case and explanation were source-traceable.

## Failure-Recovery Evidence

- Graceful worker interruption preserved a monotonic committed checkpoint and resumed the same job.
- Cooperative cancellation stopped at a committed boundary and retained verified staging only for the resume window.
- The resumed cancellation job imported the remaining rows without duplicate checkpoint replay.
- An expired `run_detection` lease failed closed with `Worker lease expired before completion.` and was not automatically retried.
- Parser failures preserved non-empty raw evidence and created normalized fallback records with explicit error status.

## Assistant Evidence And Safety

- Explicit alert context survived two follow-up questions in one conversation.
- Citations referenced the actual temporary alert ID.
- Raw-log context stayed disabled and scenario IPs were redacted.
- An injected provider request failure returned deterministic local evidence instead of failing the workflow.
- Raw logs, normalized logs, alerts, detection runs, labels, models, users, sources, and response-action counts were unchanged by assistant questions. Only assistant audit rows were added.
- No external provider call was made by this acceptance run.

## Backup And Restore Evidence

- Backup creation and manifest checksum verification passed.
- Restoring over the active disposable source database was refused.
- Restore into a separate empty disposable SQLite database passed integrity, table-count, and Alembic-revision comparison.
- The configured user database was neither a backup source nor a restore target.

## Safety Invariants

- configured database unchanged;
- no database reset or deletion;
- no users or labels created;
- no ML model run, activation, or promotion;
- no response actions;
- response automation disabled;
- real firewall blocking disabled;
- assistant read-only;
- no raw evidence, secret, private path, or API key in the public report;
- temporary artifacts removed;
- `production_ready=false` remains explicit.

## Automated Coverage

`atdr/tests/test_v48_product_acceptance.py` contains ten tests covering target refusal, argument validation, migrated temporary storage, exact ingestion counts, interruption and cancellation recovery, stale-lease failure, source-scoped detection and deduplication, case/explanation traceability, assistant grounding and provider fallback, backup/restore, observability privacy, no ML/response side effects, sanitized output, and semantic report repeatability.

## Closure Verification

- task-board render and standards check: passed;
- Ruff: passed;
- compileall for `atdr` and `migrations`: passed;
- focused v4.8 tests: `10 passed`;
- full backend: `612 passed, 1 skipped`;
- Alembic check: no new upgrade operations;
- replay dry-run: two safe rows parsed, zero rows written;
- configured-DB performance smoke: passed with no warnings;
- release gate: `ok=true`, no failed required checks;
- frontend lint/build/Playwright: not repeated because v4.8 changes no frontend source or behavior;
- exact allowlist audit: 17 changed, 17 allowed, zero missing/outside;
- tracked protected-artifact audit: none.

## Remaining Risks

- Synthetic evidence cannot prove real firewall/router compatibility or real attack prevalence.
- SQLite acceptance does not prove multi-host PostgreSQL capacity or lock behavior.
- Assistant provider availability, quota, privacy approval, and real-provider quality remain environment-backed concerns.
- Detection/ML candidate promotion remains blocked by independent evidence and governance gates.
- Computed cases are grouped views, not a separately persisted incident-management workflow.
- Real response enforcement remains intentionally unimplemented.

## Recommended v4.9

Run **v4.9 Approved-Host And Provider Acceptance Evidence** only when an approved PostgreSQL host, MFU IAM provider configuration, or real firewall/syslog source is available. Until then, preserve v4.8 as the reproducible local product acceptance gate and focus only on defects found by it.
