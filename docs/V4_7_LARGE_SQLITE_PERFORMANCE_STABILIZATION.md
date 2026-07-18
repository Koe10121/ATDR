# v4.7 Large-SQLite Overview Performance Stabilization

## Decision

v4.7 repairs the uncached Overview query shape on the current large local SQLite database without changing the API response, cache TTL, schema, detection, ML, IAM, assistant, or response behavior. SQLite remains the normal local profile and PostgreSQL remains the recommended shared deployment profile.

This is a measured local performance improvement, not a production SLA or production-readiness claim.

## Scope And Baseline

The configured database was profiled read-only with approximately:

- 145,232 raw logs;
- 145,232 normalized logs;
- 3,231 alerts.

The inherited v4.6 evidence recorded one true cold-disk Overview/ingestion summary at `9.341s`, first cached at `0.374s`, and warm cached at `0.0062s`. At the start of v4.7, after operating-system pages were warm, five independent application-cache misses measured:

| Before Metric | Min | Median | p95 | Max | Queries |
| --- | ---: | ---: | ---: | ---: | ---: |
| Application-cache miss | 0.423614s | 0.486496s | 0.494161s | 0.495627s | 49 |
| Warm cache hit | 0.006505s | 0.006569s | 0.007523s | 0.007593s | 5 |

All five payload fingerprints matched. The historical cold-disk result is retained because an application-cache benchmark does not flush operating-system or SQLite page caches.

## Root Cause

SQLAlchemy timing and `EXPLAIN QUERY PLAN` identified three concrete issues:

1. The data-quality aggregate used five `SUM(CASE ...)` expressions and `LOWER(app)` in one statement. SQLite reported `SCAN normalized_logs`, forcing a scan of the wide 145k-row table. This step alone measured about `0.302s` after pages were warm and was the strongest explanation for the much larger true cold-disk result.
2. The ten recent alerts lazily loaded `alert.evidence`, creating ten extra queries.
3. Every warm cache check issued five separate freshness queries.

The grouped action, protocol, application-risk, and destination-country queries already used covering indexes. No new index was justified.

## Implementation

`atdr/app/services/dashboard_service.py` now:

- counts missing timestamp/source/destination/action values through scalar subqueries that use existing indexes;
- groups application values through the existing application index and performs the same case-insensitive unknown-app classification in Python;
- fetches recent-alert evidence counts through one correlated indexed subquery instead of ten lazy relationship queries;
- reuses the already calculated raw-log count;
- checks cache freshness through one portable statement;
- includes raw-log count, alert update time, run completion time, suppression state, and watchlist state in the freshness signature;
- fetches parser-error examples and raw excerpts in one bounded join for small databases.

`atdr/scripts/profile_dashboard_summary.py` now provides repeatable five-run application-cache distributions, query counts, database execution time, stable response fingerprints, and safe SQLite query-plan details. It is read-only.

## Query Plan Before And After

Before:

```text
quality aggregate: SCAN normalized_logs
recent alerts: SCAN alerts; USE TEMP B-TREE FOR ORDER BY
```

After, the data-quality path reports:

```text
SEARCH normalized_logs USING INDEX ix_normalized_logs_generated_time
SEARCH normalized_logs USING COVERING INDEX ix_normalized_logs_src_ip
SEARCH normalized_logs USING COVERING INDEX ix_normalized_logs_dst_ip
SEARCH normalized_logs USING COVERING INDEX ix_normalized_logs_action
SEARCH normalized_logs USING COVERING INDEX ix_normalized_logs_app
```

The recent-alert sort remains a bounded scan of 3,231 alert rows, but evidence counting no longer performs N+1 round trips. Its measured cost is small relative to the removed normalized-log scan, so no schema change was added.

## Result

Five post-change application-cache runs measured:

| After Metric | Min | Median | p95 | Max | Queries |
| --- | ---: | ---: | ---: | ---: | ---: |
| Application-cache miss | 0.122366s | 0.129154s | 0.156620s | 0.157619s | 35 |
| Warm cache hit | 0.010211s | 0.010340s | 0.010919s | 0.011031s | 1 |

The v4.7 targets pass:

- cold application-cache median target `<=2.0s`: passed;
- cold application-cache p95 target `<=3.0s`: passed;
- warm cached target `<=0.05s`: passed.

The warm wall-clock median increased by about `0.0038s` because the single signature is more complete, but it remains far below the target and query round trips fell from five to one. The quality aggregate improved from about `0.302s` to `0.012s`; the detailed uncached summary improved from `0.4798s` to `0.1588s` on warm operating-system pages.

The full read-only performance smoke after the repair reported:

| Metric | Result |
| --- | ---: |
| Overview / ingestion summary | 0.1617s |
| First cached Overview | 0.1286s |
| Warm cached Overview | 0.0105s |
| ML Governance lightweight summary | 1.1921s |
| Alert list | 0.0334s |
| Case summary | 0.0685s |
| Feature generation sample | 0.2754s |
| Warnings | none |

## Correctness And Safety

- A fixed-time, field-by-field comparison against the pre-v4.7 implementation matched all 27 business response fields on the configured database.
- Cold and warm response fingerprints matched across all five benchmark runs.
- Empty, small, disabled-source, parser-error, recent-alert evidence, raw-only insert, alert creation/update, failed ingestion run, and failed detection run behavior is covered.
- Cache invalidation exposes fresh raw, alert, and run state on the next request.
- Concurrent file-backed SQLite readers return the same counts without lock errors.
- Optimized statements compile with the PostgreSQL SQLAlchemy dialect and contain no SQLite-only shared-service SQL.
- No migration or index was added. The configured database was not reset, copied, migrated, or modified.
- Summary reads create no ML model run or response action.

## Verification

- focused v4.7/cache/profile tests: passed;
- related dashboard/ingestion/profile regression set: `24 passed`;
- persistence-path rerun under the approved `.tmp` root: `14 passed`;
- full backend suite: `602 passed, 1 skipped`;
- Ruff and compileall: passed;
- Alembic check: no drift; PostgreSQL offline migration SQL generation: passed;
- final read-only five-run profiler: cold median `0.124564s`, cold p95 `0.159519s`, warm median `0.010435s`, warm p95 `0.010747s`, with equal response fingerprints and no warnings;
- final read-only performance smoke: Overview `0.1622s`, warm cached Overview `0.0104s`, ML Governance `1.1731s`, alerts `0.0336s`, cases `0.0695s`, features `0.2846s`, with no warnings;
- replay dry-run: parsed the two-line safe sample and wrote zero rows;
- release gate: `ok: true` with no failed required checks.

The final repository-wide matrix is recorded in the task board after closure.

## Remaining Risks

- The original `9.341s` result included true cold operating-system/disk effects. v4.7 removes its dominant full-table query plan, but a controlled OS-page-cache flush was not performed because it would be platform-specific and disruptive.
- SQLite remains a one-worker local profile. This result is not PostgreSQL capacity evidence, a shared-host load test, or an SLA.
- The recent-alert query still sorts a small alert table without a dedicated created-time index. Current cost does not justify a migration.

## Manual Check

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.profile_dashboard_summary --runs 5 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
```

Then start the normal system, sign in through the MFU shell, open **Overview**, import a safe sample if needed, and refresh Overview. Confirm counts update, Operations Health remains current, and the page loads without a performance warning.
