# v5.35 Large-SQLite Overview Stabilization

## Status

v5.35 repairs the cold Overview regression introduced when source-scoped alert
volume was added to Detection Operations. The API payload, React Overview,
cache TTL and invalidation contract, detection behavior, ML lifecycle, and
response controls are unchanged.

SQLite remains the supported local profile. The covering indexes are also
valid PostgreSQL indexes, but the measurements below are local SQLite evidence,
not a shared-host or production SLA.

## Measured Baseline

The configured database contains 145,232 raw logs, 145,232 normalized logs,
and 3,231 alerts. The inherited v5.34 run recorded a true disk-cold Overview
and ingestion summary at `5.8552s`, while its cached Overview was `0.0197s`.

A fresh v5.35 process reproduced the uncached issue at `4.8389s`. Once operating
system pages were warm, three application-cache misses had median `0.285277s`,
p95 `0.319578s`, and 33 queries. Cached hits had median `0.011900s`, p95
`0.012245s`, and one query. Three separate pre-change performance-smoke
processes measured Overview at `0.3329s`, `0.3308s`, and `0.3224s` after the
disk pages had become warm.

## Root Cause And SQL Evidence

The v5.32 source-alert-volume aggregate follows:

`alert_evidence -> normalized_logs -> raw_logs -> log_sources`

There are 21,894 evidence rows. Before v5.35, SQLite scanned that evidence and
performed primary-key table reads for every normalized and raw lookup:

```text
SCAN alert_evidence
SEARCH normalized_logs USING INTEGER PRIMARY KEY
SEARCH raw_logs USING INTEGER PRIMARY KEY
SEARCH log_sources USING INTEGER PRIMARY KEY
```

Those random reads are inexpensive after the 567 MiB database is in the OS
page cache, but dominate a true disk-cold request. The existing quality and
distribution queries already use covering indexes and were not the regression.

On a disposable consistent database copy, adding covering lookup indexes
changed the source-volume median from `0.139567s` to `0.026895s`. The exact
result rows matched before and after.

## Implementation

Migration `f8a9b0c1d2e3` adds:

- `ix_normalized_logs_id_raw_log_id_cover` on `(id, raw_log_id)`; and
- `ix_raw_logs_id_source_id_cover` on `(id, source_id)`.

Refreshing planner statistics exposed a second measurable query-plan weakness:
the ML Governance anomaly distributions grouped by source IP, destination IP,
and protocol took about `2.03s` together. A disposable-copy comparison reduced
the complete Governance report from `2.238696s` to `0.381723-0.395239s` with
an identical response. Additive migration `b9c0d1e2f3a4` therefore adds:

- `ix_normalized_anomaly_src_ip` on `(is_anomaly, src_ip)`;
- `ix_normalized_anomaly_dst_ip` on `(is_anomaly, dst_ip)`; and
- `ix_normalized_anomaly_protocol` on `(is_anomaly, protocol)`.

Both migrations are additive. They do not update or delete application rows.
SQLite planner statistics are refreshed so the new indexes are selected
immediately. PostgreSQL offline SQL generation creates the same portable
indexes and contains no data rewrite.

The resulting configured-database plan is:

```text
SCAN alert_evidence
SEARCH normalized_logs USING COVERING INDEX ix_normalized_logs_id_raw_log_id_cover
SEARCH raw_logs USING COVERING INDEX ix_raw_logs_id_source_id_cover
SEARCH log_sources USING INTEGER PRIMARY KEY
```

The profiler now times source-alert volume explicitly and reports its query
plan. Performance smoke now enforces the v5.35 budgets rather than the older,
looser cached/list thresholds.

## Correctness And Cache Safety

The stable 29-field Overview payload matched before and after migration. Exact
raw-log, normalized-log, alert, severity, status, source-alert-volume,
ingestion-quality, and deduplication aggregates remained equal. The configured
database retained all 2,672 labels, 45 model-run records, 31 detection-run
records, and zero response actions.

Regression coverage proves:

- distinct alert counting remains exact when one alert has repeated evidence;
- enabled and disabled sources retain historical source-linked counts;
- the complete Overview payload is equal with and without the two source
  indexes;
- ML Governance responses are equal before and after its three distribution
  indexes;
- Overview remains within the fixed 35-query ceiling;
- a cached hit remains one query;
- imports, alert updates, and completed/failed runs still invalidate cache;
- empty and synthetic larger datasets remain supported;
- both migrations preserve existing rows and are non-destructive;
- shared statements and migration SQL remain PostgreSQL compatible; and
- summary reads create no label, model, detection, or response action.

## Performance Result

The post-migration five-run profiler measured:

| Metric | Result | Target | Status |
| --- | ---: | ---: | --- |
| Full uncached Overview | `0.1828s` | `<=1.0s` | pass |
| Application-cache miss median | `0.148659s` | `<=1.0s` | pass |
| Application-cache miss p95 | `0.191350s` | `<=1.0s` | pass |
| Cached hit median | `0.010624s` | `<=0.05s` | pass |
| Cached hit p95 | `0.011001s` | `<=0.05s` | pass |
| Source-alert-volume step | `0.0174s` | diagnostic | improved |
| ML Governance, three smoke runs | `0.2619-0.2658s` | `<=2.0s` | pass |
| Alert list, three smoke runs | `0.0333-0.0386s` | `<=0.25s` | pass |
| Case summary, three smoke runs | `0.0601-0.0620s` | `<=0.25s` | pass |
| Cold query count | `33` | `<=35` | pass |
| Cached query count | `1` | `<=1` | pass |

All five response fingerprints matched each other and every warm response
matched its cold response. Three final independent performance-smoke processes
reported no warnings. The final full verification result is recorded in the
task board and T1-T20 record.

## Safety And Scope

- No database was reset, deleted, reimported, or rewritten.
- No log, alert, case, label, run, user, audit, or response row was removed.
- No rule, parser, threshold, deduplication, IsolationForest, supervised model,
  model lifecycle, IAM, Assistant, or frontend contract changed.
- Rules remain alert-authoritative; supervised ML remains shadow observation.
- Automatic response and real firewall blocking remain disabled.

## Remaining Limits

A platform-independent flush of the Windows operating-system file cache was
not attempted because it is disruptive and not a reliable application test.
The inherited true disk-cold measurement is therefore retained as the baseline,
while query-plan removal and repeatable fresh-process/application-cache evidence
prove the fix. SQLite remains a local single-host profile; PostgreSQL v5.18
evidence remains the shared-scale reference.

The full test suite still emits existing scikit-learn missing-feature and
Windows physical-core discovery warnings. They are model/test diagnostics, not
v5.35 performance failures; no model behavior was changed to suppress them.

The locally controllable ATDR core is substantially complete after v5.35. Four
major external/evidence gates remain: qualified blind human detection review,
a second physical source/device, human Assistant/privacy and Gemini operations
acceptance, and MFU/shared-preproduction deployment acceptance.

## Commands

Apply the additive migration:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

Measure Overview without writing data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.profile_dashboard_summary --runs 5 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
```
