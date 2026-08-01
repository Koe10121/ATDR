# v5.18 Approved-Host PostgreSQL Scale Qualification And SLO Lock

Date: 2026-07-30

## Decision

The v5.18 local approved-host qualification passed on disposable PostgreSQL
16.14 databases. The staged runner qualified 100,000 rows before it was
allowed to continue to 250,000 rows. Both the 2-worker and 4-worker profiles
passed all 13 fixed SLO checks at both scales.

This closes the PostgreSQL capacity, concurrency, recovery, and isolated
backup/restore gate for the measured single-host profile. It does not prove a
multi-host deployment, production SLA, real-device ingestion, independent
Detection/ML accuracy, MFU provider readiness, or production security.

Normal local SQLite startup and behavior remain unchanged.

## Approved-Host Preflight

The execution was allowed only after all of these checks passed:

| Check | Result |
| --- | --- |
| Host approval | explicitly enabled for the disposable run |
| PostgreSQL server | 16.14; minimum major version 16 |
| Required extension | `plpgsql` present |
| Target and restore databases | distinct, empty, disposable, and not the configured ATDR database |
| PostgreSQL tools | `psql`, `pg_dump`, and `pg_restore` 16.14 |
| Available memory | 10,562,043,904 bytes |
| Free disk | 114,805,370,880 bytes |
| Connection headroom | 91 available; 12 required |
| Configured pool capacity | 15; 8 required for the largest worker profile |
| URLs or credentials returned | no |

The PostgreSQL runtime and data directories used for this qualification were
temporary ignored host assets. They are not part of the repository.

## Fixed SLO Contract

The 100,000-row profiles required:

- at least 250 rows/second;
- no more than 600 seconds ingestion runtime;
- no more than 10 seconds chunk commit p99;
- no more than 4,096 MiB full-stage peak RSS;
- no more than 1 GiB database growth;
- cold Overview at or below 3 seconds;
- cached Overview at or below 0.1 seconds;
- alert list at or below 5 seconds;
- case summary at or below 3 seconds;
- source detail at or below 3 seconds;
- no connection-pool timeout;
- no ungranted lock waiter; and
- the full functional acceptance contract must pass.

The 250,000-row profiles used the same throughput, chunk, query, pool, lock,
and functional gates, with a 1,500-second runtime ceiling, 8,192 MiB memory
ceiling, and 2.5 GiB database-growth ceiling.

## Qualification Results

| Rows | Workers | SLO | Rows/s | Ingestion | Chunk p99 | Peak RSS | DB growth |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 2 | 13/13 | 1,061.94 | 94.1676s | 2.7800s | 549.48 MiB | 309.94 MiB |
| 100,000 | 4 | 13/13 | 884.46 | 113.0637s | 5.8507s | 566.84 MiB | 309.94 MiB |
| 250,000 | 2 | 13/13 | 694.97 | 359.7255s | 4.6566s | 1,221.77 MiB | 752.11 MiB |
| 250,000 | 4 | 13/13 | 699.45 | 357.4247s | 8.0259s | 1,256.19 MiB | 751.68 MiB |

Four workers did not improve the 100,000-row result and only narrowly
improved the 250,000-row result. The database workload, not worker count
alone, is therefore the likely scaling limit on this host. Two workers remain
the conservative default until a deployment-specific load test proves a
benefit from four.

## Exact Data And Detection Results

Every profile produced exact raw, normalized, source, and parser counters:

- raw logs equaled the target row count;
- normalized logs equaled the target row count;
- source logs received equaled the target row count;
- parse successes equaled the target row count;
- parse failures were zero;
- two distinct source-scoped detection runs completed;
- seven alerts and seven cases were produced;
- alert-evidence rows equaled the target row count;
- duplicate alert-evidence groups were zero;
- occurrence and related-log counts reconciled; and
- response actions created were zero.

Detection contention time was:

| Rows | Workers | Detection time |
| ---: | ---: | ---: |
| 100,000 | 2 | 18.3601s |
| 100,000 | 4 | 18.3471s |
| 250,000 | 2 | 51.8168s |
| 250,000 | 4 | 44.7813s |

Rules remained alert-authoritative. No parser mapping, rule threshold,
severity meaning, dedup key, case key, supervised lifecycle, or response
policy was changed.

## Query And Pool Results

| Rows | Workers | Cold Overview | Cached Overview | Alerts | Cases | Source detail | Pool peak |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 2 | 0.1960s | 0.0281s | 0.1558s | 0.1751s | 0.3478s | 4 |
| 100,000 | 4 | 0.2502s | 0.0171s | 0.2739s | 0.1782s | 0.2796s | 8 |
| 250,000 | 2 | 0.5276s | 0.0547s | 0.4285s | 0.3121s | 1.1486s | 4 |
| 250,000 | 4 | 0.4083s | 0.0592s | 0.3470s | 0.2956s | 0.8974s | 8 |

Every profile recorded zero pool timeouts and zero ungranted lock waiters.
Representative plans returned node types only and exposed neither SQL text nor
parameters.

The alert and case paths now use exact aggregate evidence counts with bounded
ID samples and source metadata. The API exposes an explicit truncation flag
when only the first evidence IDs are returned. This removed the prior
100,000-row ORM graph hydration bottleneck without changing alert counts,
evidence counts, source traceability, or case results.

## Recovery, Backup, And Restore

Every profile passed:

- distinct worker claims;
- private lease-token fencing;
- fail-closed stale recovery with checkpoint preservation;
- committed-boundary cancellation and exact resume;
- concurrent idempotency containment;
- source counter reconciliation;
- checksum, row-count, and Alembic-revision backup manifest creation;
- restore into a second empty disposable database;
- restored row-count and migration-revision equality;
- configured-database preservation; and
- target, restore, staging, and backup cleanup.

## Safety And Privacy

For all four profiles, before and after counts were:

```text
labels: 0
model runs: 0
response actions: 0
```

The runner returned no database URL, credential, private path, raw log, IP,
fingerprint, SQL parameter, or secret. It did not activate or promote a model,
enable automatic response, or enable real firewall blocking.

## Running The Gate

Use only two new empty disposable PostgreSQL databases. Set values in the
current private process without printing them:

```powershell
$env:ATDR_V518_POSTGRES_DATABASE_URL='<DISPOSABLE_POSTGRES_DATABASE>'
$env:ATDR_V518_RESTORE_DATABASE_URL='<SECOND_EMPTY_DISPOSABLE_POSTGRES_DATABASE>'
$env:ATDR_V518_APPROVED_HOST='true'
```

Preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v518_postgres_scale_qualification --pretty
```

Execute the staged 100k then conditional 250k qualification:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v518_postgres_scale_qualification `
  --execute `
  --confirm APPROVED_DISPOSABLE_V518_SCALE_DATABASES `
  --pretty
```

Use `--stop-after-100k` for the smaller gate. The 250k stage is not attempted
unless every 100k profile passes.

## Verification

The final repository verification completed successfully:

- taskboard render and standards check passed;
- Ruff and `compileall` passed;
- focused PostgreSQL/detection/API tests passed: `67 passed`;
- the clean full backend suite passed: `782 passed, 1 skipped`;
- seven Windows path-sensitive tests were also rerun under a short temporary
  root and passed after the first long-path-only failure;
- Alembic upgrade and no-drift check passed on a disposable SQLite database;
- React lint and production build passed;
- Playwright passed: `26 passed, 1 skipped`;
- controlled detection quality passed: `23/23`;
- layered detection validation passed: `288/288`;
- assistant QA passed: `20/20`;
- replay dry-run parsed the two-row safe sample and wrote zero rows;
- performance smoke passed without warnings; cold/cached Overview measured
  `0.7727s`/`0.0115s`, alert list `0.0687s`, case summary `0.0322s`,
  and ML Governance `1.3601s`; and
- the release gate returned `ok: true` with every required check passing.

The Windows long-path observation was environmental rather than a product
failure: the same affected tests and the complete suite passed under short
temporary roots. No safeguard was weakened.

## Roadmap Accounting

Four major gates were open at the start of v5.18. This phase closes the
measured single-host PostgreSQL gate. Three major gates remain:

1. real multi-device and live-source acceptance;
2. independent labeled Detection/ML evidence; and
3. provider, deployment, and security closure.

The first two require approved real devices and independently governed labels.
The third requires approved MFU/provider inputs and a real preproduction
deployment environment. Repository hardening can continue locally, but none
of those external results should be invented.

ATDR remains a controlled productization system, not certified production
software. The supervised lifecycle remains `shadow_observation`, deterministic
rules remain alert-authoritative, response automation remains disabled, and
real firewall blocking remains disabled.

The exact review boundary is recorded in
`docs/V5_18_COMMIT_ALLOWLIST.md`. No commit or push is authorized by this
qualification.
