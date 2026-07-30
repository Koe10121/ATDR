# v5.16 Full-Scale Memory And Query Stabilization

Date: 2026-07-30

## Decision

v5.16 passes the locally controllable full-scale memory and query boundary.
ATDR processed the complete 773,551-row private PAN-OS stream in disposable
SQLite storage while keeping whole-process peak resident memory at
1,947.68 MiB. Cold Overview completed in 0.9467 seconds, cached Overview in
0.0815 seconds, and source detail in 1.1927 seconds.

The configured database remained unchanged and disposable evidence was
removed. Rules remain alert-authoritative, supervised ML remains in
`shadow_observation`, and no label, model, response, automation, or firewall
authority changed.

This is controlled local runtime evidence. It is not a production capacity
SLA, PostgreSQL concurrency result, independent-device test, or labeled
detection-accuracy claim.

## Root-Cause Audit

The v5.15 full run peaked at 12,029.34 MiB of traced Python memory. Profiling
identified five material causes:

1. rule detection loaded complete `NormalizedLog` and `RawLog` ORM graphs;
2. detection retained context, candidate, grouping, and evidence collections
   for the full source scope;
3. every evidence link was retained as an ORM relationship object;
4. case counting loaded complete alert/evidence graphs; and
5. source detail repeated normalized/application scans and inspected parser
   JSON even when aggregate parser quality proved there were no errors.

A proposed one-pass dashboard aggregate was measured and rejected. On the
current indexed database, the existing quality query completed in about
0.0226 seconds while the scan-based alternative took about 0.2804 seconds.
The indexed dashboard design and existing schema indexes were therefore
preserved; no migration was justified.

## Implementation

- Rule detection now has an opt-in bounded scalar-projection path for the
  disposable acceptance runner. Normal API behavior remains unchanged.
- Alert evidence is accumulated in bounded buffers and inserted globally in
  1,000-row batches after alert identities are flushed.
- Dedup lookup avoids loading complete evidence relationships when bounded
  mode is enabled.
- Case reconciliation uses exact scalar case-key counting instead of loading
  every case/evidence graph.
- Detection releases stage-local collections and session identity state after
  committed work.
- Source quality combines normalized and unresolved-application counts,
  removes a redundant alert join, and skips parser JSON inspection only when
  aggregate quality completely proves zero parser errors.
- The acceptance runner records process RSS, phase-scoped tracing, ORM
  identity-map samples, query counts, privacy-safe SQLite plan steps, rates,
  growth, integrity, and safety.

No rule, threshold, parser mapping, dedup key, alert severity, case key,
response rule, API contract, or model lifecycle was changed.

## Progressive Results

Each run used a fresh process and disposable database.

| Rows | Peak process RSS | Detection-scoped traced peak | Ingestion rows/s | Detection rows/s | Cold Overview | Cached Overview | Source detail |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 677.13 MiB | 216.57 MiB | 825.08 | 2,917.50 | 0.1772s | 0.0164s | 0.6226s |
| 250,000 | 1,498.56 MiB | 526.78 MiB | 751.38 | 2,840.52 | 0.4328s | 0.0405s | 1.5005s |
| 773,551 | 1,947.68 MiB | 632.00 MiB | 753.85 | 2,937.96 | 0.9467s | 0.0815s | 1.1927s |

The v5.16 memory gate uses whole-process peak RSS when the operating system
provides it. Phase-scoped `tracemalloc` is retained for diagnosis and is not
presented as directly comparable to the v5.15 full-run tracing scope.

## Full-Scale Comparison

| Measure | v5.15 baseline | v5.16 result | Decision |
| --- | ---: | ---: | --- |
| Memory | 12,029.34 MiB full-run traced peak | 1,947.68 MiB whole-process peak RSS | passes `< 8 GiB` |
| Ingestion | about 426-456 rows/s by stage | 753.85 rows/s weighted | no regression |
| Detection | 781.38 rows/s | 2,937.96 rows/s | improved |
| Cold Overview | 5.3571s | 0.9467s | passes `< 3s` |
| Cached Overview | 0.0748s | 0.0815s | passes `< 0.1s` |
| Source detail | 4.7248s | 1.1927s | passes `< 3s` |
| Database growth | 4,741,283,840 bytes | 4,741,275,648 bytes | effectively unchanged |
| Overview/source query count | not recorded | 34 / 6 | bounded |

The full process returned to 260.84 MiB RSS after cleanup. Total runtime was
1,499.0167 seconds.

## Persistence And Detection Reconciliation

| Measure | Result |
| --- | ---: |
| Raw rows | 773,551 |
| Normalized rows | 773,551 |
| Parse failures | 0 |
| Rule evaluations | 773,551 |
| Alert records created | 8,033 |
| Deduplicated alert updates | 5,805 |
| Suppressed groups | 7,875 |
| Evidence links | 408,776 |
| Computed cases | 6,011 |
| Response actions | 0 |

The v5.15 fault-injected run reported 8,036 created alerts, 5,802 dedup
updates, and 6,012 time-bucketed cases. v5.16's no-fault performance run
reported three fewer creates and three more dedup updates. The total alert
group operations remained exactly 13,838, and evidence links, suppressed
groups, rule evaluations, source traceability, integrity, and unsafe-write
counts matched. One case boundary also moved because case keys include
wall-clock time buckets.

This timing-sensitive split is recorded rather than hidden. No dedup or case
meaning changed, but byte-for-byte equality of fault-injected and no-fault
wall-clock grouping is not claimed.

## Query And Integrity Gates

- cold Overview queries: 34;
- cached Overview queries: 1;
- source-detail queries: 6;
- query-plan output contains plan steps only, with no SQL parameters or
  private values;
- peak sampled ORM identity-map size: 8,035;
- peak sampled pending-new count: 1;
- SQLite integrity check: `ok`;
- foreign-key violations: 0;
- configured database modified: false;
- disposable cleanup complete: true; and
- privacy findings: 0.

## Safety State

- deterministic rules remain alert-authoritative;
- supervised lifecycle remains `shadow_observation`;
- model activation/promotion: false/false;
- labels/model runs/response actions created: 0/0/0;
- automatic response: disabled;
- real firewall blocking: disabled;
- private path/raw evidence/IP/fingerprint/secret returned: false; and
- no generated runtime report is source-controlled.

## Verification

| Check | Result |
| --- | --- |
| Taskboard render and standard check | passed |
| Ruff | passed |
| Compileall | passed |
| Focused v5.14-v5.16 tests | `22 passed` |
| Full backend tests | `759 passed, 1 skipped` |
| Alembic | no drift |
| React lint and build | passed |
| Playwright | `26 passed, 1 skipped` |
| Controlled source scenarios | `24/24` passed |
| Layered validation | `288/288` passed; zero controlled FP/FN |
| SOC Assistant QA | `20/20` passed; zero mutations |
| Replay dry-run | passed; zero writes |
| Performance smoke | passed; no warnings |
| Official release gate | passed; `759 passed, 1 skipped` |

The inherited scikit-learn sparse-feature/calibration warnings and Windows
physical-core lookup fallback remain non-failing diagnostics. No v5.16
verification error remains.

## CLI

Preflight/profile-only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v516_memory_query_stabilization `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --target-rows 100000 `
  --chunk-size 1000 `
  --use-temp-db `
  --profile-only `
  --pretty
```

Full disposable acceptance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v516_memory_query_stabilization `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --target-rows 773551 `
  --chunk-size 1000 `
  --use-temp-db `
  --run-detection `
  --pretty
```

Runtime processing fails closed without `--use-temp-db`.

## Remaining External Blockers

1. The evidence is one device and one collection period.
2. Detector outputs do not have independent ground-truth labels.
3. Approved-host PostgreSQL, concurrent workers, and shared staging remain
   unmeasured.
4. Live syslog reconnect/loss accounting still requires approved hardware.
5. Independent labeled multi-device evidence is required before supervised
   lifecycle advancement.
6. A shared-host memory limit and concurrency SLA still require deployment
   owner approval and measurements.

The exact source-controlled review boundary is in
`docs/V5_16_COMMIT_ALLOWLIST.md`. It does not authorize staging, commit, or
push.
