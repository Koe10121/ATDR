# v5.15 Long-Duration Runtime Soak And Recovery Acceptance

Date: 2026-07-29

## Decision

v5.15 passes the locally controllable long-duration runtime-soak boundary.
ATDR processed the complete 773,551-row private PAN-OS stream through
progressive 250,000, 500,000, and full-file checkpoints in one disposable
SQLite database. It recovered from repeated worker handoff, cooperative
cancellation, explicit cancelled-job resume, simulated process loss,
fail-closed stale-lease recovery, explicit failed-job resume, and a bounded
SQLite lock wait.

The configured database marker remained unchanged. Disposable staging,
prepared segments, database, and SQLite journal resources were removed. No
private path, raw row, IP address, fingerprint, secret, database, or generated
evidence report is returned or tracked.

This proves local runtime behavior under controlled faults. It is not a
production capacity SLA, real multi-device validation, labeled detection
accuracy, or authorization to advance ML or response authority.

## Resource Preflight

The full-file aggregate preflight completed before any disposable writes.

| Measure | Result |
| --- | ---: |
| Available rows | 773,551 |
| Selected rows | 773,551 |
| File bytes observed | 597,820,068 |
| Estimated temporary storage | 7,000,053,926 bytes |
| Required free space at 3x headroom | 21,000,161,778 bytes |
| Free space before processing | 116,976,885,760 bytes |
| Physical memory | 33,568,067,584 bytes |
| Available memory before processing | 17,740,353,536 bytes |
| Parser errors | 0 |
| Structural warnings | 0 |
| Exact duplicate input rows | 0 |

The resource check returned aggregate values only. Each progressive stage
rechecked the remaining disk envelope before proceeding. All three checks
passed.

## Progressive Runtime

One observed device stream was divided into three explicitly simulated
chronological logical windows. They are not independent firewalls.

| Stage | Stage rows | Cumulative rows | Import/parse rows/s | DB growth / 100k |
| --- | ---: | ---: | ---: | ---: |
| A | 250,000 | 250,000 | 456.06 | 611,763,814 bytes |
| B | 250,000 | 500,000 | 427.31 | 613,808,538 bytes |
| C | 273,551 | 773,551 | 426.03 | 613,177,418 bytes |

Final persistence:

- raw rows: 773,551;
- normalized rows: 773,551;
- parsed successfully: 773,551;
- parse failures: 0;
- source received/parsed counters: 773,551/773,551;
- ingestion-run received/raw counters: 773,551/773,551; and
- resume-created extra rows: 0.

Repeated raw events remain evidence by policy. The measured input contained
no exact duplicate rows. Resume containment is proven by exact cumulative
counts and monotonic line/byte checkpoints, not by deleting legitimate
repeated events.

## Fault And Recovery Evidence

The combined plan injected:

- three consecutive Stage A worker handoffs after committed chunks;
- one Stage A cancellation at a committed boundary;
- one explicit cancelled-job resume;
- one simulated Stage A process loss after a committed chunk;
- fail-closed stale-lease recovery for the evidence-mutating job;
- one explicit failed-job resume;
- one Stage B handoff;
- one Stage C handoff; and
- one bounded SQLite writer lock wait.

All five handoffs, the cancellation/resume, and stale-lease recovery
completed. Staged evidence remained available while resumable and was removed
after success.

| Measure | Result |
| --- | ---: |
| Chunk samples | 774 |
| Chunk p50 | 2.275210s |
| Chunk p95 | 2.431301s |
| Chunk p99 | 3.030145s |
| Chunk maximum | 3.267247s |
| Resume creation p50 | 0.538463s |
| Cancellation acknowledgement | 0.017849s |
| SQLite lock wait/release | 0.2634s |

## Database Integrity

- `PRAGMA integrity_check`: `ok`;
- foreign-key violations: 0;
- orphan normalized rows: 0;
- raw rows without normalized rows: 0;
- raw rows without source links: 0;
- orphan alert-evidence rows: 0;
- final disposable database growth: 4,741,283,840 bytes; and
- measured growth per 100,000 rows: 612,924,531 bytes.

The growth is close to the v5.14 100,000-row baseline of 610,840,576 bytes.
The configured database was never a runtime target and its marker remained
unchanged.

## Source, Detection, And Investigation

All three simulated windows retained exact source counters, `last_seen`,
current parser-contract status, zero parser errors, and complete ingestion
and detection history. Earlier chronological windows became `idle` by the
time the final window completed; this is truthful recency status, not parser
failure.

| Measure | Result |
| --- | ---: |
| Deterministic rule evaluations | 773,551 |
| New alert records | 8,036 |
| Deduplicated alert updates | 5,802 |
| Suppressed low/rule-matched groups | 7,875 |
| Alert evidence links | 408,776 |
| Computed case groups | 6,012 |
| Aggregate detection throughput | 781.38 rows/s |
| Response actions | 0 |

Every persisted alert was traceable to normalized/raw/source evidence, and
computed cases reconciled with alert groups. A source-scoped reporting defect
found during the soak was fixed: stage traceability now compares against
source-scoped evidence rather than the database-wide alert total. Detection
rules, thresholds, and alert behavior were not changed.

Detector totals are operational outputs and must not be presented as
human-labeled accuracy.

## Dashboard And Memory

| Read path | Stage A | Stage B | Stage C |
| --- | ---: | ---: | ---: |
| Overview cold | 0.5857s | 2.9681s | 5.3571s |
| Overview cached | 0.0255s | 0.0542s | 0.0748s |
| Alert list | 0.1570s | 0.1471s | 0.1648s |
| Case summary | 0.1887s | 0.2781s | 0.2604s |
| Source detail | 2.3480s | 3.3943s | 4.7248s |

Peak traced Python memory was 12,029.34 MiB during the complete
ingestion/detection/dashboard run. This is the principal local-capacity
warning. The cached Overview and alert/case reads remained bounded, but a
production deployment needs PostgreSQL/shared-host load testing, process
memory limits, and streaming/batched detection optimization.

## Cleanup And Safety

- disposable cleanup duration: 0.3554s;
- prepared segments removed: true;
- staged inputs removed: true;
- disposable database removed: true;
- SQLite journals removed: true;
- configured database unchanged: true;
- labels/model runs/response actions created: 0/0/0;
- rules remain alert-authoritative;
- supervised lifecycle remains `shadow_observation`;
- model activation/promotion: false/false;
- automatic response: disabled;
- real firewall blocking: disabled; and
- privacy findings: 0.

## Verification

| Check | Result |
| --- | --- |
| Taskboard render and standard check | passed |
| Ruff | passed |
| Compileall | passed after removing one ignored prior pytest workspace |
| Focused v5.14/v5.15 tests | `12 passed` |
| Full backend tests | `753 passed, 1 skipped` |
| Alembic | no drift |
| React lint and build | passed |
| Playwright | `26 passed, 1 skipped` |
| Controlled scenarios | `24/24` passed |
| Layered validation | `288/288` passed; zero controlled FP/FN |
| SOC Assistant QA | `20/20` passed; zero mutations |
| Replay dry-run | passed; zero writes |
| Performance smoke | passed; no warnings |
| Official release gate | passed |

The inherited scikit-learn sparse-feature/calibration warnings and Windows
logical-core fallback remain non-failing diagnostics. The ignored prior pytest
workspace contained intentionally malformed fixture copies; it was removed
and exact compileall then passed.

## CLI

Safe aggregate/resource preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v515_runtime_soak_acceptance `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --target-rows 773551 `
  --preflight-only `
  --pretty
```

Full disposable combined-fault acceptance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v515_runtime_soak_acceptance `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --target-rows 773551 `
  --chunk-size 1000 `
  --use-temp-db `
  --fault-plan combined `
  --run-detection `
  --pretty
```

Runtime processing fails closed without `--use-temp-db`. The private file
must remain outside Git.

## Remaining External Blockers

1. The evidence represents one device and one short collection period.
2. No independent human/provider ground truth exists for these detector
   outputs.
3. Approved-host PostgreSQL/shared-staging duration and capacity remain
   unmeasured.
4. Live syslog reconnect/loss accounting still needs approved hardware.
5. The 12 GiB local peak requires memory and detection-query optimization
   before larger or concurrent deployment claims.
6. Independent labeled multi-device evidence remains required before any
   supervised lifecycle advancement.

The exact source-controlled review boundary is in
`docs/V5_15_COMMIT_ALLOWLIST.md`. It does not authorize staging, commit, or
push.
