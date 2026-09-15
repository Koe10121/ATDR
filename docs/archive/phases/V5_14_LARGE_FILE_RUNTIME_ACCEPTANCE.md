# v5.14 Large-File Multi-Source Runtime Acceptance

Date: 2026-07-29

## Decision

v5.14 passes the locally controllable large-file runtime acceptance boundary.
ATDR scanned the complete private PAN-OS evidence as aggregates and processed
a bounded 100,000-row slice through the real staging, queue, worker,
transactional ingestion, source-quality, rule-detection, alert, and computed
case services in disposable SQLite storage.

The configured database was not an acceptance target and its file marker
remained unchanged. No private path, raw row, IP address, row fingerprint,
database, model artifact, label, secret, or generated evidence file is
returned or tracked.

This is runtime and operational evidence, not labeled detection accuracy,
multi-device validation, a capacity SLA, or production certification.

## Evidence Roles

The private file contains one observed device identity. v5.14 does not
fabricate a second device. For source-scoped runtime testing, the bounded
chronological stream is divided into two explicitly named simulated logical
windows:

- `simulated-logical-source-1`
- `simulated-logical-source-2`

They prove source creation, counters, health, run history, detection scope,
and investigation traceability. They are not represented as independent
physical firewalls.

## Full-File Aggregate Preflight

| Measure | Result |
| --- | ---: |
| Nonblank rows inspected | 773,551 |
| TRAFFIC records | 771,932 |
| THREAT records | 1,619 |
| Parser errors | 0 |
| Structural warnings | 0 |
| Exact duplicate rows | 0 |
| Unknown/incomplete application rows | 54,909 |
| Unknown/incomplete application rate | 7.0983% |
| Observed device identities | 1 |
| Read-only overlap with configured DB | 120,000 rows / 15.5129% |
| Aggregate scan throughput | 11,272.78 rows/second |

The preflight returned only safe counts, schema classes, and chronological
coverage. It returned no path, raw content, private identifier, fingerprint,
or secret.

## Disposable Runtime Acceptance

The measured run used:

- 100,000 PAN-OS rows;
- two 50,000-row simulated logical windows;
- 1,000-row transactional chunks;
- one forced worker handoff after the first committed chunk;
- same-job checkpoint resume;
- an independent safe-boundary cancellation probe;
- an isolated SQLite lock-wait probe; and
- source-scoped deterministic rule detection.

### Ingestion

| Measure | Result |
| --- | ---: |
| Raw rows persisted | 100,000 |
| Normalized rows persisted | 100,000 |
| Parsed successfully | 100,000 |
| Parse failures | 0 |
| Chunk commits | 100 |
| Progress monotonic | yes |
| Bounded chunks | yes |
| Resume extra rows | 0 |
| Idempotent duplicate enqueue reused original job | yes |
| Completed staged inputs removed | yes |
| Ingestion throughput | 334.56 rows/second |
| Peak traced Python memory | 26.02 MiB |
| Disposable DB growth | 610,840,576 bytes |

Exact repeated records are counted but intentionally retained as raw
evidence. The source file had no exact repeats. "No duplicate rows after
resume" means checkpoint resume did not recommit already committed input; it
does not mean ATDR deletes legitimate repeated log events.

### Interruption, Cancellation, And Lock Handling

- the forced interruption released the worker after a 1,000-row commit;
- the verified staged input remained available;
- progress resumed from the stored line and byte checkpoint;
- the first 50,000-row window completed after resume;
- cooperative cancellation stopped after exactly one 1,000-row chunk;
- the cancelled job remained resume-eligible;
- cancellation acknowledgement took 0.0118 seconds after the safe boundary;
- a second SQLite writer waited for a temporary lock and completed after
  release in 0.2625 seconds; and
- no configured-database connection participated in the lock probe.

### Sources And Parser Quality

Both simulated logical sources:

- received exactly 50,000 rows;
- recorded `last_seen`;
- recorded one ingestion and one source-scoped detection run;
- parsed all rows successfully;
- reported `current_contract`;
- reported healthy parser/source status;
- recorded zero parser errors and structural warnings; and
- retained unresolved-application counts as context rather than source
  failure.

### Detection And Investigation

| Measure | Result |
| --- | ---: |
| Rule-evaluated rows | 100,000 |
| New alert records | 930 |
| Deduplicated alert updates | 1,347 |
| Suppressed low/rule-matched groups | 1,144 |
| Computed case groups | 762 |
| Alerts linked to source evidence | 930 |
| Logical windows represented in alert evidence | 2 |
| Rule-evaluation throughput | 2,807.64 rows/second |
| Response actions created | 0 |

Attack-type totals are combined from the two source-scoped runs and are
run-scoped occurrence/grouping evidence. They must not be interpreted as
ground-truth incidents or accuracy metrics.

The acceptance deliberately uses rules-only runtime detection. Existing
IsolationForest and supervised output authority remains advisory/shadow.
No ML model run, activation, promotion, label write, automatic response, or
real blocking occurred.

## Dashboard Query Evidence

| Read path | Time |
| --- | ---: |
| Overview cold summary | 0.1338s |
| Overview cached summary | 0.0093s |
| Alert list | 0.0483s |
| Case summary | 0.5331s |
| Source detail | 0.6680s |

No dashboard wording or layout change was needed. Existing source, operation,
alert, case, and parser-quality views correctly represent the accepted
runtime state.

## CLI

Aggregate-only full-file preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v514_large_file_runtime_acceptance `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --preflight-only `
  --pretty
```

Disposable 100,000-row acceptance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v514_large_file_runtime_acceptance `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --limit 100000 `
  --chunk-size 1000 `
  --use-temp-db `
  --simulate-interruption `
  --resume `
  --run-detection `
  --pretty
```

Without `--use-temp-db`, runtime processing fails closed. The private input
is supplied only through the CLI and must remain outside Git.

## Safety State

- configured database targeted: false;
- configured database marker unchanged: true;
- private path/raw/IP/fingerprint/secret returned: false;
- labels or model runs created: 0;
- model activated or promoted: false;
- rules remain alert-authoritative;
- supervised lifecycle remains `shadow_observation`;
- response actions created: 0;
- automatic response remains disabled;
- real firewall blocking remains disabled; and
- production readiness is not claimed.

## Verification

| Check | Result |
| --- | --- |
| Taskboard render and standard check | passed |
| Ruff | passed |
| Compileall | passed |
| Focused v5.14 tests | `5 passed` |
| Full backend tests | `746 passed, 1 skipped` |
| Alembic | no drift |
| React lint and build | passed |
| Playwright | `26 passed, 1 skipped` |
| Controlled scenarios | `24/24` passed |
| Layered validation | `288/288` passed; zero controlled FP/FN |
| SOC Assistant QA | `20/20` passed; zero mutations |
| Replay dry-run | passed; zero writes |
| Performance smoke | passed; no warnings |
| Official release gate | passed |

The backend suite emits existing scikit-learn sparse-feature/calibration
warnings and a Windows logical-core fallback warning. They did not fail the
suite and are not caused by the v5.14 runtime acceptance implementation.

## Remaining External Evidence

1. The accepted file represents one device and one short collection period.
2. Simulated logical windows do not replace two independently collected
   physical sources.
3. Detector output has no independent human/provider ground truth in this
   runtime acceptance.
4. Approved-host PostgreSQL/shared-staging duration and capacity remain
   external validation.
5. Long-duration live syslog forwarding, reconnect behavior, and device-side
   loss accounting still require approved hardware/environment access.
6. Independent labeled multi-device evidence remains required before
   supervised lifecycle advancement.

The exact source-controlled path boundary is listed in
`docs/V5_14_COMMIT_ALLOWLIST.md`. That list does not authorize staging,
commit, or push.
