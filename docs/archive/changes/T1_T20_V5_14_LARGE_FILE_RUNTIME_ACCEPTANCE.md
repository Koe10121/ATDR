# T1-T20: v5.14 Large-File Multi-Source Runtime Acceptance

## T1 Change Title

v5.14 Large-File Multi-Source Runtime Acceptance.

## T2 Requirement

Prove that current ATDR runtime services can safely ingest, parse, normalize,
checkpoint, resume, cancel, source-scope, detect, and investigate a large
private PAN-OS dataset without modifying the configured database or exposing
private evidence.

## T3 Source Evidence

- `atdr/app/services/resumable_ingestion_service.py`
- `atdr/app/services/staging_service.py`
- `atdr/app/services/job_service.py`
- `atdr/app/services/operation_worker.py`
- `atdr/app/services/source_service.py`
- `atdr/app/services/runtime_parser_quality_service.py`
- `atdr/app/services/detection_service.py`
- `atdr/app/services/case_service.py`
- `atdr/app/services/private_log_preflight_service.py`
- v5.13/v5.13.1 state and parser-contract records
- private file supplied through a CLI argument only

## T4 Current Behavior

Before v5.14, resumability and 100,000-row ingestion were validated mainly
with synthetic generic syslog, while real PAN-OS work focused on aggregate
preflight and ML/parser diagnostics. No single acceptance runner composed
large private PAN-OS ingestion, two transparent logical source windows,
interruption/resume, cancellation, source quality, rule detection, cases,
dashboard timings, privacy, and configured-database preservation.

## T5 Impacted Areas/Agents

- Backend/runtime: isolated acceptance orchestration and CLI.
- Data/source: disposable persistence, source health, run history.
- Detection/investigation: rule throughput, dedup, evidence, case grouping.
- Security/privacy: aggregate-only output and temporary cleanup.
- QA: focused behavioral and redaction tests.
- Product/docs: state lock, PRD, traceability, runbook, taskboard.

## T6 Scope

Included:

- complete aggregate-only private-file preflight;
- bounded disposable PAN-OS ingestion;
- two simulated logical chronological windows from one physical stream;
- forced checkpoint interruption and resume;
- cancellation, idempotent enqueue, and SQLite lock handling;
- source-quality and run-history validation;
- source-scoped deterministic rule detection;
- alert/log/source and computed case traceability;
- performance and dashboard read timings; and
- privacy/safety assertions.

Excluded:

- configured-database import or reset;
- claims of two physical devices;
- private raw/path/IP/fingerprint export;
- human-label fabrication;
- ML training, activation, promotion, or authority change;
- automatic response or real blocking;
- PostgreSQL/approved-host capacity certification; and
- Git staging, commit, or push.

## T7 Functional Requirements

1. Refuse runtime processing without explicit disposable storage.
2. Scan the full private file while returning aggregates only.
3. Preserve one raw and normalized row per accepted nonblank input.
4. Persist progress at bounded transactional chunks.
5. Resume from a committed checkpoint without recommitting prior rows.
6. Stop cancellation only at a committed boundary.
7. Reuse an idempotent duplicate enqueue instead of creating another job.
8. Track source counts, health, parser quality, and run history.
9. Keep rule detection source-scoped and evidence-traceable.
10. Create no label, model run, response action, activation, or promotion.

## T8 Acceptance Criteria

- 773,551-row aggregate preflight completes with no private disclosure.
- 100,000 disposable rows import and normalize exactly.
- Parser errors and resume extra rows are zero.
- Progress is monotonic and every chunk is bounded.
- Cancellation and SQLite lock probes pass.
- Both logical source windows have exact counters and run history.
- Every created alert has linked log/source evidence.
- Cases are computed without persisting autonomous incident/action state.
- Configured database marker remains unchanged.
- Focused, full, frontend, scenario, assistant, performance, release, diff,
  and hygiene verification passes.

## T9 API Contract

No API route or payload changes. v5.14 is a CLI/service acceptance harness over
existing authenticated runtime contracts.

## T10 Data Model / Migration

No schema or migration change. All runtime writes occur in a temporary SQLite
database created from current SQLAlchemy metadata and removed after the run.

## T11 Backend Plan / Changes

- Add a privacy-safe acceptance service.
- Add the required CLI and fail-closed target validation.
- Compose existing staging, queue, worker, ingestion, source, detection,
  alerts, cases, and dashboard services.
- Return only bounded aggregate summaries.
- Add focused tests for resume, duplicate semantics, traceability, privacy,
  cancellation, lock handling, and zero unsafe side effects.

## T12 Frontend Plan / Changes

No frontend behavior change. Existing dashboard read paths are timed against
the disposable 100,000-row database. No clarity or overflow defect requiring
a UI patch was found.

## T13 Security / Response / AI Safety

- The private path exists only as a CLI input.
- Temporary raw evidence is deleted with the disposable workspace.
- Output is recursively checked for path, IP, raw, fingerprint, and secret
  leakage.
- Logical windows are explicitly simulated and never called devices.
- Rules remain authoritative.
- ML authority/lifecycle remains unchanged and no ML run is created.
- Response automation and real firewall blocking remain disabled.

## T14 Test Plan

- Runtime processing requires `--use-temp-db`.
- Forced handoff resumes exactly.
- Idempotent duplicate enqueue reuses the original job.
- Repeated events are counted/preserved without resume duplication.
- Source counters, history, and evidence links are consistent.
- Cancellation and lock wait complete safely.
- Private path/raw/IP/fingerprint/secret output is absent.
- No response, label, or model run is created.
- Aggregate-only preflight remains read-only.

## T15 Implementation Summary

v5.14 adds
`run_v514_large_file_runtime_acceptance`, which partitions one private device
stream into two transparent simulated logical windows in disposable storage
and exercises normal runtime services end to end. It returns no generated
report file and removes temporary database/staging evidence on exit.

## T16 Tests Run / Evidence

Measured acceptance:

- full private preflight: 773,551/773,551 rows, zero parser errors, zero
  structural warnings, zero exact duplicates;
- disposable runtime: 100,000 raw/normalized, zero parse failures;
- 100 bounded commits with monotonic progress;
- forced 1,000-row interruption, exact resume, and zero extra rows;
- cancellation at 1,000-row boundary, resume eligible;
- SQLite lock waiter completed after release;
- two 50,000-row source windows, both healthy/current-contract;
- 100,000 rule evaluations, 930 new alerts, 1,347 dedup updates, 762 computed
  cases, and full alert/source evidence linkage;
- zero response actions, labels, and model runs; and
- focused v5.14 suite: 5 passed.

The complete release matrix is recorded in the taskboard after closure.

## T17 PRD / Docs Updated

- v5.14 status
- this T1-T20 record
- current system state lock
- PRD
- requirement traceability
- lab runbook
- taskboard Markdown/HTML
- README current baseline
- exact commit allowlist

## T18 Risks / Blockers / Assumptions / Decisions

- The input represents one physical device; two logical windows are not
  multi-device evidence.
- Detection totals are operational outputs without independent labels.
- The 100,000-row run is a measured local acceptance, not a throughput SLA.
- SQLite remains the local profile; approved-host PostgreSQL capacity is
  outside this phase.
- Existing independently labeled multi-device evidence blockers remain.

## T19 Release / Rollback

Rollback removes the new service, CLI, tests, and docs. No configured database
or schema rollback is needed. No commit or push is authorized by this record.

## T20 Final Handoff

Use the v5.14 CLI only with private local input and `--use-temp-db`. Preserve
the distinction between one physical device and simulated logical windows,
between detector output and accuracy, and between advisory ML and
authoritative rules. Keep supervised lifecycle `shadow_observation`, response
automation disabled, and real firewall blocking disabled.
