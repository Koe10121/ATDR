# T1-T20: v5.15 Long-Duration Runtime Soak And Recovery Acceptance

## T1 Change Title

v5.15 Long-Duration Runtime Soak And Recovery Acceptance.

## T2 Requirement

Prove that ATDR sustains progressive large PAN-OS ingestion and deterministic
detection, survives repeated operational faults with exact checkpoints, and
cleans all disposable resources without touching configured data or changing
ML/response authority.

## T3 Source Evidence

- v5.14 runtime-acceptance service, tests, and measured status;
- staging, durable job, worker, lease, resumable-ingestion, and coordination
  services;
- source, parser-quality, detection, alert, case, and dashboard services;
- private evidence supplied through a CLI argument only; and
- current state lock, PRD, traceability, and lab runbook.

## T4 Current Behavior

v5.14 proved 100,000 rows, one handoff, cancellation eligibility, lock
recovery, and complete cleanup. It did not prove progressive 250,000,
500,000, and full-file operation or repeated handoff, cancelled-job resume,
stale-lease fail-closed recovery, full integrity, and stage-by-stage
performance.

## T5 Impacted Areas/Agents

- Backend/runtime orchestration and safe CLI.
- Database/integrity and disposable cleanup.
- Ingestion, queue, worker, lease, source, parser, and progress contracts.
- Detection, alert evidence, computed cases, and dashboard reads.
- Security/privacy and AI/response safety.
- QA, governance, traceability, and release review.

## T6 Scope

Included: resource preflight, progressive stages, transactional chunks,
handoff, cancellation/resume, stale lease/recovery, idempotency, lock wait,
integrity, sources, deterministic detection, investigation traceability,
performance, privacy, and cleanup.

Excluded: configured-database writes, schema changes, independent-device
claims, ground-truth accuracy, ML activation/promotion, automatic response,
real blocking, approved-host capacity certification, commit, and push.

## T7 Functional Requirements

1. Refuse processing without explicit disposable storage.
2. Require three times estimated temporary-storage headroom.
3. Process 250,000, 500,000, and complete-file checkpoints progressively.
4. Keep line, byte, and progress checkpoints monotonic.
5. Recover every injected fault without recommitting checkpoint rows.
6. Preserve repeated raw events while containing retry duplication.
7. Reconcile database, source, and ingestion-run counters.
8. Prove database/evidence integrity and deterministic detection traceability.
9. Remove every disposable artifact.
10. Create no labels, model runs, response actions, activation, or promotion.

## T8 Acceptance Criteria

- full-file preflight and every stage resource gate pass;
- 773,551 raw and normalized rows reconcile with zero parse failures;
- five handoffs, one cancellation/resume, one stale-lease recovery, and lock
  wait pass;
- SQLite integrity and all orphan checks pass;
- every alert links to log/source evidence and cases reconcile;
- configured database and safety authority remain unchanged;
- privacy findings and unsafe writes remain zero;
- cleanup is complete; and
- complete verification and hygiene matrix passes.

## T9 API Contract

No API changes. The new service/CLI composes existing runtime contracts.

## T10 Data Model / Migration

No schema or migration change. Current SQLAlchemy metadata is created only in
a disposable SQLite database.

## T11 Backend Plan / Changes

- Add progressive resource and runtime-soak orchestration.
- Inject faults only after committed chunk boundaries.
- Exercise public lease/recovery/resume contracts.
- Add integrity, performance, traceability, privacy, and cleanup gates.
- Correct source-scoped traceability reporting discovered by the soak.

## T12 Frontend Plan / Changes

No frontend change. Existing progress states and dashboard reads remained
clear. The measured read paths are recorded without redesign.

## T13 Security / Response / AI Safety

The private path is CLI-only and absent from output/docs. Raw evidence exists
only in disposable storage. Rules remain authoritative, supervised ML remains
`shadow_observation`, and no label/model/response authority is changed.

## T14 Test Plan

Test configured-database refusal, low-disk fail-closed behavior, combined
recovery, repeated-event preservation, checkpoint containment, counters,
integrity, source/alert/case traceability, privacy, cleanup, zero unsafe
writes, safe preflight, and invalid fault-plan refusal.

## T15 Implementation Summary

`run_v515_runtime_soak_acceptance` adds aggregate preflight, three-times
storage gating, staged progressive windows, committed-boundary fault
orchestration, integrity checks, performance measurement, and guaranteed
cleanup. A source-scoped traceability calculation was corrected without
changing detection behavior.

## T16 Tests Run / Evidence

Measured evidence:

- full-file preflight: 773,551 rows, zero parser errors/warnings;
- full progressive run: 773,551 raw/normalized, zero parse failures;
- combined faults: 5 handoffs, 1 cancellation/resume, 1 stale recovery;
- SQLite integrity `ok`, zero FK/orphan mismatches;
- deterministic detection: 773,551 evaluations, 8,036 alert records, 5,802
  dedup updates, 6,012 computed cases, zero response actions;
- configured database unchanged and cleanup complete; and
- focused v5.14/v5.15 tests: 12 passed;
- full backend/release: 753 passed, 1 skipped;
- Alembic: no drift;
- React lint/build and Playwright: 26 passed, 1 skipped;
- controlled/layered/Assistant: 24/24, 288/288, 20/20;
- replay and warning-free performance smoke: passed; and
- official release gate: passed.

## T17 PRD / Docs Updated

- v5.15 status and this T1-T20 record;
- current state lock;
- PRD and requirement traceability;
- lab runbook and README;
- taskboard Markdown/HTML; and
- exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- One device and one time range cannot prove multi-device operation.
- Unlabeled detector totals are not accuracy.
- Peak traced memory was about 12 GiB and needs optimization/approved-host
  validation before capacity claims.
- Local SQLite is not a production/shared-host SLA.
- Independent labeled evidence still blocks supervised advancement.

## T19 Release / Rollback

Rollback removes the v5.15 service, CLI, tests, and docs and reverts the
source-scoped reporting correction. No configured database or schema rollback
is needed. This record does not authorize Git publication.

## T20 Final Handoff

Keep private input outside Git and use `--use-temp-db`. Preserve simulated
window wording, operational-not-accuracy semantics, `shadow_observation`,
rule authority, disabled response automation, and disabled real blocking.
Address peak memory and approved-host PostgreSQL/live-source evidence in a
later separately governed phase.
