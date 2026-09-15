# T1-T20: v5.44 Chronological Evidence Expansion

## T1 Change Title

v5.44 Chronological Evidence Expansion and Label-Coverage Qualification.

## T2 Requirement

Broaden development-only evidence without tuning on protected v5.39-v5.43
evaluation data, fabricating human labels, or changing model/alert/response
authority.

## T3 Source Evidence

The v5.39 consumed decision, v5.40 development boundary, v5.41 candidate
custody, v5.42/v5.43 freeze state, configured 1,467-row development contract,
and a private PAN-OS source supplied only through the CLI.

## T4 Current Behavior

v5.43 compared five repairs over narrow one-source evidence and passed `0/3`
folds. No candidate was frozen.

## T5 Impacted Areas / Agents

Detection/ML, parser/evidence governance, privacy/security, QA, Release/Ops,
and documentation.

## T6 Scope

Disposable streaming, prior-evidence quarantine, chronological cohorting,
aggregate label/pattern coverage, advisory anomaly audit, assisted preview,
private custody lock, CLI, tests, governance, and allowlist. Training,
activation, schema migration, configured-DB import, commit, and push are out of
scope.

## T7 Functional Requirements

- Revalidate v5.39-v5.43 custody before private inspection.
- Accept the source path only as a CLI argument and return aggregates only.
- Quarantine configured, consumed, exact, near, temporal, and candidate
  overlap.
- Isolate duplicate families across fit/calibration/threshold/future roles.
- Never open future labels during development coverage analysis.
- Keep all generated decisions assisted, non-human, and non-import-ready.
- Preserve rules, model lifecycle, response safety, and configured state.

## T8 Acceptance Criteria

Full source streams with bounded memory; parser/chronology/cohort counts are
measured; protected evidence is excluded; no cross-role family exists; no
private value is returned; no configured count/artifact changes; readiness is
conservative; focused and full repository verification pass.

## T9 API Contract

No new API. The safe operator interface is
`python -m atdr.scripts.run_v544_chronological_evidence_expansion` with
`--sample-path`, `--use-temp-db`, `--preflight-only`, and `--pretty`.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Disposable and private-lock SQLite files and
aggregate reports remain ignored under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Extend the disposable PAN-OS index with opaque device presence and v5.41 near-
family compatibility; add the v5.44 custody, cohort, coverage, anomaly,
sufficiency, review-pack, and private-lock workflow plus CLI.

## T12 Frontend Plan / Changes

No frontend behavior change. Existing AI Governance continues to show the
authoritative v5.43 lifecycle until a separately governed model-repair phase.

## T13 Security / Response / AI Safety

Raw rows, paths, IPs, source identities, fingerprints, predictions, and
secrets are excluded from public output. New decisions are assisted only.
Rules remain authoritative; lifecycle is `shadow_observation`; response
automation and real blocking stay disabled.

## T14 Test Plan

Test shared near-family contract, device-count redaction, prior-boundary
quarantine, chronological/duplicate isolation, high-signal taxonomy,
future-label sealing, assisted provenance, private-lock reuse/tamper failure,
aggregate-only output, and zero authoritative mutation.

## T15 Implementation Summary

Implemented the aggregate-only v5.44 workflow and CLI, shared boundary
contract, policy-bound private lock, assisted preview, tests, measured full
run, status, governance, taskboard, and exact allowlist.

## T16 Tests Run / Evidence

Focused v5.44/v5.41/v5.6 regression passes `24/24`. Real preflight and full
773,551-row disposable execution pass. Backend/release report `970 passed, 1
skipped`; Alembic has no drift; React lint/build pass; Playwright reports `35
passed, 1 skipped`; controlled/layered/Assistant/replay/performance gates and
release `ok: true` pass. Exact closure evidence is recorded on the taskboard.

## T17 PRD / Docs Updated

v5.44 status, this change record, PRD, traceability, compliance, AI runbook,
current AI/ML status, taskboard Markdown/HTML, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The source spans about 21 minutes and represents one device. New labels are
assisted, not independent human truth. IsolationForest is under-sensitive.
Development repair may proceed, but independent validation and activation may
not.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes v5.44 code/tests/docs and
restores the three-column disposable-index extension; no configured database,
label, model, alert, or response rollback is required.

## T20 Final Handoff

Use the locked 540,921-row development population for one fixed development-
only repair phase. Keep 112,004 future rows sealed. Do not call assisted
coverage independent accuracy or activate a model without the remaining five
governed phases.
