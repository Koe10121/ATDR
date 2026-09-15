# T1-T20: v3.99 Independent Multi-Source Evidence And Frozen Revalidation

## T1 Change Title

v3.99 Independent Multi-Source Evidence And Frozen Revalidation.

## T2 Requirement

Address the v3.98 single-source and narrow-time-window evidence blocker with a reproducible source-separated synthetic evidence pack and an evaluation path whose fit, calibration, threshold, and final roles cannot mix.

## T3 Source Evidence

- `atdr/app/detection/v398_independent_holdout_validation.py`
- `ml_baseline_reviews/v3_98_validation_latest.json` (ignored local evidence)
- `atdr/app/ml/features.py`
- `atdr/app/detection/rules.py`
- `atdr/app/detection/v362_supervised_training_target_contract.py`
- `atdr/app/db/models.py`

Current evidence: 2,235 latest reviewed labels, all from `local_import`, spanning approximately three minutes; strict source/time validation is unavailable and random FPR is unstable.

## T4 Current Behavior

v3.98 groups exact/near/feature duplicates and separates fit/calibration/threshold/final partitions. It correctly fails closed for source and temporal holdout on the current corpus, evaluates three grouped random splits, and keeps readiness `candidate_only`.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection validation
- Evidence provenance
- QA and release verification
- Documentation and university traceability

No runtime API, dashboard, database schema, active model, or response workflow is changed.

## T6 Scope

In scope: synthetic evidence generator, manifest, overlap quarantine, isolated feature workspace, frozen evaluator, reports, tests, docs, and task-board evidence.

Out of scope: real-device collection, external provider data, human label review, label import, model activation, threshold deployment, automatic response, and firewall enforcement.

## T7 Functional Requirements

- Generate at least three source-separated sets and four time windows.
- Record source, parser, provenance, scenario, label provenance, evidence kind, and duplicate audit.
- Quarantine exact, near-pattern, or feature overlap with reviewed evidence.
- Fit/calibrate/select thresholds using internal reviewed partitions only.
- Evaluate rules, anomaly, supervised queue, hybrid, Logistic Regression, and majority baselines.
- Report per-split metrics, calibration, bootstrap intervals, error patterns, and readiness.

## T8 Acceptance Criteria

- At least 300 accepted rows, three sources, and four windows.
- Zero accepted exact/near/feature overlap with internal evidence.
- Five final splits evaluated without final labels entering tuning.
- Generated expectations remain non-human and non-importable.
- No database/model/label/response side effects.
- Readiness never exceeds `candidate_only` without real/provider-independent evidence.

## T9 API Contract

No API contract changes. CLI:

```text
python -m atdr.scripts.run_v399_multisource_frozen_revalidation
```

Options include `--rows-per-source`, `--seed`, `--output-dir`, `--no-report`, `--summary-only`, and `--pretty`.

## T10 Data Model / Migration

No schema change or migration. External features are generated in ephemeral in-memory SQLite tables. Source CSVs/manifests/reports are written only beneath ignored output directories.

## T11 Backend Plan / Changes

- Add `v399_multisource_frozen_revalidation.py`.
- Add deterministic evidence records and source manifest.
- Add fingerprint quarantine and fail-closed requirements.
- Freeze internal roles before external scoring.
- Reuse v3.98 metric/calibration/bootstrap/error helpers.
- Add a CLI with compact summary output.

## T12 Frontend Plan / Changes

No frontend behavior change. v3.99 evidence is technical validation and is not surfaced as a production metric.

## T13 Security / Response / AI Safety

- Synthetic expectations are not human-reviewed labels.
- No labels are imported.
- No model is activated or promoted.
- No active artifact is written.
- No response actions are created.
- Automatic response and real firewall blocking stay disabled.
- Reports exclude raw lines, IP values, secrets, and private paths.

## T14 Test Plan

- deterministic source/window generation;
- overlap quarantine;
- grouped final splits and source/time isolation;
- final-label tuning isolation;
- conservative readiness;
- ignored non-importable outputs;
- zero DB/model/label/response side effects;
- full repository verification matrix.

## T15 Implementation Summary

Added three deterministic source families with 720 total rows and four windows, in-memory feature generation, exact/near/feature quarantine, one frozen internal fit/calibration/threshold partition, five external final views, six strategy comparisons, and safety/readiness reports.

## T16 Tests Run / Evidence

- Focused v3.99 tests: `5 passed`.
- Full evaluator: completed in `175.959s` on the migrated disposable database.
- Evidence: 720 attempted/accepted, zero overlap, zero quarantine.
- Primary queue: F1 `0.9524-0.9551`, FPR `0.0`, suspicious/malicious recall `1.0`.
- Calibration: weak on all five splits.
- Database counts/artifact/session state: unchanged.
- Ruff and compileall: passed.
- Full backend: `549 passed, 1 skipped`.
- Disposable Alembic check: no drift at `b4c5d6e7f8a9 (head)`.
- React lint/build and Playwright: passed (`21 passed, 1 skipped`).
- Replay dry-run and warning-free performance smoke: passed.
- Release gate: `ok: true`.
- Full command-level evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE_AND_FROZEN_REVALIDATION.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/ATDR_PRODUCTIZATION_ROADMAP.md`
- `docs/LAB_RUNBOOK.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Synthetic patterns may be easier than uncontrolled real traffic.
- No provider-blinded or real-device evidence exists.
- Calibration remains weak despite strong classification metrics.
- Unknown allowed services account for all primary false negatives.
- Decision: retain `candidate_only`; do not tune against v3.99 final results.

## T19 Release / Rollback

No runtime release or migration is required. Rollback is removal of v3.99 code/tests/docs; ignored evidence can be deleted independently. Existing active model and configured database remain unchanged.

## T20 Final Handoff

The repository now has a reproducible synthetic multi-source regression harness and frozen final-evidence protocol. It closes the tooling gap but not the real-world evidence gap. Next work should acquire independently reviewed real/provider-blinded multi-source and temporal evidence, not optimize against this synthetic final set.
