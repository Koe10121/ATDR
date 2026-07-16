# T1-T20: v4.1 Schema-Aware SOC Queue Model Redesign

## T1 Change Title

v4.1 Schema-Aware SOC Queue Model Redesign.

## T2 Requirement

Redesign ATDR supervised decision-support diagnostics so firewall logs and external network-flow records are handled through explicit schema contracts, without using the locked v4.0 evidence in any development role.

## T3 Source Evidence

- `atdr/app/detection/v398_independent_holdout_validation.py`
- `atdr/app/detection/v400_provider_blinded_external_validation.py`
- `atdr/app/detection/schema_contracts.py`
- `atdr/app/detection/v401_schema_aware_soc_queue.py`
- `atdr/app/ml/features.py`
- `atdr/app/detection/rules.py`
- Official [CSE-CIC-IDS2018 page](https://www.unb.ca/cic/datasets/ids-2018.html) and [AWS registry](https://registry.opendata.aws/cse-cic-ids2018/)
- Official [UNSW-NB15 page](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

## T4 Current Behavior

v4.0 used a prediction-before-label external benchmark and exposed total cross-schema failure: FPR `1.0000`, weak calibration, and queue F1 `0.4815`. Its evidence is now final and locked.

## T5 Impacted Areas / Agents

- AI/ML governance and candidate evaluation
- Detection feature/schema contracts
- Validation, QA, and release evidence
- Documentation, traceability, task board, and hygiene

No runtime API, UI, database schema, active model, or response workflow changes are in scope.

## T6 Scope

In scope: development-only corpus verification, v4.0 hash lock, schema contracts, missingness/schema indicators, diagnostic strategy comparison, split-stability/calibration reporting, tests, docs, and ignored reports.

Out of scope: v4.0 label tuning, provider-label import, human-label creation, model activation/promotion, artifact writes, response automation, firewall control, configured-database migration, commit, and push.

## T7 Functional Requirements

- Enforce v4.0 file/hash boundary for all development roles.
- Use separate documented official provider development evidence.
- Define Palo Alto, generic syslog, provider flow, and raw fallback contracts.
- Do not fabricate unavailable fields or score unavailable rules as negative evidence.
- Compare the requested firewall, flow, pooled, routed, calibrated, three-class, anomaly, rules, and hybrid diagnostics.
- Use time, source-group, repeated-random, and schema-held-out evidence where supported.
- Keep readiness `candidate_only` regardless of development metrics.

## T8 Acceptance Criteria

- Locked v4.0 inputs are rejected by path, name, and SHA-256.
- Provider rows remain non-human and non-importable.
- Development sample provenance, checksums, class counts, and duplicate quarantine are recorded.
- Schema contracts expose unavailable fields and rule applicability.
- Evaluation records precision, recall, F1, FPR, suspicious/malicious recall, queue rate, calibration, and worst split.
- No label, active artifact, model run, detection run, response action, or configured DB mutation occurs.

## T9 API Contract

No API change. New read-only diagnostic CLI:

```text
python -m atdr.scripts.run_v401_schema_aware_soc_queue
```

Options: `--development-dir`, `--output-dir`, `--rows-per-provider-label`, `--seed`, `--min-samples`, `--no-report`, `--summary-only`, and `--pretty`.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration change. Provider evidence, development samples, manifests, and reports stay in ignored directories. The configured database is not migrated or altered.

## T11 Backend Plan / Changes

- Add machine-enforced v4.0 evidence lock and reserve a future untouched benchmark.
- Add explicit evidence-schema contracts and normalized common features with availability flags.
- Add flow-specific, firewall-specific, pooled, routed, and held-out diagnostic evaluators.
- Use fingerprint-component groups to keep exact/near/feature-related rows out of cross-role leakage.
- Add a safe CLI and no-side-effect runner.

## T12 Frontend Plan / Changes

No frontend behavior change. The development diagnostics remain ignored governance evidence and must not be shown as active-model performance.

## T13 Security / Response / AI Safety

- No provider data becomes human-reviewed or import-ready.
- No raw operational logs are added to reports.
- No active model or model registry entry is written.
- No assistant, detection, label, user, or response action is executed.
- Automatic response and real firewall blocking remain disabled.

## T14 Test Plan

- v4.0 lock and reserved benchmark rejection;
- schema unavailable-field rejection;
- flow missingness without invented fields;
- unsupported rule availability behavior;
- row and fingerprint-disjoint partitions;
- multiclass prefit calibration regression;
- diagnostic selection remains non-activating;
- runner state-integrity/no-side-effect check;
- full repository verification matrix.

## T15 Implementation Summary

Added schema contracts, v4.1 evaluator, CLI, and 12 focused tests. The full 3,000-per-provider-label run accepted 16,817 development-only provider flows after quarantining 1,545 exact duplicate flows. It compared all requested strategy families and produced ignored reports without using v4.0 labels or changing any operational state.

## T16 Tests Run / Evidence

- Focused v4.1 suite: `12 passed`.
- Full v4.1 diagnostic: `completed_candidate_only` in `308.2807s`.
- v4.0 hash lock: all seven locked records verified before and after.
- Development data: `18,362` attempted, `16,817` accepted, `1,545` exact duplicates quarantined, `0` schema violations.
- Best cross-schema development diagnostic: pooled schema-aware calibrated ExtraTrees; random F1 `0.9237-0.9524`, FPR `0.0882-0.1997`, calibration weak `3/3`.
- Schema-held-out provider-flow FPR: `1.0000`; schema-held-out Palo Alto queue recall: `0.3066`.
- Disposable database counts, active artifact metadata, and session state: unchanged. No labels, model runs, detections, or response actions created.
- Closure matrix: task-board render/check, Ruff, compileall, full backend `568 passed, 1 skipped`, disposable Alembic no-drift, React lint/build, Playwright `21 passed, 1 skipped`, replay dry-run, warning-free performance smoke, and release gate `ok: true`.

## T17 PRD / Docs Updated

- `docs/V4_1_SCHEMA_AWARE_SOC_QUEUE_MODEL_REDESIGN.md`
- `docs/V4_1_CHANGESET_MANIFEST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/ATDR_PRODUCTIZATION_ROADMAP.md`
- `docs/LAB_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md` and generated HTML

## T18 Risks / Blockers / Assumptions / Decisions

- Random-split strength does not transfer to time/source shifts.
- Internal firewall source holdout remains unavailable because the reviewed corpus has one source identity.
- Schema-held-out transfer fails in both directions.
- Calibration remains weak for every evaluated strategy.
- Decision: retain all candidates as diagnostic-only; do not activate, promote, or tune against v4.0.

## T19 Release / Rollback

No runtime release, migration, or deployment change is required. Rollback is removal of the v4.1 evaluator/CLI/tests/docs only. Ignored provider development data and reports can be removed separately. The configured database and active artifact are untouched.

## T20 Final Handoff

v4.1 establishes a schema-aware development boundary and demonstrates why one cross-schema classifier is not enough. It improves honest evaluation and feature handling, but does not clear the quality/calibration gate. The next ML validation requires a separately approved untouched benchmark and authorized real-source evidence.
