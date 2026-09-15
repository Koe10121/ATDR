# T1-T20: v4.0 Provider-Blinded External Evidence And Frozen Validation

## T1 Change Title

v4.0 Provider-Blinded External Evidence And Frozen Validation.

## T2 Requirement

Evaluate the frozen ATDR detection/ML queue on legally usable external provider evidence without consulting final labels during sampling, mapping, model fitting, calibration, threshold selection, or prediction generation.

## T3 Source Evidence

- Official CSE-CIC-IDS2018 page: <https://www.unb.ca/cic/datasets/ids-2018.html>
- Official AWS catalog: <https://registry.opendata.aws/cse-cic-ids2018/>
- `atdr/app/detection/v398_independent_holdout_validation.py`
- `atdr/app/detection/v399_multisource_frozen_revalidation.py`
- `atdr/app/detection/rules.py`
- `atdr/app/ml/features.py`
- ignored verified provider files and self-hashed manifests under `.tmp/external_evidence/`

## T4 Current Behavior

v3.99 validates frozen roles and overlap controls on ATDR-authored synthetic evidence. It cannot establish external generalization. The current internal reviewed corpus is single-source and narrow-window.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection validation
- Evidence provenance and privacy
- QA and release verification
- Documentation and university traceability

No runtime API, dashboard, database schema, active artifact, or response workflow changes.

## T6 Scope

In scope: official-source research, verified acquisition, deterministic feature-only sampling, manifests, feature adapter, rule applicability, overlap quarantine, frozen predictions, post-freeze label reveal, multi-strategy evaluation, tests, and docs.

Out of scope: benchmark-label tuning, label import, active artifact writes, model activation, runtime scoring changes, automatic response, firewall enforcement, and production claims.

## T7 Functional Requirements

- Use one officially published dataset whose terms allow academic validation.
- Record source identity, version, terms, checksum, row counts, sampling, mapping, provenance, and limitations.
- Never invent unavailable Palo Alto fields.
- Freeze and hash predictions before opening provider labels.
- Quarantine overlap with reviewed internal and v3.99 evidence.
- Keep external fit/calibration/threshold counts at zero.
- Evaluate applicable rules, IsolationForest, supervised queue, hybrid, Logistic Regression, and majority baseline.
- Report classification, calibration, bootstrap, errors, stability, readiness, and safety.

## T8 Acceptance Criteria

- Verified provider file size and SHA-256.
- Deterministic label-independent sample.
- Prediction timestamp and hash precede label read.
- Zero accepted exact/near/feature overlap with both reference corpora.
- Provider labels remain `human_reviewed=false` and `import_ready=false`.
- No operational DB/model/response side effects.
- Readiness never exceeds `candidate_only`.

## T9 API Contract

No API change. New diagnostic CLI:

```text
python -m atdr.scripts.run_v400_provider_blinded_external_validation
```

Options: `--evidence-dir`, `--output-dir`, `--rows-per-file`, `--seed`, `--no-report`, `--summary-only`, and `--pretty`.

## T10 Data Model / Migration

No model or migration change. The configured database is not migrated. External data and generated evidence remain ignored files; provider labels are never inserted into operational tables.

## T11 Backend Plan / Changes

- Add the v4.0 evaluator and CLI.
- Verify source objects against fixed size/SHA-256 identities.
- Select features with label-independent min-hash sampling.
- Build a missingness-aware flow adapter.
- Reuse frozen v3.98/v3.99 internal candidates and thresholds.
- Freeze predictions before a second provider-file pass reveals labels.
- Produce immutable self-hashed manifests and ignored reports.

## T12 Frontend Plan / Changes

No frontend behavior change. Failed external generalization is governance evidence and is not surfaced as an active production metric.

## T13 Security / Response / AI Safety

- No benchmark label is represented as human review.
- No labels, active models, model runs, detection runs, or response actions are created.
- No raw provider row is added to source-controlled documentation.
- External files and reports remain ignored.
- Automatic response and real blocking remain disabled.
- `candidate_only` is unconditional for this phase.

## T14 Test Plan

- label-independent sampling;
- direct-only field mapping;
- prediction artifact excludes labels;
- label reveal requires an intact prediction hash;
- internal/v3.99 overlap quarantine;
- unsupported rules remain unavailable;
- runner keeps candidate-only and no-side-effect state;
- full repository verification matrix.

## T15 Implementation Summary

Added a two-pass provider evidence protocol over two CSE-CIC-IDS2018 days. The implementation freezes a 4,000-row feature sample, accepts 3,993 rows after duplicate quarantine, records prediction and manifest hashes, reveals provider labels only after prediction freeze, and evaluates six frozen strategies across all/provider-day/temporal/random views.

## T16 Tests Run / Evidence

- Focused v4.0 tests: `7 passed`.
- Final full external run: 3,993 rows scored in 322.3603 seconds; metrics and prediction hash reproduced the first run exactly.
- Prediction-before-label ordering: passed.
- Internal/v3.99 exact, near, and feature overlap after quarantine: all zero.
- Primary all-external: precision `0.3171`, recall `1.0000`, F1 `0.4815`, FPR `1.0000`.
- Primary calibration: weak; Brier `0.6538`, ECE `0.6614`.
- Disposable DB counts and active artifact metadata: unchanged.
- Task-board render/check, Ruff, and compileall: passed.
- Full backend: `556 passed, 1 skipped`.
- Disposable Alembic check: no drift at `b4c5d6e7f8a9 (head)`.
- React lint/build: passed; Playwright `21 passed, 1 skipped`.
- Replay dry-run parsed two safe rows and wrote zero.
- Read-only performance smoke: no warnings; Overview `0.4683s`, cached Overview `0.0069s`, ML Governance `1.2817s`, alerts `0.0355s`, cases `0.0923s`.
- Release gate: `ok: true`; all required checks passed.

## T17 PRD / Docs Updated

- `docs/V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE_AND_FROZEN_VALIDATION.md`
- `docs/V4_0_CHANGESET_MANIFEST.md`
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

- The benchmark schema lacks IP, action, application, zone, source-port, and app-risk fields.
- The frozen supervised model queues every benign external flow; FPR is 1.0.
- Confidence calibration is weak.
- Most deterministic rule families are unavailable on this schema.
- Decision: lock v4.0 as final evidence and prohibit tuning against its labels.

## T19 Release / Rollback

No runtime release or migration is required. Rollback is removal of the v4.0 evaluator/CLI/tests/docs. Ignored provider data and reports can be deleted independently. Existing model and database state remain unchanged.

## T20 Final Handoff

v4.0 closes the absence of public provider evidence but exposes a severe cross-schema generalization failure. The correct next step is a separately governed development dataset and schema-aware model redesign followed by a new untouched benchmark, not threshold tuning against v4.0.
