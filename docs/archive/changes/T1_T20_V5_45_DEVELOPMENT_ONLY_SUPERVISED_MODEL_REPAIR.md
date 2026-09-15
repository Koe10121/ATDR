# T1-T20: v5.45 Development-Only Supervised Model Repair

## T1 Change Title

v5.45 Development-Only Supervised Model Repair and Candidate Freeze Gate.

## T2 Requirement

Use only eligible v5.44 development roles to compare supervised repairs and
freeze at most one diagnostic recipe only when every unchanged gate passes.

## T3 Source Evidence

The consumed v5.39 decision, v5.40-v5.43 custody state, v5.44 chronological
lock, configured manual/reviewed anchors, private source supplied only through
the CLI, existing rule/ML safety contracts, and fixed v5.42 gates.

## T4 Current Behavior

v5.44 supplied three populated development roles and kept the newest future
role sealed. It did not train, freeze, activate, or independently validate a
candidate.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, backend/API, React AI Governance,
privacy/security, QA, Release/Ops, and documentation.

## T6 Scope

Custody revalidation, broader candidate-near containment, provenance-aware
development views, eight-strategy comparison, calibration/threshold selection,
residual and IsolationForest audits, aggregate status API/UI, tests, governance,
and allowlist. Label creation, future-label access, active artifacts,
authoritative ML alerts, response, commit, and push are out of scope.

## T7 Functional Requirements

- Use only fit/calibration/threshold roles for development decisions.
- Prevent exact, propagation, and broader candidate-near family leakage.
- Keep assisted aggregate weight below manual-anchor weight.
- Apply unchanged v5.42 gates to every mandatory view.
- Exclude an optional view when it cannot exercise every fixed gate.
- Freeze only a recipe manifest when all gates pass; never an active model.
- Keep IsolationForest separate and advisory.
- Return only safe aggregate status to the dashboard.

## T8 Acceptance Criteria

Custody passes; future labels stay sealed; three valid views exist; all eight
strategies run; failure remains fail-closed; no configured state changes; API
and UI expose aggregates only; tests and repository verification pass.

## T9 API Contract

The operator interface is
`python -m atdr.scripts.run_v545_development_model_repair`. The authenticated
read-only dashboard interface is
`GET /api/evidence-review/development-model-repair/status`.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Disposable SQLite, reports, and any diagnostic
recipe remain ignored under private/generated storage.

## T11 Backend Plan / Changes

Add v5.45 custody/model/audit workflow, CLI, safe public projection, router,
schema, and focused tests. Reuse existing feature/model helpers but correct
provenance so only `manual` and `reviewed_import` are human anchors.

## T12 Frontend Plan / Changes

Add a compact AI Governance card for diagnostic leader, passing views,
candidate-freeze state, IsolationForest advisory state, and unchanged rule/
shadow authority. Do not expose raw reports.

## T13 Security / Response / AI Safety

No raw row, path, IP, source identity, prediction, fingerprint, secret, or
future label is exposed. Rules remain alert-authoritative. Model activation,
promotion, automated response, and real blocking remain false.

## T14 Test Plan

Cover assisted-weight caps, temporal duplicate containment, leakage failure,
future-role rejection, candidate-near quarantine, gate-class support, recipe-
only freeze, no mutations, public redaction, authenticated aggregate API, UI
rendering, and full repository regressions.

## T15 Implementation Summary

Implemented eight diagnostic strategies over three mandatory role-based views,
candidate-near containment, calibrated thresholds, residual/IsolationForest
audits, fail-closed freeze decision, aggregate API/UI, tests, measured run,
governance, taskboard, and exact allowlist.

## T16 Tests Run / Evidence

The measured run completed in `532.4228s`, compared eight strategies, selected
calibrated ExtraTrees diagnostically, passed `0/3` views, froze no recipe, and
changed no authoritative state. Taskboard render/check, Ruff, canonical source
compile, backend `981 passed, 1 skipped`, Alembic no drift, React lint/build,
Playwright `35 passed, 1 skipped`, isolated scenario, layered detection
`288/288`, Assistant QA `20/20`, replay dry-run, warning-free performance, and
the release gate all pass. Full evidence is recorded on the taskboard.

## T17 PRD / Docs Updated

v5.45 status, this T1-T20 record, PRD, traceability, compliance checklist, AI
runbook, current AI/ML status, corrected v5.44 duplicate-language, taskboard,
and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Assisted cohorts are much easier than the manual holdout. Calibration is weak,
suspicious recall drops, broader candidate-near overlap is substantial, and
evidence still represents one genuine device. Five supervised phases remain.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes v5.45 code/API/UI/tests/docs
and restores the prior taskboard; no configured DB, label, model, alert, or
response rollback is required.

## T20 Final Handoff

Keep lifecycle `shadow_observation`, rules authoritative, future labels sealed,
and candidate freeze blocked. The next model phase must repair manual-anchor
transfer and calibration without weakening gates or reusing protected evidence.
