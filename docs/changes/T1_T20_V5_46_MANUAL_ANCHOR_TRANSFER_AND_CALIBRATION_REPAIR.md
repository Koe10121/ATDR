# T1-T20: v5.46 Manual-Anchor Transfer And Calibration Repair

## T1 Change Title

v5.46 Manual-Anchor Transfer and Calibration Repair.

## T2 Requirement

Diagnose and repair v5.45 manual-anchor transfer using development evidence
only, without opening reserved-future labels or weakening fixed gates.

## T3 Source Evidence

Source code, tests, v5.39-v5.45 custody records, configured manual anchors,
the private PAN-OS source supplied only through the CLI, and unchanged v5.42
gates.

## T4 Current Behavior

v5.45 passed `0/3` views. Its assisted-cohort performance did not transfer to
the manual holdout and calibration remained weak.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, backend/API, React AI Governance,
privacy/security, QA, Release/Ops, and documentation.

## T6 Scope

Custody revalidation, aggregate transfer diagnosis, runtime-derived features,
nine diagnostic strategies, manual-prioritized weighting, sigmoid/isotonic
calibration, fixed-gate threshold selection, residual/anomaly audits,
read-only status, tests, governance, and exact allowlist. Label creation,
future-label access, active artifacts, ML alert authority, response, commit,
and push are out of scope.

## T7 Functional Requirements

- Use development roles only and keep future labels sealed.
- Keep assisted effective weight below manual-anchor weight.
- Exclude provenance/source identity from predictive features.
- Select calibration and thresholds without evaluation labels.
- Apply unchanged v5.42 gates across three mandatory views.
- Freeze at most an immutable recipe, never an active artifact.
- Keep IsolationForest separate and advisory.
- Return only safe aggregate status.

## T8 Acceptance Criteria

All strategies execute fail-closed; custody and authority stay unchanged;
private material remains redacted; a recipe freezes only after every gate;
tests and repository verification pass.

## T9 API Contract

Operator CLI:
`python -m atdr.scripts.run_v546_manual_anchor_transfer_repair`.
Authenticated read-only status:
`GET /api/evidence-review/manual-anchor-transfer/status`.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Disposable SQLite and generated diagnostics
remain ignored.

## T11 Backend Plan / Changes

Add the v5.46 evaluator, CLI, safe status projection, schema/router contract,
and focused tests while reusing the governed v5.44-v5.45 boundaries.

## T12 Frontend Plan / Changes

Add a compact AI Governance card for transfer status, manual-anchor F1/FPR,
calibration, rule authority, and shadow lifecycle.

## T13 Security / Response / AI Safety

No private row, path, IP, identity, timestamp boundary, prediction,
fingerprint, secret, or future label is exposed. Rules stay authoritative;
activation, promotion, automatic response, and real blocking stay disabled.

## T14 Test Plan

Cover runtime-derived features, provenance exclusion, deterministic sampling,
assisted-weight caps, threshold leakage prevention, unchanged gates,
recipe-only freeze, no mutations, authenticated redacted API, frontend status,
and full regressions.

## T15 Implementation Summary

Implemented eight transfer/model variants plus one conservative ensemble,
aggregate cohort-shift diagnosis, calibration/threshold policies, residual and
IsolationForest audits, fail-closed freeze decision, API/UI, tests, measured
run, governance records, and exact allowlist.

## T16 Tests Run / Evidence

The measured run completed in `301.5918s`, selected hierarchical two-stage
diagnostically, passed `0/3` views, froze nothing, and changed no authoritative
state. Taskboard checks, Ruff, canonical compileall, and Alembic passed;
backend and release testing passed `990 passed, 1 skipped`; React lint/build
passed; Playwright passed `35` with `1` intentional live-source skip;
controlled source acceptance passed; layered detection passed `288/288`;
Assistant QA passed `20/20`; replay dry-run and performance smoke passed; and
the release gate completed successfully in `447.6s`.

## T17 PRD / Docs Updated

v5.46 status, this change record, PRD, traceability, compliance checklist, AI
runbook, current AI/ML status, taskboard, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Manual and assisted evidence differ materially by labels, applications,
schemas, and traffic patterns. Manual suspicious recall and calibration remain
unsafe. One-device evidence cannot establish source generalization.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes v5.46 code/API/UI/tests/docs
and restores the prior taskboard; no configured data or active artifact needs
rollback.

## T20 Final Handoff

Keep `shadow_observation`, rules authoritative, future evidence sealed, and
candidate freeze blocked. Obtain new prediction-blind human anchors and a
second real source before another independent activation decision.
