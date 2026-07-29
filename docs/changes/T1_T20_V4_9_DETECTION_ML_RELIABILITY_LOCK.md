# T1-T20: v4.9 Detection and ML Decision-Support Reliability Lock

## T1 Change Title

v4.9 Detection and ML Decision-Support Reliability Lock

## T2 Requirement

Strengthen parser/rule provenance, label integrity, leakage-safe features, multi-view model evaluation, calibration gates, explanations, and registry clarity without activating a model or enabling response automation.

## T3 Source Evidence

- Runtime: `atdr/app/parsers/paloalto_parser.py`, `atdr/app/detection/*`, `atdr/app/ml/features.py`, `atdr/app/services/alert_service.py`.
- Governance: `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`, v4.0/v4.1 evidence, PRD, traceability, and taskboard.
- Primary references: Palo Alto field docs, Sigma specification, MITRE ATT&CK, UNB CSE-CIC-IDS2018, and scikit-learn validation/calibration documentation listed in `docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md`.

## T4 Current Behavior

Rules and scenario validation existed, but attack mappings overclaimed some low-specificity evidence, correlation was batch-global, feature history could include future/global context, the registry displayed an unregistered active artifact unclearly, and no single strict evaluator covered split stability, calibration, external evidence, and no-write safety.

## T5 Impacted Areas/Agents

Detection/parser, ML/AI Governance, backend/services, React dashboard, QA/UAT, Security/Response Safety, Product/Docs, and Release/Ops.

## T6 Scope

In scope: contracts, parser/rule fixes, source-scoped correlation, causal features, read-only evaluation, explanation provenance, registry wording, tests, docs, and generated ignored diagnostics. Out of scope: model activation/promotion, automatic labeling, response automation, real blocking, schema migration, and deployment.

## T7 Functional Requirements

- Preserve raw evidence and parser failure status.
- Version rule metadata and claim boundaries.
- Keep source/time correlations isolated.
- Keep feature history causal and source-scoped.
- Separate fit/calibration/threshold/final roles.
- Compare required model/rule/anomaly/hybrid strategies.
- Enforce strict FPR, F1, recall, and calibration gates.
- Preserve label provenance and avoid AI-authored human review.
- Expose truthful active/candidate registry state.

## T8 Acceptance Criteria

- 24/24 controlled scenarios pass with zero unexpected alerts/attack types/responses.
- Five split views and all strategies evaluate.
- Leakage audits pass and final labels do not influence development roles.
- Operational DB counts and active artifact remain unchanged.
- Readiness stays conservative when any strict gate fails.
- Full repository verification passes.

## T9 API Contract

No route shape or startup command changes. Existing supervised registry responses retain secret-safe no-promotion/no-automation fields. React wording changes only.

## T10 Data Model / Migration

No schema change and no migration. No database reset or data deletion.

## T11 Backend Plan / Changes

Add a rule catalog and v4.9 evaluator; repair parser field anchoring, attack mapping, source/window correlation, causal bulk feature generation, and explanation provenance; extend held-out partition support.

## T12 Frontend Plan / Changes

Rename registry status to distinguish active artifact presence from unavailable metadata and diagnostic candidates. Keep response automation visibly disabled.

## T13 Security / Response / AI Safety

Evaluation is read-only, does not write labels/models/artifacts, and cannot create response actions. Generated evidence remains ignored. Provider labels remain non-human and non-importable. No production claim is allowed.

## T14 Test Plan

Catalog alignment, parser trailing fields, source/time correlation, scalar/bulk feature equivalence, causal/future-safe windows, explanation provenance, partition disjointness, threshold isolation, strict calibration, no activation, no response, controlled scenarios, React regression, and full release gate.

## T15 Implementation Summary

Implemented versioned taxonomy/rule/label contracts, corrected overclaims, source-scoped five-minute rules, causal source-scoped feature generation, unified five-split evaluator, strict gates, provider manifest, honest explanations, and registry wording.

## T16 Tests Run / Evidence

Focused v4.9, parser, rule, scenario, registry, and performance tests passed. Recovery revalidation on 2026-07-22 reproduced the five-split `candidate_only` result without database or artifact changes. Ruff, compileall, and Alembic checks passed; the full backend suite passed `632 passed, 1 skipped`; React lint/build passed; Playwright passed `25 passed, 1 skipped`; the controlled scenario matrix passed `24/24`; assistant QA passed `20/20`; replay dry-run wrote zero rows; performance smoke had no warnings; and the release gate returned `ok: true`. The recovery also repaired two stale pre-sanitization API test expectations and removed MFU-specific identifiers from tracked demo/syslog fixtures.

## T17 PRD / Docs Updated

`docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md`, taxonomy, rule/label standards, rule/scenario contracts, current AI/ML status, PRD, traceability, compliance checklist, docs index, taskboard, and commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- Risk: one physical firewall prevents true source-disjoint validation.
- Blocker: no candidate passes every strict internal split.
- Blocker: locked external FPR remains 1.0.
- Assumption: zone holdout is a proxy only.
- Decision: retain `candidate_only`; do not activate or promote.

## T19 Release / Rollback

Runtime changes are additive and can be reverted file-by-file. No data rollback is required because there is no migration or write. Generated reports can be removed without affecting runtime. No commit/push is authorized by this change record.

## T20 Final Handoff

- Status: implementation and local verification complete; readiness remains `candidate_only`.
- Behavior: safer rule semantics, source/causal feature context, read-only reliability evaluation, and clearer registry.
- Remaining risks: independent multi-device evidence, schema transfer, calibration, and external validation.
- Next command: `.\.venv\Scripts\python.exe -m atdr.scripts.run_v49_detection_ml_reliability --pretty`.
