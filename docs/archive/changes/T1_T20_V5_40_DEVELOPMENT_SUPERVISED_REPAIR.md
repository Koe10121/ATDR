# T1-T20: v5.40 Development-Only Supervised Model Repair

## T1 Change Title

v5.40 Development-Only Supervised Model Repair and New Evidence Design.

## T2 Requirement

Repair supervised SOC queue diagnostics using only eligible development
evidence, permanently exclude consumed v5.39 evidence, and design a new
untouched validation protocol without changing model or alert authority.

## T3 Source Evidence

The private v5.39 frozen state and sealed pack boundary; existing v5.2/v5.4/
v5.5 dataset, partition, calibration, and safety helpers; current configured
reviewed evidence; supervised feature pipeline; model artifact and database
state counters; current AI training runbook and lifecycle contracts.

## T4 Current Behavior

v5.39 consumed one final evidence set and rejected activation. Earlier repair
experiments did not permanently enforce that consumed boundary in a dedicated
new development contract. Current labels are single-source, temporally
concentrated, duplicate-bearing, and include assisted provenance.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, security/privacy, QA, Release/Ops,
documentation, and future genuine human review.

## T6 Scope

Consumed-evidence exclusion, development audit, feature repair, six-strategy
comparison, nested temporal and duplicate-group validation, calibration,
fixed thresholds, aggregate error analysis, candidate gating, blind-evidence
design, tests, governance, taskboard, and exact allowlist.

Model activation/promotion, active artifact writes, label creation/overwrite,
v5.39 reevaluation, rule changes, response automation, real blocking, and
database schema changes are out of scope.

## T7 Functional Requirements

- Fail closed if the v5.39 freeze or sealed pack changes.
- Read only exclusion tokens, never protected labels/predictions/errors.
- Remove any token match before every modeling role.
- Audit provenance, class balance, sources, duplicates, missingness, and time.
- Add causal or row-local robust evidence features without a hard guard.
- Compare six required strategies on nested isolated folds.
- Calibrate only on dedicated development partitions.
- Select thresholds only from predefined profiles and threshold roles.
- Freeze at most one metadata-only diagnostic configuration if every gate
  passes; otherwise freeze nothing.
- Design a future disjoint pack with no predictions or automatic labels.

## T8 Acceptance Criteria

Zero protected v5.39 rows in fit/calibration/threshold/model selection; leakage
audit passes; all six strategies are evaluated; sigmoid/isotonic behavior and
fixed thresholds are reported; no configured count or artifact changes; no
private row data is returned; readiness stays conservative.

## T9 API Contract

No API changes. v5.40 is a local operator diagnostic CLI and tracked
governance contract.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Optional diagnostic reports are
ignored under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the v5.40 evaluator and CLI, reuse established canonical partitions and
nested temporal folds, rebuild duplicate groups after feature augmentation,
apply provenance-aware sample weighting, compare the six strategies, and
verify all authority state before and after execution.

## T12 Frontend Plan / Changes

No frontend behavior changes. The current AI Governance lifecycle remains
`shadow_observation`.

## T13 Security / Response / AI Safety

No raw evidence, source identity, private token, digest, reviewer identity, or
secret in output. No label/model/detection/alert/response write. Rules remain
alert-authoritative; ML remains advisory; response automation and real
blocking remain disabled.

## T14 Test Plan

Test boundary integrity, tamper failure, pre-model exclusion, robust feature
semantics, fixed-threshold isolation, calibration output, duplicate-group fold
isolation, aggregate error privacy, conservative freeze gates, blind-pack
design, and no authority mutation.

## T15 Implementation Summary

Implemented a fail-closed v5.39 boundary, 13-feature evidence-aware extension,
development audit, six-strategy comparison, dedicated calibration, fixed
threshold selection, aggregate FP/FN analysis, conservative metadata freeze,
future blind protocol, CLI, and focused tests.

## T16 Tests Run / Evidence

Focused v5.40 tests pass `11/11`. The measured configured run excludes every
protected role, evaluates 1,467 development rows, changes no database count or
artifact, and calls no v5.39 evaluator. Taskboard checks, Ruff, compileall,
backend/release `938 passed, 1 skipped`, Alembic no drift, React lint/build,
Playwright `35 passed, 1 skipped`, controlled source acceptance, layered
`288/288`, Assistant `20/20`, v5.38 `11/11`, replay dry-run, warning-free
performance, release `ok: true`, privacy, exact allowlist, and tracked hygiene
pass.

## T17 PRD / Docs Updated

v5.40 status, this T1-T20 record, new blind-evidence protocol, current AI/ML
status, AI training runbook, requirement traceability, taskboard Markdown/HTML,
and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Only one source identity exists; 549 rows have assisted/weak provenance; 421
rows belong to multirow duplicate groups; and evidence is concentrated in one
short collection. The best ranking passes zero complete folds, loses too many
threat cases, and remains weakly calibrated. No candidate is frozen.

## T19 Release / Rollback

No commit or push is authorized. Release requires separate approval of the
exact allowlist. Rollback removes the evaluator, CLI, tests, and v5.40 docs;
there is no database, label, model, alert, or response rollback.

## T20 Final Handoff

Preserve v5.39 as consumed evidence and keep lifecycle at
`shadow_observation`. Collect a new future multi-source pack under the v5.40
protocol. Do not call assisted labels human-reviewed, open blind predictions
before review, or activate a model without a new one-shot decision and
separate explicit approval.
