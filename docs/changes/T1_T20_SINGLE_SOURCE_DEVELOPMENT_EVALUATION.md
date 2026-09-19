# T1-T20: Single-Source Supervised Development Evaluation

## T1 Change Title

- Title: New, honestly-scoped single-source supervised development
  evaluation (explicitly not a qualification decision)
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; new capability, not a fix to existing
  published behavior.

## T2 Requirement

The project owner confirmed no second physical PAN-OS source is realistically
obtainable right now and asked what is still honestly possible toward
supervised ML. `FIXED_PROMOTION_GATES["minimum_real_source_identities"] = 2`
in `v530_supervised_evidence_closure.py` is a hard, unconditional threshold
with no waiver path, and this project's own governance explicitly forbids
weakening a fixed gate after the fact — so the official qualification
decision cannot be reached with one source, full stop. What *can* be
answered honestly: once genuine human-reviewed rows exist in the existing
v5.62/v5.63 protected workspaces, does a simple classifier show any
development-only signal on this one source, using a proper chronological
split, without ever touching the sealed evaluation role reserved for the
official campaign.

## T3 Source Evidence

Direct reading of `v562_supervised_qualification_campaign.py` (confirmed:
prepares evidence and manages review only — no training/evaluation code
exists there or anywhere else for this campaign, because review has been at
0/1,000 since it was created), `v563_fresh_evidence_expansion.py` (confirmed
the same 4-role chronological structure: `development_fit`, `calibration`,
`threshold_selection`, and the sealed `untouched_future_evaluation`),
`v549b_combined_fixed_revalidation.py` (confirmed this is a *different*,
already-consumed evidence pack, not reusable here), and
`supervised_detector.py` (`_optional_imports`, `_model_for_type`,
`_metrics_from_predictions`, `_feature_importances` — reused directly rather
than reimplemented).

## T4 Current Behavior (before this change)

No code existed to train or evaluate anything against the v5.62/v5.63
reviewed rows — only to prepare the evidence and manage the review workflow.
This was never built because review never progressed past 0/1,000, so there
was nothing to evaluate.

## T5 Impacted Areas / Agents

New `atdr/app/detection/single_source_development_evaluation.py`, new
`atdr/scripts/run_single_source_development_evaluation.py`, new
`atdr/tests/test_single_source_development_evaluation.py`. Also
incidentally found and fixed a fifth instance of the zone-classification
substring bug in `atdr/app/ml/features.py` while designing this module's
feature set — recorded in
`docs/changes/T1_T20_RULE_ENGINE_ZONE_CLASSIFICATION_FIX.md`, not duplicated
here.

## T6 Scope

In scope: a read-only-to-the-database, disposable evaluator that (1) reads
only the `working` CSV of the v5.62 and v5.63 protected review workspaces,
(2) uses only rows already marked `human_reviewed` in a development role,
(3) trains a simple classifier on `development_fit` and reports metrics
only on the other development-role rows, (4) never reads, counts, or reports
anything about the sealed `untouched_future_evaluation` role, and
(5) structurally marks every output as not a qualification decision. Out of
scope, explicitly: anything that touches the sealed role, any database
write, any model artifact, any change to the official campaign's own gates
or protocol, and any claim of cross-device generalization.

## T7 Functional Requirements

- Fails closed without `--use-temp-db`.
- Fails closed (`insufficient_reviewed_data`) below a minimum of 20 total
  reviewed development-role rows and 5 per class — thresholds chosen to be
  far below and structurally incapable of being confused with the official
  campaign's fixed gates (1,000 rows, 100/class, 2 sources), stated in the
  output itself.
- Fails closed (`insufficient_role_split`) if reviewed rows exist but are
  not yet spread across `development_fit` and at least one other
  development role, since there would be nothing to evaluate against.
- Applies the same integrity validation
  (`validate_campaign_protocol`/`validate_expansion_protocol`) the official
  review services use before trusting the working CSV, for defense in depth.
- Every result unconditionally includes `qualification_decision: false`,
  `single_source_only: true`, `cross_device_generalization_established: false`,
  `sealed_evaluation_role_accessed: false`, and zero-value safety counters
  (database writes, model artifacts, alerts, response actions) — these are
  hardcoded return values, not something a caller or a future edit could
  accidentally flip without touching this file directly.

## T8 Acceptance Criteria

New tests prove: the insufficient-data path reports correctly with zero real
rows; a sealed row marked reviewed (which the official service should never
allow, but this module defends against anyway) is never loaded or counted;
`--use-temp-db` is enforced; a synthetic but structurally realistic set of
26 reviewed rows across three development roles trains successfully, splits
train/test exactly along the existing role boundaries, and reports metrics
plus the mandatory disclosure fields; a role-split-insufficient case (all
reviews in one role) is correctly refused. Full backend suite passes
unchanged otherwise, since this module is entirely new and additive.

## T9 API Contract

None — CLI-only, no HTTP endpoint. New CLI:
`atdr.scripts.run_single_source_development_evaluation` with `--status-only`,
`--use-temp-db`, `--model-type`, `--v562-output-dir`, `--v563-output-dir`,
`--pretty`.

## T10 Data Model / Migration

None. No database interaction at all — this module only reads two local CSV
files that already exist outside the configured database.

## T11 Backend Plan / Changes

Reuses `supervised_detector._optional_imports`, `_model_for_type`,
`_metrics_from_predictions`, and `_feature_importances` directly rather than
reimplementing them. Builds its own `ColumnTransformer`-based pipeline over
a feature set drawn only from `APPROVED_EVIDENCE_FIELDS` (the fields already
present in the protected review export), since the full production feature
set (`build_log_features`) requires live windowed-history queries against
the original private evidence that the review workspace deliberately does
not retain. Two zone-derived flags reuse the canonical, now-fixed
`is_outside_to_inside`/`is_internal_to_external` from `rules.py` via a
lightweight `SimpleNamespace` adapter, rather than a third reimplementation.

## T12 Frontend Plan / Changes

None. This is a CLI-only research tool for the project owner, not an
analyst-facing dashboard feature — surfacing it in the UI would risk
implying it is part of the governed workflow, which it deliberately is not.

## T13 Security / Response / AI Safety

No detection, response, or Assistant authority is touched. No model
artifact is ever written, so there is no path from this module to
`active_advisory`/`active_shadow` runtime state. The sealed evaluation role
is excluded at the data-loading stage, before any feature engineering or
training occurs, so no downstream code path in this module can access it
even by a future bug in a different function.

## T14 Test Plan

`atdr/tests/test_single_source_development_evaluation.py`: insufficient-data
status, sealed-role defense-in-depth, missing-acknowledgement refusal, a
full successful run against synthetic multi-role data (verifying the exact
train/test row counts, the mandatory disclosure fields, and that metrics are
computed only over `benign_like`/`threat_positive` labels), and an
insufficient-role-split case. Full backend suite re-run in full afterward.

## T15 Implementation Summary

One new ~340-line module, one ~60-line CLI, one new test file (5 tests).
Zero changes to any existing file's behavior except the incidental
`features.py` zone-bug fix recorded separately.

## T16 Tests Run / Evidence

`atdr/tests/test_single_source_development_evaluation.py`: `5 passed`.
CLI verified manually against the real (currently empty) protected
workspaces: correctly reports `total_reviewed_development_rows: 0`,
`ready: false`, and every mandatory disclosure field, with zero errors and
zero database access. Full backend suite result recorded in
`docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

This change record only, plus the separately-recorded `features.py` fix.
No PRD/traceability/compliance claim changes: the official supervised
qualification status remains exactly `unqualified`, `0/1,000` reviewed,
`1/2` sources — this module does not change any of those numbers or claims,
it only adds a way to honestly report a narrower, explicitly-labeled
side-finding once review data exists.

## T18 Risks / Blockers / Assumptions / Decisions

The feature set here is narrower than the production `build_log_features`
pipeline (no 5/15/60-minute windowed history, since the review export
deliberately does not retain per-row surrounding context to keep the
protected workspace self-contained and disposable). This is disclosed in
the module's own docstring and output rather than worked around, since
reconstructing that context would mean re-touching the original private
evidence outside the already-locked review contract. The minimum-row
thresholds (20 total, 5/class) are a judgment call, deliberately generous
enough to let a first honest signal be measured soon after review begins,
while remaining structurally incapable of being mistaken for the official
1,000-row/100-per-class gates because every output states both sets of
numbers side by side.

## T19 Release / Rollback

Fully reversible: delete the three new files. No migration, no data
written, no artifact touched, no existing file's behavior changed by this
change record (the separate `features.py` fix is independently reversible
per its own change record).

## T20 Final Handoff

Not runnable to a meaningful result yet — `0/1,000` reviewed rows currently
exist. Ready to produce a real, honestly-labeled development-only signal the
moment the project owner has reviewed roughly 20+ rows spanning
`development_fit` and at least one other development role, using the
keyboard-accelerated review workflow from
`docs/changes/T1_T20_SUPERVISED_REVIEW_KEYBOARD_ACCELERATION.md`. Does not
and cannot substitute for the official qualification decision, which remains
blocked on genuine 1,000-row review and a second physical source.
