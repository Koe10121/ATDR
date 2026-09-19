# T1-T20: v5.67 Signal-Concentrated (Fourth-Tier) Comparable Evidence Expansion

## T1 Change Title

- Title: A fourth governed evidence-expansion tier, built on the locked
  v562+v563+v565 1,500-row pack, with coverage-group weighting re-calibrated
  to the categories that ACTUALLY produced threat-positive decisions across
  all genuine review so far -- dropping a category v5.65 had wrongly
  included
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; new capability, not a fix.

## T2 Requirement

After the project owner genuinely, independently reviewed all 500 v5.65
rows (on top of the already-reviewed 1,000 v562+v563 rows), the combined
qualification gates showed `threat_positive_rows: 79/100 fail` (up from
`47/100`, still short by 21) and `real_source_identities: 1/2 fail`
(structural, unrelated to review volume). The project owner explicitly
chose to keep pushing on `threat_positive_rows` (the only gate still
reachable through review) via `AskUserQuestion`, and separately confirmed a
`500`-row target size for this tier (matching v5.65's size) over a smaller
`300`-row attempt or an open-ended dynamic-sizing approach.

## T3 Source Evidence

Before writing any code, computed the ACTUAL per-coverage-group
threat-positive rate across all 1,455 development-role rows reviewed so far
(v562+v563+v565 combined, sealed-role rows correctly excluded to match the
real gate math):

| coverage_group | rows | threat-positive | rate |
| --- | ---: | ---: | ---: |
| unknown_transport_context | 235 | 33 | 14.0% |
| incomplete_transport_context | 241 | 24 | 10.0% |
| high_activity_context | 241 | 19 | 7.9% |
| boundary_context | 173 | 2 | 1.2% |
| vendor_security_context | 230 | 1 | 0.4% |
| routine_service_context | 171 | 0 | 0.0% |
| web_transport_context | 164 | 0 | 0.0% |

This falsified one of v5.65's own design assumptions: `vendor_security_context`
was included in v5.65's `HIGH_YIELD_COVERAGE_GROUPS` (weighted 3x, 97 rows
sampled from it) on the strength of the original 1,000-row v562+v563 sample,
but it produced **zero** new threat-positive rows in that 500-row round --
it was not actually predictive, just correlated in a smaller sample. The
three categories that are actually predictive
(`unknown_transport_context`, `incomplete_transport_context`,
`high_activity_context`) together account for 76 of the 79 threat-positive
rows found so far (96.2%).

Also re-read `v565_extended_evidence_expansion.py` (the immediately-prior
tier) in full to mirror its exact protocol-lock, digest-guard,
family-dedup, and role-target patterns for the new tier, rather than
inventing a divergent design.

## T4 Current Behavior (before this change)

`threat_positive_rows` sat at `79/100`; the only lever left to close it is
another human-reviewed evidence tier, but the existing v5.65 weighting
scheme was already known (from its own real run's results) to be
mis-calibrated -- continuing to weight `vendor_security_context` would
waste review capacity on a category with no observed signal.

## T5 Impacted Areas / Agents

New `atdr/app/detection/v567_signal_concentrated_evidence_expansion.py`,
new `atdr/app/services/v567_signal_concentrated_expansion_review_service.py`,
new `atdr/scripts/run_v567_signal_concentrated_evidence_expansion.py`, new
`atdr/tests/test_v567_signal_concentrated_evidence_expansion.py`. Extended
(not duplicated) `atdr/app/services/supervised_review_worksheet_service.py`
and `atdr/scripts/export_supervised_review_worksheet.py` to add `v567` as a
fourth `--workspace` option. Extended
`atdr/tests/test_supervised_review_worksheet_service.py` with a v567 case.
Also extended `atdr/app/detection/single_source_development_evaluation.py`
(and its CLI/tests) to include v567's reviewed rows in the combined
development-only signal check, alongside v562/v563/v565.

## T6 Scope

In scope: a fifth append-only tier built on top of the validated v565
protocol (which itself validates v563, which validates v562), excluding
every row already consumed by v562, v563, or v565 (checked against all
three source-shape token formulas), with the same chronological role split,
prediction-blind selection, and immutable digest-guarded protocol lock. The
one deliberate design change from v5.65: `HIGH_YIELD_COVERAGE_GROUPS` drops
`vendor_security_context` and keeps only the three empirically-confirmed
categories, and `COVERAGE_GROUP_ROUND_ROBIN_WEIGHT` is raised from `3` to
`5` to restore a similar ~80% concentration ratio with one fewer
high-weight category. Target size: `500` rows across `5` batches
(`TARGET_SIGNAL_ROWS`), the project owner's explicit choice via
`AskUserQuestion` over a smaller `300`-row attempt or dynamic sizing. Out
of scope: touching v562/v563/v565's own locked packs, changing any fixed
gate, using any rule/model prediction on the new candidate rows to select
or label them, or claiming an official qualification result.

## T7 Functional Requirements

- Fails closed unless the v562+v563+v565 boundary validates as exactly
  `1,500` combined rows (`EXPECTED_COMBINED_ROWS`).
- Excludes a candidate row if its computed review-token, under *any* of the
  v562, v563, or v565 projection formulas, already appears in the combined
  set of consumed tokens -- mirroring the exact mechanism v565 used against
  v562+v563, extended to three prior tiers.
- The coverage-group weighting is a disclosed, code-level constant
  (`HIGH_YIELD_COVERAGE_GROUPS`, `COVERAGE_GROUP_ROUND_ROBIN_WEIGHT`)
  computed from the human reviewer's own already-recorded independent
  decisions across all three prior tiers -- never from a model or rule
  prediction evaluated on the new candidate rows themselves.
  `predictions_used_for_selection`, `model_scores_used_for_selection`, and
  `rules_used_as_labels` remain hardcoded `False`, identical to
  v562/v563/v565.
- Every result carries the same mandatory disclosure fields as prior tiers:
  `training_allowed: false`, `activation_allowed: false`,
  `evaluation_labels_accessible: false`, `rules_alert_authoritative: true`,
  `response_mode: simulation_only`.

## T8 Acceptance Criteria

New tests prove: the coverage-group round-robin order replicates high-yield
groups `COVERAGE_GROUP_ROUND_ROBIN_WEIGHT` (`5`) times relative to others;
`vendor_security_context` is confirmed absent from the new high-yield set;
selection still excludes the sealed evaluation role and de-dupes families;
selection excludes rows already consumed by *any* of v562's, v563's, or
v565's token formula; a synthetic append-only protocol correctly reports
`total_comparable_capacity` as the sum of the locked `1,500`-row pack plus
the new rows; the public status reports combined gates spanning all four
tiers; and a full review-service round trip (start batch, save an item,
read status) works end to end. The CSV worksheet tool's `v567` branch and
the single-source development evaluation's v567 inclusion are each covered
by a dedicated test. (7 detection/service tests, 1 worksheet test, 1
single-source-evaluation test = 9 new tests.)

## T9 API Contract

None -- CLI-only, matching v562/v563/v565's own scope decision. New CLI:
`atdr.scripts.run_v567_signal_concentrated_evidence_expansion` with
`--sample-path`, `--use-temp-db`, `--preflight-only`,
`--prepare-signal-review`, `--confirm`, `--signal-limit`, `--batch-size`,
`--output-dir`, `--status-only`, `--pretty`. The existing
`export_supervised_review_worksheet.py` / `import_supervised_review_worksheet.py`
CLIs now also accept `--workspace v567` (or the existing `all` default,
which now covers all four tiers). `run_single_source_development_evaluation.py`
now also accepts `--v567-output-dir`.

## T10 Data Model / Migration

None. Same as prior tiers: local CSV + JSON files outside the configured
database, in a new `ml_baseline_reviews/v5_67_evidence_expansion/`
directory.

## T11 Backend Plan / Changes

`_v565_boundary_snapshot` replaces v5.65's `_v563_boundary_snapshot` role:
it validates v5.65's own protocol (which transitively validates v563, which
validates v562), reads all three sealed packs directly to build the
combined token/role-count picture, and asserts the combined row count
(`1,500`). `select_signal_concentrated_review_candidates` mirrors v5.65's
selection exactly except for two changes: triple token-formula exclusion
(checking v562, v563, AND v565 token shapes) and the re-calibrated
`_coverage_round_robin_order` constants. The main run function replays
THREE sequential quarantine-then-reaggregate phases (v562, then v563, then
v565) before computing v567's own candidate tokens, since each prior tier's
coverage-group/aggregate features were computed only after the earlier
tier(s)' families were already quarantined -- reconstructing them correctly
requires replaying that exact construction order, not a flat single pass
(the same lesson learned and fixed during v5.65's own build). Everything
else (digest guards, atomic CSV/JSON writes, `_assert_pack_contract` reuse,
disposable SQLite streaming via `v56`/`v545`/`v547`) is reused directly
from `v562` exactly as v563 and v565 already do, not reimplemented.

## T12 Frontend Plan / Changes

None, by the same reasoning as v563/v565: this is a CLI-only research tool
for the project owner, and the existing CSV worksheet workflow already
covers it without implying it's part of the governed analyst-facing
product.

## T13 Security / Response / AI Safety

No detection, response, or Assistant authority is touched. No model
artifact is ever written. The sealed `untouched_future_evaluation` role
from v562, v563, and v565 remains excluded at the earliest possible stage
(role-rank check before any coverage-group bucketing), and the
coverage-group weighting never influences which decision a human records --
it only changes which rows are shown to them, and every row is still
reviewed fully blind to any prediction, exactly as before.

## T14 Test Plan

`atdr/tests/test_v567_signal_concentrated_evidence_expansion.py` (7 tests):
round-robin weighting, confirmation that `vendor_security_context` is no
longer high-yield, evaluation-role/duplicate-family exclusion, triple-tier
consumed-evidence exclusion, append-only protocol construction on a
synthetic locked v562+v563+v565 base, combined-gate status reporting across
all four tiers, and a full review-service round trip.
`atdr/tests/test_supervised_review_worksheet_service.py`: one new test for
the `v567` export/import branch. `atdr/tests/test_single_source_development_evaluation.py`:
one new test proving v567 rows are pulled into the combined development
pool. Full backend suite re-run afterward.

## T15 Implementation Summary

One new ~700-line detection module, one new ~450-line review service, one
~70-line CLI, one new ~250-line test file, plus small additive extensions
to the existing worksheet CSV tool, the single-source development
evaluation module, and their respective tests. Zero changes to v562's,
v563's, or v565's own behavior -- this only reads their locked output.

## T16 Tests Run / Evidence

`test_v567_signal_concentrated_evidence_expansion.py`: `7 passed`.
`test_supervised_review_worksheet_service.py`: `10 passed` (1 new).
`test_single_source_development_evaluation.py`: `7 passed` (1 new). `ruff
check .` and `compileall` clean across the full repository. Full backend
suite: `1190 passed, 1 skipped` (up from the `1181` prior confirmed
baseline: +9 new tests). Real run against the live source: preflight
confirmed the supplied file matches the locked `1,500`-row boundary
exactly; the real preparation selected `500/500` rows across `5` batches of
`100`, with coverage counts `high_activity_context: 138,
incomplete_transport_context: 133, unknown_transport_context: 125` (the 3
re-weighted groups, 396/500 = 79.2% of the pack) vs `boundary_context: 28,
routine_service_context: 26, vendor_security_context: 25,
web_transport_context: 25` (~20.8%, each now at parity rather than
`vendor_security_context` getting a 3x share it did not earn); worksheet
exported (`500` rows, `0` warnings) for the project owner's independent
review.

## T17 PRD / Docs Updated

This change record only. The official supervised qualification status is
unchanged by this record alone -- it only becomes relevant once the
project owner reviews the newly-selected rows; see the taskboard for the
live gate numbers after that review happens.

## T18 Risks / Blockers / Assumptions / Decisions

The `500`-row target and the `5x` weighting factor are both judgment calls,
not derived from a formal power calculation -- real threat-traffic
incidence in the untouched portion of the source remains unknown until
sampled, and yield may decline further as these categories get sampled
repeatedly across tiers. If `500` weighted rows still don't reach `100`
threat-positive decisions, the same pattern can be repeated as a further
tier on top of v5.67's own lock. The `real_source_identities: 1/2` gate
remains permanently outside this module's reach; no amount of additional
review of the same physical source can close it.

## T19 Release / Rollback

Fully reversible: delete the new files and the
`ml_baseline_reviews/v5_67_evidence_expansion/` directory (gitignored, no
data ever enters git). No migration, no database write, no artifact
touched, no existing file's behavior changed.

## T20 Final Handoff

The real preparation has already run against the live private source
(`ok: true`, `status: ready_for_batched_human_review`); the CSV worksheet
(`ml_baseline_reviews/review_worksheet_v567.csv`, gitignored) has been
exported with all `500` rows and `0` warnings for the project owner's
independent review, exactly like v562/v563/v565.
