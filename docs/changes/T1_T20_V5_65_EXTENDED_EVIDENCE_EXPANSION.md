# T1-T20: v5.65 Extended (Third-Tier) Comparable Evidence Expansion

## T1 Change Title

- Title: A third governed evidence-expansion tier, built on the locked
  v562+v563 1,000-row pack, with coverage-group selection weighted toward the
  categories that empirically produced threat-positive human decisions
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; new capability, not a fix.

## T2 Requirement

After the project owner genuinely, independently reviewed all 1,000 rows
across the locked v562 (300) and v563 (700) packs, the combined qualification
gates showed `independent_comparable_rows: 1000/1000 pass` but
`threat_positive_rows: 47/100 fail`. The 1,000-row pool is fixed and fully
consumed — no more rows can come from it. Closing this gate requires a new,
equally rigorous evidence tier, explicitly confirmed by the project owner
after being told the real scope (comparable to rebuilding v563) via
`AskUserQuestion` before any code was written.

## T3 Source Evidence

Direct reading of `v563_fresh_evidence_expansion.py` (1,545 lines) and
`v563_supervised_expansion_review_service.py` (686 lines) in full, to mirror
their exact protocol-lock, digest-guard, family-dedup, and role-target
patterns rather than inventing a divergent design. A dedicated research pass
(Explore agent) confirmed: no third-tier module or scaffolding existed;
`total_comparable_capacity` is a derived report value, not an enforced
ceiling (the actual fixed gate is `>=`, a floor); v562/v563 selection is
already coverage-group-stratified but explicitly not threat/label-aware
(`predictions_used_for_selection`, `rules_used_as_labels` hardcoded `False`);
and the `coverage_group` categories themselves already trace to rule-like
risk heuristics (scan-like, high-risk app, unknown transport, etc.).

## T4 Current Behavior (before this change)

No mechanism existed to add more comparable rows once v563's 700-row cap
was reached. `threat_positive_rows` had no path to `100` other than hoping
the fixed 1,000-row sample happened to contain enough naturally-occurring
suspicious/malicious traffic (real PAN-OS telemetry is heavily benign-skewed:
47/1000 ≈ 4.7% in the actual reviewed data).

## T5 Impacted Areas / Agents

New `atdr/app/detection/v565_extended_evidence_expansion.py`, new
`atdr/app/services/v565_extended_expansion_review_service.py`, new
`atdr/scripts/run_v565_extended_evidence_expansion.py`, new
`atdr/tests/test_v565_extended_evidence_expansion.py`. Extended (not
duplicated) `atdr/app/services/supervised_review_worksheet_service.py` and
`atdr/scripts/export_supervised_review_worksheet.py` to add `v565` as a third
`--workspace` option (and rename the "both" default to "all", covering all
three tiers) so the existing CSV worksheet tool works against this tier
without any new UI. Extended
`atdr/tests/test_supervised_review_worksheet_service.py` with a v565 case.

## T6 Scope

In scope: a fourth append-only tier built on top of the validated v563
protocol (which itself validates v562), excluding every row already consumed
by v562 or v563 (checked against both source-shape token formulas, not just
family strings, exactly mirroring how v563 excluded v562's evidence), with
the same chronological role split, prediction-blind selection, and immutable
digest-guarded protocol lock. The one deliberate design change: round-robin
coverage-group allocation gives categories in `HIGH_YIELD_COVERAGE_GROUPS`
(`vendor_security_context`, `high_activity_context`,
`incomplete_transport_context`, `unknown_transport_context`) a 3x larger
share than the three categories that produced zero threat-positive decisions
across all 1,000 prior rows (`boundary_context`, `routine_service_context`,
`web_transport_context`), while still guaranteeing every category is
represented. Target size: 500 rows across 5 batches (`TARGET_EXTENDED_ROWS`),
a judgment call sized similarly to a v563 batch round, not a guarantee of
closing the gate in one pass. Out of scope: touching v562/v563's own locked
packs, changing any fixed gate, using any rule/model prediction on the new
candidate rows to select or label them, or claiming an official qualification
result.

## T7 Functional Requirements

- Fails closed unless the v562+v563 boundary validates as exactly 1,000
  combined rows (`EXPECTED_COMBINED_ROWS`).
- Excludes a candidate row if its computed review-token, under *either* the
  v562 projection formula or the v563 projection formula, already appears in
  the combined set of consumed tokens — mirroring the exact mechanism v563
  used against v562, extended to two prior tiers.
- The coverage-group weighting is a disclosed, code-level constant
  (`HIGH_YIELD_COVERAGE_GROUPS`, `COVERAGE_GROUP_ROUND_ROBIN_WEIGHT`) computed
  from the human reviewer's own already-recorded independent decisions on
  this same source — never from a model or rule prediction evaluated on the
  new candidate rows themselves. `predictions_used_for_selection`,
  `model_scores_used_for_selection`, and `rules_used_as_labels` remain
  hardcoded `False`, identical to v562/v563.
- Every result carries the same mandatory disclosure fields as v562/v563:
  `training_allowed: false`, `activation_allowed: false`,
  `evaluation_labels_accessible: false`, `rules_alert_authoritative: true`,
  `response_mode: simulation_only`.

## T8 Acceptance Criteria

New tests prove: the coverage-group round-robin order actually replicates
high-yield groups `COVERAGE_GROUP_ROUND_ROBIN_WEIGHT` times relative to
others; selection still excludes the sealed evaluation role and de-dupes
families exactly like v563; selection excludes rows already consumed by
*either* v562's or v563's token formula; a synthetic append-only protocol
correctly reports `total_comparable_capacity` as the sum of the locked
combined rows plus the new rows; the public status reports combined gates
spanning all three tiers; and a full review-service round trip (start batch,
save an item, read status) works end to end. The CSV worksheet tool's `v565`
branch is covered by a dedicated export/import test.

## T9 API Contract

None — CLI-only, no HTTP endpoint or frontend surface, matching v563's own
scope decision (a research/evidence-preparation tool for the project owner,
not an analyst-facing feature). New CLI:
`atdr.scripts.run_v565_extended_evidence_expansion` with `--sample-path`,
`--use-temp-db`, `--preflight-only`, `--prepare-extended-review`, `--confirm`,
`--extended-limit`, `--batch-size`, `--output-dir`, `--status-only`,
`--pretty`. The existing `export_supervised_review_worksheet.py` /
`import_supervised_review_worksheet.py` CLIs now also accept
`--workspace v565` (or the new default `all`, covering v562+v563+v565).

## T10 Data Model / Migration

None. Same as v562/v563: local CSV + JSON files outside the configured
database, in a new `ml_baseline_reviews/v5_65_evidence_expansion/` directory.

## T11 Backend Plan / Changes

`_v563_boundary_snapshot` replaces v563's `_v562_snapshot` role: it validates
v563's own protocol (which transitively validates v562's), reads both sealed
packs directly to build the combined token/role-count picture, and asserts
the combined row count. `select_extended_review_candidates` mirrors
`select_supplemental_review_candidates` exactly except for two changes: dual
token-formula exclusion (checking both `v562._candidate_projection` and
`v563._supplemental_projection` token shapes) and the weighted
`_coverage_round_robin_order` helper in place of v563's plain
`sorted(buckets...)`. `_role_targets` generalizes v563's hardcoded
`{150, 60, 45}` dict into a parameter computed at runtime from the actual
combined v562+v563 role counts, since v565 depends on two prior tiers'
realized splits rather than one fixed constant. Everything else (digest
guards, atomic CSV/JSON writes, `_assert_pack_contract` reuse, disposable
SQLite streaming via `v56`/`v545`/`v547`) is reused directly from `v562`
exactly as v563 already does, not reimplemented.

## T12 Frontend Plan / Changes

None, by the same reasoning as v563 (`docs/changes/T1_T20_V5_63_FRESH_COMPARABLE_EVIDENCE_EXPANSION.md`
equivalent decision): this is a CLI-only research tool for the project owner,
and the existing CSV worksheet workflow already covers it without implying
it's part of the governed analyst-facing product.

## T13 Security / Response / AI Safety

No detection, response, or Assistant authority is touched. No model artifact
is ever written. The sealed `untouched_future_evaluation` role from both
v562 and v563 remains excluded at the earliest possible stage (role-rank
check before any coverage-group bucketing), and the coverage-group weighting
never influences which decision a human records — it only changes which rows
are shown to them, and every row is still reviewed fully blind to any
prediction, exactly as before.

## T14 Test Plan

`atdr/tests/test_v565_extended_evidence_expansion.py` (6 tests): round-robin
weighting, evaluation-role/duplicate-family exclusion, dual-tier consumed-
evidence exclusion, append-only protocol construction on a synthetic locked
v562+v563 base, combined-gate status reporting, and a full review-service
round trip. `atdr/tests/test_supervised_review_worksheet_service.py`: one
new test for the `v565` export/import branch. Full backend suite re-run
afterward.

## T15 Implementation Summary

One new ~640-line detection module, one new ~430-line review service, one
~65-line CLI, one new ~245-line test file, plus small additive extensions to
the existing worksheet CSV tool and its tests. Zero changes to v562's or
v563's own behavior — this only reads their locked output.

## T16 Tests Run / Evidence

`test_v565_extended_evidence_expansion.py`: `6 passed`.
`test_supervised_review_worksheet_service.py`: `9 passed` (1 new). `ruff
check .` and `compileall` clean across the full repository. Full backend
suite result recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

This change record only. The official supervised qualification status is
unchanged by this record alone — it only becomes relevant once the project
owner reviews the newly-selected rows; see the taskboard for the live
gate numbers after that review happens.

## T18 Risks / Blockers / Assumptions / Decisions

The `TARGET_EXTENDED_ROWS = 500` size and the `3x` weighting factor are both
judgment calls, not derived from a formal power calculation — real threat
traffic incidence in the untouched portion of the source is unknown until
sampled. If 500 rows (weighted) still don't reach 100 threat-positive
decisions, the same pattern can be repeated as a further tier (a "v567") on
top of v565's own lock, without touching anything already reviewed. The
`real_source_identities: 1/2` gate remains permanently outside this module's
reach; no amount of additional review of the same physical source can close
it.

## T19 Release / Rollback

Fully reversible: delete the new files and the
`ml_baseline_reviews/v5_65_evidence_expansion/` directory (gitignored, no
data ever enters git). No migration, no database write, no artifact touched,
no existing file's behavior changed.

## T20 Final Handoff

Ready to run against the real private source with `--use-temp-db
--prepare-extended-review --confirm PREPARE_V565_EXTENDED_EVIDENCE_EXPANSION`.
Once prepared, the existing CSV worksheet tool (`--workspace v565` or the new
`all` default) exports the new rows for the project owner's independent
review, exactly like v562/v563.
