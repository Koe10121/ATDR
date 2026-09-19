# T1-T20: Rule Engine Zone Classification Fix

## T1 Change Title

- Title: Fix substring-based zone direction misclassification in the
  alert-authoritative rule engine
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; fix against the published v5.63.1 baseline
  (`fea2857`). Not part of the uncommitted v5.64 work. A version number and
  commit boundary are for the project owner to assign.

## T2 Requirement

Zone direction classification must correctly classify traffic direction from
`src_zone`/`dst_zone` for any zone-naming convention, including Palo Alto
Networks' own default zone names, everywhere it is used — not only in the
rule engine.

## T3 Source Evidence

Direct reading of `atdr/app/detection/rules.py`, empirical reproduction of
the defect, `atdr/tests/test_rules.py` fixture review (which uses only
`SG-Outside`/`LAN-Inside`/`WLAN-Inside` zone names, never PAN-OS's actual
`trust`/`untrust` defaults), and a repository-wide search for the same
substring pattern (`"untrust" in`) once the first instance was confirmed,
which found two further independent reimplementations of the identical
defect.

## T4 Current Behavior (before fix)

Both direction-classification functions matched zone tokens with a raw
substring check, e.g. `"trust" in dst_zone.lower()`. Because `"untrust"`
contains `"trust"` as a substring, any zone literally named `untrust` — the
literal Palo Alto Networks default outside-zone name — was misread as an
inside zone whenever compared against the `"trust"` token. Confirmed by
direct execution:

```
untrust->untrust  outside_to_inside:      True   (expected False, same zone)
untrust->untrust  internal_to_external:   True   (expected False, same zone)
untrust->outside  internal_to_external:   True   (expected False, untrust is not internal)
```

This fed false directional context into six rules:
`outside_to_inside`, `possible_port_scan`, `possible_horizontal_scan`,
`unusual_destination_port`, `connection_flood_suspicion`, and — the two
highest-value rules in the catalog — `beaconing_like_outbound` (C2-like
detection) and `high_outbound_bytes` (exfiltration suspicion), both of which
require `_is_internal_to_external(log)` to fire.

The existing test suite never exercised this because its fixtures use
non-default zone names (`SG-Outside`/`LAN-Inside`), so the collision between
`"trust"` and `"untrust"` never occurred in any covered scenario.

The identical defect was independently reimplemented in three more places,
found by a repository-wide search after the first fix:

- `atdr/app/detection/explanations.py`'s `explain_log_triage` — the
  "give suggestions" / SOC-Assistant-facing log explanation shown to
  analysts would report a false "external-to-internal direction" signal for
  same-zone `untrust` traffic.
- `atdr/app/services/detection_service.py`'s `_outside_to_inside` (used by
  `_group_key`) — **this one affects actual alert grouping, not just
  explanatory text.** `INTERNET_SWEEP_RULES` matches would have been
  wrongly merged into a single `"multiple-internet-sources"` alert group for
  same-zone `untrust` traffic that never actually crossed a trust boundary,
  and `APP_RISK_POLICY_RULES` matches would have inconsistently skipped the
  `"multiple-app-risk-sources"` merge for the same reason. Neither had any
  existing test coverage at all before this fix.
- `atdr/app/ml/features.py`'s `_zone_contains` (used by both `_behavior_flags`
  and `_bulk_behavior_flags`) — **this one corrupts the actual supervised-model
  feature vector.** `external_to_internal_flag` and `internal_to_external_flag`
  are real training/scoring features (also surfaced in the Assistant's
  behavior-feature explanation), and same-zone `untrust` traffic would have
  produced the wrong value for both flags. Found while designing the
  single-source development evaluation module (see
  `docs/changes/T1_T20_SINGLE_SOURCE_DEVELOPMENT_EVALUATION.md`), since it
  would have corrupted that evaluation's inputs too.

## T5 Impacted Areas / Agents

`atdr/app/detection/rules.py` (alert-authoritative; now the single canonical
source, functions promoted from `_is_outside_to_inside`/
`_is_internal_to_external` to public `is_outside_to_inside`/
`is_internal_to_external`, and `OUTSIDE_ZONE_TOKENS` extended with `"wan"`
to match the broader token set `features.py` already used),
`atdr/app/detection/explanations.py`,
`atdr/app/services/detection_service.py` (alert grouping),
`atdr/app/ml/features.py` (supervised feature vector), all rules and
features gated on these functions, `atdr/tests/test_rules.py`,
`atdr/tests/test_detection_explanations.py`,
`atdr/tests/test_detection_grouping.py`,
`atdr/tests/test_ml_features_zone_fix.py`.

## T6 Scope

In scope: token-based zone matching in all four locations, consolidating
three duplicate reimplementations to import the one canonical (now public)
implementation in `rules.py`, regression tests for all four call sites, full
backend and layered-detection regression. Out of scope: any change to rule
thresholds, scoring weights, or the rule catalog's declared metadata
(`rule_catalog.py` was not touched — its `condition` text already correctly
describes intent, only the implementation's matching mechanism was wrong).

## T7 Functional Requirements

- Zone tokens must be compared as whole tokens, not substrings.
- Existing zone-naming conventions already covered by tests
  (`SG-Outside`/`LAN-Inside`/`WLAN-Inside`) must classify identically to
  before the fix.
- Palo Alto's default `trust`/`untrust` zone names must classify correctly
  in both directions, and same-zone (`untrust`->`untrust`) traffic must not
  be misclassified as crossing a trust boundary in either direction.

## T8 Acceptance Criteria

`_zone_tokens` tokenizes on non-alphanumeric separators; direction checks use
set-intersection against `OUTSIDE_ZONE_TOKENS`/`INSIDE_ZONE_TOKENS` instead of
substring `in` checks. New tests reproduce both the original defect (would
fail against the pre-fix implementation) and confirm no regression for
existing zone-naming fixtures. Full backend suite and layered detection
validation pass after the change.

## T9 API Contract

No API change. Internal detection-layer function behavior only.

## T10 Data Model / Migration

None.

## T11 Backend Plan / Changes

Added `_zone_tokens`, `OUTSIDE_ZONE_TOKENS`, `INSIDE_ZONE_TOKENS` to
`atdr/app/detection/rules.py`; rewrote the two direction predicates to use
token-set intersection and promoted them to public names
(`is_outside_to_inside`, `is_internal_to_external`) since they are now
shared across modules. Removed the duplicate reimplementation in
`explanations.py`'s `explain_log_triage` in favor of importing the canonical
function. Removed the duplicate `_outside_to_inside` in
`detection_service.py` (which already imported other symbols from
`rules.py`) in favor of importing the same canonical function, used by
`_group_key` for both the `INTERNET_SWEEP_RULES` and
`APP_RISK_POLICY_RULES` grouping branches.

## T12 Frontend Plan / Changes

None. No UI change; the fix reduces false directional context feeding
existing rules, which are already displayed as-is.

## T13 Security / Response / AI Safety

No change to rule authority, response policy, or advisory-layer boundaries.
This fix only corrects direction classification; deterministic rules remain
alert-authoritative and this change does not touch that boundary.

## T14 Test Plan

`atdr/tests/test_rules.py`: added
`test_default_paloalto_untrust_zone_is_not_misread_as_an_inside_zone`
(same-zone `untrust` traffic must not fire `outside_to_inside` or
`unusual_destination_port`) and
`test_default_paloalto_trust_untrust_zones_still_detect_real_direction`
(genuine `trust`<->`untrust` traffic in both directions still classifies
correctly). `atdr/tests/test_detection_explanations.py`: added
`test_explain_log_triage_does_not_report_false_direction_for_same_zone_untrust`
and a companion genuine-direction test.
`atdr/tests/test_detection_grouping.py`: added three tests directly
exercising `_group_key` (previously untested) — same-zone `untrust` traffic
is not merged into `"multiple-internet-sources"`, genuine `untrust`->`trust`
traffic still is, and the `APP_RISK_POLICY_RULES` merge is consistent for
both genuinely-outbound and same-zone traffic. New
`atdr/tests/test_ml_features_zone_fix.py`: two tests proving
`external_to_internal_flag`/`internal_to_external_flag` are correct for
same-zone `untrust` traffic and for genuine direction in both directions.
Ran each affected test file in isolation, then the full backend suite, then
layered detection validation.

## T15 Implementation Summary

One small set of additive helpers in `rules.py` (now public), two duplicate
reimplementations removed in favor of importing them, and a handful of new
tests covering a genuinely alert-grouping-affecting path that had zero prior
test coverage. No rule threshold, score, or catalog metadata changed.

## T16 Tests Run / Evidence

`atdr/tests/test_rules.py`: `14 passed` (12 existing + 2 new).
`atdr/tests/test_detection_explanations.py`: `6 passed` (4 existing + 2 new).
`atdr/tests/test_detection_grouping.py`: `9 passed` (6 existing + 3 new).
All three files combined: `29 passed` (7 new). Full backend suite and
layered detection validation evidence recorded in the taskboard verification
log after execution.

## T17 PRD / Docs Updated

This change record only. `docs/DETECTION_RULE_CATALOG.md` was checked and
needs no correction — its `outside_to_inside` and `high_outbound_bytes`
condition text already describes the correct *intent* ("crosses from
untrusted/internet/outside to trusted/inside/corp"); only the
implementation's matching mechanism was wrong.

## T18 Risks / Blockers / Assumptions / Decisions

Assumed PAN-OS zone names are separated by non-alphanumeric characters
(hyphen, underscore, space) when compound, consistent with every zone name
observed in the codebase's own fixtures and scenario data. If a deployment
uses a zone name that concatenates tokens without a separator (e.g.
`InsideLAN` as one word), token-based matching would not recognize it either
— same limitation as before, not a regression.

## T19 Release / Rollback

Fully reversible by reverting `atdr/app/detection/rules.py`,
`atdr/app/detection/explanations.py`, `atdr/app/services/detection_service.py`,
`atdr/app/ml/features.py`, and the four touched/new test files. No
migration, no data written, no artifact touched.

## T20 Final Handoff

Awaiting project-owner decision on whether to fold this into a versioned
release entry (e.g. as part of the next published version) and on commit
approval. Full backend and layered-detection regression results are recorded
in `docs/tasks/tasklist-progress.md` once the background verification
completes.
