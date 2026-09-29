# v5.63 Fresh Comparable Evidence Expansion

Date: 2026-09-17

## Decision

v5.63 expands the prediction-blind supervised evidence campaign from 300 to
1,000 comparable rows without changing the original v5.62 pack. It does not
qualify, train, evaluate, freeze, activate, promote, or write an active
supervised model.

Runtime truth remains:

- deterministic rules: `active_authoritative`;
- IsolationForest and hybrid output: advisory only;
- supervised runtime: `unqualified`;
- lifecycle: `shadow_observation`;
- response: `simulation_only`;
- automatic response and real firewall blocking: disabled.

## Append-Only Custody

The complete v5.62 protocol was revalidated before selection. Its 300 review
tokens, role assignments, protected digest, sealed pack digest, source digest,
fixed qualification gates, and 45-row untouched evaluation role remain
unchanged. v5.63 cannot open or modify v5.62 decisions.

The private PAN-OS input was supplied only as a CLI argument and processed in
disposable SQLite. Public results contain aggregate values only.

| Measure | Result |
| --- | ---: |
| Source records streamed | 773,551 |
| Parser successes | 773,551 |
| Parser failures | 0 |
| Fresh development-safe event rows after exclusions | 252,268 |
| Eligible unique supplemental families | 220,547 |
| Original review rows preserved | 300 |
| Supplemental rows selected | 700 |
| Total comparable-evidence capacity | 1,000 |
| Original-pack overlap selected | 0 |
| Future-evaluation rows added | 0 |
| Duplicate families rejected | 18,962 |
| Sealed future-role families rejected | 44,696 |
| Independent chronological windows | 19 |
| Verified physical source identities | 1 |

The 700 selected rows span seven coverage groups and three development roles:

| Development role | Rows |
| --- | ---: |
| Development fit | 411 |
| Calibration | 165 |
| Threshold selection | 124 |

Roles were assigned before labels were opened. Every selected duplicate family
is unique, and no supplemental row enters the sealed future-evaluation role.

## Protected Review Batches

The supplemental pack is divided into seven immutable 100-row batches. Each
batch has independent owner assignment, optimistic revision control, resumable
progress, validation, and explicit closure. A closed batch cannot be edited.

Authenticated analysts and administrators can review the batches in
**Evidence Review -> Supervised Qualification**. The interface exposes only
approved normalized fields and withholds:

- predictions, scores, rule recommendations, and suggested labels;
- raw records, IP addresses, source identities, and fingerprints;
- private paths, digests, reviewer identities, and secrets; and
- every sealed future-evaluation label and class-support value.

Automated or AI-like reviewer identities are rejected. The workflow never
claims a human decision automatically and never imports its decisions into the
application database.

Current exact workload:

- original v5.62 review: `0/300` reviewed, 300 remaining;
- supplemental v5.63 review: `0/700` reviewed, 700 remaining;
- combined human workload: `0/1,000` reviewed, 1,000 remaining;
- supplemental batches closed: `0/7`;
- invalid decisions: 0.

## Fixed Qualification Gates

The v5.62 gates are unchanged. Evidence capacity now reaches 1,000 selected
rows, but the comparable-row gate counts valid independent human-reviewed rows,
not merely selected capacity.

| Gate | Current aggregate | State |
| --- | ---: | --- |
| Independent human blind labels >= 20 | 0 | fail |
| Independently comparable reviewed rows >= 1,000 | 0 | fail |
| Benign-like rows >= 100 | 0 | fail |
| Threat-positive rows >= 100 | 0 | fail |
| Real physical sources >= 2 | 1 | fail |
| Independent time windows >= 2 | 19 | pass |
| Untouched evaluation class support | sealed | blocked |
| F1, recall, FPR, and calibration gates | no candidate evaluated | blocked |

Development training cannot begin. The original review and every supplemental
batch must be valid and closed, class support must be honest, and a second
independently verified physical source remains required. No decision may be
changed merely to satisfy a quota.

## Second-Source Intake

The guarded CLI accepts a future private log path at runtime and parses it only
in disposable storage. It compares hashed device identity evidence against the
primary source and fails closed when:

- disposable processing is not acknowledged;
- the file is unavailable or unparseable;
- no device identity is present;
- only an already-known physical device is present; or
- the candidate file is the same protected source.

A passing preflight reports aggregate source counts only. It does not add the
candidate to the campaign, update the source gate, copy the file, expose an
identity, or retain raw evidence. Synthetic tests prove same-device rejection
and distinct-device recognition; no second real device is claimed today.

## Operator Commands

Safe aggregate status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v563_fresh_evidence_expansion --status-only --pretty
```

Private second-source preflight when a genuine new device becomes available:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v563_fresh_evidence_expansion `
  --second-source-path "<private-second-source-log>" `
  --use-temp-db `
  --check-second-source `
  --pretty
```

Do not rerun preparation over a different source or overwrite either protected
workspace. Review output under `ml_baseline_reviews/` remains ignored and must
never be committed.

## Safety Evidence

- Configured database counts changed by zero for raw logs, normalized logs,
  alerts, ML labels, model runs, detection runs, and response actions.
- Active model artifacts were unchanged.
- Predictions and model scores were not used for selection.
- Rules and assisted labels were not used as human labels.
- Training, evaluation, freeze, activation, and promotion remained false.
- Rules remain alert-authoritative and response remains `simulation_only`.

## Verification

- Taskboard render and standard checks pass.
- Ruff, compileall, and Alembic drift checks pass.
- Focused v5.63 backend tests pass `6/6`.
- Full backend tests pass `1114 passed, 1 skipped`; the independent release
  gate repeats the same suite successfully.
- React lint and production build pass; Playwright passes `45 passed, 1
  skipped`, including the protected qualification and expansion workspaces.
- The controlled source scenario parses `10/10`, creates the expected
  rule-authoritative port-scan alert, and creates zero response actions.
- Layered detection passes `288/288` mode runs with zero controlled false
  positives or false negatives.
- Assistant QA passes all 30 quality cases and the context-preserving follow-up
  sequence with zero authoritative side effects.
- Governed hybrid inspection confirms rules authoritative, IsolationForest
  advisory, supervised unqualified, and response `simulation_only`.
- Replay dry-run, repository surface audit, tracked-source security acceptance,
  performance smoke, and the release gate pass. Performance smoke reports no
  warnings; cold Overview is `0.8425s` and the cached path is `0.0105s`.
- The repository audit finds no broken or non-portable references, and the
  security scan finds zero tracked-source findings across 1,441 text files.
- `git diff --check` and final ignored/private-artifact hygiene are required
  immediately before any separately approved publication.

## Remaining Qualification Work

1. Complete and close the original 300-row review honestly.
2. Complete and close all seven supplemental 100-row batches honestly.
3. Obtain and preflight evidence from a second real physical device.
4. Confirm reviewed benign-like and threat-positive class support without
   changing decisions to satisfy gates.
5. Run development-only supervised repair in v5.64 after every development
   input gate passes.
6. Freeze at most one diagnostic candidate before any blind evaluation.
7. Open a new untouched evaluation only under a separate one-shot protocol.
8. Require separate approval before any `active_shadow` model state.

Supervised ML is not qualified by v5.63.

## v5.64 Recommendation

The next governed implementation phase is **v5.64 Reviewed Development
Evidence Lock and Candidate Repair**. It may begin only after all 1,000 rows
are genuinely reviewed and immutable, the fixed benign-like and
threat-positive support gates pass honestly, and a second real physical source
passes the independent-source intake. If any prerequisite fails, v5.64 must
remain status-only and must not train.

When eligible, v5.64 should seal the combined development manifest, compare
the locked supervised strategies using development-fit, calibration, and
threshold-selection roles only, and freeze at most one diagnostic candidate.
It must not open untouched evaluation labels, activate or promote a model,
change alert authority, or enable response automation.

After the external review and source prerequisites, three substantial
supervised-learning phases remain:

1. v5.64 development-only repair and diagnostic candidate freeze;
2. v5.65 one-shot blind validation on new untouched evidence; and
3. v5.66 shadow-runtime qualification and a separately approved activation
   decision.

Any production promotion remains a later, separately governed decision.
