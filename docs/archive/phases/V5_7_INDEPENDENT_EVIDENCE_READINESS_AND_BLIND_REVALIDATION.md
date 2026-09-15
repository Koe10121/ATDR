# v5.7 Independent Evidence Readiness And Blind Revalidation

Date: 2026-07-26

## Decision

The v5.7 shadow evaluator is implemented and reproducible. The v5.6
`calibrated_hist_gradient_boosting` diagnostic candidate is frozen with its
feature, preprocessing, sigmoid calibration, threshold, training-manifest,
code-contract, and artifact identities. It is inactive, not production
promoted, and uses a calibrated threshold only; no post-prediction suppression
guard is present.

Valid independent evidence is not currently available. The complete private
PAN-OS source is the same evidence already analyzed in v5.6. Existing v5.3
final/rolling/external and v5.6 future roles are already opened and locked.
The correct outcome is therefore `independent_evidence_required`, blind
validation is not run, and lifecycle remains `shadow_observation`.

## Evidence Lock Audit

The current governed label set still matches the tracked v5.3 evidence lock.
The ignored v5.4-v5.6 manifests/reports and v5.6 candidate artifact also match
their recorded identities.

| Evidence role | Rows | v5.7 treatment |
| --- | ---: | --- |
| v5.3 fit | 957 | locked development |
| v5.3 calibration | 282 | locked development |
| v5.3 threshold | 228 | locked development |
| v5.3 temporal final | 532 | previously opened; not independent |
| v5.3 rolling future | 532 | previously opened; not independent |
| v5.3 quarantine | 236 | excluded |
| v5.3 external benchmark | locked | previously failed; not reusable |
| v5.6 development fit | 352,312 | reused development |
| v5.6 calibration | 113,519 | reused development |
| v5.6 threshold | 75,090 | reused development |
| v5.6 private future | 112,004 | previously opened; not independent |
| v5.6 quarantine | 120,626 | excluded |

Role, manifest, code, and artifact fingerprints are recorded in existing
tracked/ignored locks and the ignored v5.7 lock-audit file. Runtime/API output
does not expose those fingerprints, private paths, raw rows, IP addresses, or
secrets.

## Frozen Diagnostic Candidate

| Contract | Frozen value |
| --- | --- |
| Candidate | `calibrated_hist_gradient_boosting` |
| Model family | `HistGradientBoostingClassifier` |
| Calibration | sigmoid |
| Decision threshold | `0.3` |
| Feature contract | 40 fields |
| Decision policy | calibrated threshold only |
| Post-prediction guard | none |
| Active | false |
| Production promoted | false |
| Response automation allowed | false |
| Rules alert-authoritative | true |

The current ignored freeze matches the current v5.7 code contract. The
candidate artifact was unchanged before and after preflight.

## Private Disposable Preflight

The private source was supplied only as a CLI argument and processed through
disposable SQLite. It was not imported into the configured database.

| Measure | Result |
| --- | ---: |
| Rows streamed | 773,551 |
| Parser successes | 773,551 |
| Parser failures | 0 |
| Configured-database overlap | 120,000 |
| Exact duplicate rows | 0 |
| Near-duplicate rows | 52,881 |
| Matches reused v5.6 evidence | true |
| Runtime | 135.9372s |

This result proves parser/regression consistency and identifies reuse. It is
not a new accuracy measurement.

## Independent Evidence Research

Official/primary source review covered the Palo Alto Networks PAN-OS traffic
schema, CSE-CIC-IDS2018, UNSW-NB15, and Splunk BOTS v3.

- The vendor reference defines PAN-OS fields but supplies no labeled corpus.
- CSE-CIC-IDS2018 is flow-schema evidence, was already opened in ATDR, failed
  the prior transfer gate, and is locked.
- UNSW-NB15 provides labeled packet/flow evidence but not native PAN-OS logs.
- BOTS v3 is a useful multi-sourcetype security corpus but has no compatible
  native PAN-OS ground-truth contract for this evaluator.

No source met all requirements for fresh native PAN-OS schema, independent
devices/time periods, unopened labels, compatible ground truth, and verified
non-overlap. Details are in
`docs/detection/V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md`.

## Blind Protocol

The new CLI supports:

```text
--sample-path
--evidence-manifest
--preflight-only
--use-temp-db
--predictions-only
--reveal-labels
--pretty
```

Qualification requires a compatible schema, sufficient parsed/chronological
evidence, two real devices, two independent periods, zero configured-DB and
prior-evidence overlap, duplicate containment, documented permission, sealed
labels, and advisor protocol acknowledgement.

Prediction mode creates an immutable ignored prediction freeze and a
prediction-blind review pack. Reveal mode requires an unchanged evidence
contract, complete confirmed labels with allowed provenance, and advisor
approval. A completed reveal is sealed and cannot be repeated.

No AI-, Codex-, rule-, vendor-assisted, or weak-supervision decision is
accepted as human-reviewed ground truth.

## Blind And IsolationForest Results

| Evaluation | Status |
| --- | --- |
| Supervised blind validation | `not_run_independent_evidence_required` |
| Blind supervised metrics | intentionally unavailable |
| Independent IsolationForest audit | `pending_independent_labels` |
| Readiness | `shadow_observation` |

IsolationForest remains advisory. Its previous v5.6 single-source assisted
result cannot substitute for an independent labeled audit.

## Fixed Readiness Gates

- Threat/SOC queue F1 `>=0.85`.
- Benign-like false-positive rate `<=0.05`.
- Suspicious recall `>=0.80`.
- Malicious recall `>=0.80`.
- Expected calibration error `<=0.10`.
- Maximum confidence/accuracy gap `<=0.15`.
- No evidence leakage.
- No actual threat suppressed by a post-prediction guard.
- Independent source/time evidence satisfied.

Passing every gate would permit only a later manual decision-support review.
It would not automatically activate or promote a model.

## Dashboard Status

AI Governance exposes aggregate-only status:

- Frozen Diagnostic Candidate;
- Independent Evidence Pending;
- Blind Validation Pending;
- Shadow Observation;
- Rules Authoritative; and
- Response Automation Disabled.

It withholds blind metrics until a legitimate one-time label reveal.

## Safety

- Configured database counts before and after are identical.
- Existing model artifact states before and after are identical.
- Labels, model runs, detection runs, alerts, and response actions created:
  `0`.
- Active model written/replaced, activated, or promoted: `false`.
- Automatic response enabled: `false`.
- Real firewall blocking enabled: `false`.
- Private path, raw logs, IP addresses, row fingerprints, and secrets returned:
  `false`.

## Verification

The completed local verification matrix passed:

- taskboard render and standard checks;
- whole-repository Ruff and compileall;
- focused v5.7 backend tests: `15 passed`;
- full backend tests: `694 passed, 1 skipped`;
- Alembic drift check: no new upgrade operations;
- React lint and production build;
- Playwright: `26 passed, 1 skipped` (the skip requires live hardware);
- controlled detection corpus: `24/24`;
- layered validation: `288/288`, zero controlled false positives/negatives;
- deterministic assistant QA: `20/20`, with zero mutation side effects;
- replay dry-run: two safe rows parsed and zero rows written;
- read-only performance smoke: no warnings, Overview `0.1593s`, cached
  Overview `0.0114s`, AI Governance `1.1176s`, alerts `0.0335s`, cases
  `0.0720s`, and feature generation `0.0065s`; and
- official release gate: `ok: true`, with no failed required checks.

The first release-gate attempt encountered disposable malformed fixture copies
left under ignored processed test output by a custom full-suite invocation.
Only that generated test directory was removed; no configured data or source
was changed. The clean rerun passed.

## Remaining External Evidence

1. Human- or provider-confirmed PAN-OS-compatible labels.
2. At least two independently operated real source devices.
3. At least two new collection periods outside every v5.3-v5.6 role.
4. Local fingerprint and duplicate-family non-overlap evidence.
5. Advisor protocol acknowledgement before prediction freeze.
6. Advisor approval before the one-time label reveal.

Until those inputs exist, repeating model tuning or assigning AI-generated
labels would weaken evidence integrity. The correct next action is acquisition
and shadow monitoring, not activation.

No commit or push is authorized by this document.
