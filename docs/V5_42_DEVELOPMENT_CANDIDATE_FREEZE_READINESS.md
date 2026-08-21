# v5.42 Development Candidate Freeze Readiness

## Status

v5.42 is implemented and measured. It revalidated the v5.39 consumed-evidence
boundary, rebuilt the v5.40 development population, confirmed that the v5.41
blind workspace remained unchanged, compared exactly five predeclared
development-only strategies, and correctly froze no candidate.

Current lifecycle remains `shadow_observation`:

- diagnostic candidate frozen: **no**
- model activated or promoted: **no**
- deterministic rules alert-authoritative: **yes**
- automatic response: **disabled**
- real firewall blocking: **disabled**
- supervised phases remaining: **5**

## Boundary Revalidation

All eight protected-boundary checks passed:

- v5.39 consumed pack custody matched; its labels, predictions, and errors were
  not read
- v5.40 development population rebuilt to exactly 1,467 rows
- v5.40 cutoff, exact, near-duplicate, and source boundaries matched v5.41
- duplicate groups remained isolated
- v5.41 custody status remained valid and its workspace stayed byte-identical
- locked-final rows, v5.39 rows, and v5.41 blind rows used for modeling: `0`

## Fixed Candidate Set

Only these predeclared strategies were evaluated:

1. calibrated ExtraTrees
2. calibrated HistGradientBoosting
3. calibrated regularized Logistic Regression
4. three-class SOC queue
5. hierarchical two-stage model

Every strategy used development-only nested temporal folds with separate fit,
calibration, threshold, and evaluation roles. Threshold choice came only from
the threshold role. No post-prediction low-signal guard was used.

## Fixed Freeze Gates

Every fold had to pass all of these unchanged gates:

| Gate | Requirement |
| --- | ---: |
| Threat precision | >= 0.80 |
| Threat recall | >= 0.80 |
| Threat F1 | >= 0.85 |
| Benign-like FPR | <= 0.10 |
| Suspicious recall | >= 0.80 |
| Malicious recall | >= 0.80 |
| ECE | <= 0.10 |
| Maximum confidence/accuracy gap | <= 0.15 |
| Queue-rate spread across folds | <= 0.20 |
| Leakage/duplicate crossing | 0 |

Gates were not weakened to obtain a candidate.

## Measured Result

The best development-only ranking remained `hierarchical_two_stage`, but it
passed `0/3` folds and was not eligible to freeze.

| Metric across folds | Minimum | Maximum | Mean |
| --- | ---: | ---: | ---: |
| Threat precision | 0.8333 | 0.9865 | 0.9059 |
| Threat recall | 0.1000 | 0.5828 | 0.3290 |
| Threat F1 | 0.1786 | 0.7068 | 0.4501 |
| Benign-like FPR | 0.0120 | 0.1176 | 0.0513 |
| Suspicious recall | 0.0719 | 0.5164 | 0.2405 |
| Malicious recall | 0.0000 | 0.9259 | 0.5489 |
| Weighted F1 | 0.4442 | 0.6945 | 0.5644 |
| Review queue rate | 0.0451 | 0.4153 | 0.2412 |
| ECE | 0.1862 | 0.5054 | 0.3244 |
| Maximum confidence gap | 0.3454 | 0.9015 | 0.5612 |

Queue-rate spread was `0.3702`, above the `0.20` stability ceiling. Threshold
profiles also changed across folds (`low_noise_soc_queue`, then `balanced`),
which is another sign that one operating threshold is not stable over time.

## Root Causes

- Evidence comes from one source and a very short interval.
- 549 of 1,467 development rows have assisted/weak provenance and remain
  down-weighted rather than being represented as human ground truth.
- 421 rows belong to multi-row duplicate groups; groups are isolated, but the
  concentration limits effective diversity.
- Chronological fit-to-evaluation distribution shift reached total variation
  `0.8047` in at least one aggregate dimension.
- The primary failure is temporal false negatives and calibration, not only
  benign false-positive noise.
- Across nested folds the leader produced 275 false-negative observations,
  mostly suspicious scan-like evidence, including incomplete, unknown UDP,
  QUIC, SSL, BitTorrent, and JSON-RPC patterns.
- It produced 12 false-positive observations, all manually labeled
  `benign_unusual`, primarily allowed scan-like SSL/443 traffic.

## Immutable Freeze Behavior

The freeze service supports at most one ignored diagnostic artifact. It writes
only after every fixed fold and queue-stability gate passes. An identical
request reuses the existing immutable seal; a different candidate or a
tampered artifact fails closed.

No artifact was written in the measured v5.42 run because no strategy passed.
Even a future frozen diagnostic artifact would remain inactive,
not production-promoted, unable to create or suppress alerts, and unable to
execute response actions.

## AI Governance Surface

Authenticated analysts and admins can read the aggregate status:

```text
GET /api/evidence-review/candidate-freeze/status
```

The response and React AI Governance panel show only candidate name, passing
folds, calibration status, lifecycle blockers, and remaining phases. They do
not expose private paths, digests, blind predictions, fingerprints, source
identities, raw logs, or secrets.

## Safe Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v542_candidate_freeze_readiness --pretty
```

Custody-only preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v542_candidate_freeze_readiness --preflight-only --no-report --pretty
```

Generated diagnostics stay ignored under `ml_baseline_reviews/`.

## Remaining Supervised Phases

1. Repair enough development-only stability to freeze one diagnostic
   candidate without weakening gates.
2. Collect qualifying future evidence from two independently verified devices
   across at least three windows.
3. Complete genuine prediction-blind human review with required class support.
4. Run one frozen evaluation without tuning.
5. Make a separate governance decision and, only if approved, complete manual
   shadow observation before any broader authority is considered.

Independent devices, future windows, genuine labels, and advisor/owner
approval remain external requirements. Code cannot honestly manufacture them.

## Verification

The complete local closure matrix passes:

- custody preflight: all `8/8` v5.39-v5.41 boundary checks
- focused backend/API regression: `17 passed`
- full backend/release suite: `953 passed, 1 skipped`
- Alembic: no new upgrade operations
- React lint/build: pass
- Playwright: `35 passed, 1 skipped`
- controlled port-scan scenario: 10/10 parsed, one alert, one case, zero
  response actions
- layered detection validation: `288/288`, zero controlled false positives
  and false negatives
- Assistant QA: `20/20`, all citation and word-budget gates, zero side effects
- v5.41 preflight: qualifying evidence remains absent and custody remains
  closed
- replay dry-run: pass with no writes
- performance smoke: pass with no warnings; Overview `0.1470s` cold and
  `0.0091s` cached, AI Governance `0.2233s`, alerts `0.0282s`, and cases
  `0.0452s`
- release gate: `ok: true`

Source compileall passes while excluding preserved ignored
`atdr/data/processed/` negative-test copies that are intentionally malformed.
No candidate artifact, label, alert, detection run, response action, or
configured database state was created or changed by v5.42.
