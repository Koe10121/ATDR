# v5.43 Development Temporal Stability And Calibration Repair

## Status

v5.43 is implemented and measured. It revalidates the v5.39-v5.42 evidence
boundaries, compares exactly five predeclared repair variants using only the
1,467-row development population, audits feature drift, and correctly freezes
no candidate.

Current lifecycle remains `shadow_observation`:

- passing variants: **0/5**
- diagnostic candidate frozen: **no**
- model activated or promoted: **no**
- deterministic rules alert-authoritative: **yes**
- automatic response and real firewall blocking: **disabled**
- supervised phases remaining: **5**

## Custody And Protocol

All v5.39-v5.42 custody checks pass. No consumed v5.39 row, v5.41 blind row,
or locked-final row is used for fit, calibration, threshold selection, model
ranking, or diagnosis. Duplicate groups remain isolated across fit,
calibration, threshold, and final development roles.

The unchanged v5.42 gates require, on every fold: precision and recall at
least `0.80`, F1 at least `0.85`, benign-like FPR at most `0.10`, suspicious
and malicious recall at least `0.80`, ECE at most `0.10`, confidence gap at
most `0.15`, queue spread at most `0.20`, and zero leakage.

## Fixed Repair Set

1. existing hierarchical two-stage baseline
2. inverse duplicate-cluster weighting
3. temporal/provenance-balanced weighting
4. stronger assisted-label down-weighting
5. compact stable-feature hierarchical model

All variants use calibrated ExtraTrees queue/severity stages. The old hard
low-signal guard is not used. Threshold selection uses only each fold's
threshold role.

## Measured Result

`temporal_provenance_balanced_weighting` ranked first diagnostically but
passed `0/3` folds and is not eligible to freeze.

| Metric across folds | Minimum | Maximum | Mean |
| --- | ---: | ---: | ---: |
| Threat precision | 0.4219 | 1.0000 | 0.7555 |
| Threat recall | 0.2542 | 0.5762 | 0.4568 |
| Threat F1 | 0.4053 | 0.6850 | 0.5213 |
| Benign-like FPR | 0.0000 | 0.4458 | 0.2113 |
| Suspicious recall | 0.1895 | 0.6333 | 0.4382 |
| Malicious recall | 0.1429 | 0.9259 | 0.4803 |
| Weighted F1 | 0.3920 | 0.6663 | 0.5380 |
| Review queue rate | 0.2171 | 0.4812 | 0.3782 |
| ECE | 0.1637 | 0.5019 | 0.3257 |
| Maximum confidence gap | 0.3134 | 0.9143 | 0.6186 |

Queue spread is `0.2641`, above the fixed `0.20` ceiling. The chosen threshold
also changes between `0.70` and `0.50` across folds.

## Feature And Error Audit

- The evidence has one source identity and spans about three minutes.
- 549/1,467 rows are assisted/weak and remain explicitly down-weighted.
- 421 rows belong to multi-row duplicate groups.
- Fit-to-evaluation distribution shift reaches `0.8047`.
- Application, evidence-family, traffic-family, byte-volume, source-diversity,
  and scan-pressure features shift materially between folds.
- The leader records 53 false-positive and 266 false-negative observations
  across nested prefixes; nested rows may repeat between prefixes.
- False positives are mostly manually labeled allowed SSL/QUIC benign-unusual
  rows. False negatives are mostly suspicious scan-like incomplete, QUIC,
  unknown-UDP, JSON-RPC, and SSL rows.
- No potential label-derived feature is detected by the feature-name audit.

The compact 49-feature variant does not improve stability. Weighting alone
cannot compensate for the narrow one-source, short-window evidence contract.

## Safe Interfaces

Run custody preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v543_temporal_stability_repair --preflight-only --no-report --pretty
```

Run the fixed comparison:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v543_temporal_stability_repair --pretty
```

Authenticated aggregate status:

```text
GET /api/evidence-review/temporal-stability/status
```

Generated diagnostics remain ignored under `ml_baseline_reviews/`. Public
status excludes paths, hashes, private rows, source identities, predictions,
raw logs, IP addresses, and secrets.

## Remaining Supervised Phases

1. Freeze one development-only candidate that passes every unchanged gate.
2. Collect qualifying future evidence from two genuine sources across three
   disjoint windows.
3. Complete prediction-blind human review with required class support.
4. Run one frozen evaluation without tuning.
5. Make a separate governance decision and complete shadow observation.

Software cannot honestly manufacture the external devices, future windows,
human ground truth, or governance approval required by phases 2, 3, and 5.

## Verification

Focused evaluator and authenticated API regression passes `20/20`. The
measured run completed in `26.9336s`; configured label, model-run,
detection-run, alert, response-action, and active-artifact state remained
unchanged. Full backend and release verification passes `962 passed, 1
skipped`; Alembic reports no drift; React lint/build pass; Playwright reports
`35 passed, 1 skipped`; controlled layered detection passes `288/288` with
zero controlled false positives or false negatives; Assistant QA passes
`20/20`; replay remains dry-run only; and the release gate returns `ok: true`.
Performance smoke is warning-free on 145,232 normalized rows: Overview cold
`0.6656s`, cached `0.0094s`, AI Governance `0.9114s`, Alerts `0.0499s`, and
Cases `0.0525s`.

Full verification also exposed a pre-existing Windows long-path failure in
the supervisor-template launcher backup name. The backup now uses a short
timestamped filename in the same directory; target content, rollback safety,
and startup behavior are unchanged.
