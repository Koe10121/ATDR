# v5.45 Development-Only Supervised Model Repair

## Status

v5.45 is implemented and measured. It revalidates the v5.39-v5.44 custody
chain, reconstructs the private chronological source in disposable storage,
uses only `development_fit`, `calibration`, and `threshold` roles, and compares
eight supervised strategies without opening untouched-future labels.

No strategy passed every unchanged v5.42 development gate. No diagnostic
recipe or model artifact was frozen, activated, or promoted.

- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- candidate freeze ready: no
- model activated or promoted: no
- automatic response and real firewall blocking: disabled
- supervised phases remaining: 5

## Custody Finding

The v5.44 lock correctly isolated exact and propagation-family duplicates, but
v5.45's broader label-blind `candidate_near_hash` audit found candidate-near
families spanning chronological roles. The disposable v5.45 reconstruction
quarantined 62,961 such families and 407,689 represented events, including
65,580 reserved-future events, before any modeling view was built.

The audit inspected no labels, returned no family identifier, and opened no
future label. Candidate-near cross-role count after containment was zero. This
finding narrows the earlier v5.44 duplicate-isolation claim; it does not modify
the configured database or overwrite the private v5.44 lock.

## Development Protocol

The evaluator uses three mandatory leakage-safe views:

1. calibration-cohort holdout
2. threshold-cohort holdout
3. manual-anchor holdout

An optional nested fit holdout was excluded because its evaluation partition
had no suspicious support and therefore could not exercise every fixed gate.
Counting it as mandatory would have made a pass impossible by construction.
The fixed thresholds and gates were not changed.

The selected fit sample contains 8,027 rows: 408 manual/reviewed anchors and
7,619 assisted rows. Aggregate assisted weight is capped at 50% of manual
anchor weight for the leading strategy. Assisted labels never dominate the
manual anchors and no label is rewritten.

## Models Compared

- calibrated ExtraTrees, flat five-class
- calibrated HistGradientBoosting, flat five-class
- calibrated Logistic Regression, flat five-class
- binary threat-positive ExtraTrees
- three-class SOC queue ExtraTrees
- hierarchical two-stage ExtraTrees
- binary ExtraTrees with strict manual-anchor weighting
- binary ExtraTrees with maximum bounded manual-anchor weighting

All strategies are diagnostic only. None passed a complete view.

## Diagnostic Leader

`calibrated_extra_trees_flat_5class` ranked first.

| View | Precision | Recall | F1 | Benign-like FPR | Suspicious recall | Malicious recall | ECE | Confidence gap | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Calibration holdout | 0.9969 | 0.9855 | 0.9912 | 0.0020 | 0.9813 | 1.0000 | 0.1785 | 0.4113 | fail |
| Threshold holdout | 0.9981 | 0.9894 | 0.9937 | 0.0014 | 0.9874 | 1.0000 | 0.0889 | 0.3437 | fail |
| Manual-anchor holdout | 0.9701 | 0.6599 | 0.7855 | 0.1290 | 0.5175 | 0.8537 | 0.3232 | 0.5737 | fail |

The leader passes `0/3` views. Review-queue-rate spread is `0.1999`, which
passes the unchanged `0.20` stability limit. The blockers are calibration on
all relevant views plus FPR, queue F1/recall, and suspicious recall on the
manual-anchor holdout.

Manual-versus-assisted sensitivity remains material: queue-F1 absolute gap is
`0.2082` and FPR absolute gap is `0.1276`. Strong assisted-cohort performance
therefore cannot be treated as independent field accuracy.

## Residual Errors

Across the leader's three views, aggregate false-negative patterns are:

- incomplete/allow/80: 51
- scan-like behavior: 27
- unknown UDP/TCP: 10
- benign QUIC/443 boundary: 3
- suspicious/malicious boundary: 1

False positives are scan-like behavior (8) and unknown UDP/TCP (1). No row
prediction, timestamp, path, IP address, source identity, or private family
identifier is returned.

## IsolationForest

IsolationForest remains a separate advisory signal. On the threshold cohort
its FPR is `0.2412`, F1 `0.8368`, suspicious recall `0.9543`, and malicious
recall `1.0000`. On the manual-anchor holdout its FPR is `0.1935`, F1 `0.8846`,
suspicious recall `0.7632`, and malicious recall `0.9024`.

It fails the fixed reliability requirements and cannot create, suppress, or
change authoritative alerts.

## Safety Result

The measured run made zero changes to configured database counts, protected
workspaces, active artifacts, labels, model runs, detection runs, alerts, or
response actions. It created no human-reviewed label, opened no future label,
and returned no private path, fingerprint, raw row, prediction, IP, or secret.

## Verification Result

The complete local closure matrix passed:

- taskboard render and standard checks
- Ruff and canonical source `compileall`
- backend tests: `981 passed, 1 skipped`
- Alembic check: no drift
- React lint and production build
- Playwright: `35 passed, 1 skipped`
- isolated port-scan scenario: 10/10 parsed, one critical alert, one case, and
  zero response actions
- layered detection validation: `288/288` passed with zero controlled false
  positives or false negatives
- Assistant QA: `20/20` cases passed with no side effects
- replay dry-run
- performance smoke with no warnings
- release gate: `ok: true`

Large-SQLite timings were Overview cold/cached `0.8068s/0.0119s`, AI
Governance `0.9933s`, Alerts `0.0587s`, and Cases `0.0841s`.

## Safe Commands

Preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v545_development_model_repair `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --preflight-only --no-report --pretty
```

Measured aggregate-only evaluation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v545_development_model_repair `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --summary-only --pretty
```

Generated JSON/Markdown stays ignored under `ml_baseline_reviews/`.

## Remaining Supervised Phases

1. Repair development transfer and calibration until one strategy passes all
   fixed manual/assisted cohort gates.
2. Freeze at most one diagnostic recipe without activating it.
3. Acquire prediction-blind human labels from at least two genuine devices and
   multiple future windows.
4. Run one frozen independent evaluation without tuning.
5. Make a separate governance decision and complete shadow observation.

External blockers are genuine multi-device evidence, human review, an
independent future evaluation, and advisor/provider authority. Software alone
cannot honestly substitute for these controls.
