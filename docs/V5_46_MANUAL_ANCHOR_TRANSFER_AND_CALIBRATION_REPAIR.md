# v5.46 Manual-Anchor Transfer And Calibration Repair

## Status

v5.46 is implemented and measured. It revalidates the v5.39-v5.45 evidence
chain, uses only `development_fit`, `calibration`, and `threshold` roles, keeps
reserved-future labels sealed, and compares nine development-only transfer
strategies against the unchanged v5.42 gates.

No strategy passed all three mandatory views. No recipe or model artifact was
frozen, activated, or promoted.

- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- candidate freeze ready: no
- model activated or promoted: no
- automatic response and real firewall blocking: disabled
- supervised phases remaining: 5

## Evidence And Transfer Diagnosis

The disposable evaluation used 918 human-reviewed anchors and 12,022 assisted
development representatives. The cohorts differ materially:

- label-distribution total variation: `0.2242`
- application-mix total variation: `0.3613`
- residual-pattern total variation: `0.4062`
- schema total variation: `1.0000`

The largest numeric differences are unknown-application count, destination
and port diversity, and high-risk-application count. These differences explain
why strong assisted-cohort results do not transfer reliably to the manual
holdout. They are aggregate diagnostics only; no private row, path, IP, source
identity, timestamp boundary, prediction, or fingerprint is returned.

## Strategies Compared

1. v5.45 calibrated ExtraTrees baseline
2. provenance-balanced ExtraTrees
3. manual-anchor-prioritized ExtraTrees
4. HistGradientBoosting transfer
5. Logistic Regression transfer
6. binary threat-positive ExtraTrees
7. three-class SOC queue ExtraTrees
8. hierarchical two-stage ExtraTrees
9. conservative calibrated ensemble

The transfer feature set adds only runtime-derivable context: QUIC/443,
incomplete/80, unknown transport, routine service, rule support, parser
quality, scan/destination diversity, unknown/high-risk application rates,
deny intensity, evidence strength, traffic ratios, time regime, and transport
context. Provenance and source identity are not predictive features.

## Diagnostic Leader

`hierarchical_two_stage_transfer` ranked first diagnostically but passed
`0/3` mandatory views.

| Measure | Range across mandatory views |
| --- | ---: |
| Queue precision | `0.7883-0.9286` |
| Queue recall | `0.3959-1.0000` |
| Queue F1 | `0.5552-0.8973` |
| Benign-like FPR | `0.1624-0.1935` |
| Suspicious recall | `0.0614-1.0000` |
| Malicious recall | `0.8537-1.0000` |
| ECE | `0.1288-0.2381` |
| Confidence/accuracy gap | `0.2197-0.7455` |
| Review-queue-rate spread | `0.1429` |

On the manual-anchor holdout, F1/FPR/suspicious recall/malicious recall were
`0.5552/0.1935/0.0614/0.8537`. Calibration remained weak with ECE `0.2381`
and maximum confidence/accuracy gap `0.7455`.

Compared with v5.45, manual-anchor F1 fell by `0.2303`, FPR increased by
`0.0645`, and suspicious recall fell by `0.4561`. The FPR transfer gap narrowed,
but the queue-F1 transfer gap widened from `0.2082` to `0.3421`. The transfer
therefore did not improve overall and cannot be frozen.

## Residual And Anomaly Findings

Leader false negatives remain concentrated in unknown UDP/TCP and
incomplete/allow/80 traffic. False positives remain concentrated in unknown
UDP/TCP and scan-like behavior. The manual holdout contains 119 of the 121
aggregate false negatives across all three views.

IsolationForest remains advisory. Its behavior changes sharply by cohort and
contamination setting; it does not pass the fixed reliability requirements and
cannot create, suppress, or modify authoritative alerts.

## Safety Result

The measured run changed zero configured database rows, protected workspaces,
labels, model runs, detection runs, alerts, response actions, or active model
artifacts. It created no human-reviewed label, opened no future label, and
returned no private path, raw row, IP, source identity, fingerprint,
prediction, provider payload, or secret.

## Verification Result

- Taskboard render and standards checks passed.
- Ruff and canonical compileall passed.
- Backend and release-gate tests passed `990 passed, 1 skipped`.
- Alembic reported no migration drift.
- React lint/build passed; Playwright passed `35`, with `1` intentional
  live-source skip.
- Controlled port-scan acceptance passed with `10/10` parsed, one alert, one
  case, and zero response actions.
- Layered detection validation passed `288/288` with zero false positives and
  zero false negatives on the controlled corpus.
- Assistant QA passed `20/20`; citations and concise-answer budgets passed,
  and no authoritative state changed.
- Replay dry-run parsed `2/2` safe sample rows without writes.
- Performance smoke passed without warnings: Overview `0.1723s`, cached
  Overview `0.0106s`, ML Governance `0.2433s`, alert list `0.0316s`, and case
  summary `0.0527s`.
- The release gate completed successfully in `447.6s`.

## Repository Hygiene

The cumulative v5.43-v5.46 worktree contains exactly the `44` paths listed in
`docs/V5_46_COMMIT_ALLOWLIST.md`; no file is staged and no commit or push is
authorized. `git diff --check` passes. No protected path is changed, no secret
or personal path pattern appears in the diff, and `.env`, databases, private
evidence, and generated diagnostics remain ignored. The measured v5.46 JSON
and Markdown reports exist only under the ignored `ml_baseline_reviews/`
workspace.

## Safe Commands

Preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v546_manual_anchor_transfer_repair `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --preflight-only --no-report --pretty
```

Measured aggregate-only evaluation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v546_manual_anchor_transfer_repair `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --summary-only --pretty
```

Generated diagnostics remain ignored under `ml_baseline_reviews/`.

## Next Decision

Do not run another threshold-only repair against the same evidence. The next
supervised phase requires additional prediction-blind human anchors that cover
the failing unknown-transport, incomplete/80, scan-like, and low-signal
suspicious boundaries across genuinely later windows. A second real device is
still required before source-generalization claims. Until then, rules remain
authoritative and supervised ML remains shadow decision support.
