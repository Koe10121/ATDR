# v1.4c Malicious Recall Recovery And Confidence Calibration

ATDR v1.4c evaluates whether exact malicious recall and confidence calibration can improve without undoing the v1.4b QUIC/443 false-positive reduction.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v14c_malicious_recovery --split time --test-size 0.3 --min-samples 6 --review-limit 150 --pretty
```

The command:

- analyzes malicious rows predicted as suspicious or benign-like;
- reports whether the QUIC safeguard suppressed malicious evidence;
- compares six candidate-only threshold and calibration profiles;
- rejects profiles above the `0.15` benign-like false-positive budget;
- fits calibrators using a held-out portion of the training window;
- evaluates calibration on the untouched chronological test window;
- exports an actionable malicious-recovery review sample when candidates exist.

## Outputs

Generated files stay under ignored `ml_baseline_reviews/`:

- `v1_4c_malicious_recall_analysis_<timestamp>.md`
- `v1_4c_malicious_recall_recovery.md`
- `v1_4c_malicious_recall_recovery.json`
- `v1_4c_malicious_recall_review_sample.csv`

The review CSV excludes protected manual and reviewed labels by default. It focuses on unlabeled or unreviewed rows with malicious/suspicious boundary evidence, threat-positive false-negative risk, denied or incomplete traffic, uncommon ports, rule/anomaly disagreement, and other strong non-QUIC evidence.

## Interpretation

Exact suspicious-versus-malicious classification is evaluated separately from combined threat-positive triage. A malicious row predicted suspicious remains useful for analyst triage, but it is still an exact-class error and must remain visible in the report.

Calibration passing on the calibration subset alone is insufficient. The recommended calibration method must also remain within tolerance on the chronological test window. This is still candidate evaluation, not production certification.

## Safety

- No model artifact is written or activated.
- No model is production-promoted.
- ML remains SOC triage decision support.
- Response automation remains disabled.
- Response actions remain simulated and analyst-approved.
- Real firewall blocking remains disabled.
