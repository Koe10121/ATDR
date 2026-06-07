# v1.4b False Positive Mitigation

## Purpose

v1.4b turns the v1.4 false-positive findings into an actionable review and mitigation workflow. The previous review sample was valid but contained protected manual labels, so importing it correctly made no database changes.

The v1.4b default export includes only:

- unlabeled rows
- unreviewed assisted labels
- rows whose human review can add or change training information

Protected manual labels and reviewed non-manual labels are excluded unless explicitly requested.

## Run

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v14b_false_positive_mitigation --split time --test-size 0.3 --min-samples 6 --review-limit 200 --pretty
```

Optional diagnostic flags:

```powershell
--include-manual
--include-reviewed
--no-only-actionable
```

Including protected rows is diagnostic only. Manual labels remain protected during CSV import unless `overwrite_manual=true` is explicitly used, which is not recommended for the normal review workflow.

## Outputs

Generated files remain under ignored `ml_baseline_reviews/`:

- `v1_4b_quic_false_positive_mitigation.md`
- `v1_4b_quic_false_positive_mitigation.json`
- `v1_4b_actionable_false_positive_review_sample.csv`

## Mitigation Safety

The normal QUIC/443 prior applies only to `quic-base`, `allow`, destination port `443` rows without stronger evidence. It does not suppress rows with:

- deny, drop, or reset behavior
- firewall threat classification
- high-risk application metadata
- strong anomaly evidence
- scanning-like behavior
- many destination ports or IPs
- repeated external-to-internal attempts
- high outbound bytes

All strategies are evaluated offline. No model is written or activated, response automation remains disabled, and the metrics are not production-accuracy claims.

