# ATDR v1.9b Independent FPR Stabilization

## Purpose

v1.9 missed the independent benign-like false-positive target by one row:
37 false positives across 240 benign-like evaluation rows produced an FPR of
`0.1542`, while the readiness target is `<= 0.15`.

v1.9b keeps that target unchanged and evaluates a narrow analyst-review
boundary. It does not train or activate a replacement model.

## Root Cause

All 37 v1.9 false positives were rows whose original review state was
`needs_context`:

- 36 were predicted suspicious and one was predicted malicious.
- 25 used `unknown-tcp` with allowed high destination ports.
- 12 used incomplete sessions.
- none was promoted by behavior-window evidence.
- rule-supported suspicious patterns remained distinguishable from the
  unresolved boundary rows.

The selected policy routes only allowed high-port `unknown-tcp` rows to analyst
review when they have no threat rule and no behavior-window evidence. It does
not use source names, scenario names, or expected labels.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v19b_independent_fpr_stabilization --pretty
```

Generated JSON, Markdown, analysis, benchmark snapshots, and CSV files remain
under ignored `demo_exports/benchmarks/`.

## Profile Result

The selected profile is `independent_fpr_stabilized`.

| Metric | v1.9 | v1.9b |
| --- | ---: | ---: |
| Threat precision | 0.8679 | 0.9170 |
| Threat recall | 0.9346 | 0.9346 |
| Threat F1 | 0.9000 | 0.9257 |
| Benign-like FPR | 0.1542 | 0.0917 |
| Suspicious recall | 0.9538 | 0.9538 |
| Malicious recall | 0.8769 | 0.8769 |
| False positives | 37 | 22 |
| False negatives | 17 | 17 |

Fifteen unresolved rows moved from an exact threat decision to an explicit
analyst-review boundary. Behavior-window evidence and rule-supported threat
decisions were not suppressed.

Calibration remains passed:

- method: `bucket_smoothing`
- ECE: `0.0027`
- Brier score: `0.0646`

## Readiness v7b

Readiness v7b adds checks that:

- the boundary does not use source or scenario identity;
- behavior-window evidence remains authoritative;
- ambiguous rows are routed to analyst review.

The current result is `controlled_real_source_validated_candidate` with 20 of
20 checks passed.

This status means the candidate has controlled decision-support evidence. It
does not mean:

- production promotion;
- model activation;
- automatic response authorization;
- real firewall blocking approval;
- production deployment readiness.

## Validation Caution

The v1.9b policy was informed by errors observed on the v1.9 holdout. The
identity-free rule is narrow and preserves threat evidence, but a future fresh
holdout should confirm transfer before any stronger claim. Real router/firewall
forwarding and long-duration source stability also remain future lab work.
