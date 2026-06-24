# v3.54 Severity Target Semantics Audit

## Status

v3.54 is complete as a diagnostic-only audit.

## Purpose

v3.52 and v3.53 showed that downstream severity classification remains unstable even after repairing the queue/severity interface and adding severity-specific evidence features. v3.54 audits the severity target meanings directly to check whether the model is being asked to learn clean, separable classes.

The audited severity targets are:

- `unusual_needs_review`
- `evidence_backed_suspicious`
- `malicious_high_confidence`

## What Was Checked

The audit checks:

- target support and reviewed/manual coverage
- categorical ambiguity by pattern, source, traffic family, evidence bucket, severity tier, service family, label, and label source
- numeric separability for v337 and v353 evidence features
- split target-rate drift across the standard validation split suite
- semantic contradictions such as benign-like labels with strong evidence
- simple policy reframing variants

No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Result

- Rows analyzed: `2252`
- Target distribution:
  - `unusual_needs_review`: `1365`
  - `evidence_backed_suspicious`: `498`
  - `malicious_high_confidence`: `389`
- Readiness: `diagnostic_only`
- Checks passed: `6 / 9`
- Max split target-rate shift: `0.1552`
- Residual diagnostic sample: `ml_baseline_reviews/v3_54_severity_semantics_residual_sample.csv`
- Residual sample import-ready: `false`

## Main Findings

The severity target support is large enough and split target drift is acceptable, but the target classes overlap strongly.

Major blockers:

- Top categorical conflict ratio: `0.625`
- Strongest numeric minimum pairwise effect size: `0.5345`, below the `0.70` diagnostic target
- High-severity semantic issue rows: `1300`
- `unusual_needs_review` rows with strong evidence: `1353`

The strongest numeric separator was `v337_source_diversity_pressure`, but its weakest pairwise separation was still not enough to justify activating a severity model.

## Ambiguous Patterns

Examples of high-conflict patterns:

- `app=incomplete|action=allow|port=443`
- `app=icloud-base|action=allow|port=443`
- `app=incomplete|action=allow|port=80`
- `app=ping|action=allow|port=-`

The large `rule_backed` evidence bucket is split across all three severity targets:

- `unusual_needs_review`: `891`
- `evidence_backed_suspicious`: `467`
- `malicious_high_confidence`: `371`

This means "has rule/evidence" is not enough to separate severity target classes.

## Policy Variant Diagnostic

Simple target reframing variants were checked without training or activation:

- Current three-severity target:
  - `unusual_needs_review`: `1365`
  - `evidence_backed_suspicious`: `498`
  - `malicious_high_confidence`: `389`
- Merge unusual and suspicious:
  - `review_needed`: `1863`
  - `malicious_high_confidence`: `389`
- Merge suspicious and malicious:
  - `unusual_needs_review`: `1365`
  - `threat_evidence`: `887`
- Binary review queue:
  - `needs_review`: `2252`

The binary queue target is trivial and not useful for severity classification. The two-class variants are candidates for later testing, but v3.54 did not activate or promote any model.

## Interpretation

The current downstream severity target is not clean enough for a stable three-class severity classifier. The main blocker is target semantics: many rows with similar evidence patterns are assigned to different severity targets.

This supports a policy redesign rather than more blind labeling or more post-prediction guards.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

Generated reports remain under `ml_baseline_reviews/` and are ignored.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v354_severity_target_semantics_audit --test-size 0.3 --min-samples 6
```

## Next Phase

v3.55 should test severity target policy reframing. Recommended candidates:

- collapse the downstream severity target to two classes: `review_needed` vs `malicious_high_confidence`
- or use `unusual_needs_review` vs `threat_evidence`
- reserve exact suspicious/malicious separation for explanation/ranking until labels and evidence semantics are cleaner
- keep all evaluation diagnostic-only with no activation, no automatic response, and no model artifact writing
