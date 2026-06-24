# v3.46 Queue Target Separability And Training Signal Audit

## Status

v3.46 is a diagnostic-only supervised ML audit. It does not write labels, activate models, write active model artifacts, enable automatic response, or change detection behavior.

## Purpose

v3.44 and v3.45 showed an unstable tradeoff:

- ExtraTrees keeps queue/threat recall but stays noisy.
- Logistic regression reduces queue noise but suppresses too many review-worthy rows.

v3.46 audits whether the current behavior-aware SOC queue target is separable enough for stable supervised learning.

## What It Checks

- Queue target distribution.
- SOC target distribution.
- Top numeric feature separators.
- Ambiguous app/action/port patterns.
- Ambiguous traffic families.
- Ambiguous evidence buckets.
- Ambiguous sources.
- Label/review-status mix.
- Queue target drift across time, grouped/source-aware, and random splits.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Expected Interpretation

If queue targets are highly mixed by pattern/source/family or drift strongly across splits, more model tuning is unlikely to fix the problem by itself. The next phase should improve target definitions, benchmark coverage, or behavior-window features before considering activation.

## Current Result

- Rows audited: `2672`
- Queue target distribution: `needs_review=1859`, `non_threat=813`
- SOC target distribution: `non_threat=813`, `unusual_needs_review=972`, `evidence_backed_suspicious=498`, `malicious_high_confidence=389`
- Assessment: `diagnostic_only`
- Checks passed: `4 / 7`

Failed checks:

- Ambiguous pattern share: `0.4308`, target `<= 0.35`
- Traffic family ambiguity: `0.8046`, target `<= 0.45`
- Queue target split drift: `0.2636`, target `<= 0.2`

Passed signal check:

- Strongest numeric separator: `v331_rule_score`, effect size `2.2645`

Top numeric separators:

- `v331_rule_score`
- `v337_rule_backed_allow_flag`
- `v331_quic_443_allow_no_rule_flag`
- `v331_benign_web_allow_no_rule_flag`
- `v337_benign_web_likelihood_score`
- `v337_behavior_evidence_strength`
- `app_risk`
- `external_to_internal_flag`

Top ambiguous patterns include:

- `app=itunes-base|action=allow|port=443`
- `app=adobe-creative-cloud-base|action=allow|port=443`
- `app=stun|action=allow|port=3478`
- `app=facebook-base|action=allow|port=443`
- `app=gmail-base|action=allow|port=443`

## Interpretation

v3.46 explains why v3.44/v3.45 could not stabilize the supervised queue:

- There are useful features, especially rule score and benign web/no-rule indicators.
- However, the same high-level app/action/port families contain both `non_threat` and `needs_review` rows.
- The time split has a large queue-rate shift: train `0.7749` needs-review vs test `0.5112`.
- Random splits are much more balanced, which suggests deployment-like time/source drift is a major blocker.

The next phase should not activate a model. The best next step is to create a queue-target repair diagnostic that separates stable deterministic evidence rules from ambiguous app families and proposes weak target adjustments for review, without writing labels automatically.
