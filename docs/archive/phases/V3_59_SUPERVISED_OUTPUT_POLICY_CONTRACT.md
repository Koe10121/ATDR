# v3.59 Supervised Output Policy Contract

## Status

v3.59 is complete as a diagnostic-only supervised ML safety contract.

## Purpose

Recent supervised ML work showed an important pattern:

- The binary SOC review queue target is stable.
- Exact suspicious/malicious/benign-like/needs_context separation is still semantically unstable.
- Queue-vs-rule/hybrid agreement is useful, but evidence-only disagreements still require analyst review.

v3.59 turns that evidence into a machine-readable policy contract so future work does not accidentally treat unstable exact labels as production-ready classifier outputs.

## Current Result

Latest local run:

- Decision: `decision_support_contract_ready`
- Recommended supervised strategy: `binary_soc_review_queue`
- Runtime activation: `false`
- Dashboard guidance readiness: `true`
- Exact classification policy: `explanation_or_ranking_only`
- Checks passed: `7 / 7`
- Label rows: `2672`
- Trainable latest rows: `2672`
- Excluded rows: `0`

## Evidence Used

v3.55 queue policy:

- Status: `stable`
- Splits: `5 / 5`
- Queue F1 min: `0.9725`
- Queue recall min: `0.948`
- Queue precision min: `0.9907`
- Benign-like FPR max: `0.04`
- Calibration: `passed`

v3.57 queue/evidence agreement:

- Status: `usable_with_review`
- Splits: `4 / 5`
- Queue F1 min: `0.9725`
- Queue FPR max: `0.04`
- Agreement min: `0.884`
- Main remaining disagreement: evidence-only rows still require analyst review.

Exact severity policies:

- Stable exact severity policies: `0 / 6`
- Therefore exact suspicious/malicious/needs_context output is not a stable active classifier target.

## Allowed Outputs

| Output | Status | Allowed Use |
| --- | --- | --- |
| SOC review queue score | `allowed_for_decision_support` | Prioritize analyst review and support alert explanations. |
| Exact severity or attack label | `explanation_or_ranking_only` | Supporting context after rule/hybrid evidence, not final authority. |
| Rule/hybrid evidence | `primary_detection_evidence` | Alert creation, why-flagged explanations, SOC Assistant citations. |

## Blocked Uses

- Automatic response from supervised ML output.
- Real firewall blocking from supervised ML output.
- Production promotion based on queue diagnostics alone.
- Marking AI-generated labels as human-reviewed.
- Treating exact suspicious/malicious/needs_context labels as stable production classes.
- Sending raw logs to an external assistant or LLM by default.

## Safety

v3.59 does not:

- write labels
- create active model artifacts
- activate or promote a model
- enable automatic response
- enable real firewall blocking
- include raw logs in reports

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v359_supervised_output_policy_contract --pretty
```

Generated outputs stay under `ml_baseline_reviews/` and remain ignored.

## Next Phase

Use this contract to make downstream behavior more consistent:

- dashboard wording should emphasize queue-based decision support
- assistant answers should reference exact labels as supporting context only
- future model work should optimize queue admission and explanation quality before exact class activation
