# v3.55 Severity Target Policy Reframing

## Status

v3.55 is complete as a diagnostic-only evaluation.

## Purpose

v3.54 showed that the current three-way downstream severity target is semantically ambiguous. v3.55 tests whether simpler target policies are more stable:

- current three-severity target
- `review_needed` vs `malicious_high_confidence`
- `unusual_needs_review` vs `threat_evidence`
- binary SOC review queue: `non_threat` vs `needs_review`

No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Result

Best diagnostic candidate:

- Strategy: `binary_review_queue_queue_only`
- Policy: `binary_review_queue`
- Readiness: `candidate_only`
- Checks passed: `10 / 10`
- Passing splits: `5 / 5`
- Policy positive F1 minimum: `0.9725`
- Positive false-positive rate maximum: `0.04`
- Critical recall minimum: `0.948`
- Queue F1 minimum: `0.9725`
- Macro F1 minimum: `0.7481`
- Calibration: `passed`

Safety:

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Strategy Comparison

| Strategy | Passing Splits | Positive F1 Min | FPR Max | Critical Recall Min | Queue F1 Min | Calibration |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `binary_review_queue_queue_only` | `5/5` | `0.9725` | `0.04` | `0.948` | `0.9725` | `passed` |
| `review_needed_vs_malicious_extra_trees` | `1/5` | `0.8037` | `0.0395` | `0.6881` | `0.9725` | `passed` |
| `review_needed_vs_malicious_logistic_regression` | `0/5` | `0.4247` | `0.4202` | `0.3837` | `0.9725` | `passed` |
| `current_three_severity_extra_trees` | `0/5` | `0.6277` | `0.7625` | `0.4571` | `0.9725` | `passed` |
| `current_three_severity_logistic_regression` | `0/5` | `0.2291` | `0.1245` | `0.0` | `0.9725` | `passed` |
| `unusual_vs_threat_evidence_extra_trees` | `0/5` | `0.6308` | `0.7756` | `0.2083` | `0.9725` | `passed` |
| `unusual_vs_threat_evidence_logistic_regression` | `0/5` | `0.516` | `0.1983` | `0.4054` | `0.9725` | `passed` |

## Interpretation

The most stable supervised target is currently the SOC queue decision:

```text
non_threat vs needs_review
```

This is useful because it matches the analyst workflow: the model can help decide which logs/alerts deserve analyst attention.

However, this is not the same as stable exact severity classification. The exact severity policies still fail broad split stability. The current evidence supports:

- using ML as SOC triage decision support
- keeping exact severity labels as explanation/ranking signals
- avoiding production promotion or automatic response
- not forcing suspicious/malicious exact separation until target semantics are cleaner

## What Improved

v3.55 shows a clean path forward:

- The queue admission target is stable.
- False positives are low for the queue candidate.
- Calibration passes.
- Independent split stability passes for the binary queue target.

## What Did Not Improve

The downstream exact severity target remains unstable:

- current three-severity policy: `0/5` passing splits
- suspicious/malicious-style exact policies: still unstable
- two-tier severity policies are better than the three-class target in places, but not stable enough to activate

## Safety

This phase is diagnostic only. It does not:

- write labels
- create active model artifacts
- activate or promote a model
- enable automatic response
- enable real firewall blocking

Generated reports remain under `ml_baseline_reviews/` and are ignored.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v355_severity_target_policy_reframing --test-size 0.3 --min-samples 6
```

## Next Phase

v3.56 should evaluate a safe SOC queue candidate integration path:

- expose the stable `needs_review` queue candidate as a diagnostic queue score
- keep exact severity as rules/explanation/ranking, not active supervised classification
- compare queue score with current alert/rule/hybrid scoring
- keep model activation disabled unless a separate reviewed activation phase is approved
