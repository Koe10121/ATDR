# v3.48 Repaired Queue Target Model Evaluation

## Status

v3.48 is complete. It evaluates whether the v3.47 repaired queue target can train a more stable diagnostic SOC queue model. It is diagnostic only.

## Purpose

v3.47 improved queue-target ambiguity and split drift as a target proposal, but that does not prove the target trains better. v3.48 compares:

- original queue target + ExtraTrees
- original queue target + Logistic Regression
- repaired queue target + ExtraTrees
- repaired queue target + Logistic Regression

The evaluation uses train-internal threshold selection and the standard split set:

- time
- grouped/source-aware
- random seed 7
- random seed 17
- random seed 42

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Current Diagnostic Result

Best diagnostic strategy: `repaired_queue_target_extra_trees`

| Strategy | Passing Splits | Queue Precision Range | Queue Recall Range | Queue F1 Range | Queue FPR Range | Calibration |
| --- | ---: | --- | --- | --- | --- | --- |
| `original_queue_target_extra_trees` | 4 / 5 | `0.6911-0.9961` | `0.8807-0.9878` | `0.8133-0.9558` | `0.0082-0.4617` | passed |
| `original_queue_target_logistic_regression` | 0 / 5 | `0.5564-0.9443` | `0.5494-0.7098` | `0.6238-0.7626` | `0.0886-0.5918` | passed |
| `repaired_queue_target_extra_trees` | 5 / 5 | `0.9886-1.0000` | `0.9559-0.9937` | `0.9720-0.9969` | `0.0000-0.0467` | passed |
| `repaired_queue_target_logistic_regression` | 0 / 5 | `0.9144-0.9953` | `0.6047-0.8023` | `0.7363-0.8884` | `0.1437-1.0000` | passed |

Readiness result:

- Decision: `candidate_only`
- Checks passed: 9 / 9
- Independent queue stability: 5 / 5 splits
- Queue recall minimum: `0.9559`
- Queue false-positive rate maximum: `0.0467`
- Queue F1 minimum: `0.9720`
- Calibration: passed
- Threshold selection: train-internal only
- Target repair changed rows: 505 / 2672 (`18.9%`)
- Remaining queue false-positive patterns: mostly `quic-base/allow/443`, `ping/allow`, and a few rule/evidence-strength edge cases

The repaired target substantially improves queue-model stability. This does not activate a model and does not validate final suspicious/malicious severity classification. The next phase should test downstream severity modeling for rows admitted by this repaired queue.

## Expected Interpretation

The repaired target improves queue stability across splits, so the next phase can evaluate downstream severity modeling against that target. ATDR must still keep ML as decision support only until severity separation, external validation, and activation controls are proven.
