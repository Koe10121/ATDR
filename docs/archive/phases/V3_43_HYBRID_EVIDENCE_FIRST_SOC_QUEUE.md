# v3.43 Hybrid Evidence-First SOC Queue Candidate

## Status

v3.43 is a diagnostic-only supervised/heuristic ML phase. It does not write labels, activate models, write active model artifacts, enable automatic response, or change detection behavior.

## Purpose

v3.42 showed that label-policy reframing can describe ATDR's supervised-learning problem, but it still fails independent split stability. v3.43 tests a safer SOC design:

1. Evidence and rule context decide whether an event belongs in the SOC review queue.
2. Supervised ML can adjust confidence inside that evidence boundary.
3. Low-signal web/utility traffic should not become a threat solely because the supervised model is noisy.

## Strategies Evaluated

- `deterministic_evidence_first_queue`
- `hybrid_evidence_first_extra_trees`
- `hybrid_evidence_first_logistic_regression`

All strategies are evaluated against behavior-aware SOC targets:

- `non_threat`
- `unusual_needs_review`
- `evidence_backed_suspicious`
- `malicious_high_confidence`

## Current Result

Best diagnostic candidate:

- `hybrid_evidence_first_extra_trees`
- SOC review queue recall min: `0.9342`
- Threat-positive F1 min: `0.5611`
- Benign-like false-positive rate max: `0.9891`
- Evidence-backed suspicious recall min: `0.12`
- Malicious/high-confidence recall min: `0.7373`
- Calibration: passed
- Readiness: `candidate_only`

## Interpretation

The evidence-first queue is good at catching rows that should be reviewed, but it over-promotes many review-worthy rows into threat-positive classes. This is a useful architecture finding:

- Queue admission can be evidence-first.
- Exact severity should be a separate second-stage problem.
- `unusual_needs_review` must not be counted as suspicious/malicious automatically.

The next phase should split SOC queue admission from severity classification:

1. Stage A: review queue admission vs non-threat.
2. Stage B: within queued rows, classify unusual/needs-review vs evidence-backed suspicious vs malicious high-confidence.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

