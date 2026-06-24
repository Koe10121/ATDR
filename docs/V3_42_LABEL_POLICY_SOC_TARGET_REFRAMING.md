# v3.42 Label Policy And SOC Target Reframing

## Status

v3.42 is a diagnostic-only supervised ML phase. It does not write labels, activate models, write active model artifacts, enable response automation, or change detection behavior.

## Why This Phase Was Needed

v3.41 showed that ATDR's supervised ML instability is partly caused by label-semantics conflicts, not only model thresholds. Similar traffic patterns such as `ssl/443`, `quic-base/443`, `incomplete/80`, `ping`, and `dns/53` appear with both benign-like and threat-like labels. That makes split-stable supervised learning difficult.

## Label Policy

- `benign`: routine allowed traffic with no meaningful rule, anomaly, scan, diversity, deny/drop/reset, or high-risk service evidence.
- `benign_unusual`: allowed or utility traffic that is uncommon/noisy but lacks enough corroborating evidence for suspicious.
- `needs_context`: ambiguous traffic where parser/log context is limited or more related logs are needed.
- `suspicious`: evidence-backed probing, scanning, repeated failures, unknown-app pressure, anomaly/rule agreement, or risky behavior needing SOC review.
- `malicious`: high-confidence malicious behavior with strong multi-signal evidence such as C2/exfiltration, repeated external attacks, or clear denied high-risk service attempts.

## Diagnostic SOC Targets

v3.42 evaluates alternative training targets without changing stored labels:

- `non_threat`
- `unusual_needs_review`
- `evidence_backed_suspicious`
- `malicious_high_confidence`

The goal is to test whether separating "unusual needs review" from exact threat verdicts improves stability.

## Current Result

Best diagnostic candidate:

- `soc_policy_queue_logistic_regression`
- FPR max: `0.1404`
- Threat-positive F1 min: `0.5678`
- Evidence-backed/suspicious recall min: `0.2`
- Malicious/high-confidence recall min: `0.0459`
- Calibration: passed
- Readiness: `candidate_only`

The result controls false positives better, but recall collapses across independent splits. It is not safe to promote or activate.

## Interpretation

This phase confirms that a cleaner target taxonomy helps describe the problem, but target reframing alone is not enough. The next phase should focus on label-policy-assisted training data repair or a hybrid detector that separates:

- low-signal normal web/utility traffic
- unusual-but-not-threat traffic
- evidence-backed suspicious behavior
- high-confidence malicious behavior

Any AI-generated labels must remain weak/assisted and must not be marked human-reviewed.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Response automation allowed: false
- Real firewall blocking: false
- Labels written: false

