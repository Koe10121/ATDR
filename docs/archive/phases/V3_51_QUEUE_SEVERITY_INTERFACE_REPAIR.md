# v3.51 Queue / Severity Target Interface Repair

## Status

v3.51 compares diagnostic target-interface variants for rows admitted by the repaired queue. It is diagnostic only.

## Purpose

v3.50 found that `449` repaired-queue rows were admitted for analyst review but still mapped to downstream `non_threat`. That created a mismatch between queue admission and severity classification.

v3.51 tests target-interface repair options before another classifier pass:

- keep the current interface
- add an explicit `queue_low_confidence_review` class
- map queued `non_threat` rows to `unusual_needs_review`
- demote queued `non_threat` rows out of the downstream severity layer
- promote or demote queued `non_threat` rows based on evidence strength

## Result

- Rows audited: 2252
- Best diagnostic interface: `map_non_threat_to_unusual`
- Assessment: `diagnostic_only`
- Checks passed: `8 / 9`
- Remaining blocker: pattern ambiguity remains high

## Variant Comparison

| Variant | Retained Rows | Dropped Rows | Non-Threat Mismatch | Pattern Ambiguity | Max Split Drift | Checks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline_current_interface | 2252 | 0 | 449 | 0.7278 | above target | 2 / 5 |
| low_confidence_review_class | 2252 | 0 | 0 | 0.7278 | above target | 3 / 5 |
| map_non_threat_to_unusual | 2252 | 0 | 0 | 0.7278 | 0.1552 | 4 / 5 |
| demote_non_threat_from_queue | 1803 | 449 | 0 | 0.6606 | above target | 3 / 5 |
| evidence_promote_or_demote | 2252 | 0 | 0 | 0.7278 | 0.1552 | 4 / 5 |

Best candidate distribution:

| Target | Rows |
| --- | ---: |
| unusual_needs_review | 1365 |
| evidence_backed_suspicious | 498 |
| malicious_high_confidence | 389 |

## Interpretation

Mapping queued `non_threat` rows to `unusual_needs_review` is the cleanest diagnostic interface so far:

- it removes the downstream `non_threat` mismatch
- it keeps all admitted queue rows available for analyst review
- it improves split drift enough to pass the target
- it avoids adding a new fourth severity class for now

However, high pattern, traffic-family, and evidence-bucket ambiguity remains. That means the next classifier should use this interface only as a diagnostic target candidate. Activation is still blocked.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Next Recommended Phase

v3.52 should rerun downstream severity classification using the repaired v3.51 interface, especially `map_non_threat_to_unusual`, and compare it against the v3.49 baseline. It must remain diagnostic-only unless all split-stability, calibration, false-positive, recall, and safety gates pass.
