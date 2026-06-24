# v3.18 Detection Corpus And FP/FN QA

## Status

v3.18 expands ATDR's controlled detection validation corpus and adds explicit false-positive / false-negative QA reporting. It does not change production detection thresholds, ML activation, startup commands, IAM behavior, response automation, or real firewall blocking.

ATDR remains a controlled lab prototype. ML remains decision support only. Response automation and real firewall blocking remain disabled.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Parser and parser profiles | `atdr/app/parsers/paloalto_parser.py` |
| Log persistence | `atdr/app/services/log_service.py` |
| Detection orchestration | `atdr/app/services/detection_service.py` |
| Rule catalog and attack mapping | `atdr/app/detection/rules.py`, `atdr/app/detection/attack_mapping.py`, `docs/DETECTION_RULE_CATALOG.md` |
| Explanations | `atdr/app/detection/explanations.py` |
| Scenario registry | `atdr/scripts/run_source_scenario.py` |
| Detection validation | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/validate_detection_quality.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Scenario samples | `data/samples/scenarios/*.txt`, `data/samples/scenarios/scenario_expectations.json` |
| Tests | `atdr/tests/test_detection_validation_suite.py`, `atdr/tests/test_v318_detection_corpus.py` |

## New Safe Scenarios

Added synthetic, non-private scenario samples:

- `benign_dns_web_traffic`
- `benign_incomplete_allow_noise`
- `benign_repeated_internal_service`
- `benign_high_volume_single_service`
- `suspicious_horizontal_scan`
- `suspicious_denied_ssh_burst`
- `suspicious_rare_port_probe`
- `malicious_like_c2_beacon`
- `malicious_like_exfiltration_burst`
- `malformed_vendor_mixed_fields`

These scenarios use lab-safe RFC1918 and documentation-range addresses. They are designed to test normal controls, parser warnings, scan-like behavior, denied access bursts, rare-port probing, C2-like beaconing, exfiltration-like bursts, and malformed vendor rows.

## Parser / Normalization Validation

Command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_parser_normalization --pretty
```

Latest targeted result:

| Metric | Result |
| --- | ---: |
| Files checked | 25 |
| Sample lines checked | 173 |
| Parsed successfully | 170 |
| Parse failures | 3 |
| Raw fallback count | 3 |
| Missing timestamp count | 5 |
| Missing source IP count | 10 |
| Missing destination IP count | 10 |
| Missing action count | 11 |
| Unknown app count | 86 |

Interpretation:

- Palo Alto-style synthetic samples parse successfully.
- Generic syslog and malformed rows preserve raw evidence.
- Raw fallback parse failures are expected and counted.
- Unknown/incomplete app values remain visible as data-quality signals, especially for scan-style or partially established traffic.

## Detection FP/FN QA

Command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
```

Latest targeted result:

| Metric | Result |
| --- | ---: |
| Scenarios | 23 |
| Passed scenarios | 23 |
| Benign/no-alert scenarios | 11 |
| Positive alert scenarios | 12 |
| Expected alerts | 12 |
| Actual alerts | 12 |
| False-positive scenario count | 0 |
| False-negative scenario count | 0 |
| Unexpected attack type count | 0 |
| Alerts created | 11 |
| Alerts deduplicated | 1 |
| Raw logs imported in temp DB | 144 |
| Normalized logs created in temp DB | 141 |
| Parse failures | 3 |
| Parser warning count | 56 |
| Raw fallback count | 3 |
| Explanation completeness score | 1.0 |
| Response actions created | 0 |

## Rule-Level QA

Each scenario now reports whether the outcome came from:

- `rule`
- `anomaly`
- `supervised`
- `hybrid`
- `parser_warning_only`
- `no_alert`

Current v3.18 validation is rule-first with hybrid summary context. Supervised ML remains decision support only and is not activated or promoted.

## Explanation QA

Alert explanations expose:

- what happened
- why suspicious / why flagged
- normalized fields used
- rule evidence
- anomaly evidence
- ML evidence marked decision support only
- attack mapping
- recommended analyst next steps
- safety note

No-alert and parser-warning scenarios remain covered through parser/normalization validation and Log Explorer "Why not flagged?" behavior.

## Safety Controls Preserved

- No automatic response.
- No real firewall blocking.
- No ML activation or production promotion.
- No external IAM/OIDC/Google login.
- No DB reset or deletion.
- No raw evidence deletion.
- No production readiness claim.

## Known Limitations

- The corpus is controlled and synthetic.
- It improves regression confidence but does not prove production accuracy.
- Real-source traffic may introduce new parser fields, source drift, or alert noise.
- False-positive/false-negative counts are scenario-level QA counts, not real-world SOC metrics.

## Manual Dashboard Checks

After starting backend/frontend:

1. Open Log Explorer and inspect a benign scenario log for "Why not flagged?"
2. Open Alerts and inspect a scan/brute-force/exfiltration-style alert.
3. Confirm "Why flagged?" includes normalized fields, rule evidence, and analyst next steps.
4. Confirm Response & Audit has no automatic response actions.
5. Confirm SOC Assistant can explain an alert as decision support only.
