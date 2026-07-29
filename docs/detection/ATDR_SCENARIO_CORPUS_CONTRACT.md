# ATDR Scenario Corpus Contract

## Status

v4.9 controlled scenario-corpus contract. These samples are synthetic/safe and are intended for parser, source-scoped detection, source health, deduplication, explanation, and response-safety regression. They are not production accuracy claims and are not real private logs.

## Source Evidence

- Scenario registry: `atdr/scripts/run_source_scenario.py`
- Scenario expectations: `data/samples/scenarios/scenario_expectations.json`
- Scenario files: `data/samples/scenarios/*.txt`
- Detection validation: `atdr/scripts/validate_detection_pipeline.py`
- Detection quality validation: `atdr/scripts/validate_detection_quality.py`
- Rule contract: `docs/detection/ATDR_RULE_PACK_CONTRACT.md`
- Taxonomy: `docs/detection/ATDR_DETECTION_TAXONOMY.md`

## Safety Contract

- Scenarios must be synthetic/safe.
- Scenarios must not require real firewall hardware.
- Scenarios must not mutate the current database when run through temp-DB validators.
- Scenarios must preserve raw evidence.
- Scenarios must require zero response actions.
- Scenarios must not activate models or enable automatic response.
- Expected labels are regression expectations, not human-reviewed training labels.
- Alert-positive expectations must identify a claim boundary and analyst-verifiable evidence.

## Scenario Families

| Family | Purpose |
| --- | --- |
| Normal / benign | Prove common allowed traffic does not create noisy alerts. |
| Suspicious / malicious-like | Prove expected alert types are generated with useful explanations. |
| Deduplication | Prove repeated behavior updates an existing alert instead of creating endless duplicates. |
| Parser fallback | Prove generic syslog and malformed/raw fallback preserve evidence and count quality issues. |
| Mixed validation | Prove normal, suspicious, and malformed rows can be handled together. |

## Scenario Registry

| Scenario | Parser Profile | Expected Result | Expected Alert Type(s) | No Response |
| --- | --- | --- | --- | --- |
| `normal_allowed_traffic` | `palo_alto` | No alerts | `normal` | true |
| `normal_web_dns_quic_traffic` | `palo_alto` | No alerts | `normal` | true |
| `benign_dns_web_traffic` | `palo_alto` | No alerts | `normal` | true |
| `benign_incomplete_allow_noise` | `palo_alto` | Parser warnings, no alerts | `normal` | true |
| `benign_repeated_internal_service` | `palo_alto` | No alerts | `normal` | true |
| `benign_high_volume_single_service` | `palo_alto` | No alerts | `normal` | true |
| `normal_high_volume_but_allowed_traffic` | `palo_alto` | No alerts | `normal` | true |
| `normal_repeated_same_service_traffic` | `palo_alto` | No alerts | `normal` | true |
| `mixed_small_subnet_validation` | `palo_alto` | Three expected alerts | `port_scan`, `brute_force`, `malware_c2` | true |
| `port_scan_like_traffic` | `palo_alto` | One port-scan alert | `port_scan` | true |
| `suspicious_horizontal_scan` | `palo_alto` | One port-scan alert | `port_scan` | true |
| `brute_force_like_traffic` | `palo_alto` | One brute-force alert | `brute_force` | true |
| `suspicious_denied_ssh_burst` | `palo_alto` | One brute-force alert | `brute_force` | true |
| `suspicious_rare_port_probe` | `palo_alto` | One policy/suspicious access alert | `policy_violation` | true |
| `malware_c2_like_beaconing` | `palo_alto` | One beaconing/C2-style alert | `malware_c2` | true |
| `malicious_like_c2_beacon` | `palo_alto` | One beaconing/C2-style alert | `malware_c2` | true |
| `data_exfiltration_suspicion` | `palo_alto` | One data-transfer suspicion alert | `data_exfiltration_suspicion` | true |
| `malicious_like_exfiltration_burst` | `palo_alto` | One high outbound-transfer alert | `data_exfiltration_suspicion` | true |
| `ddos_or_connection_flood_like` | `palo_alto` | One flood-like alert | `dos_ddos` | true |
| `repeated_dedup_traffic` | `palo_alto` | One alert with dedup update | `brute_force` | true |
| `generic_syslog_mixed` | `generic_syslog` | Raw evidence preserved, no alert | `unknown_anomaly` | true |
| `malformed_raw_fallback` | `raw_fallback` | Parse failures counted, raw evidence preserved | `unknown_anomaly` | true |
| `malformed_vendor_mixed_fields` | `palo_alto` | Parser warnings, raw evidence preserved | `unknown_anomaly` | true |
| `policy_violation_suspicious_app` | `palo_alto` | One suspicious-app policy alert | `policy_violation` | true |

## Required Expectation Fields

Every scenario expectation must define:

- `expected_alert_present`
- `expected_attack_type` or `expected_primary_attack_type`
- `expected_min_severity`
- `expected_parser_success_min`
- `expected_parse_failures_min`
- `expected_raw_preserved`
- `expected_no_response_actions`
- `expected_evidence_keywords`

Alert-positive scenarios must also define:

- `expected_alert_count_min`
- `expected_alert_count_max`
- `expected_min_risk_score`
- `expected_max_risk_score`

No-alert scenarios must define:

- `expected_alert_count_max`
- `expected_max_risk_score`

## Validation Commands

Contract-only validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
```

Scenario behavior validation with temporary DB:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
```

Full controlled detection pipeline:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_pipeline --pretty
```

The v4.9 controlled quality matrix passes 23 of 23 scenarios with zero scenario-level false positives, false negatives, unexpected attack types, or response actions. This result validates the controlled corpus only; it does not establish real-source accuracy or production readiness.
