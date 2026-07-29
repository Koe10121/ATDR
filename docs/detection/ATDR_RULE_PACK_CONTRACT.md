# ATDR Rule Pack Contract

## Status

v4.9 source-backed rule-pack contract for catalog `atdr_rule_catalog_v4.9.0`. This document describes the current deterministic detection rules as a versioned decision-support contract. It does not authorize model activation, response automation, or real firewall blocking.

## Source Evidence

- Rule implementation: `atdr/app/detection/rules.py`
- Versioned metadata: `atdr/app/detection/rule_catalog.py`
- Attack mapping: `atdr/app/detection/attack_mapping.py`
- Alert grouping/deduplication: `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py`
- Scenario contract: `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`
- Rule standard: `docs/security/ATDR_DETECTION_RULE_STANDARD.md`

## Safety Contract

- Rules generate evidence for SOC triage and can create grouped/deduplicated alerts.
- Rules do not trigger automatic response or perform real firewall blocking.
- Rules do not write labels or activate ML models.
- Raw and normalized evidence remains preserved.
- Analyst review remains required before any simulated response action.

## Rule Pack v4.9

| Catalog ID / Code | Product Label | Attack Type Hint | Evidence Strength | Window | Trigger Summary | Claim Boundary |
| --- | --- | --- | --- | --- | --- | --- |
| `ATDR-NET-001` / `deny_drop_action` | Deny or drop action | `policy_violation` | high field confidence, low attack confidence | event | Firewall action/session metadata indicates deny, drop, or reset. | A policy action is not proof of hostile intent. |
| `ATDR-NET-002` / `paloalto_threat_log` | Palo Alto threat event | `unknown_anomaly` | high vendor-event confidence | event | Vendor log type is `THREAT`. | Subtype, severity, signature, and action still require review; generic THREAT is not C2 proof. |
| `ATDR-NET-003` / `app_risk_4` | High application risk | `policy_violation` | medium context | event | Palo Alto app risk equals 4. | Vendor risk is context, not proof of compromise. |
| `ATDR-NET-004` / `app_risk_5` | Very high application risk | `policy_violation` | medium context | event | Palo Alto app risk is at least 5. | Approved high-risk applications can be benign. |
| `ATDR-NET-005` / `suspicious_app_characteristic` | Suspicious app characteristic | `policy_violation` | medium context | event | Vendor app characteristics match a versioned risk set. | A broad application characteristic is not malware attribution. |
| `ATDR-NET-006` / `outside_to_inside` | Outside-to-inside traffic | `unknown_anomaly` | high direction confidence, informational risk | event | Source zone is external and destination zone is internal. | Published services and expected inbound traffic are common. |
| `ATDR-NET-007` / `repeated_source_ip` | Repeated source activity | `unknown_anomaly` | medium | source-scoped 5m | Source produces at least 25 events. | NAT, monitoring, and busy clients can repeat legitimately. |
| `ATDR-NET-008` / `multiple_denied_connections` | Multiple denied connections | `policy_violation` | medium | source-scoped 5m | Source produces at least 5 denied, dropped, or reset events. | Expected block noise and misconfiguration remain plausible. |
| `ATDR-NET-009` / `brute_force_like_attempts` | Brute-force-like attempts | `brute_force` | medium | source-scoped 5m | Source produces at least 5 denied/reset attempts to authentication or service ports. | Traffic retries do not prove password guessing. |
| `ATDR-NET-010` / `possible_port_scan` | Possible port scan | `port_scan` | medium | source-scoped 5m | Source touches at least 10 distinct destination ports. | Intent and scanner authorization require analyst context. |
| `ATDR-NET-011` / `beaconing_like_outbound` | Beaconing-like outbound behavior | `malware_c2` | medium | source-scoped 5m | At least 6 repeated internal-to-external connections share a destination and risky/uncommon context. | Behavior is C2-like, not proof of malware. |
| `ATDR-NET-012` / `connection_flood_suspicion` | Connection flood-like behavior | `dos_ddos` | medium | source-scoped 5m | Source makes at least 20 connections to one destination service. | Service impact requires independent telemetry. |
| `ATDR-NET-013` / `unusual_destination_port` | Unusual destination port | `unknown_anomaly` | low | event | Outside-to-inside traffic uses a non-common port. | Custom services can be legitimate. |
| `ATDR-NET-014` / `high_outbound_bytes` | High outbound byte volume | `data_exfiltration_suspicion` | low | event | Internal-to-external bytes exceed the versioned threshold. | Volume alone does not establish data theft. |
| `ATDR-NET-015` / `unknown_or_incomplete_app` | Unknown/incomplete app | `unknown_anomaly` | high parser/context confidence, informational risk | event | App identification is unknown, incomplete, or not applicable. | Early classification and parser limitations are expected causes. |
| `ATDR-NET-016` / `high_bytes_outlier` | High byte-count outlier | `unknown_anomaly` | low | event | Total bytes exceed the versioned threshold. | Directionless volume is not an exfiltration claim. |
| `ATDR-NET-017` / `high_packets_outlier` | High packet-count outlier | `unknown_anomaly` | low | event | Packet count exceeds the versioned threshold. | Directionless volume is not a denial-of-service claim. |
| `ATDR-ML-001` / `ml_anomaly_detected` | ML anomaly detected | `unknown_anomaly` | low/experimental | event | IsolationForest diagnostic score crosses its configured threshold. | Statistically unusual does not mean malicious. |

The machine-readable catalog is authoritative for required fields, status, false positives, references, MITRE technique IDs, explanation template, and claim boundary. Correlation is source-scoped and bounded to five minutes so two devices reporting the same IP cannot inflate one another's counts.

## Evidence And Mapping Rules

- `THREAT` log type is a vendor event family, not a C2 classification by itself.
- Application risk and characteristics are policy/context signals, not malware proof.
- Directionless byte and packet outliers remain `unknown_anomaly`; only directional outbound volume can support `data_exfiltration_suspicion`.
- MITRE mappings describe behavior hypotheses. They do not prove intent, attribution, impact, or compromise.
- IsolationForest is assistive anomaly evidence only.

## Versioning Rules

Future rule changes must update the catalog and this contract when they add, remove, rename, or materially change:

- rule ID, code, version, or status;
- score contribution, trigger, required field, correlation scope, or time window;
- attack type, MITRE mapping, evidence confidence, or claim boundary;
- explanation template, analyst check, or false-positive expectation; or
- primary references.

## Primary References

Accessed 2026-07-18:

- Palo Alto Networks, [Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields).
- Palo Alto Networks, [Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields).
- SigmaHQ, [Sigma Rules Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).
- MITRE ATT&CK: [T1046](https://attack.mitre.org/techniques/T1046/), [T1110](https://attack.mitre.org/techniques/T1110/), [T1498](https://attack.mitre.org/techniques/T1498/), [T1071](https://attack.mitre.org/techniques/T1071/), and [T1048](https://attack.mitre.org/techniques/T1048/).

## Validation

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
```

The contract validator checks implementation/catalog/document alignment, scenario expectations, source files, controlled taxonomy values, and no-response safety. The scenario validator executes all safe cases against a disposable database.
