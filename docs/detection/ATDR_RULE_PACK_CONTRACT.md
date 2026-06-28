# ATDR Rule Pack Contract

## Status

v3.71 source-backed rule-pack contract. This document describes the current deterministic detection rules as a product contract. It does not change rule thresholds, detection behavior, model behavior, response behavior, or database schema.

## Source Evidence

- Rule implementation: `atdr/app/detection/rules.py`
- Attack mapping: `atdr/app/detection/attack_mapping.py`
- Alert grouping/deduplication: `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py`
- Current rule documentation: `docs/DETECTION_RULE_CATALOG.md`
- Productization plan: `docs/DETECTION_ML_PRODUCTIZATION_PLAN.md`

## Safety Contract

- Rules generate evidence for SOC triage.
- Rules may create alerts through grouped/deduplicated detection logic.
- Rules do not trigger automatic response.
- Rules do not perform real firewall blocking.
- Rules do not write labels or activate ML models.
- Raw and normalized log evidence must remain preserved.
- Analyst review remains required before any simulated response action.

## Rule Pack v1

| Rule ID | Product Label | Attack Type Hint | Evidence Strength | Required Normalized Fields | Trigger Summary | False-Positive Risk | Analyst Check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `deny_drop_action` | Deny/drop action | `policy_violation` | medium when repeated | `action`, `subtype`, `session_end_reason`, `action_source` | Firewall action/session metadata indicates deny, drop, or reset. | Expected firewall policy blocks. | Check repetition, source, ports, and whether policy deny is expected. |
| `paloalto_threat_log` | Palo Alto threat event | `malware_c2` | high vendor signal | `log_type` | Vendor log type is `THREAT`. | Low-risk signature, blocked benign signature, noisy threat feed. | Review vendor threat fields and raw evidence. |
| `app_risk_4` | High application risk | `malware_c2` | context only | `app_risk` | Palo Alto app risk equals 4. | Approved high-risk business app. | Validate business need and destination pattern. |
| `app_risk_5` | Very high application risk | `malware_c2` | medium when combined | `app_risk` | Palo Alto app risk is 5 or higher. | Approved remote access, tunneling, or file transfer. | Review app category, source, user context, and repetition. |
| `suspicious_app_characteristic` | Suspicious app characteristic | `malware_c2` | context only | `app_characteristic` | App characteristics include malware-prone, evasive, misuse, file-transfer, or high bandwidth tags. | Broad vendor app tags. | Check if app is approved and whether traffic pattern is unusual. |
| `outside_to_inside` | Outside-to-inside traffic | `unknown_anomaly` | context only | `src_zone`, `dst_zone` | Traffic crosses from outside/untrusted/internet to inside/trusted/corp. | Published services, VPN, NAT, accepted inbound applications. | Pair with deny/drop, scan, port, and service context. |
| `repeated_source_ip` | Repeated source activity | `unknown_anomaly` | medium when diverse | `src_ip` | Source appears at least 25 times in the detection batch. | NAT, proxy, monitoring, update systems. | Check destination diversity, port diversity, and deny ratio. |
| `multiple_denied_connections` | Multiple denied connections | `policy_violation` | medium | `src_ip`, deny/drop fields | Source has at least 5 denied/dropped logs. | Expected block noise or misconfigured client. | Check target services, zones, and whether attempts are external-to-internal. |
| `brute_force_like_attempts` | Brute-force-like attempts | `brute_force` | high when repeated | `src_ip`, `dst_port`, deny/drop fields | Source has at least 5 denied/reset attempts against auth/service ports. | Misconfigured client repeatedly retrying a service. | Check target account/service context if available. |
| `possible_port_scan` | Possible port scan | `port_scan` | high when combined | `src_ip`, `dst_port` | Source touches at least 10 distinct destination ports. | Approved scanner or monitoring tool. | Confirm scanner authorization and scope. |
| `beaconing_like_outbound` | Beaconing-like outbound behavior | `malware_c2` | high when repeated | `src_ip`, `dst_ip`, `dst_port`, zones, app context | Internal source makes repeated outbound connections to same destination/port with uncommon, risky, or unknown app context. | Legitimate polling, update clients, health checks. | Check periodicity, destination reputation, and endpoint context. |
| `connection_flood_suspicion` | Connection flood-like behavior | `dos_ddos` | high volume triage | `src_ip`, `dst_ip`, `dst_port` | Source makes at least 20 repeated connections to same destination/port. | Load testing, health checks, busy retrying client. | Confirm business activity and service impact. |
| `unusual_destination_port` | Unusual destination port | `unknown_anomaly` | low/context only | `dst_port`, zones | Outside-to-inside traffic uses uncommon destination port. | Custom app port or test service. | Verify service ownership and whether paired with stronger rules. |
| `high_outbound_bytes` | High outbound byte volume | `data_exfiltration_suspicion` | medium/high | `bytes`, zones | Internal-to-external bytes exceed batch outlier threshold. | Backup, file transfer, software update. | Validate transfer destination and business context. |
| `unknown_or_incomplete_app` | Unknown/incomplete app | `unknown_anomaly` | low/context only | `app`, `app_category` | App is unknown, incomplete, not-applicable, or category is unknown. | Early session classification, parser limitations. | Check parser completeness and stronger evidence. |
| `high_bytes_outlier` | High byte-count outlier | `data_exfiltration_suspicion` | medium | `bytes` | Bytes exceed batch outlier threshold. | Normal large transfer. | Check direction, destination, app, and baseline. |
| `high_packets_outlier` | High packet-count outlier | `dos_ddos` | medium | `packets` | Packets exceed batch outlier threshold. | High-volume allowed traffic. | Check service, direction, and availability impact. |
| `ml_anomaly_detected` | ML anomaly detected | `unknown_anomaly` | assistive only | `is_anomaly`, `anomaly_score` | IsolationForest marks the event as unusual. | Rare but benign traffic. | Treat as triage signal only and verify rule evidence. |

## Versioning Rules

Future rule changes must update this contract when they add, remove, rename, or substantially change:

- rule ID
- score contribution
- trigger condition
- required normalized field
- attack type hint
- analyst next check
- false-positive expectation

## Validation

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
```

The validator checks that implemented rule IDs are documented, scenario expectations are present, scenario sample files exist, response actions remain forbidden, and scenario attack types use known controlled taxonomy values.
