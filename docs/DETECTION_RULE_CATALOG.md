# ATDR Detection Rule Catalog

This catalog documents the deterministic rule layer used by ATDR for SOC triage. Rules are evidence generators, not automatic truth. Alert severity is derived from the combined score of all matched rules in a grouped finding.

Source evidence: `atdr/app/detection/rules.py`, `atdr/app/detection/attack_mapping.py`, `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py`.

## Rule Summary

| Rule Code | Rule Name | Attack Type Hint | Score | Confidence | Required Normalized Fields | Trigger Conditions | Likely False Positives | Analyst Next Step |
| --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| `deny_drop_action` | Deny or drop action | `policy_violation` | 25 | Triage-only | `action`, `subtype`, `session_end_reason`, `action_source` | Action/session metadata includes deny, drop, or reset. | Normal firewall policy denies, scanning blocked by edge controls. | Check repeated attempts, source reputation, and whether the deny is expected policy behavior. |
| `paloalto_threat_log` | Palo Alto threat event | `malware_c2` | 30 | High-confidence vendor signal | `log_type` | Palo Alto classified the row as `THREAT`. | Benign IDS signatures or blocked low-risk signatures. | Review vendor threat fields and related raw evidence. |
| `app_risk_4` | High application risk | `malware_c2` / policy triage | 15 | Triage-only | `app_risk` | Palo Alto application risk is 4. | Legitimate high-risk apps used for business. | Validate business need and look for repeated or unusual destinations. |
| `app_risk_5` | Very high application risk | `malware_c2` / policy triage | 25 | Triage-only unless combined | `app_risk` | Palo Alto application risk is 5. | File sharing, remote access, or tunneling tools used by approved users. | Review app category, destination, user/source, and repetition. |
| `suspicious_app_characteristic` | Suspicious application characteristic | `malware_c2` | 15 | Triage-only | `app_characteristic` | Characteristics include malware-prone, evasive, file-transfer, misuse, or high bandwidth indicators. | Common apps with broad Palo Alto characteristic tags. | Check whether the app is allowed and whether the destination/source pattern is normal. |
| `outside_to_inside` | Outside-to-inside traffic | `unknown_anomaly` / policy context | 15 | Context-only | `src_zone`, `dst_zone` | Traffic crosses from untrusted/internet/outside to trusted/inside/corp. | Normal inbound services, NAT, VPN, or published apps. | Confirm exposed service ownership and paired rules such as deny/drop or port scan. |
| `repeated_source_ip` | Repeated source activity | `unknown_anomaly` | 20 | Triage-only | `src_ip` | Source appears in at least 25 logs in the detection batch. | Busy proxy, NAT, monitoring, update service. | Look for diversity of destinations/ports and deny rates. |
| `multiple_denied_connections` | Multiple denied or dropped connections | `policy_violation` | 20 | Medium | `src_ip`, deny/drop fields | Source has at least 5 denied/dropped logs in the batch. | Expected blocks from scanners or misconfigured clients. | Check ports, zones, and whether attempts are external-to-internal. |
| `brute_force_like_attempts` | Brute-force-like service attempts | `brute_force` | 30 | High when repeated | `src_ip`, `dst_port`, deny/drop fields | Source has at least 5 denied/reset attempts against auth/service ports. | Misconfigured client repeatedly retrying a service. | Review target service, account/user context if available, and repeated attempts. |
| `possible_port_scan` | Possible port scanning behavior | `port_scan` | 25 | High when combined | `src_ip`, `dst_port` | Source touched at least 10 distinct destination ports. | Vulnerability scanner or monitoring tool. | Confirm authorization and scope; inspect related destinations and ports. |
| `beaconing_like_outbound` | Beaconing-like repeated outbound behavior | `malware_c2` | 30 | High when repeated | `src_ip`, `dst_ip`, `dst_port`, zone path, app risk/characteristic | Internal source makes at least 6 repeated outbound connections to same destination/port and has uncommon/risky/unknown app context. | Legitimate polling or update clients on uncommon ports. | Check periodicity, destination reputation, app identity, and endpoint context. |
| `connection_flood_suspicion` | Connection flood-like behavior | `dos_ddos` | 35 | High volume triage | `src_ip`, `dst_ip`, `dst_port` | Source made at least 20 repeated connections to the same destination/port. | Load testing, health checks, busy client retries. | Confirm business activity and destination availability impact. |
| `unusual_destination_port` | Unusual destination port | `unknown_anomaly` | 10 | Low/context-only | `dst_port`, zone path | Outside-to-inside traffic used an uncommon destination port. | Custom application ports, test services. | Verify service ownership and whether paired with scan/deny patterns. |
| `high_outbound_bytes` | High outbound byte volume | `data_exfiltration_suspicion` | 35 | Medium/high | `bytes`, zone path | Internal-to-external bytes exceed batch outlier threshold. | Backup, file transfer, software updates. | Validate transfer destination, business context, and repeated volume. |
| `unknown_or_incomplete_app` | Unknown or incomplete application | `unknown_anomaly` | 10 | Low/context-only | `app`, `app_category` | App is unknown, incomplete, not-applicable, unknown-tcp, or category unknown. | Early session classification, partial logs, unsupported parser fields. | Review parser completeness and whether stronger rules also fired. |
| `high_bytes_outlier` | High byte-count outlier | `data_exfiltration_suspicion` | 20 | Medium | `bytes` | Bytes exceed batch outlier threshold. | Normal large transfer. | Check direction, destination, app, and baseline. |
| `high_packets_outlier` | High packet-count outlier | `dos_ddos` | 20 | Medium | `packets` | Packet count exceeds batch outlier threshold. | High-volume allowed traffic. | Check service, direction, and whether availability is affected. |
| `ml_anomaly_detected` | ML anomaly detected | `unknown_anomaly` | 25 | Assistive only | `is_anomaly`, `anomaly_score` | IsolationForest marked event unusual. | Rare but benign traffic. | Treat as triage signal only; check rule evidence and human context. |

## Grouping And Deduplication Notes

- Internet sweep context rules (`outside_to_inside`, `unusual_destination_port`, `unknown_or_incomplete_app`) are grouped by multi-source sweep behavior to avoid one alert per internet source.
- App-risk policy rules (`app_risk_4`, `app_risk_5`, `suspicious_app_characteristic`) group across multiple internal sources when they are part of the same app-risk pattern, reducing policy alert noise.
- Multi-event pattern rules (`possible_port_scan`, `beaconing_like_outbound`, `connection_flood_suspicion`) group across a repeated-pattern window so one scan/flood/beaconing behavior does not split into multiple alert rows.
- Raw logs and normalized evidence are never deleted by alert grouping or deduplication.

## Current Validation Expectations

The controlled validation suite now distinguishes:

- expected primary attack type
- allowed secondary attack types
- minimum expected alert count
- maximum acceptable alert count
- unexpected/noisy attack types
- dedup behavior

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_pipeline --pretty
```

Expected v3.18 result: 24 scenarios pass, 15 expected alerts, 15 actual alerts, no unexpected attack types, explanation completeness 1.0, and zero response actions.

## v3.18 Parser And Detection Quality Commands

For parser/normalization quality without mutating the current database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_parser_normalization --pretty
```

Latest v3.18 targeted result: 25 safe sample files checked, 173 sample lines, 170 parsed successfully, 3 raw-fallback parse failures preserved as evidence, and zero response actions.

For a compact controlled detection-quality summary:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
```

Latest v3.18 targeted result: 23 detection-quality scenarios passed, 12 expected alerts, 12 actual alerts, 0 false-positive scenarios, 0 false-negative scenarios, 1 deduplicated alert update, explanation completeness 1.0, and zero response actions.

## v3.19 No-Hardware Soak Command

For a longer simulated multi-source validation without real firewall hardware:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_no_hardware_soak --use-temp-db --iterations 3 --source-count 3 --run-detection --pretty
```

Latest v3.19 targeted result: 27 events passed, 138 raw logs imported into a temporary DB, 138 normalized rows created, 9 raw-fallback parse failures preserved as evidence, 4 alerts created, 8 deduplicated alert updates, 0 false-positive scenarios, 0 false-negative scenarios, explanation completeness 1.0, and zero response actions.

The default soak mix intentionally excludes targeted boundary/noise probes such as `benign_repeated_internal_service` and `malicious_like_exfiltration_burst`. Those scenarios remain available through `--scenario-mix` for future rule-noise investigation. The default command is a stable no-hardware smoke/soak baseline, not a production-accuracy claim.
