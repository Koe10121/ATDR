# ATDR Detection Rule Catalog

This catalog documents the deterministic rule layer used by ATDR for SOC triage. Rules are evidence generators, not automatic truth. Alert severity is derived from the combined score of all matched rules in a grouped finding.

Source evidence: `atdr/app/detection/rules.py`, `atdr/app/detection/rule_catalog.py`, `atdr/app/detection/attack_mapping.py`, `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py`.

Current machine-readable contract: `atdr_rule_catalog_v5.31.0`. The machine-readable catalog is authoritative when prose and code differ.

## Rule Summary

| Rule Code | Rule Name | Attack Type Hint | Score | Confidence | Required Normalized Fields | Trigger Conditions | Likely False Positives | Analyst Next Step |
| --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| `deny_drop_action` | Deny or drop action | `policy_violation` | 25 | Triage-only | `action`, `subtype`, `session_end_reason`, `action_source` | Action/session metadata includes deny, drop, or reset. | Normal firewall policy denies, scanning blocked by edge controls. | Check repeated attempts, source reputation, and whether the deny is expected policy behavior. |
| `paloalto_threat_log` | Palo Alto threat event | `unknown_anomaly` | 10-45 | High vendor-event confidence; attack meaning unresolved | `log_type`, parsed threat severity/name | Palo Alto classified the row as `THREAT`; score follows informational/low/medium/high/critical vendor severity. | Informational, low-severity, or blocked signatures. | Verify subtype, severity, signature/name, action, and related traffic or endpoint evidence. |
| `app_risk_4` | High application risk | `policy_violation` | 15 | Context-only | `app_risk` | Palo Alto application risk is 4. | Legitimate high-risk apps used for business. | Validate business need and look for stronger behavioral evidence. |
| `app_risk_5` | Very high application risk | `policy_violation` | 25 | Context-only unless combined | `app_risk` | Palo Alto application risk is at least 5. | File sharing, remote access, or tunneling tools used by approved users. | Review app category, destination, user/source, and repetition. |
| `suspicious_app_characteristic` | Suspicious application characteristic | `policy_violation` | 15 | Context-only | `app_characteristic` | Characteristics intersect the versioned misuse/evasion/transfer/bandwidth set. | Common apps with broad Palo Alto characteristic tags. | Check whether the app is approved and whether stronger evidence supports escalation. |
| `outside_to_inside` | Outside-to-inside traffic | `unknown_anomaly` / policy context | 15 | Context-only | `src_zone`, `dst_zone` | Traffic crosses from untrusted/internet/outside to trusted/inside/corp. | Normal inbound services, NAT, VPN, or published apps. | Confirm exposed service ownership and paired rules such as deny/drop or port scan. |
| `repeated_source_ip` | Repeated source activity | `unknown_anomaly` | 20 | Context-only | `src_ip`, event time, source identity | Source represents at least 25 sessions in one registered-source five-minute window. | Busy proxy, NAT, monitoring, update service. | Look for diversity of destinations/ports, deny rates, and source ownership. |
| `multiple_denied_connections` | Multiple denied or dropped connections | `policy_violation` | 20 | Medium | `src_ip`, deny/drop fields, event time | Source has at least 5 denied/dropped/reset sessions in one source-scoped five-minute window. | Expected blocks from scanners or misconfigured clients. | Check ports, zones, targets, and whether attempts are expected policy noise. |
| `brute_force_like_attempts` | Brute-force-like service attempts | `brute_force` | 30 | Medium behavioral confidence | `src_ip`, `dst_ip`, `dst_port`, deny/drop fields, event time | Source has at least 5 denied/reset attempts to the same destination and authentication/service port in five minutes. | Misconfigured credentials, health checks, password-manager retries. | Verify target/service and identity-provider or authentication logs. |
| `possible_port_scan` | Possible vertical port scanning behavior | `port_scan` | 25 | Medium behavioral confidence | `src_ip`, `dst_port`, event time | Source touches at least 10 distinct destination ports in five minutes with deny, inbound, unresolved-app, or vendor-scan support. | Authorized vulnerability scanner, asset discovery, monitoring. | Confirm authorization, target scope, port spread, and deny rate. |
| `possible_horizontal_scan` | Possible horizontal service scanning behavior | `port_scan` | 25 | Medium behavioral confidence | `src_ip`, `dst_ip`, `dst_port`, event time | Source reaches at least 10 destinations on one service port in five minutes with deny, inbound, or unresolved-app support. | Authorized scanner, asset discovery, service health sweep. | Confirm scanner authorization, destination ownership, service port, and deny rate. |
| `beaconing_like_outbound` | Beaconing-like repeated outbound behavior | `malware_c2` | 30 | Medium behavioral confidence | `src_ip`, `dst_ip`, `dst_port`, zone path, event time, app context | At least 6 outbound events to one endpoint have 5-300 second mean cadence, jitter ratio at most 0.25, and uncommon/unknown/high-signal app context. | Telemetry, keepalive, monitoring, software-update polling. | Inspect cadence, approved schedules, destination ownership, application, and endpoint process context. |
| `connection_flood_suspicion` | Connection flood-like behavior | `dos_ddos` | 35 | Medium behavioral confidence | `src_ip`, `dst_ip`, `dst_port`, event time, action/repeat count | At least 20 repeated sessions have deny/reset or vendor flood evidence, or volume reaches at least 100 PAN session events. | Load tests, health checks, high-volume API clients. | Confirm service health and packet/bandwidth impact; volume alone does not prove DoS. |
| `unusual_destination_port` | Unusual destination port | `unknown_anomaly` | 10 | Low/context-only | `dst_port`, zone path | Outside-to-inside traffic used an uncommon destination port. | Custom application ports, test services. | Verify service ownership and whether paired with scan/deny patterns. |
| `high_outbound_bytes` | High outbound byte volume | `data_exfiltration_suspicion` | 35 | Low behavioral confidence | `bytes_sent` or fallback `bytes`, zone path | Internal-to-external outbound volume exceeds the versioned threshold. | Backup, cloud sync, file transfer, software updates. | Validate direction, data owner, destination, protocol, and approved transfer schedule. |
| `unknown_or_incomplete_app` | Unknown or incomplete application | `unknown_anomaly` | 10 | Low/context-only | `app`, `app_category` | App is unknown, incomplete, not-applicable, unknown-tcp, or category unknown. | Early session classification, partial logs, unsupported parser fields. | Review parser completeness and whether stronger rules also fired. |
| `high_bytes_outlier` | High byte-count outlier | `unknown_anomaly` | 20 | Low | `bytes` | Directionless total bytes exceed the versioned threshold. | Normal large transfer. | Check direction, destination, app, and baseline before assigning an attack type. |
| `high_packets_outlier` | High packet-count outlier | `unknown_anomaly` | 20 | Low | `packets` | Directionless packet count exceeds the versioned threshold. | High-volume allowed traffic. | Check service, direction, baseline, and availability telemetry before assigning impact. |
| `ml_anomaly_detected` | ML anomaly detected | `unknown_anomaly` | 25 | Assistive only | `is_anomaly`, `anomaly_score` | IsolationForest marked event unusual. | Rare but benign traffic. | Treat as triage signal only; check rule evidence and human context. |

## Grouping And Deduplication Notes

- Registered source identity is part of every alert-group key and dedup comparison. Two devices that report the same IP cannot merge their alerts.
- Context-only internet rules require at least five related events; a single outside/unknown/unusual-port row cannot alert merely because small scores add together.
- Multi-event pattern rules (`possible_port_scan`, `possible_horizontal_scan`, `beaconing_like_outbound`, `connection_flood_suspicion`) group only inside their exact source-scoped correlation episode.
- Rows without event-time evidence cannot contribute to cross-row temporal correlation, and findings without complete event-time bounds do not deduplicate.
- Internet-sweep and app-risk grouping still reduce row explosion, but only inside one registered source identity.
- Raw logs and normalized evidence are never deleted by alert grouping or deduplication.

## v5.31 Adversarial Reliability Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v531_detection_explainability_adversarial_reliability --pretty
```

The tracked synthetic corpus covers positive, negative, near-miss, degraded-input, duplicate, timing-boundary, missing-time, independent-episode, and multi-source behavior. The current run passes 27/27 cases with zero expected-rule false-positive cases, zero false-negative cases, near-miss/negative accuracy 1.0, no configured-database use, no label/model writes, and no response actions. This is controlled adversarial regression evidence, not a real-world accuracy estimate.

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
