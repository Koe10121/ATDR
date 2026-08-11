# ATDR Rule Pack Contract

## Status

v5.31 source-backed contract for catalog `atdr_rule_catalog_v5.31.0`. Deterministic rules remain ATDR's alert-authoritative layer. IsolationForest and supervised ML remain advisory decision support and cannot create, suppress, classify, or change an authoritative alert.

## Source Evidence

- Runtime rules: `atdr/app/detection/rules.py`
- Versioned metadata: `atdr/app/detection/rule_catalog.py`
- Attack mapping: `atdr/app/detection/attack_mapping.py`
- Grouping and deduplication: `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py`
- Explanation contract: `atdr/app/detection/explanations.py`
- Synthetic adversarial corpus: `data/samples/scenarios/adversarial/v5_31_detection_corpus.json`
- Scenario contract: `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`
- Rule standard: `docs/security/ATDR_DETECTION_RULE_STANDARD.md`

## Safety Contract

- Rules can create grouped and deduplicated SOC triage alerts.
- Rules cannot execute response actions or perform real firewall blocking.
- Rules do not write labels, train models, or activate ML artifacts.
- Raw and normalized evidence remains preserved.
- Analyst review and justification remain mandatory before any simulated response.
- ATT&CK mappings describe evidence-supported behavior hypotheses, not attribution or proof of compromise.

## Rule Pack v5.31

| Catalog ID / Code | Evidence | Scope | Attack Hint | Claim Boundary |
| --- | --- | --- | --- | --- |
| `ATDR-NET-001` / `deny_drop_action` | Deny, drop, or reset action/session metadata | event | `policy_violation` | A firewall policy action does not prove hostile intent. |
| `ATDR-NET-002` / `paloalto_threat_log` | Vendor `THREAT` event scored by vendor severity with name retained | event | `unknown_anomaly` | Subtype, severity, signature/name, action, and corroborating telemetry require review. |
| `ATDR-NET-003` / `app_risk_4` | PAN-OS app risk 4 | event | `policy_violation` | Vendor risk is context, not a malware finding. |
| `ATDR-NET-004` / `app_risk_5` | PAN-OS app risk at least 5 | event | `policy_violation` | Approved high-risk applications can be benign. |
| `ATDR-NET-005` / `suspicious_app_characteristic` | Versioned PAN-OS app characteristic set | event | `policy_violation` | Broad app characteristics do not establish malicious use. |
| `ATDR-NET-006` / `outside_to_inside` | External-to-internal zone direction | event/context | `unknown_anomaly` | Published services and expected inbound traffic are common. |
| `ATDR-NET-007` / `repeated_source_ip` | At least 25 effective session events | registered source + source IP + 5m | `unknown_anomaly` | NAT, monitoring, and busy clients can repeat legitimately. |
| `ATDR-NET-008` / `multiple_denied_connections` | At least 5 denied/drop/reset session events | registered source + source IP + 5m | `policy_violation` | Policy noise and misconfiguration remain plausible. |
| `ATDR-NET-009` / `brute_force_like_attempts` | At least 5 denied/reset attempts to the same target and auth/service port | registered source + source IP + target/service + 5m | `brute_force`, T1110 | Traffic retries do not prove password guessing or account compromise. |
| `ATDR-NET-010` / `possible_port_scan` | At least 10 destination ports plus deny, inbound, unresolved-app, or vendor-scan support | registered source + source IP + 5m | `port_scan`, T1046 | Intent and scanner authorization require analyst context. |
| `ATDR-NET-018` / `possible_horizontal_scan` | At least 10 destinations on one port plus deny, inbound, or unresolved-app support | registered source + source IP + service + 5m | `port_scan`, T1046 | Same-service probing resembles discovery; authorization remains unknown. |
| `ATDR-NET-011` / `beaconing_like_outbound` | At least 6 outbound events, 5-300 second mean cadence, jitter ratio at most 0.25, plus uncommon/unknown/high-signal app context | registered source + source IP + destination/service + 5m | `malware_c2`, T1071 | Periodic traffic is C2-like, not proof of malware or command-and-control. |
| `ATDR-NET-012` / `connection_flood_suspicion` | At least 20 repeated sessions with deny/vendor flood support, or at least 100 effective PAN session events | registered source + source IP + destination/service + 5m | `dos_ddos`, T1498 | Availability impact requires independent service telemetry. |
| `ATDR-NET-013` / `unusual_destination_port` | Inbound use of a non-common service port | event/context | `unknown_anomaly` | Custom services can be legitimate. |
| `ATDR-NET-014` / `high_outbound_bytes` | Internal-to-external `bytes_sent`, falling back to total bytes only when direction-specific bytes are absent, exceeds threshold | event | `data_exfiltration_suspicion`, T1048 | Volume alone does not establish theft, protocol misuse, or authorization. |
| `ATDR-NET-015` / `unknown_or_incomplete_app` | App identity/category unresolved | event/context | `unknown_anomaly` | Early classification, unsupported protocols, and parser limits are expected causes. |
| `ATDR-NET-016` / `high_bytes_outlier` | Directionless total bytes exceed threshold | event/context | `unknown_anomaly` | Directionless volume is not an exfiltration claim. |
| `ATDR-NET-017` / `high_packets_outlier` | Directionless packets exceed threshold | event/context | `unknown_anomaly` | Directionless packet volume is not a denial-of-service claim. |
| `ATDR-ML-001` / `ml_anomaly_detected` | IsolationForest marks the event statistically unusual | event/advisory | `unknown_anomaly` | Unusual does not mean malicious; this signal cannot create an alert by itself. |

The machine-readable catalog is authoritative for exact fields, score contribution, rule version, status, false positives, references, explanation template, and claim boundary.

## Correlation, Grouping, And Deduplication

- Correlation uses registered source identity, source IP, and a bounded five-minute window.
- Missing event timestamps cannot support cross-row temporal correlation.
- Multi-event findings retain the exact correlation episode; independent windows do not collapse into one alert.
- Vertical scans require destination-port diversity; repeated duplicate rows on one port do not satisfy that condition.
- Horizontal scans require destination diversity on one service.
- Brute-force-like evidence is target/service-specific rather than a source-wide sum.
- Beaconing requires measured periodicity; ordinary rapid repetition is insufficient.
- Flood-like behavior requires corroborated or very-high effective session volume; inbound direction alone is insufficient.
- Context-only evidence requires at least five grouped candidate rows even when small scores sum above the alert threshold.
- Group and dedup keys preserve registered source identity, so distinct devices cannot merge merely because they report the same IP or timing.
- Deduplication fails closed when either finding lacks complete event-time bounds.

## Explanation Contract

Every generated alert exposes:

- alert identity, title, type, severity, and risk score;
- exact deterministic score components and observed rule explanations;
- rule confidence and claim boundaries;
- likely false-positive factors and missing context;
- prioritized, rule-specific analyst checks;
- registered source IDs, bounded related-log IDs, occurrence/related counts, and computed case trace;
- ATT&CK mapping only when a deterministic rule or qualifying human-reviewed disposition supports it; and
- explicit decision-support and response-automation-disabled safety state.

Assisted/weak labels cannot become ATT&CK ground truth. Only `manual` or `reviewed_import` labels marked reviewed may serve as a fallback when deterministic rules provide no specific mapping.

## Validation

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v531_detection_explainability_adversarial_reliability --pretty
```

The v5.31 adversarial corpus contains 27 synthetic positive, negative, near-miss, degraded-input, duplicate, timing-boundary, missing-time, independent-episode, and multi-source cases. A passing run requires zero expected-rule false-positive cases, zero false-negative cases, near-miss/negative accuracy 1.0, correct timing/source/duplicate behavior, no configured-database access, no labels/models, and no response actions.

## Primary References

Accessed 2026-08-09:

- Palo Alto Networks, [Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields).
- Palo Alto Networks, [Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields).
- MITRE ATT&CK, [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/).
- MITRE ATT&CK, [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/).
- MITRE ATT&CK, [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498/).
- MITRE ATT&CK, [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/).
- MITRE ATT&CK, [T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/).
- IETF, [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
- IETF, [RFC 792: Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792.html).
