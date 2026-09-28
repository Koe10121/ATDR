# ATDR Detection Taxonomy

Version: `atdr_detection_taxonomy_v5.36.0`

## Purpose

This taxonomy keeps observed firewall evidence, rule inferences, ML diagnostics, and analyst decisions separate. It is a controlled SOC vocabulary, not a claim that ATDR has proven attacker intent or compromise.

## Alert Attack Types

| Attack type | Meaning in ATDR | ATT&CK context | Minimum supported evidence | Required claim boundary |
| --- | --- | --- | --- | --- |
| `normal` | No supported threat claim from evaluated evidence | none | no alert-producing evidence | Not proof that the activity is safe. |
| `port_scan` | Vertical service probing across ports or horizontal same-service probing across destinations | T1046 | source-scoped port or destination diversity plus supporting scan context within a bounded window | Intent and authorization are unknown. |
| `brute_force` | Repeated access-like attempts to authentication/service ports | T1110 | repeated denied/reset attempts in a bounded window | Traffic logs do not prove password guessing or compromise. |
| `dos_ddos` | Connection-flood-like volume | T1498 | repeated volume to a destination service | Service impact requires independent telemetry. |
| `malware_c2` | Outbound contact resembling or confirmed as a malware channel | T1071 | repeated destination/port plus risky or uncommon context, a firewall malware/C2 signature, or a watchlisted destination | C2-like does not prove malware or command-and-control. |
| `exploit_attempt` | Traffic matching a known exploit or web-attack signature aimed at a service | T1190 | a firewall vulnerability signature naming an exploit (code execution, traversal, injection, exploit file scanning), or one rated medium or higher | An attempt, not proof it succeeded; whether the target was vulnerable needs checking. |
| `policy_violation` | Local firewall or acceptable-use policy concern | internal governance | deny/drop or vendor application policy evidence | This is not a MITRE technique or compromise claim. |
| `data_exfiltration_suspicion` | Unusual directional outbound transfer | T1048 | high outbound bytes plus direction | Volume alone does not establish theft or unauthorized transfer. |
| `unknown_anomaly` | Unusual, incomplete, or vendor-reported evidence requiring investigation | none assigned | anomaly, parser limitation, generic THREAT, or low-specificity rule | No specific attack technique is supported. |

## Supervised Review Labels

| Label | Queue meaning | Threat-positive target |
| --- | --- | --- |
| `benign` | Expected activity with sufficient context | no |
| `benign_unusual` | Unusual but currently explained or allowed activity | no |
| `needs_context` | Evidence is insufficient; analyst context is required | yes for review-queue evaluation |
| `suspicious` | Supported concern requiring investigation | yes |
| `malicious` | Strong multi-signal evidence supports a threat conclusion | yes |

The binary SOC queue groups `needs_context`, `suspicious`, and `malicious` as `needs_review`; this grouping is a triage target, not a maliciousness label.

## Evidence Layers

1. **Observed evidence:** normalized fields, parser status, source identity, timestamps, raw-evidence reference, counts, and run IDs.
2. **Rule inference:** versioned rule match, correlation scope/window, score, confidence, false positives, and claim boundary.
3. **Anomaly evidence:** IsolationForest unusualness score; never an attack verdict.
4. **Supervised diagnostic:** queue probability/class from a candidate or active artifact with provenance and readiness state.
5. **Hybrid recommendation:** bounded decision-support combination; never an automatic response authorization.
6. **Analyst decision:** human-authored disposition retained with actor, time, source, and review provenance.

## Mapping Discipline

- Each matched rule carries an attack type: the catalog default, or a narrower one its log's evidence names. A Palo Alto `THREAT` record is typed from its subtype and signature name (a scan or discovery signature is `port_scan`, an exploit signature `exploit_attempt`, a flood `dos_ddos`); a record that names no attack, such as "Non-RFC Compliant SSL Traffic", stays `unknown_anomaly`. An unsolicited, unanswered connection from outside to an uncommon port, or with an application that never completed, is `port_scan`. A watchlisted outside destination is `malware_c2`; a watchlisted app or country is `policy_violation`.
- An alert takes the type of its strongest rule, with two orderings on top of rule priority: a type named by a firewall signature or a watchlist indicator outranks one inferred from traffic shape (a host the firewall names as an XMRig miner is `malware_c2`, although its retries also look like a scan), and `unknown_anomaly` never hides a type that a behavioural rule names. Supporting-only context rules (app risk, app characteristics, inbound direction, busy source) cannot outrank `unknown_anomaly`, as they cannot raise an alert on their own.
- When one rule's logs name different types, the alert keeps the most specific: `malware_c2`, then `exploit_attempt`, `data_exfiltration_suspicion`, `brute_force`, `dos_ddos`, `port_scan`, `policy_violation`, `unknown_anomaly`.
- Vertical and horizontal scan rules both map to `port_scan` / T1046 because they observe network-service discovery behavior; neither establishes hostile intent.
- App risk and app characteristics map to policy context, not C2.
- Directionless byte/packet outliers remain `unknown_anomaly`.
- ATT&CK mappings are behavioral context, not attribution.
- A provider benchmark label is preserved as provider ground truth and must not be presented as an ATDR human-reviewed label.

Source truth: `atdr/app/detection/attack_mapping.py`, `atdr/app/detection/rule_catalog.py`, `atdr/app/db/models.py`, and `docs/security/ATDR_DETECTION_LABELING_POLICY.md`.
