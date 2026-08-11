# ATDR Detection Taxonomy

Version: `atdr_detection_taxonomy_v5.31.0`

## Purpose

This taxonomy keeps observed firewall evidence, rule inferences, ML diagnostics, and analyst decisions separate. It is a controlled SOC vocabulary, not a claim that ATDR has proven attacker intent or compromise.

## Alert Attack Types

| Attack type | Meaning in ATDR | ATT&CK context | Minimum supported evidence | Required claim boundary |
| --- | --- | --- | --- | --- |
| `normal` | No supported threat claim from evaluated evidence | none | no alert-producing evidence | Not proof that the activity is safe. |
| `port_scan` | Vertical service probing across ports or horizontal same-service probing across destinations | T1046 | source-scoped port or destination diversity plus supporting scan context within a bounded window | Intent and authorization are unknown. |
| `brute_force` | Repeated access-like attempts to authentication/service ports | T1110 | repeated denied/reset attempts in a bounded window | Traffic logs do not prove password guessing or compromise. |
| `dos_ddos` | Connection-flood-like volume | T1498 | repeated volume to a destination service | Service impact requires independent telemetry. |
| `malware_c2` | Repeated outbound behavior resembling an application-layer channel | T1071 | repeated destination/port plus risky or uncommon context | C2-like does not prove malware or command-and-control. |
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

- Generic Palo Alto `THREAT` events map to `unknown_anomaly` until subtype/signature evidence supports a narrower claim.
- Vertical and horizontal scan rules both map to `port_scan` / T1046 because they observe network-service discovery behavior; neither establishes hostile intent.
- App risk and app characteristics map to policy context, not C2.
- Directionless byte/packet outliers remain `unknown_anomaly`.
- ATT&CK mappings are behavioral context, not attribution.
- A provider benchmark label is preserved as provider ground truth and must not be presented as an ATDR human-reviewed label.

Source truth: `atdr/app/detection/attack_mapping.py`, `atdr/app/detection/rule_catalog.py`, `atdr/app/db/models.py`, and `docs/security/ATDR_DETECTION_LABELING_POLICY.md`.
