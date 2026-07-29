# ATDR Detection Rule Standard

Version: `v4.9`

## Purpose

ATDR uses a Sigma-inspired rule contract while retaining Python execution for current normalized firewall/syslog data. Sigma is a design reference, not a claim that ATDR executes arbitrary Sigma YAML.

## Required Rule Metadata

Every rule must define:

- stable catalog ID and code;
- title, semantic version, and lifecycle status (`test`, `stable`, `deprecated`, or `experimental`);
- supported log source/parser profile;
- required normalized fields and missing-field behavior;
- explicit condition and source-scoped correlation window;
- alert level and evidence confidence;
- ATDR attack type and optional MITRE technique IDs;
- known false positives;
- primary references;
- analyst-facing explanation template; and
- claim boundary.

The source of truth is `atdr/app/detection/rule_catalog.py`.

## Runtime Requirements

- Correlation must be bounded by event time and source identity. Same-address events from different sources cannot be merged for rule counts.
- Single-event rules must not imply repeated behavior.
- Missing required fields must weaken or make a rule unavailable; fields must not be fabricated.
- Parser warnings and raw-fallback status must remain visible to explanations.
- Rule matches may create/deduplicate alerts but cannot create response actions, labels, model runs, or firewall changes.
- Rule evidence stored with an alert must include the catalog metadata used at detection time.

## Evidence Language

Use:

- “observed,” “matched,” “resembles,” “consistent with,” “suspicion,” and “requires analyst review.”

Avoid unsupported claims such as:

- “compromised,” “malware confirmed,” “data stolen,” “DDoS succeeded,” or “attacker,” unless independent evidence explicitly establishes the statement.

## Change Control

A material rule change requires:

1. source evidence and rationale;
2. catalog/contract version update;
3. expected benign and alert-positive scenarios;
4. false-positive and false-negative regression cases;
5. explanation and claim-boundary review;
6. source/time scoping tests;
7. no-response safety test; and
8. taskboard, PRD/traceability, and T1-T20 updates.

No rule threshold may be selected on a frozen final benchmark. Development, calibration, threshold, and final evidence roles must remain separate.

## Primary References

Accessed 2026-07-18:

- [Sigma Rules Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Palo Alto Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
- [MITRE ATT&CK](https://attack.mitre.org/)

## Validation

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
```
