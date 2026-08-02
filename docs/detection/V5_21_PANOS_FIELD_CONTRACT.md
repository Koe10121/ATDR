# v5.21 PAN-OS Field And Evidence Contract

Date: 2026-08-01

## Purpose

This contract defines how ATDR interprets native PAN-OS evidence during v5.21
evidence preparation and future governed model work. It does not replace Palo
Alto Networks documentation and does not convert vendor fields into human
ground truth.

## Primary Sources

- [PAN-OS Syslog Field Descriptions](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions)
- [PAN-OS Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
- [PAN-OS Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields)
- [PAN-OS Application Objects](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/applications)

Only official vendor documentation is source truth for field meaning. ATDR
tests and source code remain source truth for the implemented parser mapping.

## Format Contract

- PAN-OS syslog payloads use comma-separated fields.
- `FUTURE_USE` positions are reserved and must not become evidence features.
- Field count and log type determine parser compatibility.
- Raw evidence must be preserved by ingestion, but v5.21 derived outputs must
  not contain raw rows or identifying addresses.

## TRAFFIC Evidence

Required session context includes generated time, source/destination address
presence, application, source/destination zone, destination port, protocol,
and action. Supporting context includes byte and packet counts, elapsed time,
session end reason, and application risk.

TRAFFIC records describe observed sessions. The following are not sufficient
malicious labels on their own:

- `allow` or `deny`;
- application risk;
- an unknown or incomplete application;
- port 80 or 443;
- QUIC, ping, TCP, or UDP; or
- a single unusual port or direction.

Repeated probing, destination/port diversity, rule evidence, network direction,
volume, and temporal context may justify analyst review, but human confirmation
is required for ground truth.

## THREAT Evidence

THREAT records indicate a match to a configured Security Profile. ATDR may use
the record type, threat name/ID, severity, action, application, direction, and
network context for prioritization and weak assistance.

A vendor THREAT record is strong evidence, but it is not automatically an ATDR
human-reviewed malicious label. Policy configuration, false positives,
suppression context, and analyst investigation still matter.

## Application Risk

PAN-OS application risk is contextual. A high-risk application can be
legitimate, and a low-risk application can participate in malicious behavior.
Application risk must not be used as a single-feature malicious label.

## Evidence Roles

- `development_fit`: fitting only.
- `calibration`: probability calibration only.
- `threshold`: queue-threshold selection only.
- `untouched_future_validation`: sealed final evaluation only.
- `quarantine`: excluded from model development and final evaluation.

Roles are assigned chronologically before assisted decisions. Exact and
near-duplicate families are moved wholly to their latest role to prevent
leakage backward.

## Label Integrity

- Rule/Codex/model suggestions are weak or assisted, never human-reviewed.
- The development pack is not import-ready and requires human confirmation.
- The blind pack contains no suggestions and remains sealed during development.
- No model-selection metric may use blind labels before candidate freeze.
- Provider/vendor labels must retain their provenance and must not be renamed
  as ATDR human review.

## Safety State

Rules remain alert-authoritative. Supervised ML remains decision support in
`shadow_observation`. Automatic response and real firewall blocking remain
disabled.
