# v5.9 Independent Detection Evidence Acquisition

Date: 2026-07-27

## Purpose

This document converts the v5.7 independent-evidence protocol into an
actionable advisor, device-owner, and dataset-provider request. It does not
authorize model activation, reveal labels, import private evidence, or relax
the fixed readiness gates.

## Current Finding

ATDR does not currently possess a fresh native PAN-OS-compatible,
independently labeled, multi-device holdout.

The complete private PAN-OS file is already-used v5.6 development evidence.
It may support parser regression and aggregate drift inspection, but it must
not be renamed or reused as an independent holdout.

## Official-Source Review

| Source | Useful evidence | Native PAN-OS fit | Current ATDR role |
| --- | --- | --- | --- |
| [UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Labeled benign/attack PCAP and CICFlowMeter flows across five days | No; flow/PCAP schema | Potential future transfer benchmark only |
| [UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | Labeled attack scenarios and flow features | No; flow schema | Already opened and locked; not fresh evidence |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Labeled packet/flow records and nine attack families | No; packet/Argus/Bro/CSV schema | Potential future transfer benchmark only |
| [CTU-13](https://www.stratosphereips.org/datasets-ctu13) | Manually labeled botnet, normal, and background captures | No; PCAP/NetFlow schema | Potential future anomaly/transfer benchmark only |
| [Palo Alto traffic fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) | Authoritative native traffic-log field contract | Yes, documentation only | Parser/schema contract |
| [Palo Alto syslog fields](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions) | Authoritative PAN-OS syslog field definitions | Yes, documentation only | Parser/schema contract |

No new corpus was downloaded during v5.9, so no local hash, row count, or
license acceptance is claimed. A future acquisition must record those facts
before any prediction.

## Required Advisor / Provider Package

Request the following as one approved package:

1. **Two independent devices:** distinct real firewalls or independently
   operated PAN-OS-compatible sources.
2. **Two new periods:** at least two non-overlapping collection windows not
   present in v5.3-v5.9 evidence.
3. **Native fields:** documented PAN-OS traffic/threat syslog or an explicitly
   approved compatible mapping with timestamp, type, action, application,
   source/destination addressing, ports, zones, protocol, severity/threat
   context where available, and raw evidence retained privately.
4. **Volume:** at least 100 parsable representative rows after quarantine;
   more is preferred, with benign routine traffic and confirmed suspicious or
   malicious activity represented.
5. **Ground truth:** human analyst, advisor-approved human review, or
   compatible provider labels. AI, rules, vendor suggestions, Codex, weak
   supervision, and model outputs cannot be called human-reviewed truth.
6. **Permission:** named owner/provider, collection purpose, license or
   written permission, allowed retention, allowed reviewers, and deletion
   date.
7. **Blinding:** labels withheld from Codex/model selection until predictions
   and the evidence contract are frozen.
8. **Advisor control:** acknowledgement before prediction freeze and explicit
   approval before one-time label reveal.

## Private Manifest Fields

The private manifest must record:

- evidence ID and version;
- owner/provider and permission reference;
- device IDs represented by non-sensitive aliases;
- collection periods and timezone;
- schema/parser profile and required-field mapping;
- file checksum and row count;
- license/retention/reviewer restrictions;
- configured-database overlap result;
- exact/near/feature duplicate-family audit result;
- label provenance and blinded/reveal state;
- advisor acknowledgement and reveal approval; and
- immutable prediction and candidate-contract identities.

The manifest and raw evidence stay outside Git.

## Qualification And Stop Conditions

Before prediction:

- parser compatibility must pass;
- at least two real devices and two new periods must be present;
- evidence must not overlap configured DB, v5.3-v5.9 roles, or duplicate
  families;
- provenance/permission must be complete;
- labels must remain hidden; and
- candidate and preprocessing contracts must match exactly.

Stop immediately if any requirement fails. Do not substitute synthetic source
names, split one device into fake devices, relabel reused rows, or lower gates.

## Blind Procedure

1. Copy approved evidence and private manifest to an isolated local location.
2. Run preflight with labels unavailable to the evaluator.
3. Resolve parser/quarantine issues without opening labels.
4. Freeze the exact candidate contract and predictions once.
5. Export a prediction-free human review pack.
6. Obtain independent review and advisor reveal approval.
7. Reveal labels once and seal the result.
8. Evaluate fixed supervised and IsolationForest gates.
9. Preserve result provenance and do not tune against the revealed holdout.

## Fixed Gates

| Gate | Required result |
| --- | ---: |
| Threat/SOC queue F1 | >= 0.85 |
| Benign-like false-positive rate | <= 0.05 |
| Suspicious recall | >= 0.80 |
| Malicious recall | >= 0.80 |
| Expected calibration error | <= 0.10 |
| Maximum confidence/accuracy gap | <= 0.15 |
| Evidence leakage | 0 |
| Actual threats suppressed by a guard | 0 |

Passing one dataset is not production promotion. Source/time stability,
operational observation, security review, and explicit lifecycle approval
remain separate requirements.

## Current Decision

Independent evidence is required. No assisted review pack was generated in
v5.9 because no genuinely new ambiguous native PAN-OS evidence was acquired.
The lifecycle remains `shadow_observation`, rules remain authoritative, and
response automation and real blocking remain disabled.
