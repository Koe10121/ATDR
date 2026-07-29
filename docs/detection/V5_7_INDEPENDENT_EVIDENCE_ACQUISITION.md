# v5.7 Independent Evidence Acquisition Protocol

Date: 2026-07-26

## Purpose

This protocol defines the evidence ATDR needs before the frozen v5.6
diagnostic candidate can receive a legitimate blind shadow evaluation. It
prevents reused development traffic, previously opened windows, duplicate
families, or AI-assisted decisions from being presented as independent ground
truth.

ATDR remains in `shadow_observation` until every evidence and metric gate
passes. Deterministic rules remain alert-authoritative. No step in this
protocol activates a model, changes alerts, enables response automation, or
enables real firewall blocking.

## Evidence Research Result

| Source | Version / schema | License or terms | Integrity | Decision |
| --- | --- | --- | --- | --- |
| [Palo Alto Networks traffic log fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) | Current vendor PAN-OS traffic-log field reference | Documentation reference, not a dataset license | No corpus checksum applies | Authoritative schema reference only; it is not a labeled corpus. |
| [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | 2018 CICFlowMeter flow features | Redistribution is allowed with required citation and AWS link | Approved file hashes are recorded in `data/samples/benchmarks/cse_cic_ids2018_v49_manifest.json` | Already opened, failed the transfer gate, and locked. It is not PAN-OS evidence and cannot be reused as a fresh holdout. |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | PCAP, Argus, Bro, and 49-feature CSV records | Academic research use with citation; commercial use requires author agreement | Not acquired or checksummed in v5.7 | Labeled network evidence, but not native PAN-OS logs or independent device evidence for this evaluator. |
| [Splunk BOTS v3](https://github.com/splunk/botsv3) | Pre-indexed multi-sourcetype Splunk security data | CC0-1.0 | Publisher MD5 `d7ccca99a01cff070dff3c139cdc10eb` | Useful security corpus, but it has no native PAN-OS source and no compatible row-level ground-truth contract for v5.7. |

No fresh, native PAN-OS-compatible, independently labeled corpus was found in
the approved source review. The correct current outcome is
`independent_evidence_required`.

## Required Evidence Contract

Use
`data/samples/benchmarks/v57_independent_evidence_manifest.template.json`.
The manifest is tracked; private evidence and completed review files are not.

Minimum qualification:

1. At least two independently operated real firewall/source devices.
2. At least two non-overlapping collection periods that were not used in
   v5.3-v5.6 development, calibration, threshold selection, or evaluation.
3. At least 100 parsable representative rows after quarantine and duplicate
   containment; use more evidence where practical.
4. Native PAN-OS syslog or a documented, compatible PAN-OS normalized schema.
5. Zero configured-database overlap.
6. Zero overlap with v5.3-v5.6 evidence after local cryptographic fingerprint
   and duplicate-family comparison.
7. Zero duplicate family crossing between evidence roles.
8. Owner permission or a compatible dataset license.
9. Labels unavailable to the prediction process.
10. Advisor acknowledgement before prediction freeze and advisor approval
    before label reveal.

The current disposable profiler can verify rows, parsing, chronological
windows, configured-database overlap, and duplicate families. Device
independence and collection ownership require collection records and advisor
confirmation; ATDR must not infer them from source IP addresses.

## Required Fields

The original evidence should preserve the PAN-OS fields needed for parsing and
investigation:

- event/receive and generated timestamps;
- firewall serial or a stable pseudonymous device identifier;
- log type and subtype;
- source and destination addresses, retained only in approved private storage;
- source and destination ports and protocol;
- application and application risk where available;
- action, rule, source zone, and destination zone;
- bytes, packets, duration, and repeat count where available;
- THREAT category, severity, threat identifier, and vendor action where
  available;
- parser status, schema profile, and parser warnings.

The generated review pack excludes raw log text and IP addresses. It uses
pseudonymous source/time groups and a review token that cannot be used to
reconstruct the original row.

## Ground-Truth Taxonomy

Allowed analyst decisions:

- `benign`: expected activity with adequate benign context;
- `benign_unusual`: unusual but non-threat activity supported by context;
- `needs_context`: insufficient evidence for a reliable decision;
- `suspicious`: investigation-worthy behavior with credible threat signals;
- `malicious`: confirmed malicious behavior with strong evidence.

Allowed ground-truth provenance:

- `human_reviewed`;
- `advisor_approved_human_review`;
- `provider_ground_truth`.

AI, rule, vendor-assisted, heuristic, weak-supervision, or Codex suggestions
must never be marked as human-reviewed ground truth. They may be stored as
separate review aids only.

## Prediction-Before-Label Procedure

### 1. Collect and quarantine

- Store source files outside Git and outside the configured ATDR database.
- Pseudonymize device identifiers in the manifest.
- Retain the original evidence only in approved private storage.
- Complete the overlap audit against all v5.3-v5.6 role fingerprints and
  duplicate families.

### 2. Run preflight

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v57_independent_shadow_revalidation `
  --sample-path "<INDEPENDENT_PAN_OS_FILE>" `
  --evidence-manifest "<PRIVATE_EVIDENCE_MANIFEST>" `
  --use-temp-db `
  --preflight-only `
  --pretty
```

Expected result before qualification is either
`ready_for_prediction_freeze` or a specific fail-closed blocker. Do not edit
checks merely to make the file pass.

### 3. Freeze predictions

The manifest must have:

- `status=ready_for_predictions`;
- labels `sealed` or `not_collected`;
- `available_to_prediction_runner=false`;
- completed overlap audit; and
- advisor protocol acknowledgement.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v57_independent_shadow_revalidation `
  --sample-path "<INDEPENDENT_PAN_OS_FILE>" `
  --evidence-manifest "<PRIVATE_EVIDENCE_MANIFEST>" `
  --use-temp-db `
  --predictions-only `
  --pretty
```

The command creates an ignored prediction freeze and a prediction-blind review
pack. A second run cannot replace a valid freeze.

### 4. Human review

- Give reviewers the review pack, approved private evidence viewer, taxonomy,
  and source context.
- Do not give them model predictions before their decisions are sealed.
- Require a reviewer identifier and confirmation for every non-context label.
- Keep ambiguous rows as `needs_context`.
- Review duplicate families consistently without copying a prediction.
- Store completed labels outside Git.

### 5. Seal and approve labels

After review:

- set manifest `status=ready_for_label_reveal`;
- set label status `complete_and_sealed`;
- set the allowed label provenance;
- set `ground_truth_confirmed=true`;
- obtain advisor approval; and
- do not alter collection, file, schema, or independence fields.

### 6. Reveal once

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v57_independent_shadow_revalidation `
  --sample-path "<INDEPENDENT_PAN_OS_FILE>" `
  --evidence-manifest "<PRIVATE_EVIDENCE_MANIFEST>" `
  --use-temp-db `
  --reveal-labels `
  --pretty
```

The evaluator verifies the candidate, sample, evidence contract, frozen
prediction file, label completeness, provenance, and advisor approval. It
then evaluates once and seals `labels_revealed=true`. Later reveal attempts
fail closed.

## Fixed Readiness Gates

All gates must pass in the one blind evaluation:

| Gate | Requirement |
| --- | ---: |
| Threat/SOC queue F1 | `>= 0.85` |
| Benign-like false-positive rate | `<= 0.05` |
| Suspicious recall | `>= 0.80` |
| Malicious recall | `>= 0.80` |
| Expected calibration error | `<= 0.10` |
| Maximum confidence/accuracy gap | `<= 0.15` |
| Evidence leakage | none |
| Threat suppression by post-prediction guard | none; candidate is threshold-only |
| Independent source and time evidence | required |

Failure of any gate keeps the lifecycle in `shadow_observation`. Passing every
gate permits only a later manual decision-support review; it does not
automatically activate or promote a model.

## Advisor Sign-Off Checklist

- [ ] Evidence comes from at least two real devices.
- [ ] Collection periods are independent and were not used previously.
- [ ] Ownership/license permits this evaluation.
- [ ] Schema is native or compatible PAN-OS.
- [ ] Local fingerprint and duplicate-family overlap audit is complete.
- [ ] Predictions were frozen before labels were revealed.
- [ ] Reviewers did not receive predictions before sealing decisions.
- [ ] No AI/rule/vendor suggestion is represented as human review.
- [ ] Reviewer identity and decision provenance are complete.
- [ ] Private evidence and review files remain outside Git.
- [ ] One-time reveal is approved.

Until this checklist is complete, ATDR should report
`independent_evidence_required`, show no blind metrics, and remain in
`shadow_observation`.
