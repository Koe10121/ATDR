# v5.31 Detection And Explainability Adversarial Reliability Lock

## Status

v5.31 hardens ATDR's deterministic, alert-authoritative detection layer and
its analyst-facing explanations. The change is a controlled regression lock,
not a production-readiness or real-world accuracy claim. IsolationForest and
supervised ML remain advisory, the supervised lifecycle remains
`shadow_observation`, and automatic response and real firewall blocking remain
disabled.

## Problems Found

The source audit found several places where plausible network activity could
be overclaimed or correlated too broadly:

- context-only signals could sum into a singleton alert without enough grouped
  evidence;
- alert grouping and deduplication did not consistently preserve registered
  source identity;
- timestamp-less rows shared one fallback correlation bucket and could produce
  unsupported cross-row behavior findings;
- independent five-minute behavior episodes inside one detection batch could
  collapse into one oversized alert group;
- alerts without complete event-time bounds could deduplicate indefinitely;
- authentication failures were accumulated source-wide rather than against
  the same destination and service;
- inbound direction could help satisfy connection-flood logic without enough
  volume or denial/vendor corroboration;
- repeated timestamps could resemble beaconing without a periodicity test;
- vertical port diversity existed, but horizontal same-service destination
  diversity did not have a dedicated rule;
- PAN-OS `THREAT` evidence did not use vendor severity or retain the threat
  name in the explanation; and
- older wording could make generic threat, application-risk, byte, or packet
  signals sound more conclusive than the observed evidence justified; and
- the explanation-completeness check could pass a structurally incomplete
  summary without exact signals, limitations, or full traceability.

The Assistant audit also found a context-routing regression: a computed case
citation could make an alert follow-up route as a case question. Alert context
now remains primary unless the analyst explicitly selected a case and no
alert, log, or source context is active.

## Detection Changes

### Correlation Scope

- Correlation is bounded to five minutes and includes registered source
  identity plus source IP.
- Rows without an event timestamp remain event-local and cannot contribute to
  cross-row temporal correlation.
- Multi-event alert groups retain the exact correlation episode, so separate
  five-minute windows do not collapse into one finding.
- Deduplication fails closed when complete event-time bounds are unavailable.
- Brute-force-like behavior requires at least five denied/reset attempts
  against the same destination and authentication/service port.
- Vertical scan behavior requires at least ten distinct destination ports and
  supporting deny, inbound, unresolved-application, or vendor-scan evidence.
- Horizontal scan behavior requires at least ten distinct destinations on one
  service and supporting deny, inbound, or unresolved-application evidence.
- Distinct registered sources do not combine into one behavior window or one
  deduplicated alert merely because IP/timing values match.

### Noise Resistance

- Beaconing requires at least six outbound events with a 5-300 second mean
  cadence and a jitter ratio no greater than 0.25, plus uncommon, unresolved,
  or high-signal application context.
- Connection-flood suspicion requires at least 20 effective sessions with
  deny/vendor corroboration, or at least 100 effective PAN session events.
  Inbound direction by itself is insufficient.
- `repeatcnt` contributes effective session evidence according to the PAN-OS
  field contract.
- Context-only evidence requires at least five grouped records before it may
  form an alert, even if small score contributions sum above the threshold.
- Outbound volume uses `bytes_sent` when available. Directionless total bytes
  remain a generic outlier and do not become an exfiltration claim.

### Vendor Evidence

PAN-OS `THREAT` events now retain the vendor threat name and use the vendor
severity as bounded scoring context. Informational evidence remains visible
without automatically crossing the alert threshold. A vendor event still
requires analyst review of subtype, signature, action, and corroborating
telemetry.

## Explanation Contract

Every generated alert can now expose:

- alert identity, title, severity, type, and risk score;
- exact deterministic score components and observed evidence;
- evidence-supported ATT&CK mapping, confidence, and claim boundaries;
- likely false-positive factors and missing context;
- prioritized rule-specific analyst checks;
- registered source IDs, bounded related-log IDs, occurrence/related counts,
  and computed case trace; and
- explicit decision-support and response-automation-disabled state.

Assisted or weak labels cannot become ATT&CK ground truth. Only reviewed
`manual` or `reviewed_import` labels can provide a fallback mapping when the
deterministic rules do not provide a specific mapping.

## Controlled Adversarial Corpus

The versioned corpus at
`data/samples/scenarios/adversarial/v5_31_detection_corpus.json` contains 27
synthetic cases:

| Category | Cases |
| --- | ---: |
| Positive | 9 |
| Negative | 6 |
| Near miss | 5 |
| Boundary | 3 |
| Degraded input | 2 |
| Duplicate | 1 |
| Multi-source | 1 |

It exercises vertical and horizontal scans, same-target and distributed auth
failures, periodic and irregular outbound traffic, corroborated and ordinary
connection bursts, QUIC/443, ICMP echo, high/informational vendor threats,
unknown UDP probing, timing boundaries, source isolation, duplicates,
context-only singletons, directional volume, missing fields, missing event
times, and independent scan episodes.

Current controlled result:

- `27/27` cases passed;
- expected-rule false-positive cases: `0`;
- expected-rule false-negative cases: `0`;
- near-miss/negative accuracy: `1.0`;
- timing-boundary, source-isolation, and duplicate checks: passed;
- observed catalog rules: `16/19`; and
- labels, models, and response actions written: `0/0/0`.

The three rules not directly exercised by this corpus remain covered by the
catalog contract and existing tests. The 27 synthetic cases are regression
evidence, not a measured field false-positive rate, recall value, or proof of
generalization to unseen devices.

## Scenario Regression

The updated connection-flood scenario represents 110 effective PAN sessions
through 22 synthetic rows carrying `repeatcnt=5`. It creates one High
connection-flood alert and one case, with zero response actions. The scenario
no longer depends on inbound direction alone.

## Source References

The behavior and wording were checked against these primary references on
2026-08-09:

- Palo Alto Networks Traffic Log Fields and Threat Log Fields;
- MITRE ATT&CK T1046 Network Service Discovery;
- MITRE ATT&CK T1110 Brute Force;
- MITRE ATT&CK T1498 Network Denial of Service;
- MITRE ATT&CK T1071 Application Layer Protocol;
- MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol;
- IETF RFC 9000 for QUIC; and
- IETF RFC 792 for ICMP.

Exact links and per-rule claim boundaries are recorded in
`docs/detection/ATDR_RULE_PACK_CONTRACT.md` and
`docs/DETECTION_RULE_CATALOG.md`.

## Run It

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v531_detection_explainability_adversarial_reliability --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
```

The v5.31 runner is synthetic-only, does not use the configured database, and
writes no report unless `--write-report` is explicitly supplied. Its optional
report is generated under ignored output storage.

## Decision

The deterministic layer is materially better protected against the tested
correlation, boundary, source-isolation, and overclaiming failures. It remains
a controlled lab implementation, not proof of universal detection accuracy.
Rules remain alert-authoritative, supervised ML remains
`shadow_observation`, and response authority is unchanged.

## Verification

The complete local matrix passed on 2026-08-11:

- taskboard render and standards checks;
- repository Ruff and compileall;
- backend tests: `872 passed, 1 skipped`; the skip is the existing
  hardware-dependent live-source test;
- Alembic: no new upgrade operations;
- React lint and production build;
- npm audit: zero vulnerabilities;
- Playwright: `31 passed, 1 skipped`; the skip is the existing live-source
  browser scenario;
- controlled detection: `24/24`, 15 expected and 15 actual alerts, zero
  scenario false positives/false negatives, explanation completeness `1.0`,
  one expected deduplication, and zero response actions;
- layered validation: `288/288`, zero false-positive/false-negative mode runs,
  temporary storage only;
- v5.31 adversarial lock: `27/27`, expected-rule FP/FN `0/0`, near-miss
  accuracy `1.0`, and timing/source/duplicate checks passed;
- Assistant QA: `20/20`, citation pass rate `1.0`, average/max answer length
  `74.5/200` words, and zero authoritative side effects;
- replay dry-run: two safe rows parsed and zero writes;
- read-only performance smoke: cold Overview `0.7986s`, cached Overview
  `0.0107s`, ML Governance `1.4004s`, alerts `0.0637s`, cases `0.0304s`,
  and no warnings; and
- official release gate: `ok: true` with no failed required checks.

The test warnings are existing scikit-learn small/empty-feature and calibration
diagnostics plus a local CPU-count fallback. They do not change the passing
result, but they remain useful technical-debt signals for future ML work.

## Remaining Risks

- A synthetic corpus cannot substitute for blinded real-device validation.
- Source diversity remains insufficient for broad generalization claims.
- Sophisticated distributed behavior outside the five-minute correlation
  window can evade these bounded rules.
- Availability impact, credential compromise, C2, exfiltration, and attacker
  intent require independent telemetry and analyst context.
- Independent reviewed native evidence is still required before supervised
  promotion can be reconsidered.

## Estimated Remaining Major Phases

At least three externally dependent phases remain before ATDR can be treated as
a credible preproduction candidate rather than a controlled lab system:

1. independent prediction-blind native labels across a second real source and
   time window, followed by one frozen supervised evaluation;
2. qualified human Assistant usefulness/privacy review plus approved Gemini
   quota, retention, cost, key-rotation, and host monitoring; and
3. shared preproduction acceptance covering MFU IAM/provider operations,
   multi-device live-source transport, backup/recovery, security monitoring,
   and deployment ownership.

Real response enforcement remains a separate optional safety program and is
not part of the current completion claim.
