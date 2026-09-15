# v5.19 Independent Labeled Detection/ML Evidence And Blind Validation

Date: 2026-08-01

## Decision

v5.19 acquired authoritative CTU-13 bidirectional NetFlow evidence and ran a
label-sealed, prediction-before-label transfer evaluation of ATDR's frozen
v5.6 supervised candidate. The evaluation did **not** close the independent
Detection/ML gate.

The first and only blind label reveal exposed a provider serialization mismatch:
the files serialize labels with a `flow=` wrapper while the frozen adapter
expected the documented `From-*` form. That original one-shot result is retained
as an adapter-contract failure with zero comparable rows. A narrow recovery then
removed only that wrapper and evaluated the already-frozen predictions. The
recovery is explicitly a post-blind diagnostic, not a fresh blind result and not
activation evidence.

The diagnostic found severe cross-schema false positives and weak calibration.
The supervised lifecycle remains `shadow_observation`; deterministic rules remain
alert-authoritative. No model was activated or promoted, and response automation
and real firewall blocking remain disabled.

## Authoritative Dataset Review

The selection used publisher or university sources rather than reposts.

| Dataset | Official evidence | Decision |
| --- | --- | --- |
| CTU-13 | [Stratosphere Laboratory CTU-13](https://www.stratosphereips.org/datasets-ctu13) describes 13 botnet scenarios, manually analyzed flow labels, and bidirectional Argus NetFlows. Its [dataset overview](https://www.stratosphereips.org/datasets-overview) identifies the license as CC-BY. | Selected. Four official directly downloadable bidirectional-flow scenarios were used. |
| CSE-CIC-IDS2018 | [UNB/CIC official page](https://www.unb.ca/cic/datasets/ids-2018.html) documents labeled CICFlowMeter flows and permitted redistribution with citation. | Rejected as fresh evidence because ATDR already opened it during v4.0 development/evaluation. |
| CICIDS2017 | [UNB/CIC official dataset index](https://www.cs.unb.ca/~alashkar/Data-sets.asp) documents labeled flows. | Not selected because a stable, directly reproducible official artifact was not established during this run, and the schema is not native PAN-OS. |
| UNSW-NB15 | [UNSW Canberra official page](https://research.unsw.edu.au/projects/unsw-nb15-dataset) documents 2,540,044 records, nine attack categories, and 49 labeled features. | Not selected because the official file handoff was interactive during this run and could not support the same reproducible immutable acquisition path. |

The selected evidence is independent of ATDR development, but it is a 2011
botnet-focused flow dataset, not native PAN-OS firewall output or a second real
ATDR source device. It can test binary schema transfer; it cannot prove current
firewall accuracy or production fitness.

## Selected Evidence

Four official CTU-13 bidirectional-flow scenarios were selected by provider file
size before labels were inspected:

| Scenario | Publisher behavior family | Role |
| --- | --- | --- |
| 5 | Virut botnet | Independent binary transfer |
| 7 | Sogou botnet | Independent binary transfer |
| 11 | RBot ICMP denial of service | Independent binary transfer |
| 12 | NSIS/P2P/UDP scan | Independent binary transfer |

Provider labels were mapped conservatively:

- `From-Botnet*` -> `needs_review` / threat-positive;
- `From-Normal*` -> `non_threat` / benign-like;
- background, inbound, and unsupported values -> excluded/abstained; and
- no `suspicious` or `malicious` distinction was invented.

The private immutable manifest records provider identity, official URLs,
license/citation, file sizes and checksums, schema, frozen contract, evidence
role, and label-open state. It remains under ignored storage. Public output
contains no local path, hash, raw row, IP address, database URL, or secret.

## Frozen Contract

Before reading labels, v5.19 froze:

- candidate: `calibrated_hist_gradient_boosting`;
- underlying classifier: `HistGradientBoostingClassifier`;
- candidate version: `v5.6-private-panos-assisted-model-repair-v1`;
- calibration: sigmoid;
- threshold: `0.30`;
- feature contract: 40 PAN-OS-oriented features;
- taxonomy: provider-supported binary transfer only;
- duplicate policy: exact containment plus bounded near-duplicate families;
- sampling: deterministic and label-independent;
- metrics and acceptance gates; and
- no post-prediction guard.

The adapter could directly map 10 features, derive 13 without labels, and had
17 unavailable PAN-OS fields. Missing fields were represented honestly rather
than fabricated. This mismatch is an explicit OOD warning.

## Label-Sealed Preflight

The successful preflight scanned 676,631 provider flows and selected 20,000
rows, 5,000 per scenario. It recorded:

- exact duplicates quarantined: `0`;
- near duplicates quarantined: `157`;
- malformed rows quarantined: `0`;
- labels accessed for sampling: `false`;
- labels accessed for features: `false`; and
- raw rows or IP addresses retained in public output: `false`.

Predictions were written and fingerprinted privately before the one-time label
read. The configured database and existing model artifacts were unchanged.

## One-Shot Outcome And Adapter Recovery

The original label reveal completed once, but all 20,000 rows were excluded by
the frozen adapter because of the unexpected `flow=` serialization wrapper.
That result is immutable and is not replaced by the recovery diagnostic.

The recovery changed only serialization normalization. It did not change the
model, features, calibration, threshold, sampled rows, or predictions.

| Measure | Post-blind diagnostic |
| --- | ---: |
| Attempted rows | 20,000 |
| Comparable rows | 885 |
| Threat-positive rows | 426 |
| Benign-like rows | 459 |
| Excluded/ambiguous rows | 19,115 |
| True positives | 426 |
| False positives | 458 |
| False negatives | 0 |
| True negatives | 1 |
| Threat precision | 0.4819 |
| Threat recall | 1.0000 |
| Threat F1 | 0.6504 |
| Benign-like FPR | 0.9978 |
| Macro F1 | 0.3274 |
| Weighted F1 | 0.3153 |
| Review queue rate | 0.9989 |

Calibration remained weak:

- Brier score: `0.4457`;
- expected calibration error: `0.4244`; and
- maximum confidence/accuracy gap: `0.6057`.

The fixed binary-transfer gate failed. Threat recall and minimum per-class
support passed, but F1, false-positive rate, calibration, confidence gap, and
minimum 1,000 comparable rows failed. Per-scenario benign-like FPR was `1.0`
for scenarios 5, 7, and 12 and `0.9787` for scenario 11. DNS/53 UDP and common
HTTP/80 and HTTPS/443 flows dominated false positives.

Only volume-based deterministic rule checks were representable in this flow
schema. They detected none of the comparable threats. This is a partial schema
baseline, not a test of the full PAN-OS rule engine; action, application risk,
vendor threat record, and zone-direction rules were unavailable.

## Safety And Side Effects

The preflight, one-shot run, and diagnostic recovery created:

```text
labels: 0
model runs: 0
detection runs: 0
alerts: 0
response actions: 0
active artifacts: 0
```

The configured database and model artifacts remained unchanged. Provider labels
were never called ATDR human review and were not imported into the database.

## Readiness And Roadmap

The independent evidence gate was narrowed, not closed. The result proves that
the frozen PAN-OS candidate does not safely transfer to CTU-13 flow evidence and
should abstain on incompatible schemas instead of filling the SOC queue.

Three major roadmap gates remain:

1. real multi-device and live-source acceptance;
2. schema-compatible, independently labeled Detection/ML evidence; and
3. provider, deployment, and security closure.

The estimated remaining program is three to five governed phases, depending on
access to devices, labels, MFU/provider approval, and preproduction
infrastructure. The next locally actionable phase is **v5.20 Schema-Aware
Abstention And Independent Evidence Protocol Repair**. It must lock this v5.19
result, avoid tuning on these labels, and make incompatible-schema inference
fail closed. Native PAN-OS independent validation remains externally blocked.

No commit or push is authorized by this phase.

## Verification

The engineering implementation passes the complete closure matrix even though
the frozen model-transfer gate correctly failed closed:

- taskboard render and standard checks: pass;
- Ruff and compileall: pass;
- focused v5.19 tests: `7 passed`;
- full backend/release tests: `789 passed, 1 skipped`;
- Alembic: no drift, configured SQLite database at head;
- React lint and production build: pass;
- Playwright: `26 passed, 1 skipped` (live-hardware coverage remains external);
- controlled detection validation: `23/23`;
- layered detection validation: `288/288`;
- Assistant QA: `20/20`;
- replay dry-run: two safe rows parsed and zero rows written;
- performance smoke: pass with no warnings;
- release gate: `ok: true`, no failed required checks; and
- exact allowlist, diff, privacy, ignored-evidence, staging, and tracked-hygiene
  checks: pass.

These checks validate the implementation and safety boundary. They do not turn
the failed cross-schema diagnostic into model-readiness evidence.
