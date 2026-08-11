# ATDR Current AI And ML Product Status

Date: 2026-08-11

ATDR uses several distinct AI/ML layers. They must not be presented as one
autonomous model. Deterministic rules detect explainable patterns, an
IsolationForest can add anomaly evidence, supervised models remain governed
decision-support candidates, and Gemini may summarize bounded ATDR evidence for
an analyst. None of these layers may execute a response action.

## Status At A Glance

| Layer | Current role | Current status | Authority |
| --- | --- | --- | --- |
| Deterministic detection rules | Primary explainable alert generation | v5.31 adversarial lock: 27/27 synthetic cases; 19-rule catalog contract reconciled | May create/deduplicate alerts; cannot execute response |
| IsolationForest | Assistive unusual-behavior score | v5.5 audit and v5.13 regression: advisory only; controlled anomaly layer remains 72/72 | Decision support only; cannot create an alert by itself |
| Supervised SOC queue | Rank/recommend review from labeled evidence | Registered calibrated ExtraTrees artifact remains in `shadow_observation`; v5.28 integrity/runtime audit passed but human blind review is 0/40 | Evidence only; rules remain authoritative |
| Legacy supervised artifact | Unselected local reference | Artifact exists; model/feature metadata are unknown | Not selected by the governed lifecycle |
| SOC Assistant deterministic layer | Retrieve and explain ATDR evidence | 20/20 controlled QA questions passed | Read-only |
| Gemini provider layer | Rephrase/summarize bounded evidence | Private configuration and one bounded synthetic probe passed | Explanation only; no detector or action authority |

## Where Assistant Answers Come From

The assistant does not invent a second security database. Its deterministic
context builder reads bounded records through the current SQLAlchemy service
layer and constructs citations to the relevant ATDR surface:

- alert summaries/details and `Why flagged?` evidence;
- normalized log triage fields and linked alerts;
- source health and source-quality summaries;
- operation, ingestion, and detection run history;
- current AI Governance/model-registry summaries; and
- approved workflow/runbook paths for operational how-to answers.

Source evidence: `atdr/app/services/assistant_service.py`,
`atdr/app/routers/assistant.py`, `atdr/app/schemas/assistant.py`, and
`frontend/src/pages/AssistantPage.tsx`.

Each answer reports citations when evidence exists. A missing record or missing
field must be stated as unavailable rather than inferred. Raw log lines are
removed from the external-provider context by default.

## Gemini's Exact Role

Gemini is an optional presentation and explanation layer over the deterministic
answer. When private configuration explicitly enables it, ATDR sends a bounded,
redacted prompt containing the analyst question, deterministic answer, safe
structured context, allowed citations, and suggested follow-ups. The provider
must return the structured answer contract, and citation references are filtered
against the allowlist ATDR supplied.

Gemini does not:

- ingest directly from the ATDR database;
- receive API keys in a response or audit record;
- receive raw logs by default;
- run detection, import data, alter labels, train/activate models, manage users,
  delete evidence, or create response actions; or
- replace deterministic fallback when the provider is unavailable or rejected.

Source evidence: `atdr/app/services/assistant_llm.py`,
`atdr/app/services/assistant_service.py`, `atdr/app/core/config.py`, and
`atdr/tests/test_assistant.py`.

On 2026-07-18, a secret-safe status check reported provider/model/key configured,
IP redaction enabled, raw-log context disabled, and `secrets_exposed=false`. One
bounded synthetic Gemini probe completed in about 2.0 seconds with valid
structured output and no raw-log or secret exposure. This proves the configured
adapter worked at that moment; it is not an availability, privacy, quota, cost,
or production-service guarantee.

## Assistant Safety And Quality

- Authentication is required.
- Admin and analyst access remain governed by current RBAC.
- IP redaction is enabled by default.
- Raw-log context is disabled by default.
- Questions are audited without secrets.
- Provider failure falls back to the deterministic answer.
- Feedback is review metadata only; it does not auto-tune the assistant.
- `action_executed` remains false and response automation remains disabled.

The controlled assistant evaluator passed 20/20 questions with a citation pass
rate of 1.0, unsafe-action refusal, and no changes to response actions, detection
runs, model runs, labels, alerts, or logs. Its fixture is synthetic and local;
real SOC answer evaluation and organizational provider approval remain open.

## Detection Rules

Rules are ATDR's primary explainable detection layer. They evaluate normalized
traffic fields and behavior windows, map matched evidence to alert types and
analyst explanations, and deduplicate repeated evidence into occurrence and
related-log counts. Safe scenarios cover normal traffic, scanning, repeated
deduplication, generic syslog, and raw fallback behavior.

Source evidence: `atdr/app/detection/rules.py`,
`atdr/app/services/detection_service.py`,
`atdr/app/detection/explanations.py`, `docs/DETECTION_RULE_CATALOG.md`, and
`data/samples/scenarios/`.

The v5.31 rule catalog distinguishes vertical port diversity from horizontal
same-service destination diversity, scopes correlation and deduplication by
registered source, requires same-target/service evidence for brute-force-like
activity, measured cadence for beaconing, and corroborated or very-high
effective volume for flood-like activity. PAN-OS `THREAT` severity/name and
`repeatcnt` semantics are retained. Directionless byte/packet outliers and
generic application-risk evidence are deliberately bounded so they do not
become unsupported exfiltration, DoS, malware, or C2 claims.

The controlled v5.31 corpus passes `27/27` with zero expected-rule
false-positive or false-negative cases, near-miss/negative accuracy `1.0`,
correct timing/source/duplicate behavior, and no label/model/response writes.
Missing timestamps fail closed for cross-row correlation and deduplication,
and independent behavior windows remain separate findings. This is synthetic
regression evidence, not a measured real-world accuracy or generalization
result. Exact rule assumptions, false-positive factors, and claim boundaries
are in `docs/detection/ATDR_RULE_PACK_CONTRACT.md`.

v4.9 makes correlation source-scoped and five-minute bounded, adds a versioned
rule contract, and corrects low-specificity overclaims. Generic vendor THREAT,
app-risk, and directionless byte/packet evidence no longer imply C2, exfiltration,
or DoS by themselves. The controlled matrix passed 24/24 scenarios with zero
scenario-level false positives, false negatives, unexpected attack types, or
response actions. v5.2 additionally repaired the 21 retained layered
rule/anomaly/hybrid regressions, and the current layered matrix passes 288/288
with zero controlled FP/FN and zero response actions. This is controlled regression evidence, not real-source
accuracy. ATT&CK context remains an analyst aid, not certified attribution.

## IsolationForest

`atdr/app/detection/ml_detector.py` trains and applies an IsolationForest to
identify unusual events relative to imported data. Its anomaly flag/score is
advisory evidence only. v5.2 prevents anomaly evidence from satisfying the
deterministic alert threshold or replacing a more specific rule finding, and
bounds field-poor fallback/parser-warning interpretation. Unusual does not mean
malicious; IsolationForest cannot authorize a response.

## Supervised Model Candidates

ATDR supports reviewed-label workflows, candidate comparisons, calibration,
threshold analysis, and a governed model registry. A fresh calibrated ExtraTrees
binary SOC review-queue artifact is active in `shadow_observation`. The older
local artifact still has unknown metadata, but it is an unselected legacy
reference and is not treated as the active governed model.

The v4.0 provider-blinded CSE-CIC-IDS2018 evaluation exposed the key blocker:
the frozen internal queue did not generalize to a provider-flow schema lacking
firewall fields such as application, action, zones, source port, and source
behavior context. It produced threat precision `0.3171`, recall `1.0000`, F1
`0.4815`, benign-like FPR `1.0000`, Brier `0.6538`, and ECE `0.6614`.

v4.1 added explicit schema contracts and missingness-aware development
experiments. It found useful pooled diagnostic signals, but calibration and
source/time/schema-held-out transfer remained unstable. Therefore:

- readiness remains `candidate_only`;
- `production_promoted=false`;
- no v4.0/v4.1 candidate is selected by the governed lifecycle;
- `response_automation_allowed=false`; and
- model activation requires a separately governed untouched benchmark plus
  independently collected multi-source firewall/syslog evidence.

Source evidence: `docs/V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE_AND_FROZEN_VALIDATION.md`,
`docs/V4_1_SCHEMA_AWARE_SOC_QUEUE_MODEL_REDESIGN.md`,
`atdr/app/detection/schema_contracts.py`,
`atdr/app/detection/v401_schema_aware_soc_queue.py`, and
`atdr/app/detection/supervised_workflow.py`.

## v4.9 Reliability Lock

v4.9 introduced causal source-scoped feature windows and a unified evaluator
with dedicated fit, calibration, threshold-selection, and final-test roles.
It evaluates temporal, network-zone proxy, and three repeated random views over
2,235 latest eligible label rows while preserving original label source.
Included provenance is manual 1,672, rule-assisted 529, ML-assisted 7, and
hybrid-assisted 27. The reviewed flag must not be used to claim every included
row was human-authored.

The post-evaluation diagnostic ranking selected a hybrid queue, but its F1
ranges from 0.7310 to 0.8165, FPR reaches 0.7232 on the zone proxy, suspicious
recall falls to 0.4701, malicious recall falls to 0.5286, and calibration passes
0/5 splits. The predeclared calibrated ExtraTrees candidate also passes 0/5
strict splits. The locked external evidence still has FPR 1.0.

Readiness therefore remains `candidate_only`. v4.9 authored no labels, wrote no
artifact, activated no model, created no model run or response action, and left
the database and active legacy artifact unchanged. See
`docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md`.

## v5.1 Governed Shadow Activation

v5.1 converts the v4.9 evidence into a safe operational lifecycle without
weakening its gates. It uses 2,235 latest eligible reviewed rows, preserves
manual/rule-assisted/ML-assisted/hybrid-assisted provenance, excludes weak or
unreviewed rows, isolates duplicate groups, and records a dataset fingerprint,
feature schema, calibration, threshold, checksum, code revision, and split
metrics.

The selected model is a calibrated ExtraTrees binary queue with threshold 0.85.
It passed serialization, binary checksum, probability-bound, leakage, and
single-row latency checks; p95 latency was 14.7438 ms. It passed 0/5 strict
quality splits. Temporal F1/FPR/suspicious recall/malicious recall were
0.2363/0.2198/0.1176/0.2857, and calibration remained weak. The locked external
benchmark also failed.

The resulting state is deliberately `shadow_observation`:

- supervised queue scores may be displayed as decision-support evidence;
- scores are not used for alert creation, severity, suppression, or response;
- `decision_support` activation fails closed while any strict gate fails;
- production promotion is rejected; and
- rule detection continues if the model is missing or fails.

A disposable 5,000-row private Palo Alto shadow run parsed every row, scored a
1,000-row deterministic model sample, and queued 47 rows (4.7%). It changed no
configured DB or model artifact and created zero responses. The private file had
no independent labels, so this is operational queue evidence, not accuracy.
See `docs/V5_1_SUPERVISED_SHADOW_ACTIVATION.md`.

## v5.2 Shadow Reliability And Layered Repair

v5.2 leaves the v5.1 artifact in shadow and runs a read-only multi-strategy
comparison across temporal, source, network-zone proxy, and random views. The
source-disjoint view fails closed because the eligible reviewed set contains
fewer than two independent source devices.

The leading comparator is `binary_extra_trees_lower_threat_weight`, but it is
explicitly **not selected**. It passes 0/6 required views and 10/30 aggregate
metric checks. Temporal F1 is 0.3555 with FPR 1.0; network-zone F1 is 0.7668
with suspicious recall 0.4774 and ECE 0.2238. Random views are stronger but do
not repair temporal/source transfer or threshold instability. The locked
external benchmark also remains failed.

The final lifecycle therefore remains `shadow_observation` with
`production_promoted=false` and `response_automation_allowed=false`. Aggregate
shadow telemetry can now be persisted in existing model-run/audit tables
without raw logs or identifiers. See
`docs/V5_2_SHADOW_RELIABILITY_AND_LAYERED_REPAIR.md`.

## v5.3 Temporal Generalization And OOD

v5.3 freezes the same 2,235-row reviewed evidence set and adds three disjoint
rolling future windows plus fit-only OOD and calibrated-abstention diagnostics.
It identifies the temporal failure as a chronological evidence shift: review
prevalence changes from `0.8640` in threshold selection to `0.2218` in final
test, provenance changes from mainly rule-assisted fit evidence to entirely
manual final evidence, and the final window is dominated by benign QUIC/443.
Missingness and unseen schema are minor by comparison.

The best aggregate diagnostic comparator is calibrated
HistGradientBoosting, but it passes zero strict views. Temporal F1/FPR are
`0.3636/0.9976`; rolling FPR is `0.9923` to `1.0000`; zone-proxy suspicious
recall is `0.4968`; and calibration fails chronological views. OOD rate is
`0.0733` on the temporal final view. Honest abstention remains counted in the
analyst queue and also passes zero strict views.

No v5.3 model is selected or written. Source holdout still fails closed because
fewer than two independent real devices exist, and the locked external result
remains failed without being reopened for tuning. The governed v5.1 artifact
therefore stays in `shadow_observation`; rules remain alert-authoritative and
production promotion, response automation, and real blocking remain false.
See `docs/V5_3_TEMPORAL_GENERALIZATION_AND_OOD.md`.

## v5.4 Temporal Evidence And Shadow Drift

v5.4 does not attempt another model repair. It locks the v5.3 fit,
calibration, threshold, temporal-final, rolling, external, and governed
artifact evidence with reproducible aggregate fingerprints. The lock prevents
future development from silently reusing final evaluation evidence.

Of 2,235 governed rows, 1,467 are eligible development evidence and 768 are
excluded: 532 locked temporal-final rows and 236 duplicate-quarantine rows.
Within development evidence, 918 rows are genuinely human-reviewed and 549
are assisted/weak. Assisted provenance is never described as human review.

Shadow drift is currently `OOD Warning`. Fit-to-final application, schema, and
provenance distances are `0.7428`, `0.5791`, and `0.5737`, and review-queue
rate changes by `0.6422`. The private PAN-OS aggregate provides eight
chronological windows and zero parser errors across 773,551 rows, but it has
one device and no ground-truth labels, so it cannot establish accuracy or
independence.

No candidate is selected; no label, model run, detection run, response action,
or active artifact is written. The lifecycle remains `shadow_observation`,
rules remain alert-authoritative, and production promotion, automatic
response, and real blocking remain false. See
`docs/V5_4_TEMPORAL_EVIDENCE_AND_SHADOW_DRIFT.md`.

## v5.5 Development Model Repair And Anomaly Reliability

v5.5 uses only the 1,467 locked development rows for nested chronological
strategy selection. It compares calibrated ExtraTrees, HistGradientBoosting,
Logistic Regression, a three-class SOC queue, and a hierarchical strategy
without writing any active artifact. A source-aware view still fails closed
because the reviewed evidence contains one real source identity.

The three-class ExtraTrees SOC queue is the best development diagnostic leader,
but it passes `0/3` strict folds. After that configuration was frozen, one
read-only locked temporal regression produced F1 `0.4925`, benign-like FPR
`0.0773`, suspicious recall `0.3824`, malicious recall `0.4143`, and weak
calibration with ECE `0.5405`. Noise is much lower than v5.3, but recall and
confidence reliability remain unacceptable.

The existing IsolationForest is also not reliable as a standalone detector:
development benign-like FPR is `0.2773`, threat capture is `0.0818`, and the
locked temporal anomaly rate falls from `0.1820` to `0.0094`. It remains an
advisory signal only.

No lifecycle candidate is selected or activated. Database/artifact state is
unchanged, rules remain alert-authoritative, and response automation and real
blocking remain false. See
`docs/V5_5_DEVELOPMENT_MODEL_REPAIR_AND_ANOMALY_AUDIT.md`.

## v5.6 Private PAN-OS Evidence And Assisted Repair

v5.6 streams all 773,551 private PAN-OS rows through disposable storage with
zero parser failures. It excludes 120,000 configured-DB overlaps and contains
all exact/near duplicate families within one role. The 120,626-row quarantine
never enters fitting or evaluation.

The fixed policy creates non-human assisted evidence only. Across development,
calibration, and threshold roles it marks 409,741 events training-eligible and
keeps 131,180 ambiguous events out of training. Provenance is explicitly
`codex_assisted`, `rule_assisted`, `vendor_threat_assisted`, or
`weak_supervision`; human-reviewed private labels remain zero.

Calibrated HistGradientBoosting is the frozen diagnostic leader. Against the
once-opened 3,400-row private future sample it has F1 `0.9889`, FPR `0.0211`,
and suspicious/malicious recall `1.0/1.0`. This is strong assisted-policy
agreement on one source, not independent accuracy. Calibration remains weak
because maximum confidence/accuracy gap is `0.8143`, and no strategy passes
all complete development gates.

The best diagnostic IsolationForest contamination is `0.02`; private future
FPR is `0.0057`, but threat capture is `0.4576` and suspicious recall is only
`0.16`. It remains advisory.

The optional candidate artifact is ignored and separate from active artifacts.
Configured database and active artifact hashes are unchanged; zero labels,
model runs, detection runs, alerts, or responses are created. Lifecycle remains
`shadow_observation`, rules remain alert-authoritative, and production
promotion, response automation, and real blocking remain false. See
`docs/V5_6_PRIVATE_PANOS_EVIDENCE_AND_ASSISTED_MODEL_REPAIR.md`.

## v5.7 Independent Evidence Readiness

v5.7 freezes the v5.6
`calibrated_hist_gradient_boosting` diagnostic candidate with sigmoid
calibration, threshold `0.3`, a 40-field feature contract, threshold-only
decisions, and no post-prediction suppression guard. The ignored artifact,
feature/preprocessing contract, training-manifest identity, code identity, and
artifact hash are recorded locally and remain unchanged.

The complete private PAN-OS source is reused v5.6 development evidence. It is
appropriate for parser regression, aggregate drift, and disposable preflight,
but it is not a fresh holdout. Existing v5.3 final/rolling/external evidence
and v5.6 future evidence are also already opened and locked.

No fresh native PAN-OS-compatible independently labeled corpus was found in
the approved official-source review. Consequently:

- independent evidence status is `independent_evidence_required`;
- predictions are not frozen for a new blind corpus;
- labels are not revealed;
- blind supervised metrics are not reported;
- independent IsolationForest metrics are pending;
- lifecycle remains `shadow_observation`;
- rules remain alert-authoritative; and
- model activation, production promotion, response automation, and real
  firewall blocking remain disabled.

The next evidence requirement is at least two real devices, at least two new
collection periods, a local overlap/duplicate audit, predictions frozen before
labels, independently human- or provider-confirmed ground truth, and advisor
approval. See
`docs/detection/V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md`.

## v5.8 Governed Shadow Runtime

The exact frozen v5.6/v5.7
`calibrated_hist_gradient_boosting` candidate is now available to a
disabled-by-default, bounded, read-only shadow service. Its local artifact,
code, 40-field feature, sigmoid calibration, threshold `0.3`, inactive state,
and response-safety contract all match. No fallback model is permitted.

A scoped 100-row configured-database run evaluated normalized logs only. It
reported a 47.0% advisory queue rate, `Drift Warning`, 58.0% rule/shadow
disagreement, and 9.0% persisted IsolationForest anomaly rate. Those values
are aggregate operational observations, not labeled accuracy. Database and
artifact state were unchanged and zero alerts, labels, runs, or responses
were created.

AI Governance now distinguishes:

- Frozen Diagnostic Candidate;
- Shadow Scoring Enabled/Disabled;
- Candidate Contract Matched/Mismatched;
- Independent Evidence Pending/Available;
- Rules Authoritative; and
- Response Automation Disabled.

The lifecycle remains `shadow_observation`. Independent multi-device,
multi-period, human/provider-labeled evidence remains the gate for any later
decision-support advancement.

## v5.9 Longitudinal Shadow Observation

ATDR now has a disabled-by-default, append-only aggregate observation layer
for the frozen governed candidate. It supports source/time/row-scoped
observations, deterministic idempotency, admin-only durable jobs, bounded
summary trends, explicit audited retention, and aggregate AI Governance
visibility.

The complete private PAN-OS development file was inspected in disposable
storage without importing it. All 773,551 rows parsed successfully across
eight chronological windows. Maximum application-distribution shift was
`0.117569`, maximum schema shift was `0.001429`, and aggregate status was
`Stable`. This is reused unlabeled development evidence, so it is not an
independent holdout and does not support accuracy or readiness claims.

An official-source review found useful public flow/PCAP benchmarks but no
fresh native PAN-OS, independently labeled, multi-device corpus. No new
dataset was downloaded and no assisted review pack was generated.

The lifecycle remains `shadow_observation`. Rules remain alert-authoritative,
IsolationForest remains advisory, no candidate is active/promoted, and
response automation and real blocking remain disabled.

## v5.10 Detection Operations And Shadow Acceptance

ATDR now plans bounded, non-overlapping operational scopes from existing
configured-database evidence and records aggregate shadow behavior only when
explicitly enabled. Four opaque source scopes produced eight chronological
observations. All eight completed successfully and a second run idempotently
reused all eight keys.

Operational telemetry shows a mean advisory queue rate of `0.672734`, mean
rule/shadow disagreement of `0.278047`, and mean persisted IsolationForest
anomaly rate of `0.005000`. Drift states were two `Stable`, one
`Drift Warning`, three `OOD Warning`, and two `Insufficient Evidence`.
All eight operational gates passed, but the warnings remain visible.

This is reused development operational evidence. No labels were read and no
accuracy, false-positive, recall, F1, or calibration metric was calculated.
No alert, case, label, model run, detection run, or response action changed.

The large-SQLite AI Governance cold bottleneck was also repaired. The
dedicated profiler now measures `0.290613s` cold and `0.257297s` warm with
equivalent responses; final performance smoke measured `0.2676s` cold and
`0.2520s` warm with no warnings.

The lifecycle remains `shadow_observation`. This operational pass does not
replace the independent multi-device, chronological, labeled evidence gate.

## v5.12 Parser-Profile-Aware Quality Repair

v5.12 does not change the model or alert authority. It versions the PAN-OS
TRAFFIC/THREAT/SYSTEM parser contract, repairs SYSTEM mapping, separates
unresolved application semantics from structural parser failure, preserves
generic/raw fallback evidence, and compares operational windows against
supported parser-profile/source-type baselines.

The complete private aggregate audit parsed 773,551/773,551 rows with zero
parser errors and zero structural warnings. It found 7.1739% unresolved
application evidence. This replaces the misleading broad parser-warning
interpretation without hiding data quality.

The current effective operational state remains `OOD Warning`: five windows
use the supported Palo Alto firewall baseline, three comparable file-import
windows use the governed global fallback, and genuine application-distribution
variation remains visible. Controlled detection matched the frozen 96-run
projection with zero controlled FP/FN and zero configured-database mutation.

No SYSTEM row was present in the private file; SYSTEM support is based on the
official contract and synthetic tests. Existing rows retain legacy contract
metadata. Independent labeled multi-device evidence is still required before
supervised ML can advance beyond `shadow_observation`. See
`docs/V5_12_PARSER_PROFILE_BASELINE_REPAIR.md`.

## v5.13 Runtime Parser Contract And Source Quality

v5.13 applies the v5.12 parser contract to every future file, replay, UDP
syslog, durable, and scenario ingestion path. Sources now retain aggregate
runtime quality with a fixed baseline and bounded latest window, so actual
parser errors and structural drift are distinct from legitimate unresolved
applications, generic syslog, and raw fallback.

Historical normalized rows remain `legacy_contract`; the additive source
aggregate migration did not update or reparse them. A read-only source
preview reports stored contract coverage without reading raw evidence or
writing data.

The frozen v5.11 diagnostics and v5.12 controlled projection still match.
The comparison passed 96/96 mode runs with zero authoritative entity
mutation. Rules remain alert-authoritative, ML remains advisory, and the
supervised lifecycle remains `shadow_observation`.

Remaining parser evidence includes real SYSTEM records, long-duration
real-device syslog operation, governed generic/raw fallback baselines, and
independent labeled multi-device periods. See
`docs/V5_13_RUNTIME_PARSER_CONTRACT_AND_SOURCE_QUALITY.md`.

## Remaining Product Gates

1. Independently collect and review multi-source real firewall/syslog evidence.
2. Evaluate one untouched external benchmark under a schema-compatible,
   prediction-before-label protocol.
3. Pass stability, false-positive, recall, and calibration gates across source
   and time boundaries.
4. Preserve complete artifact, feature-set, training-data, threshold, lifecycle,
   and provenance metadata for every future candidate.
5. Complete Gemini privacy approval, key custody/rotation, quota/cost monitoring,
   and real-traffic answer-quality review.
6. Keep response automation and real firewall blocking disabled unless a
   separate approved safety design is implemented and validated.

ATDR is a controlled productization candidate and AI-assisted SOC decision
support system. This status is not a production-readiness or model-accuracy
claim.

## v5.19 Independent Binary Transfer Result

ATDR's frozen v5.6 `calibrated_hist_gradient_boosting` candidate was evaluated
against independently published CTU-13 bidirectional-flow evidence under a
prediction-before-label protocol. The first label reveal exposed an adapter
serialization mismatch and is retained as a failed one-shot blind record.

A normalization-only diagnostic of the unchanged frozen predictions found:

- 885 comparable rows from 20,000 sampled flows;
- threat precision/recall/F1 `0.4819/1.0000/0.6504`;
- benign-like FPR `0.9978`;
- queue rate `0.9989`; and
- weak calibration: Brier `0.4457`, ECE `0.4244`, max gap `0.6057`.

The provider taxonomy supports binary botnet/normal transfer only. It does not
justify ATDR suspicious or malicious recall claims. The 40-feature PAN-OS
contract has 10 direct, 13 derived, and 17 unavailable fields in this flow
schema, so the result is an OOD warning. It proves that the candidate should
not be trusted on incompatible flow schemas; it does not justify tuning on the
opened v5.19 labels.

Lifecycle remains `shadow_observation`. No candidate is active or promoted,
rules remain alert-authoritative, and response automation remains disabled.
Native schema-compatible independent labels and a second real device remain
required.

## v5.20 Runtime Schema Gate

v5.20 corrects the inference-order defect exposed by v5.19. Governed
supervised scoring now checks parser profile and required PAN-OS fields before
calling the classifier. Incompatible, unknown, parser-failed, and incomplete
evidence receives an explicit abstention with no supervised probability.

This change prevents unsupported confidence; it does not improve or validate
model accuracy. Deterministic rules continue to evaluate the evidence and
remain alert-authoritative. AI Governance and alert explanations expose the
aggregate schema-gate state, abstention reason, and missing required field
names without exposing raw logs, IP addresses, local paths, fingerprints, or
secrets.

The v5.19 result remains terminal and immutable. Lifecycle stays
`shadow_observation`, no candidate is active or promoted, and response
automation remains disabled. The next evidence gate is native chronological
PAN-OS evidence with trustworthy human/advisor verification and, when
available, a second real source.

## v5.21 Native PAN-OS Evidence Foundation

v5.21 parsed the complete 773,551-row private PAN-OS stream in disposable
storage with zero parser failures. It created 22 chronological windows and
locked 433,499 development-fit, 116,422 calibration, 111,626 threshold, and
112,004 untouched-future rows. Exact and near-duplicate families do not cross
roles.

A 120-row development pack contains only weak assisted suggestions. A 40-row
blind pack contains no rule, model, or AI suggestions. Neither pack is
human-reviewed or import-ready. The configured database was not opened by the
corrected run and its marker remained unchanged.

This evidence is sufficient to attempt a diagnostic native-schema v5.22 model
rebuild, but it is not ground truth and cannot justify activation. A qualified
human/advisor must verify native labels, and a second real source remains
required for source-generalization claims. Lifecycle remains
`shadow_observation`, rules remain alert-authoritative, and automatic response
and real blocking remain disabled.

## v5.22 Native Supervised Rebuild

v5.22 reproduces the exact v5.21 role lock and compares six supervised SOC
queue strategies without opening the 112,004-row future role or the blind
verification pack. It correctly classifies 918 governed rows as genuinely
human-reviewed and 549 as assisted/weak; 500,770 private development events
receive weak training decisions while 160,777 ambiguous events stay excluded.

The frozen configuration is hierarchical two-stage ExtraTrees with dedicated
sigmoid calibration and queue threshold `0.40`. Cross-view worst-case F1 is
`0.8025`, FPR `0.0476`, suspicious recall `0.5000`, malicious recall `1.0000`,
ECE `0.3741`, and confidence gap `0.7099`. Low noise and malicious recall have
improved, but suspicious recall and calibration still fail.

No executable artifact was written or activated. The lifecycle remains
`shadow_observation`; rules remain alert-authoritative; blind human evidence,
source-disjoint validation, automatic response, and real blocking remain
unavailable or disabled. See `docs/V5_22_SUPERVISED_MODEL_REBUILD.md`.

## v5.23 Collection-To-Investigation Evidence

The v5.23 disposable local acceptance passed file, API, resumable, backpressure,
UDP replay, source health, parser quality, source-scoped rule detection,
deduplication, case linkage, why-flagged explanation, recommendations, and
audit-history checks together. This strengthens runtime evidence but does not
add supervised accuracy evidence or change model authority. A non-loopback
second-laptop or real-device sender remains required to complete the phase.

## v5.24 Gemini Investigation Quality

The bounded live Gemini evaluation passed 11/11 fixed gates over six synthetic
alert/log/source/case and follow-up questions. Record context, trusted
citations, expected evidence, visible concision, unsupported-ID checks,
provider-failure fallback, redaction, raw-context exclusion, and read-only
side-effect checks all passed. Median/p95 latency was 3,125/3,731 ms and total
usage was 18,675 tokens.

This is Assistant quality evidence, not supervised detection accuracy. Gemini
does not create or suppress alerts, change labels/models, execute response, or
replace analyst judgment. Provider drift, real-traffic evaluation, privacy
approval, quota/cost monitoring, and key rotation remain deployment work.

## v5.25 Integrated Acceptance Status

The integrated local workflow passes collection through audited simulated
analyst response without granting ML or Gemini authority. Rules remain the
only alert-authoritative layer. Supervised ML remains `shadow_observation`;
IsolationForest and hybrid scores remain advisory. The validated v5.24 Gemini
lock is evidence-grounded, read-only, redacted, raw-log-free, and mutation-free.

This closes the local v5.20-v5.25 implementation roadmap, not the supervised
accuracy gate. Independent human-reviewed native multi-device evidence is
still required before any activation or promotion reconsideration.

## v5.26 Native Blind Qualification Status

The one-time native blind protocol scored 40 sealed PAN-OS rows after
reconstructing the unchanged v5.22 candidate from development-only roles. The
complete 773,551-row private stream parsed successfully in disposable storage.
Blind evidence was excluded from fit, calibration, threshold selection, and
candidate selection.

Observed review-queue rates are rules `0.625`, IsolationForest `0.075`,
supervised shadow `0.300`, and hybrid `0.100`. These are not accuracy rates.
The blind pack contains zero genuine human-reviewed decisions, so confusion
matrices, precision, recall, F1, false-positive rate, calibration, and FP/FN
root-cause claims are unavailable.

Readiness passes 6/8 protocol/safety checks and remains
`shadow_observation`. The blockers are genuine blind labels and available blind
metrics. No model artifact was written or activated; rules remain
alert-authoritative; ML remains advisory; automatic response and real blocking
remain disabled.

## v5.27 Current Decision

- Blind-review tooling: complete and fail-closed.
- Valid independent blind decisions: `0/40`.
- Locked supervised metrics: unavailable; no FP/FN or calibration claim.
- Supervised lifecycle: `shadow_observation`.
- Rules: alert-authoritative.
- Configured Assistant provider: Gemini.
- Bounded real-record Gemini result: six calls, `12/12` fixed gates passed.
- Median/P95 provider latency: `3,521.5/3,878` ms.
- Provider usage: `21,973` total tokens.
- Configured database mutations: zero.
- Raw Assistant context: disabled; IP redaction: enabled.
- Model activation/promotion: none.
- Automatic response and real blocking: disabled.

The supervised path still needs genuine independent human review and second-
source evidence. The Assistant path still needs human semantic/privacy review
and approved-host provider governance. Automated labels cannot close the human
evidence gate, and bounded Gemini checks do not prove universal correctness.

## v5.28 Current Decision

- Sealed blind pack: unchanged and not opened by the v5.28 workflow.
- Independent human reviews: `0/40`; blind metrics remain withheld.
- Supervised artifact: registered calibrated ExtraTrees; checksum and feature,
  calibration, threshold, schema, and abstention contracts valid.
- Registered inference latency: `14.7438 ms` p95 over 100 rows; fixed gate
  passed.
- Shadow drift: `Insufficient Evidence`; durable telemetry is not yet
  available.
- Lifecycle: `shadow_observation`; no selection, retraining, recalibration,
  activation, or promotion occurred.
- Gemini bounded result: six calls and `12/12` fixed checks passed.
- Gemini latency: `3,494.5/3,795 ms` median/p95; usage `21,999` total tokens.
- Provider timeout fallback, citation/context, visible-concision, privacy, and
  unsupported-action/ID controls passed.
- Raw logs, IPs, private paths, prompts, answers, and secrets are absent from
  operational telemetry.
- Authoritative mutations, automatic response, and real blocking: zero/false.

The v5.28 review helper is ready for later qualified human use but was not run
against the actual sealed evidence. Approximately three supervised evidence
phases and two Assistant product-evidence phases remain. Their external inputs
are human review, a second source/device, institutional/provider approval, and
an approved deployment host.

## v5.29 Assistant Response Quality Decision

- Assistant response modes: nine explicit intent-specific contracts.
- Deterministic QA: `20/20`; citations and all word budgets passed.
- Average/max answer length: `73.1/184` words, reduced from `283.8/697`.
- Follow-ups: active record retained; new question answered without repeating
  the complete prior answer.
- Gemini bounded result: six calls and `12/12` checks passed.
- Gemini latency: `2,105/2,828 ms` median/p95; `20,570` total tokens.
- Direct answer: visible first; detailed evidence and provider sources:
  collapsed by default.
- Raw logs: disabled; IP redaction: enabled; secrets exposed: false.
- Assistant authority: none; zero response/detection/label/model/user/delete
  effects.

The Assistant is materially more concise and useful for routine SOC triage,
but automated tests do not replace qualified human semantic/privacy review or
approved-host provider operations. Rules remain alert-authoritative;
supervised ML remains `shadow_observation`; automatic response and real
blocking remain disabled.

## v5.30 Supervised Evidence Closure

v5.30 is the canonical promotion-readiness decision for the current supervised
program. The configured database contains 2,672 latest trainable labels: 1,672
meet the manual human-provenance contract and 1,000 remain assisted/weak. Of
the assisted rows, 563 carry `reviewed=true`, but none are counted as human
authorship. Every configured label comes from one source identity and one
calendar day.

The native PAN-OS evidence remains strong for schema and chronology but not
ground truth: 773,551 rows parse successfully across 22 windows, with 433,499
fit, 116,422 calibration, 111,626 threshold, and 112,004 locked-future rows.
The sealed 40-row blind pack still has zero legitimate human decisions. All 15
evidence-custody/leakage checks pass and the private disposable preflight
changed no configured state.

The registered v5.1 artifact remains valid for shadow scoring. Against current
human-provenance rows it reports diagnostic F1 `0.6214`, FPR `0.1167`,
suspicious recall `0.3537`, malicious recall `0.6452`, and ECE `0.2098`.
Training overlap cannot be excluded, so these are not promotion metrics. The
single-day temporal tail is weaker, and source holdout fails closed because a
second source does not exist.

The newer v5.22 configuration remains an artifact-free diagnostic candidate;
it cannot be activated or rerun by the closure audit. Independent quality
metrics remain withheld. Lifecycle stays `shadow_observation`, rules remain
alert-authoritative, and model activation, production promotion, automatic
response, and real blocking remain false. See
`docs/V5_30_SUPERVISED_EVIDENCE_CLOSURE.md`.

## v5.31 Deterministic Reliability Decision

The deterministic layer now has a source-backed 19-rule catalog and a 27-case
adversarial lock covering correlation boundaries, common benign near-misses,
degraded input, missing timestamps, independent episodes, duplicate behavior,
and registered-source isolation. Alert
explanations now expose exact score components, false-positive factors, claim
boundaries, prioritized checks, related evidence, source identity, and case
trace. Assistant follow-ups consume this bounded evidence without changing
the selected alert context.

This improves controlled reliability but does not close the independent
supervised evidence gate. Supervised lifecycle remains `shadow_observation`,
rules remain alert-authoritative, Gemini remains a read-only explanation
layer, and automatic response and real blocking remain disabled.
