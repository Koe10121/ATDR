# ATDR Current AI And ML Product Status

Date: 2026-08-31

ATDR uses several distinct AI/ML layers. They must not be presented as one
autonomous model. Deterministic rules detect explainable patterns, an
IsolationForest can add anomaly evidence, supervised models remain governed
decision-support candidates, and Gemini may summarize bounded ATDR evidence for
an analyst. None of these layers may execute a response action.

## Current Governed Decision: v5.49b

The immutable combined protocol bound 180 genuine protected decisions with
support `95/39/27`, was claimed before evaluation-label access, and was
consumed exactly once. All eight fixed strategies ran and no candidate
qualified. The 11-row evaluation role contained nine benign-like rows, zero
suspicious rows, and two malicious rows; suspicious recall was therefore not
measurable, and every strategy exceeded the fixed `0.15` confidence-gap limit.
The result cannot be rerun, repartitioned, or tuned.

No active artifact was written, activated, or promoted. Rules remain
alert-authoritative, supervised lifecycle remains `shadow_observation`, and
response automation remains disabled. See
`docs/V5_49B_IMMUTABLE_COMBINED_PROTOCOL_AND_ONE_SHOT_REVALIDATION.md`.

## Historical v5.42 Candidate Freeze Decision

The latest development-only comparison used 1,467 rows, exactly five
predeclared strategies, three duplicate-isolated nested temporal folds, fixed
threshold profiles, and dedicated calibration/threshold roles. Hierarchical
two-stage is the best diagnostic ranking, not an accepted candidate: it passes
`0/3` folds, has threat recall `0.1000-0.5828`, suspicious recall
`0.0719-0.5164`, malicious recall `0.0000-0.9259`, ECE `0.1862-0.5054`, and
queue-rate spread `0.3702`. No artifact was frozen, activated, or promoted.

The authenticated aggregate status is
`GET /api/evidence-review/candidate-freeze/status`. See
`docs/V5_42_DEVELOPMENT_CANDIDATE_FREEZE_READINESS.md`.

## Status At A Glance

| Layer | Current role | Current status | Authority |
| --- | --- | --- | --- |
| Deterministic detection rules | Primary explainable alert generation | v5.31 adversarial lock: 27/27 synthetic cases; 19-rule catalog contract reconciled | May create/deduplicate alerts; cannot execute response |
| IsolationForest | Assistive unusual-behavior score | v5.5 audit and v5.13 regression: advisory only; controlled anomaly layer remains 72/72 | Decision support only; cannot create an alert by itself |
| Supervised SOC queue | Rank/recommend review from labeled evidence | v5.49b evaluated eight fixed strategies once and selected no candidate; lifecycle remains `shadow_observation` | Evidence only; rules remain authoritative |
| Legacy supervised artifact | Unselected local reference | Artifact exists; model/feature metadata are incomplete and must not be guessed | Not selected by the governed lifecycle |
| SOC Assistant deterministic layer | Retrieve and explain ATDR evidence | 20/20 controlled QA questions passed | Read-only |
| Gemini provider layer | Rephrase/summarize bounded evidence | Private adapter configuration and bounded controlled acceptance passed; institutional privacy/operations approval remains open | Explanation only; no detector or action authority |

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

Secret-safe provider checks and bounded controlled suites have validated the
configured Gemini adapter with IP redaction enabled, raw-log context disabled,
structured output, citation filtering, safe fallback, and no authoritative
mutations. These checks prove bounded adapter behavior only; they are not an
institutional privacy approval, availability guarantee, quota/cost guarantee,
or production-service certification.

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
threshold analysis, and a governed model registry. No current supervised
candidate qualifies for activation or promotion. Registry artifacts with
incomplete metadata are historical references and must not be described as a
known active model family. The governed lifecycle remains
`shadow_observation` without alert or response authority.

The v4.0 provider-blinded CSE-CIC-IDS2018 evaluation exposed the key blocker:
the frozen internal queue did not generalize to a provider-flow schema lacking
firewall fields such as application, action, zones, source port, and source
behavior context. It produced threat precision `0.3171`, recall `1.0000`, F1
`0.4815`, benign-like FPR `1.0000`, Brier `0.6538`, and ECE `0.6614`.

v4.1 added explicit schema contracts and missingness-aware development
experiments. It found useful pooled diagnostic signals, but calibration and
source/time/schema-held-out transfer remained unstable. Those historical
results remain useful diagnostic evidence. The later v5.49b one-shot decision
is now authoritative for current candidate status. Therefore:

- no current candidate is selected;
- lifecycle remains `shadow_observation`;
- `production_promoted=false`;
- no historical candidate is selected by the governed lifecycle;
- `response_automation_allowed=false`; and
- any future activation review requires fresh development evidence, a second
  physical source, a separately governed untouched future benchmark, stable
  calibration, and explicit human approval.

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

## v5.32 Analyst Workflow Projection

The React Overview now presents governed operational counts for primary rule
alerts, distinct source-linked alerts, analyst dispositions, grouped
occurrences, deduplication updates, parser context, and recent detection runs.
This projection changes no detector, score, threshold, feature, label, model,
or lifecycle state.

Operational counts are explicitly not accuracy. The panel reports
`Insufficient Evidence` until independent labeled validation supports a
quality claim. AI Governance remains the source of truth for supervised
evidence and continues to report `shadow_observation` with no production
promotion.

Assistant acceptance confirms context replacement/reset, navigation
persistence, concise intent-specific responses, trusted citations, truthful
Gemini versus deterministic fallback labels, IP redaction, raw-log exclusion,
and zero authoritative mutations. Gemini remains read-only decision support;
rules remain alert-authoritative; automatic response and real blocking remain
disabled.

## v5.33 Independent Evidence And Human Acceptance

The existing 40-row native PAN-OS blind pack remains sealed and prediction-
blind. Prediction-before-label, unique-token, exact-overlap, near-overlap, and
evidence-role checks pass. The larger private native corpus still provides
773,551 parsed rows and 22 chronological windows, but it does not provide
human ground truth or a second verified physical device. Legitimate blind
human decisions remain `0/40`, so final detection metrics are withheld.

The Assistant now has a separate eight-question human acceptance worksheet
covering alert, log, source, case, investigation, ML governance, and safe-
response contexts. A bounded Gemini run used seven provider answers and one
safe deterministic fallback. One Gemini investigation brief exceeded the
current concision acceptance rule; the ML-governance fallback passed its
automated contract.
Raw logs and IPs were excluded, protected worksheet content passed integrity,
and configured authoritative mutation counts stayed at zero. Human Assistant
acceptance remains `0/8`; automated checks are not human approval.

Lifecycle remains `shadow_observation`. Rules remain alert-authoritative,
IsolationForest and supervised ML remain advisory, Gemini remains read-only,
and model promotion, automatic response, and real firewall blocking remain
disabled. See `docs/V5_33_INDEPENDENT_DETECTION_AND_ASSISTANT_ACCEPTANCE.md`.

## v5.34 Assistant Reliability Decision

The provider/local response pipeline now shares one compact presentation
contract. Alert explanations remain under 120 words, investigation briefs are
limited to 160 words, case handoffs have a dedicated 120-word mode, duplicate
evidence is removed, and citations survive final rendering. The refreshed
eight-case pack passes `8/8` automated answer contracts; human acceptance is
still `0/8`.

Provider availability is now evaluated separately from answer quality. The
latest bounded run accepted one Gemini answer, recorded three quota outcomes,
and used the circuit breaker for four later questions. All fallback answers
remained grounded and within contract. Safe telemetry records only category,
latency, and token aggregates; it stores no prompt, answer, raw log, IP,
provider payload, or secret.

Final v5.34 verification passes the full backend and release suites at
`890 passed, 1 skipped`, Playwright at `31 passed, 1 skipped`, controlled
detection at `24/24`, layered detection at `288/288`, and deterministic
Assistant QA at `20/20`. The existing cold large-SQLite Overview advisory
remains open; the cached path measured `0.0197s`.

Gemini quota is therefore an open provider-operations issue, not a reason to
claim that the local fallback failed. Rules remain alert-authoritative,
supervised lifecycle remains `shadow_observation`, the Assistant remains
read-only, and model promotion, automatic response, and real blocking remain
disabled. See
`docs/V5_34_SOC_ASSISTANT_CONCISION_AND_PROVIDER_RELIABILITY.md`.

## v5.36 Independent Evidence And Activation Decision

v5.36 provides the canonical current lifecycle decision. The sealed native
pack passes custody, checksum, identity, duplicate, provenance, schema, and
prediction-before-label checks, but legitimate human review remains `0/40`.
Frozen rule, IsolationForest, supervised, and hybrid quality metrics are
therefore withheld.

The registered calibrated ExtraTrees artifact remains available for read-only
shadow scoring. Its configured-data diagnostic reports queue F1 `0.6203`, FPR
`0.1167`, suspicious recall `0.3511`, malicious recall `0.6452`, and ECE
`0.2101`. These rows represent one source/day and training overlap cannot be
excluded, so the values are not activation evidence.

Only `3/9` evidence gates pass and `0/7` blind quality gates are evaluable.
Lifecycle remains `shadow_observation`; no model is activated or promoted and
rules remain alert-authoritative. Automatic response and real blocking remain
disabled.

The bounded live Gemini audit passes `12/12` automated contracts across six
redacted calls with no raw logs, IPs, secrets, or configured mutations. Human
Assistant acceptance remains `0/8`. Provider quota introspection, cost rates,
key rotation, privacy, and retention approval remain external. See
`docs/V5_36_INDEPENDENT_EVIDENCE_ACTIVATION_DECISION.md`.

## v5.39 Frozen Evidence Decision

v5.39 makes the evidence-to-decision handoff explicit and at-most-once. The
dashboard and authenticated status API now distinguish rows completed from
workspaces formally closed. After both protected reviews close, the evaluator
stores private pack/decision digests, claims one attempt, and calls the fixed
v5.36 audit without provider execution or authoritative writes. Completed
results are reused; interrupted, failed, or tampered evidence fails closed.

The genuine protected reviews are complete and closed at detection `40/40`
and Assistant `8/8`. The frozen evaluator ran exactly once, persisted only
private digests and a sanitized result, and now reuses that result without
recalculation. No reviewer decision was generated automatically. The retired
v5.36 CLI reports readiness only; v5.39 remains the sole operator evaluation
path.

Assistant human acceptance passes at `0.875` (`7` accept, `1` revise, no
reject), with all eight fixed dimension averages at least `4.0`. The frozen
supervised candidate reaches queue precision `0.7500`, recall `0.4500`, F1
`0.5625`, benign-like FPR `0.1500`, suspicious recall `1.0000`, malicious
recall `1.0000`, and weak calibration with ECE `0.3220`. It fails the fixed
activation decision because comparable-row/class support, independent source
and time-window evidence, independently excluded training overlap, queue F1,
threat recall, FPR, and calibration requirements are not all satisfied.

Lifecycle remains `shadow_observation`. Rules remain alert-authoritative,
supervised and IsolationForest outputs remain advisory, Gemini remains
read-only, and model promotion, response automation, and real blocking remain
disabled. See
`docs/V5_39_INDEPENDENT_EVIDENCE_AND_ACTIVATION_DECISION.md`.

## v5.40 Development-Only Supervised Repair

v5.40 permanently separates the consumed v5.39 decision from new development
work. The evaluator validates the private freeze and sealed pack, reads only
the 40 review tokens needed for exclusion, and reports that protected labels,
predictions, and errors were not opened. No v5.39 result is used for fit,
calibration, threshold selection, model selection, or error analysis.

The canonical development pool contains 1,467 rows: 918 manual and 549
assisted/weak. It has one source identity, 155 multirow duplicate groups with
421 affected rows, and a short concentrated time range. Duplicate families
are isolated between nested temporal roles and assisted provenance is
down-weighted without being relabeled as human evidence.

Six strategies were compared with dedicated calibration and fixed threshold
profiles. Hierarchical two-stage ranks first diagnostically, with queue F1
`0.1786-0.7068`, benign-like FPR `0.0120-0.1176`, suspicious recall
`0.0719-0.5164`, and malicious recall `0.0000-0.9259` across three nested
folds. It passes `0/3` complete development gates. Sigmoid calibration remains
weak: ECE `0.1862-0.5054` and maximum confidence/accuracy gap
`0.3454-0.9015`.

No candidate configuration is frozen, no model artifact is written, and no
model is activated or promoted. A new blind protocol is designed but not
collected; it requires future evidence from at least two independent real
sources and three windows, hidden predictions, genuine human review, and one
fixed evaluation. Lifecycle remains `shadow_observation`, rules remain
alert-authoritative, and response automation and real blocking remain
disabled. See `docs/V5_40_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`.

## v5.43 Decision Update

ATDR tested five fixed development-only repairs without opening consumed or
blind evidence. Temporal/provenance-balanced weighting ranked first but passed
`0/3` folds: minimum queue F1 is `0.4053`, maximum benign-like FPR `0.4458`,
minimum suspicious recall `0.1895`, minimum malicious recall `0.1429`, maximum
ECE `0.5019`, and queue spread `0.2641`.

Feature ablation confirms material chronology shift in application,
evidence-family, byte-volume, source-diversity, and scan-pressure signals. The
current development evidence still represents one source over about three
minutes, with 549 assisted/weak rows and 421 duplicate-family rows. No repair
can turn that evidence into independent temporal validation.

No candidate was frozen and no model or response authority changed. Five
supervised phases remain: stable development freeze, two-source/three-window
future collection, genuine blind review, one frozen evaluation, and separate
governance/shadow acceptance. Rules remain alert-authoritative.

## v5.41 Governed Blind Evidence Acquisition

v5.41 turns the future evidence protocol into a fail-closed operator workflow.
It revalidates the consumed v5.39 pack and v5.40 development cutoff, processes
candidate files only in disposable storage, requires genuine human physical-
source attestation, contains exact/near duplicate families, and exposes only
aggregate readiness through the authenticated evidence-review API and AI
Governance page.

The existing private PAN-OS file parsed 773,551/773,551 rows with no parser
failure and complete TRAFFIC/THREAT schemas. It also overlapped 120,000
configured rows, 1,273 v5.40 exact rows, and 1,619 v5.40 near families. It is
therefore rehearsal-only and cannot be relabeled as fresh blind evidence. The
configured database, labels, model runs, detection runs, alerts, response
actions, and model artifacts remained unchanged.

Current status is `Designed`: `0/2` qualifying independent sources, `0/3`
qualifying windows, and `0/240` qualifying review rows. No prediction seal or
review CSV was created because the evidence gate is incomplete and v5.40
froze no candidate. The implemented future pack contains no predictions,
scores, suggestions, fingerprints, raw logs, or IP columns; protected content
is custody-bound and genuine human confirmation is mandatory.

Four phases remain before supervised shadow activation can be considered:
future evidence acquisition, human blind review, one frozen one-shot
evaluation, and a separate governance/shadow-observation decision. The first
two require real devices and humans. See
`docs/V5_41_GOVERNED_BLIND_EVIDENCE_ACQUISITION.md`.

## v5.44 Decision Update

v5.44 converts the complete private PAN-OS history into a custody-locked,
development-only evidence population without importing it into the configured
database. All v5.39-v5.43 boundaries pass. The parser succeeds on all 773,551
rows; 120,626 rows are quarantined, 540,921 remain in three development roles,
and 112,004 newest rows remain sealed for future validation.

Assisted coverage contains 360,886 high-confidence representative groups and
133,373 ambiguous represented events. These are weak/assisted labels, not
human ground truth. The optional 200-row pack requires human confirmation and
is not import-ready. Existing governed anchors remain 918 manual/reviewed plus
549 assisted/weak rows.

The evidence is sufficient for another development-only repair run, but not
for candidate freeze, independent validation, or activation. It still
represents one genuine device. IsolationForest remains advisory because its
sampled FPR is `0.0056` while queue recall is also `0.0056` and malicious
recall is `0.0000`.

Lifecycle remains `shadow_observation`; no model/artifact/label/alert/run/
response state changed. Rules remain alert-authoritative; automatic response
and real blocking remain disabled. Five supervised phases remain.

## v5.45 Decision Update

v5.45 reruns development-only repair over the eligible v5.44 fit,
calibration, and threshold roles. It compares eight supervised strategies,
uses manual-anchor aggregate weight caps, keeps future labels sealed, and
applies unchanged v5.42 gates.

The label-blind custody audit found broader candidate-near families crossing
v5.44 role boundaries. Disposable containment quarantined 62,961 families and
407,689 represented events, including 65,580 future events, without opening
their labels. Cross-role candidate-near count is zero after containment. This
qualifies v5.44's earlier exact/propagation-family isolation claim.

Calibrated flat five-class ExtraTrees is the diagnostic leader, but passes
`0/3` mandatory views. On the manual-anchor holdout, F1 is `0.7855`, FPR
`0.1290`, suspicious recall `0.5175`, malicious recall `0.8537`, ECE `0.3232`,
and maximum confidence/accuracy gap `0.5737`. Assisted-cohort results are much
stronger, so they cannot be treated as independent field accuracy.

IsolationForest also fails reliability gates and remains advisory. No recipe
or active artifact was frozen; no label, model run, alert, detection run, or
response was created. Lifecycle stays `shadow_observation`, rules remain
alert-authoritative, and five supervised phases remain.

## v5.46 Decision Update

v5.46 tests manual-anchor transfer directly using runtime-derived context,
manual-prioritized/provenance-balanced weighting, sigmoid and isotonic
calibration, class/global thresholds, eight model variants, and one
conservative ensemble. It uses only v5.44 development roles and leaves future
labels sealed.

Aggregate diagnosis confirms material manual-versus-assisted shifts in label,
application, schema, and residual-pattern distributions. Hierarchical
two-stage transfer ranks first diagnostically but passes `0/3` views. Its
manual-anchor F1 is `0.5552`, FPR `0.1935`, suspicious recall `0.0614`,
malicious recall `0.8537`, ECE `0.2381`, and confidence gap `0.7455`.

The transfer is worse than v5.45 on F1 and suspicious recall. No recipe or
artifact is frozen, activated, or promoted. IsolationForest remains advisory;
rules remain alert-authoritative; response automation and real blocking remain
disabled. Five supervised phases remain, beginning with new prediction-blind
human anchors and broader genuine source evidence rather than another tuning
pass over the same cohorts.

## v5.47 Decision Update

v5.47 converts the v5.46 evidence recommendation into a governed human-review
workspace. A disposable run over the private PAN-OS evidence selected 120
unique development-only families across seven error/control strata. It
excluded 18,994 duplicate, 44,741 reserved-role, and 706 existing
manual-anchor families. Reserved-future rows selected: `0`.

The sealed pack contains no predictions, model scores, assisted labels, raw
logs, IPs, source identities, private paths, or fingerprints. The editable
copy is not import-ready. Human progress remains honestly `0/120`; an
automated assistant or model cannot satisfy the reviewer contract.

No configured database row, label, model run, detection run, alert, response
action, protected workspace, or active artifact changed. Rules remain
alert-authoritative, lifecycle remains `shadow_observation`, and response
automation and real blocking remain disabled. The next gate is genuine review
completion and fixed development revalidation; a second real source remains
required before activation evidence can be considered independent.

## v5.48 Decision Update

v5.48 adds the protected row-level workflow needed to complete the sealed
v5.47 development review without exposing predictions or private evidence. The
first authenticated human reviewer owns the workspace; stale revisions,
cross-user access, automated reviewer identities, incomplete closure,
post-closure edits, and protocol/state tamper fail closed.

The development protocol was locked before any decision. It fixes three
eligible evidence roles, deterministic calibration/threshold/evaluation
partitions, the feature schema, eight candidate strategies, and unchanged
v5.42 gates. The review later closed at `120/120`, but support `92/9/0` failed
the suspicious and malicious preconditions. Its execution count remains `0`;
the original protocol was never consumed.

No label was imported, no model or recipe was activated or promoted, and no
detection run, alert, or response action was created. Lifecycle remains
`shadow_observation`; rules remain alert-authoritative; response automation
and real blocking remain disabled. Genuine review, a second real source, and
later untouched independent evaluation are still required.

## v5.49 Decision Update

v5.49 has not run the fixed development evaluation. The immutable protocol is
valid and still contains eight strategies. Authoritative review evidence is
now `120/120`, invalid `0`, and formally closed, but honest support is
benign-like `92`, suspicious `9`, and malicious `0`. The fixed class-support
preconditions fail, so no supervised candidate or new metric may be claimed.

The runner now protects its single execution with an atomic private claim, and
the read-only v5.49 decision CLI is ready to validate all eight aggregate
strategy outcomes and reject any changed gate, inconsistent leader, or
authority mutation. The real claim and result remain absent and execution
count remains `0`.
Lifecycle remains `shadow_observation`; rules remain alert-authoritative;
active model state, automatic response, and real blocking remain unchanged.

## v5.49a Decision Update

v5.49a preserved the closed v5.48 review and prepared a separate
prediction-blind 60-row workspace from disposable private-source processing.
The pack contains 57 threat-enriched rows and three hard-negative controls
across nine evidence strata. It excludes original anchors, prior manual
families, duplicate groups, and locked/reserved evidence roles. Supervised
predictions and assisted labels were not used for selection or display.

The genuine review is complete at `60/60`, invalid `0`, and immutable. Its
support is `3/30/27`, producing combined support `95/39/27`. The fixed minimums
therefore passed and a private v5.49b proposal was created. v5.49a itself
performed no evaluation or authoritative write.

## v5.49b Decision Update

v5.49b bound both immutable reviews to a newly versioned fixed protocol and
consumed it exactly once. All eight locked strategies ran. The configured
database retained exactly `145,232` raw logs, `145,232` normalized logs,
`3,231` alerts, `2,672` labels, `45` model runs, `31` detection runs, and `0`
response actions before and after evaluation.

No candidate qualified. The fixed evaluation role contains 11 rows: nine
benign-like, zero suspicious, and two malicious. Several strategies score
queue F1 `1.0000` and FPR `0.0000` on that narrow role, but suspicious recall
is not measurable and every confidence gap exceeds the fixed `0.15` maximum.
The strongest binary variants have ECE `0.0977` and confidence gap `0.2720`.
These metrics cannot justify selection, especially because the supplemental
evidence was threat-enriched and is not a field-prevalence sample.

The stored result is immutable and must not be rerun or used for tuning.
Lifecycle remains `shadow_observation`; rules remain alert-authoritative;
model activation/promotion, automatic response, and real blocking remain
disabled. The next model cycle requires fresh development evidence, a
predeclared support-preserving partition, a second physical source, and a new
untouched future evaluation.

## v5.51 Detection Field Qualification Update

The next supervised evidence namespace is now implemented without opening or
reusing v5.49b. It accepts only attested post-boundary physical collections,
removes exact duplicates, contains near-duplicate families within one role,
and fixes development-fit, calibration, threshold, and untouched-future roles.
The future role remains label-closed and no model work occurs in v5.51.

Local parser/rule tooling passes, but aggregate readiness is
`hardware_required`. Field rule precision/recall/F1/FPR are intentionally
unavailable until a complete prediction-blind human review exists. No candidate
is selected; lifecycle remains `shadow_observation`; rules remain authoritative;
model activation/promotion and automatic response remain false.

## v5.52 SOC Assistant Closure Update

The deterministic Assistant remains the grounding and fallback layer. Each
answer now carries explicit provenance: deterministic or external synthesis,
safe evidence scopes, citation count, rules-authoritative status, advisory-ML
status, and raw-log exclusion. Gemini never becomes a detector or database
source.

Context continuity is primary-entity based. Alert, log, source, and case IDs
require typed wording; related citations do not hijack active context; reset or
explicit entity switches start a clean conversation; and only four sanitized
tab-scoped turns persist across navigation.

Controlled QA passes `20/20`, required citations pass `1.0000`, average answer
length is `60.9` words, maximum is `110`, and every intent budget passes. The
configured Gemini minimal probe and full synthetic Assistant path both pass
with structured output, redaction enabled, raw logs excluded, secrets hidden,
and zero label/model/detection/response writes. Institutional privacy, quota,
billing, rotation, and real-traffic operational acceptance remain external.
