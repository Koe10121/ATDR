# ATDR Current AI And ML Product Status

Date: 2026-09-19

## Decision Summary

ATDR does not use one autonomous AI model. It combines four deliberately
separate layers:

1. deterministic rules that may create and deduplicate alerts;
2. IsolationForest anomaly scoring that may add advisory evidence;
3. supervised classifiers whose governed runtime eligibility is checked and
   currently fails closed as `unqualified`; and
4. a read-only SOC Assistant with deterministic retrieval and optional Gemini
   synthesis.

Only deterministic rules are alert-authoritative. No AI or ML layer can execute
a response action. Automatic response and real firewall blocking are disabled.

## Current Status

| Layer | Status | Authority |
| --- | --- | --- |
| Nineteen deterministic rules | Locally verified: controlled `24/24`, layered `288/288` | May create/deduplicate alerts; cannot execute response |
| IsolationForest | Reproducible; v5.64 window/context audit selected no candidate; current scored-row rate 2.36% at 41.47% coverage | Advisory only; not threat-accuracy validated |
| Supervised SOC queue | v5.62-v5.63-v5.65-v5.67 campaign: `2,000/2,000` rows genuinely, independently reviewed; `5` of `6` fixed gates pass (`threat_positive_rows: 115/100` closed 2026-09-19); effective runtime `unqualified` | `real_source_identities: 1/2` is the sole remaining gate and is structural; no inference or alert authority until a genuinely distinct second physical source exists |
| Legacy supervised artifact | Registered history exists but strict validation is not satisfied | Preserved history only; ordinary prediction refuses it |
| Deterministic Assistant | v5.63.1 QA `30/30` plus context-preserving follow-up; advisor workflow `24/24`; average/max `56.1/110` words | Read-only explanation |
| Gemini Assistant synthesis | v5.63.1 bounded live structured probe passes with raw logs excluded and redaction enabled; institutional acceptance pending | Read-only rephrasing/summarization |

## Detection Rules

Rules operate on normalized source-scoped evidence and preserve an explanation
for each matched condition. The current catalog covers scanning and probing,
authentication-like failures, high-risk service access, suspicious PAN-OS
THREAT records, beaconing-like cadence, flood-like volume, and other bounded
network patterns. Correlation uses source, time, destination, service, action,
and evidence-strength constraints to avoid unsupported claims.

Controlled results establish regression behavior, not production accuracy.
Real FP/FN claims still require prediction-blind human decisions from a second
physical source and untouched future windows.

Primary source:

- `atdr/app/detection/rules.py`
- `atdr/app/services/detection_service.py`
- `atdr/app/detection/explanations.py`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/archive/phases/V5_31_DETECTION_EXPLAINABILITY_ADVERSARIAL_RELIABILITY.md`

## IsolationForest

IsolationForest scores unusual behavior. It is not trained to prove malicious
intent and cannot create an alert by itself. Current controlled audits show
meaningful benign noise and weak threat capture, so ATDR treats it only as
supporting context.

v5.63.1 corrected an important telemetry ambiguity. The configured snapshot
has 145,232 normalized rows, 60,230 scored rows, and 1,421 anomaly flags. The
advisory anomaly rate is therefore 2.36% among scored rows, scoring coverage is
41.47%, and all-row prevalence is 0.98%. The former 0.98 value was a percentage
with an all-row denominator, not a 0.98 fraction and not a 98% anomaly rate.

The v5.60 genuine clean clone intentionally contains no ignored model artifact.
Its rule workflow passes, while runtime status reports IsolationForest
`unavailable` and hybrid `abstained` until a governed local advisory artifact
exists. This is safer than copying a developer artifact or silently training on
unknown evidence. It does not change the authoritative workspace, where the
existing valid artifact remains advisory only.

v5.61 closes the reproducibility gap without changing that decision. The
operator first runs a write-free evidence preflight. Training requires exact
confirmation, occurs against disposable SQLite, and atomically installs only
the configured Git-ignored artifact and sanitized `.bootstrap.json` manifest.
The manifest contains aggregate evidence and governance fields only; it stores
no source path, raw log, IP, fingerprint, identity, or secret.

Normal `setup_team.cmd` and `start_system.cmd` never execute training. Missing
state is reported as **Advisory anomaly model unavailable** with the corrective
preflight command. Governed post-bootstrap state is **Advisory anomaly model
available**, paired with **Threat Accuracy Not Validated** and **Rules
Authoritative**. The existing local pre-v5.61 artifact is left untouched and
is honestly classified as legacy advisory state until deliberately replaced.

### v5.63.1 Reliability Decision

A private-safe, development-only audit created chronological fit,
calibration, and holdout roles in memory and compared eight fixed raw/robust
feature variants at 1%, 2%, 3%, and 5% queue targets. The existing legacy
artifact produced 17.78% controlled benign anomaly rate, 57.14% suspicious
scenario capture, 50.00% malicious scenario capture, and 2.08% private
eligible-holdout queue rate. New variants removed controlled benign flags but
captured at most 28.57% of suspicious scenarios and 50% of malicious scenarios.

No variant passed all fixed gates. No candidate was selected or installed, and
the ignored legacy artifact was not changed. This is an intentional fail-closed
decision: a quiet anomaly model that misses threat scenarios is not an
improvement.

### v5.64 Window-Aware Decision

v5.64 locked 20,000 fit, 7,337 calibration, 7,337 validation, and 7,317
untouched-holdout rows after quarantining 457 cross-role duplicate-family
rows. It compared eight declared global, robust, chronological, cohort,
context, OOD, and ensemble strategies at 1%, 2%, 3%, and 5% fixed queue
targets; seven were methodologically distinct (an initial dispatch defect
made the empirical-calibration strategy duplicate the robust-global one, now
fixed and disclosed via `duplicate_of_strategy` with no effect on any gate,
ranking, or reported number).

The best nonqualified ensemble produced 0% controlled benign anomaly, 85.71%
suspicious scenario capture, 50% malicious scenario capture, a 2.75% private
validation queue, and a 1.26 percentage-point four-window range. It missed two
C2-like scenarios and failed the unchanged 75% malicious gate. Of 202 queued
validation rows, 200 already had deterministic rule evidence.

No candidate passed validation, so none was frozen and the untouched candidate
holdout remained unused. No artifact was written or changed. Further threshold
tuning on this one-source unlabeled evidence is not justified.

## Supervised Model Decision

The immutable v5.49b protocol bound 180 genuine protected decisions with
aggregate class support `95/39/27`. It claimed the fixed evaluation before
label access, executed once, and compared eight locked strategies. No strategy
qualified because the evaluation role lacked suspicious examples and every
strategy failed the fixed confidence-gap gate.

Consequences under the v5.58 effective runtime contract:

- candidate selected: no;
- model activated or promoted: no;
- active artifact written: no;
- historical lifecycle: `shadow_observation`;
- effective runtime: `unqualified`;
- normal supervised inference: refused;
- rules alert-authoritative: yes;
- response automation allowed: no.

The consumed result cannot be rerun, repartitioned, or tuned. Any future repair
must use newly declared development evidence, followed by a new untouched
future evaluation and a separate activation decision. Protected decisions,
reviewer identities, fingerprints, predictions, and execution claims remain
private.

### v5.62 Fresh Qualification Campaign

v5.62 reconstructs and excludes all 180 consumed review families before
selecting any new evidence. Disposable streaming of private operator evidence
parsed 773,551 records without parser failure, identified 298,963 fresh
eligible rows, rejected 228 overlapping event rows, contained 52,881
near-duplicate rows, and found 19 chronological windows from one physical
source.

The locked 300-row review pack contains 150 development-fit, 60 calibration,
45 threshold-selection, and 45 untouched future-evaluation rows. Review is
currently `0/300`; evaluation labels remain sealed. The eight strategy
contracts, 40-feature schema, and all fixed qualification gates are unchanged.
Development loading is refused until review closure, and evaluation-role rows
are never returned to development code.

This source is useful for development evidence but cannot independently
qualify supervised ML. A second physical source and at least 1,000 comparable
rows remain fixed requirements. Training, evaluation, candidate freeze,
activation, promotion, and active-artifact writing remain false.

### v5.63 Comparable Evidence Expansion

v5.63 preserves the original 300-row pack exactly and adds 700 fresh,
non-overlapping, duplicate-isolated rows from development-safe chronological
roles. The combined selected capacity is now 1,000 rows: 300 original plus 700
supplemental. Supplemental roles are 411 development-fit, 165 calibration, and
124 threshold-selection; no future-evaluation row was added.

The 700 rows are split into seven protected 100-row batches with independent
owner binding, revisions, resumable progress, and immutable closure. Current
review is `0/300` original plus `0/700` supplemental. Selected capacity is not
reviewed evidence, so the 1,000-row qualification gate still reports zero
valid reviewed rows.

The second-source intake CLI is ready and fails closed for a repeated physical
device. Current support remains one verified source and 19 time windows. A
second real device is not fabricated. Training, evaluation, candidate freeze,
activation, promotion, and active-artifact writing remain false.

### v5.62-v5.63 Genuine Review Completion

The project owner independently, blindly hand-reviewed all 1,000 selected
rows (300 original plus 700 supplemental) via the CSV worksheet review tool.
Combined status showed `independent_comparable_rows: 1000/1000` (the 1,000
row floor genuinely met) and `benign_like_rows: 664/100`, but
`threat_positive_rows: 47/100` still failed: real PAN-OS traffic from this
one source is heavily benign-skewed, and the fixed 1,000-row selection
happened to contain only 47 genuine threat-positive decisions.

### v5.65 Extended (Third-Tier) Evidence Expansion

With the 1,000-row pool exhausted, a third append-only tier selected 500
more rows on top of the locked v5.62+v5.63 pack, with coverage-group
selection weighted 3x toward the four categories that had produced 100% of
the threat-positive decisions in the first 1,000 rows
(`vendor_security_context`, `high_activity_context`,
`incomplete_transport_context`, `unknown_transport_context`). The project
owner reviewed all 500 rows genuinely. Result: `threat_positive_rows`
improved to `79/100` — still short. Critically, the real result also
falsified part of the original weighting: `vendor_security_context`
produced zero new threat-positive rows out of 97 sampled from it, meaning
it had only been correlated in the smaller original sample, not actually
predictive.

### v5.67 Signal-Concentrated (Fourth-Tier) Evidence Expansion

Before selecting more rows, the actual per-category threat-positive rate
was computed across all 1,455 development-role rows reviewed so far
(sealed-role rows correctly excluded to match real gate math):
`unknown_transport_context` 14.0%, `incomplete_transport_context` 10.0%,
`high_activity_context` 7.9%, versus `boundary_context` 1.2%,
`vendor_security_context` 0.4%, `routine_service_context`/
`web_transport_context` 0.0%. A fourth append-only tier dropped
`vendor_security_context` from the high-yield set, kept only the three
empirically-confirmed categories, and raised the round-robin weight from 3x
to 5x to restore a similar concentration ratio. The project owner reviewed
all 500 new rows genuinely: 36 were threat-positive, and — confirming the
recalibration worked exactly as intended — all 36 came from the three
targeted categories, zero from the four de-weighted ones.

### Combined Result: 5 Of 6 Fixed Gates Now Pass (2026-09-19)

`2,000/2,000` rows are genuinely, independently, prediction-blind reviewed
across all four tiers (v5.62+v5.63+v5.65+v5.67), each tier `complete: true`.
Combined fixed qualification gates:

| Gate | Observed | Threshold | Status |
| --- | ---: | ---: | --- |
| `independent_human_blind_labels` | 2,000 | 20 | pass |
| `independent_comparable_rows` | 2,000 | 1,000 | pass |
| `benign_like_rows` | 1,183 | 100 | pass |
| `threat_positive_rows` | 115 | 100 | **pass** (closed 2026-09-19; was 47 at the start of the four-tier expansion) |
| `independent_time_windows` | 19 | 2 | pass |
| `real_source_identities` | 1 | 2 | **fail** — structural |

A single-source-only development evaluation (explicitly not the official
qualification decision; sealed role never touched;
`qualification_decision: false` hardcoded in every result) was run against
the full 1,955-row development pool: trained on `development_fit` (766
rows), evaluated on `calibration`+`threshold_selection` (532 rows);
`accuracy 0.857`, `threat_positive recall 0.938` / `precision 0.381`. This
demonstrates real development-only signal on this one source, with the
usual small-sample, high-variance caveats.

### Second-Source Requirement — Final Decision (2026-09-19)

The project owner asked directly whether `real_source_identities: 2` could
be waived or weakened now that every other gate passes and a large amount
of unused source data remains (251,518+ fresh rows still available in the
one physical source's file). The answer is no, and this is now the
project's recorded final decision on this question:

- The gate is not a row-count threshold; it is categorical. No volume of
  additional review of the same one physical device can ever produce a
  second device. A model trained and evaluated on one deployment's traffic
  has no evidence it generalizes to a different network, application mix,
  or attacker population — that is the exact risk `minimum_real_source_identities: 2`
  exists to catch, and more rows from the same source cannot address it.
- A candidate second-source file supplied 2026-09-19 was checked with the
  project's own privacy-safe `--check-second-source` preflight and
  confirmed to be the existing primary source
  (`independent_from_primary: false`, 773,551 rows matching the original
  v5.62 campaign exactly) — it does not satisfy the gate.
- Public firewall-log datasets were investigated as a possible substitute
  and rejected: no public dataset in ATDR's ingest format (PAN-OS
  TRAFFIC/THREAT CSV) exists, the closest candidates are either a different
  vendor's schema (would require a new parser) or a vendor's own synthetic
  demo-data generator (fabricated by design) — neither would be a real
  independent deployment even if format-compatible, and using either would
  not satisfy the gate's intent.
- Explicitly declined: modifying `FIXED_PROMOTION_GATES` (or any other
  mechanism) to report `qualified` without a genuine second source. Doing
  so would produce a false claim of the exact property the gate exists to
  verify, in a codebase whose every governed-evidence module documents that
  these gates cannot be weakened. Supervised ML remains, correctly,
  `unqualified`.

The terminal, honest state: rigorous single-source development evidence
exists (2,000 genuinely reviewed rows, 5/6 fixed gates passing, a measured
development-only signal), and official qualification remains blocked on
exactly one requirement — a genuinely distinct second physical PAN-OS
source — that no further engineering effort against this one source can
satisfy. This is not a partial or failed effort; it is the correct
fail-closed outcome for a governed supervised-ML pipeline that has not yet
been given the evidence it requires.

## Registry Wording

An older artifact can exist even when its metadata is incomplete. The dashboard
must show **Active artifact metadata unknown** and keep it separate from
candidate diagnostic runs. `unknown` is not a classifier family, and the
existence of an artifact is not evidence of production promotion.

## v5.58 Runtime Closure

Normal ML-enabled detection now reports one bounded contract for rules,
IsolationForest, supervised eligibility, hybrid triage, and response. Current
measured local state is:

- rules `active_authoritative`;
- IsolationForest `active_advisory` while its artifact is available;
- supervised `unqualified` because the latest decision selected no candidate;
- hybrid `active_advisory` from available supporting evidence; and
- response `simulation_only`.

The supervised eligibility check runs on each normal ML-enabled detection job,
but model inference runs only for `active_shadow`. Model metadata, provenance,
strict validation, shadow safety, artifact checksum, latest qualified version,
candidate freeze, protected-evidence exclusion, and private configuration must
all pass. Status reads are non-executing. Ordinary alert prediction cannot
silently fall back to the historical artifact.

A development-only repair attempt compared the existing eight governed
strategies using disposable processing and development evidence. Its diagnostic
leader passed `0/3` strict views, no candidate was frozen, and IsolationForest
also failed its reliability gate. This does not alter v5.49b, labels, registry
state, alerts, or response. See the preserved decision at
`docs/archive/phases/V5_58_GOVERNED_HYBRID_DETECTION_RUNTIME.md` and the active
governance summary in `docs/AI_TRAINING_RUNBOOK.md`.

## Where Assistant Answers Come From

The Assistant builds bounded context from ATDR's existing SQLAlchemy services.
Depending on the question, it may retrieve:

- alert detail, rule evidence, why-flagged explanation, and related logs;
- normalized log fields and linked alerts;
- source health and parser-quality summaries;
- ingestion, detection, and operation-job history;
- current ML governance and registry status; or
- approved runbook instructions.

Answers cite API routes, entity IDs, or documentation paths when evidence
exists. Missing evidence is reported as unavailable instead of being invented.
The Assistant does not maintain a separate security database.

Primary source:

- `atdr/app/services/assistant_service.py`
- `atdr/app/services/assistant_llm.py`
- `atdr/app/routers/assistant.py`
- `frontend/src/pages/AssistantPage.tsx`
- `atdr/app/detection/runtime_contract.py`
- `GET /api/ml/runtime-status`

## Gemini Boundary

When private configuration explicitly enables Gemini, ATDR sends a bounded,
redacted prompt containing the analyst question, deterministic answer, safe
structured context, allowlisted citations, and at most two proposed follow-up
questions. The provider output must satisfy the structured response contract.

Current private checks confirm:

- provider and model configured without exposing the API key;
- minimal provider call succeeded in one attempt with valid structured output,
  `2,114 ms` latency, and `824` aggregate tokens;
- full synthetic chat used Gemini in one attempt with `3,720 ms` latency,
  `4,043` aggregate tokens, and six request-allowlisted citations;
- IP redaction enabled;
- raw-log context allowed/included: false/false;
- secrets and raw lines exposed: false;
- response actions, detection runs, labels, and model runs changed: `0`.

The v5.63.1 bounded provider probe also passed with Gemini: provider/model/key
configured booleans were true, structured output was valid, external provider
use was true, raw-log context was false, redaction was true, and secrets were
not exposed. No secret value or provider payload is retained in repository
evidence.

The provider is not allowed to run detection, alter labels, activate models,
manage users, delete evidence, or execute response actions. If the call fails,
is unsafe, lacks grounding, or violates the response budget, ATDR uses the
deterministic fallback.

These checks prove adapter behavior only. MFU/provider privacy approval,
retention policy, quota/billing ownership, key rotation, service monitoring,
and representative field evaluation remain external.

## Assistant Quality

The v5.56 controlled 30-question suite and four-step contextual sequence pass
all relevance, grounding, citation, unsafe-request, concision,
intent-differentiation, continuity, privacy, and no-side-effect checks. Current
average/max answer size is `56.0/110` words, down from the historical
`283.8/697` baseline. Contextual follow-ups preserve one explicit alert, log,
source, or case; navigation keeps only bounded sanitized tab history and
logout/reset clears it.

The v5.57 disposable analyst journey independently exercises alert explanation,
related-log retrieval, alert-specific next steps, case handoff, citations,
auditing, and simulated response after ingestion and rule detection. It passes
`24/24` checks with zero Assistant-created alerts, detection runs, labels,
model runs, or response actions. This is controlled workflow evidence, not a
representative field-traffic quality claim.

Alert reasons now lead with matched evidence, related-log answers preserve
distinct record IDs, next-step answers use alert-specific checks, and source,
job, ML, and workflow questions retain separate response contracts. Provider
content is centrally bounded and Gemini citations are constrained to the exact
ATDR references supplied for that request.

The v5.60 remote-clone journey independently repeated the core investigation
without an LLM key: three intent-specific turns retained alert context, returned
`10/10/3` citations, excluded raw logs, applied redaction, and produced zero
response, label, detection-run, or model-run mutations from the Assistant.

## Assistant Operational Visibility

Authenticated status exposes aggregate request, success, failure, fallback,
latency, named failure, circuit-breaker, token, warning-threshold, and optional
cost-estimate fields. It never stores or returns prompts, answers, keys,
identities, raw logs, or provider payloads. The dashboard shows this provider
health outside the main answer.

These counters are process-local and reset on backend restart. Persistent
quota, cost, and service monitoring remains an approved-host/provider-owner
responsibility rather than a completed production control.

Controlled synthetic QA is not an independent usability study. Human analysts
must still evaluate representative real alerts, clarity, usefulness, and
failure behavior under the approved provider policy.

## Remaining AI/ML Finish Gates

1. ~~Complete the v5.62 protected 300-row review and all seven v5.63 100-row
   supplemental batches without forcing class quotas.~~ **Done 2026-09-19**,
   and extended: all `2,000` rows across four tiers (v5.62+v5.63+v5.65+v5.67)
   are genuinely reviewed; `5` of `6` fixed gates now pass.
2. **The sole remaining blocker.** Collect independently reviewed evidence
   from a genuinely distinct second physical source and preserve a
   predeclared untouched future window. No amount of further review of the
   existing single source can satisfy this; see "Second-Source Requirement
   — Final Decision" above. Waiving or weakening this gate was explicitly
   requested and explicitly declined.
3. Repair supervised models only after the development evidence gates pass,
   then require all
   fixed FPR, recall, calibration, stability, and queue-rate gates.
4. Obtain a separate human activation decision before writing or selecting any
   active artifact.
5. Complete institutional Gemini privacy, retention, cost/quota, monitoring,
   and key-rotation acceptance.
6. Run representative analyst evaluation on real but privacy-approved records.
7. Resume anomaly research only with newly declared evidence or a genuinely
   different sequence representation; v5.64 completed window/context testing
   and rejected all replacements.

IsolationForest bootstrap itself is no longer a Codex-owned implementation
gap. Field accuracy and authority remain evidence questions and must not be
inferred from successful capability bootstrap.

Until those gates close, the honest state is locally verified decision support,
not autonomous detection, autonomous response, or production-certified AI.
