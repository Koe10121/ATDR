# ATDR Current AI And ML Product Status

Date: 2026-09-03

## Decision Summary

ATDR does not use one autonomous AI model. It combines four deliberately
separate layers:

1. deterministic rules that may create and deduplicate alerts;
2. IsolationForest anomaly scoring that may add advisory evidence;
3. supervised classifiers under a governed `shadow_observation` lifecycle; and
4. a read-only SOC Assistant with deterministic retrieval and optional Gemini
   synthesis.

Only deterministic rules are alert-authoritative. No AI or ML layer can execute
a response action. Automatic response and real firewall blocking are disabled.

## Current Status

| Layer | Status | Authority |
| --- | --- | --- |
| Nineteen deterministic rules | Locally verified: controlled `24/24`, layered `288/288` | May create/deduplicate alerts; cannot execute response |
| IsolationForest | Implemented, but noisy and weak on current evidence | Advisory only |
| Supervised SOC queue | v5.49b selected no candidate; lifecycle `shadow_observation` | Advisory evidence only; no active candidate |
| Legacy supervised artifact | Artifact exists with incomplete model/feature metadata | Unselected reference, not governed current truth |
| Deterministic Assistant | `20/20` QA, citation rate `1.0`, average/max `60.9/110` words | Read-only explanation |
| Gemini Assistant synthesis | Private safe probes pass; institutional acceptance pending | Read-only rephrasing/summarization |

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
- `docs/V5_31_DETECTION_EXPLAINABILITY_ADVERSARIAL_RELIABILITY.md`

## IsolationForest

IsolationForest scores unusual behavior. It is not trained to prove malicious
intent and cannot create an alert by itself. Current controlled audits show
meaningful benign noise and weak threat capture, so ATDR treats it only as
supporting context. The performance smoke currently observes a high anomaly
rate on the configured data; that is another reason not to promote anomaly
scores to alert authority.

## Supervised Model Decision

The immutable v5.49b protocol bound 180 genuine protected decisions with
aggregate class support `95/39/27`. It claimed the fixed evaluation before
label access, executed once, and compared eight locked strategies. No strategy
qualified because the evaluation role lacked suspicious examples and every
strategy failed the fixed confidence-gap gate.

Consequences:

- candidate selected: no;
- model activated or promoted: no;
- active artifact written: no;
- lifecycle: `shadow_observation`;
- rules alert-authoritative: yes;
- response automation allowed: no.

The consumed result cannot be rerun, repartitioned, or tuned. Any future repair
must use newly declared development evidence, followed by a new untouched
future evaluation and a separate activation decision. Protected decisions,
reviewer identities, fingerprints, predictions, and execution claims remain
private.

## Registry Wording

An older artifact can exist even when its metadata is incomplete. The dashboard
must show **Active artifact metadata unknown** and keep it separate from
candidate diagnostic runs. `unknown` is not a classifier family, and the
existence of an artifact is not evidence of production promotion.

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

## Gemini Boundary

When private configuration explicitly enables Gemini, ATDR sends a bounded,
redacted prompt containing the analyst question, deterministic answer, safe
structured context, allowlisted citations, and at most two proposed follow-up
questions. The provider output must satisfy the structured response contract.

Current private checks confirm:

- provider and model configured without exposing the API key;
- minimal provider call succeeded with valid structured output;
- full synthetic chat used Gemini and returned citations;
- IP redaction enabled;
- raw-log context allowed/included: false/false;
- secrets and raw lines exposed: false;
- response actions, detection runs, labels, and model runs changed: `0`.

The provider is not allowed to run detection, alter labels, activate models,
manage users, delete evidence, or execute response actions. If the call fails,
is unsafe, lacks grounding, or violates the response budget, ATDR uses the
deterministic fallback.

These checks prove adapter behavior only. MFU/provider privacy approval,
retention policy, quota/billing ownership, key rotation, service monitoring,
and representative field evaluation remain external.

## Assistant Quality

The controlled 20-question suite passes all intent, citation, unsafe-request,
concision, and no-side-effect checks. Current average/max answer size is
`60.9/110` words, down from the historical `283.8/697` baseline. Contextual
follow-ups preserve one explicit alert, log, source, or case; navigation keeps
only bounded sanitized tab history and logout/reset clears it.

Controlled synthetic QA is not an independent usability study. Human analysts
must still evaluate representative real alerts, clarity, usefulness, and
failure behavior under the approved provider policy.

## Remaining AI/ML Finish Gates

1. Collect independently reviewed evidence from a second physical source and
   a predeclared untouched future window.
2. Repair supervised models only on fresh development roles, then require all
   fixed FPR, recall, calibration, stability, and queue-rate gates.
3. Obtain a separate human activation decision before writing or selecting any
   active artifact.
4. Complete institutional Gemini privacy, retention, cost/quota, monitoring,
   and key-rotation acceptance.
5. Run representative analyst evaluation on real but privacy-approved records.

Until those gates close, the honest state is locally verified decision support,
not autonomous detection, autonomous response, or production-certified AI.
