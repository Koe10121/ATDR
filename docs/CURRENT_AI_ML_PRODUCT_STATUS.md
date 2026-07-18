# ATDR Current AI And ML Product Status

Date: 2026-07-18

ATDR uses several distinct AI/ML layers. They must not be presented as one
autonomous model. Deterministic rules detect explainable patterns, an
IsolationForest can add anomaly evidence, supervised models remain governed
decision-support candidates, and Gemini may summarize bounded ATDR evidence for
an analyst. None of these layers may execute a response action.

## Status At A Glance

| Layer | Current role | Current status | Authority |
| --- | --- | --- | --- |
| Deterministic detection rules | Primary explainable alert generation | Implemented and scenario-tested | May create/deduplicate alerts; cannot execute response |
| IsolationForest | Assistive unusual-behavior score | Implemented, optional, not proof of an attack | Decision support only |
| Supervised SOC queue | Rank/recommend review from labeled evidence | Diagnostic candidates remain `candidate_only` | Not production-promoted or auto-activated |
| Active supervised artifact | Legacy local artifact | Artifact exists; model/feature metadata are unknown | Must not be described as a known promoted model |
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

Rules remain subject to false-positive/false-negative tuning and real-device
validation. Their ATT&CK-style context is an analyst aid, not certified attack
attribution.

## IsolationForest

`atdr/app/detection/ml_detector.py` trains and applies an IsolationForest to
identify unusual events relative to imported data. Its anomaly flag/score can
contribute evidence and hybrid triage, but unusual does not mean malicious. It
is not an independently promoted production detector and cannot authorize a
response.

## Supervised Model Candidates

ATDR supports reviewed-label workflows, candidate comparisons, calibration,
threshold analysis, and a model registry. The current registry contains
diagnostic `candidate_only` runs. A local active artifact also exists, but its
registration metadata is missing; the truthful display is **Active artifact
metadata unknown**, not a guessed classifier family or feature set.

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
- no v4.0/v4.1 candidate is active;
- `response_automation_allowed=false`; and
- model activation requires a separately governed untouched benchmark plus
  independently collected multi-source firewall/syslog evidence.

Source evidence: `docs/V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE_AND_FROZEN_VALIDATION.md`,
`docs/V4_1_SCHEMA_AWARE_SOC_QUEUE_MODEL_REDESIGN.md`,
`atdr/app/detection/schema_contracts.py`,
`atdr/app/detection/v401_schema_aware_soc_queue.py`, and
`atdr/app/detection/supervised_workflow.py`.

## Remaining Product Gates

1. Independently collect and review multi-source real firewall/syslog evidence.
2. Evaluate one untouched external benchmark under a schema-compatible,
   prediction-before-label protocol.
3. Pass stability, false-positive, recall, and calibration gates across source
   and time boundaries.
4. Register complete artifact, feature-set, training-data, threshold, and
   provenance metadata before any activation discussion.
5. Complete Gemini privacy approval, key custody/rotation, quota/cost monitoring,
   and real-traffic answer-quality review.
6. Keep response automation and real firewall blocking disabled unless a
   separate approved safety design is implemented and validated.

ATDR is a controlled productization candidate and AI-assisted SOC decision
support system. This status is not a production-readiness or model-accuracy
claim.
