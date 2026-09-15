# v3.58 Queue/Evidence Agreement Visibility

## Summary

v3.58 exposes the v3.57 queue-vs-rule/hybrid agreement diagnostic in places analysts already use:

- ML Governance shows the latest v3.57 agreement summary as a compact diagnostic card.
- The SOC Assistant can answer questions about whether the ML review queue agrees with rule, anomaly, and hybrid evidence.
- The dashboard API returns only aggregate, safe v3.57 fields from the latest ignored diagnostic JSON report.

This phase does not change detection behavior, model thresholds, labels, response controls, or active model artifacts.

## Source Evidence

- Backend API summary: `atdr/app/routers/dashboard.py`
- Assistant answer path: `atdr/app/services/assistant_service.py`
- Frontend types: `frontend/src/types/api.ts`
- ML Governance UI: `frontend/src/pages/MLGovernance.tsx`
- Backend tests: `atdr/tests/test_api.py`, `atdr/tests/test_assistant.py`
- Frontend smoke tests: `frontend/tests/smoke.spec.ts`
- Source diagnostic: `ml_baseline_reviews/v3_57_queue_rule_hybrid_agreement_latest.json`

## Behavior

The ML Governance panel now shows:

- passing validation split count
- minimum queue F1
- maximum queue false-positive rate
- minimum queue/evidence agreement rate
- evidence-only disagreement count
- queue-only disagreement count
- diagnostic readiness
- top disagreement patterns in a collapsible details section

The SOC Assistant can answer questions such as:

- "Does the ML queue agree with rule evidence?"
- "Does the model agree with hybrid evidence?"
- "What are the queue/evidence disagreements?"

Answers remain deterministic and read-only. They cite the v3.57 diagnostic report and supporting docs.

## Safety

- Production promoted: false
- Model activated: false
- Active model artifact written: false
- Labels written: false
- Raw logs included: false
- Response automation allowed: false
- Real firewall blocking: false

## Current Interpretation

The v3.57 result is useful for analyst decision support, but it remains diagnostic-only. The binary SOC review queue is strong, yet evidence-only disagreements remain reviewable, especially in one grouped/source-aware split.

## Remaining Work

- Add deeper drilldown from aggregate disagreement patterns to specific redacted examples if needed.
- Use agreement categories to improve alert explanations and assistant triage language.
- Keep validating with real or simulated source data before any production-like claims.
