# v3.56 SOC Queue Diagnostic Integration

## Status

Implemented as a dashboard/API visibility improvement. It does not activate a model, write a model artifact, create labels, retrain, tune thresholds, enable automatic response, or enable real firewall blocking.

## Purpose

v3.55 showed that exact downstream severity targets remain unstable, but a binary SOC review-queue target is stable across the standard validation split suite. v3.56 makes that result visible in ML Governance as a diagnostic candidate so analysts can understand the safer supervised-learning direction.

## What Changed

- `/api/dashboard/validation-summary` now includes `v355_soc_queue` when `ml_baseline_reviews/v3_55_severity_target_policy_reframing_latest.json` exists.
- ML Governance now shows a compact **SOC Review Queue Diagnostic** panel.
- The panel separates the stable queue candidate from exact severity classification.
- The panel states that exact severity remains explanation/ranking only.
- Safety fields remain explicit:
  - `production_promoted=false`
  - `model_activated=false`
  - `model_artifact_written=false`
  - `labels_written=false`
  - `response_automation_allowed=false`

## Current v3.55 Queue Result

Latest local diagnostic:

- Best strategy: `binary_review_queue_queue_only`
- Passing splits: `5/5`
- Queue F1 minimum: `0.9725`
- Queue recall minimum: `0.948`
- Queue precision minimum: `0.9907`
- Benign-like FPR maximum: `0.04`
- Calibration status: `passed`
- Readiness: `candidate_only`

## Interpretation

The supervised model is safer as a SOC queue assistant than as an exact severity classifier right now.

Recommended use:

- Use queue score as diagnostic decision support.
- Keep exact severity as explanation/ranking only.
- Continue using rule/hybrid evidence and analyst review for final triage.

## What Did Not Change

- No active supervised model was replaced.
- No generated diagnostic model was promoted.
- No response automation was enabled.
- No labels were created or modified.
- No database migration was added.

## Next Recommended Phase

v3.57 should evaluate how the stable queue diagnostic can be compared against rule/hybrid alert explanations on recent alerts, still without activation. The goal is to improve analyst-facing explanations and identify where queue diagnostics agree or disagree with rules.
