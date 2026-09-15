# T1-T20 Change Document: v3.57 Queue-vs-Rule/Hybrid Agreement Diagnostic

## T1 Change Title

v3.57 Queue-vs-Rule/Hybrid Agreement Diagnostic

## T2 Requirement

Compare the stable binary SOC review-queue diagnostic against deterministic rule/anomaly/hybrid evidence without activating a model, writing labels, or enabling response automation.

## T3 Source Evidence

- `atdr/app/detection/v355_severity_target_policy_reframing.py`
- `atdr/app/detection/v353_severity_feature_repair.py`
- `atdr/app/detection/v337_evidence_feature_enrichment.py`
- `atdr/app/detection/v348_repaired_queue_target_model.py`
- `docs/V3_56_SOC_QUEUE_DIAGNOSTIC_INTEGRATION.md`

## T4 Current Behavior

The dashboard can show the stable v3.55 binary SOC review-queue diagnostic. It does not yet explain where that queue decision agrees or disagrees with rule/anomaly/hybrid evidence.

## T5 Impacted Areas / Agents

- Detection / AI-ML Governance
- QA
- Documentation

No runtime detection behavior, database schema, frontend UI, response logic, or authentication behavior changes.

## T6 Scope

In scope:

- Diagnostic-only in-memory queue/evidence comparison.
- Ignored Markdown/JSON reports under `ml_baseline_reviews/`.
- Focused backend tests.
- Progress and traceability docs.

Out of scope:

- Model activation or promotion.
- Active artifact writing.
- Label creation/update.
- Automatic response.
- Real firewall blocking.
- Dashboard integration.

## T7 Functional Requirements

- Evaluate standard split modes.
- Train queue model in memory using existing v3.55/v3.48 helpers.
- Select thresholds on train-internal calibration only.
- Compare queue prediction with deterministic evidence decision.
- Report agreement categories and top disagreement patterns.
- Redact IP examples and exclude raw logs.

## T8 Acceptance Criteria

- Diagnostic returns `ok=true`.
- Safety fields show no labels/model runs/response actions were created.
- Report includes queue/evidence agreement categories.
- Threshold report does not expose large training/calibration index arrays.
- Tests prove no side effects.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No database migration.

## T11 Backend Plan / Changes

- Added `atdr/app/detection/v357_queue_rule_hybrid_agreement.py`.
- Added `atdr/scripts/run_v357_queue_rule_hybrid_agreement.py`.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

- Diagnostic-only.
- No model activation.
- No response actions.
- No automatic response.
- No raw logs in report examples.
- IP values are redacted in examples.

## T14 Test Plan

- Evidence snapshot behavior.
- Agreement category behavior.
- Full diagnostic no-side-effect behavior.
- Threshold output does not include raw fit/calibration index arrays.

## T15 Implementation Summary

Implemented queue-vs-evidence comparison across standard splits with aggregate readiness, disagreement patterns, and ignored output reports.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\ruff.exe check atdr\app\detection\v357_queue_rule_hybrid_agreement.py atdr\scripts\run_v357_queue_rule_hybrid_agreement.py atdr\tests\test_v357_queue_rule_hybrid_agreement.py`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v357_queue_rule_hybrid_agreement.py -q --basetemp .pytest_tmp\v357 -p no:cacheprovider`
- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v357_queue_rule_hybrid_agreement --test-size 0.3 --min-samples 6`

## T17 PRD / Docs Updated

- `docs/V3_57_QUEUE_RULE_HYBRID_AGREEMENT.md`
- `docs/changes/T1_T20_V3_57_QUEUE_RULE_HYBRID_AGREEMENT.md`
- `docs/tasks/tasklist-progress.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/AI-DOCS-INDEX.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Evidence-only disagreement remains above budget for one split, so readiness is `diagnostic_only`.
- Disagreement examples must not be auto-labeled.
- Queue candidate remains decision support only.

## T19 Release / Rollback

Rollback is simple: remove the v3.57 diagnostic module, runner, tests, and docs. No migration or runtime behavior changed.

## T20 Final Handoff

v3.57 adds evidence-grounded diagnostics for the stable SOC review queue. Next recommended phase is to use disagreement categories to improve assistant explanations or add dashboard read-only visibility, still without model activation.
