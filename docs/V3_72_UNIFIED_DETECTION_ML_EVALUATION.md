# v3.72 Unified Detection/ML Evaluation

## Status

Implemented and verified as a read-only productization evaluator.

This phase does not change parser behavior, detection thresholds, ML training, model activation, IAM behavior, response behavior, database schema, or dashboard behavior.

## Goal

ATDR had strong individual validators, but the Detection/ML productization path was spread across separate commands and ignored diagnostic artifacts. v3.72 adds one safe command that summarizes the current productization state without mutating data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --pretty
```

Equivalent explicit versioned command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v372_unified_detection_ml_evaluation --pretty
```

Optional controlled scenario validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --include-scenarios --scenario normal_allowed_traffic --scenario port_scan_like_traffic --pretty
```

## Source Evidence

- Rule contract validator: `atdr/scripts/validate_rule_pack_contract.py`
- Unified evaluator: `atdr/app/detection/v372_unified_detection_ml_evaluation.py`
- CLI wrapper: `atdr/scripts/run_v372_unified_detection_ml_evaluation.py`
- Product command alias: `atdr/scripts/evaluate_detection_ml_productization.py`
- Controlled scenario validator: `atdr/scripts/validate_detection_quality.py`
- Supervised output policy artifact reader: `atdr/app/detection/v359_supervised_output_policy_contract.py`
- Safe training target artifact reader: `atdr/app/detection/v362_supervised_training_target_contract.py`
- Rule contract docs: `docs/detection/ATDR_RULE_PACK_CONTRACT.md`
- Scenario contract docs: `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`

Supervisor-template evidence was rechecked from:

- `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\docs\AI-WORKFLOW.md`
- `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\docs\tasks\tasklist-progress.md`
- `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\docs\templates\T1-T20-change-document.md`

The template supplies process discipline and traceability expectations. It does not supply reusable ATDR detection/ML logic.

## What The Evaluator Reports

- Rule-pack and scenario-corpus contract status.
- Optional controlled scenario quality using a temporary SQLite database.
- Latest supervised output policy status when ignored v3.59 artifacts exist.
- Latest safe training-target status when ignored v3.62 artifacts exist.
- Lightweight label/model/response counts.
- Safety invariants:
  - current DB not mutated
  - production promoted false
  - model activated false
  - model artifact written false
  - labels written false
  - response actions created 0
  - response automation false
  - real firewall blocking false
  - raw logs included false

## Current Local Result

Quick mode:

- readiness: `diagnostic_evaluation_passed`
- required checks: `5 / 5`
- advisory checks: `2 / 3`
- advisory: controlled scenario quality skipped unless `--include-scenarios` is used
- DB mutation: false
- ML labels: `2672`
- ML model runs: `41`
- response actions: `0`
- feature generation: not run

Two-scenario mode:

- readiness: `diagnostic_evaluation_passed`
- required checks: `6 / 6`
- scenario count: `2`
- passed scenarios: `2`
- expected alerts: `1`
- actual alerts: `1`
- false-positive scenarios: `0`
- false-negative scenarios: `0`
- response actions created: `0`
- current DB mutation: false

## Important Design Choice

The evaluator intentionally uses lightweight training-data counts by default. It does not run feature generation during a normal productization status check. Deeper ML diagnostics still live in the dedicated v3.x scripts and ignored `ml_baseline_reviews/` artifacts.

## Remaining Gaps

- The command summarizes latest ignored ML diagnostic artifacts if present; it does not regenerate those artifacts.
- Exact suspicious/malicious/needs_context classification remains explanation/ranking only.
- Binary SOC queue remains decision support only.
- Real-source hardware/syslog validation remains separate.
- No model activation, production promotion, or response automation is introduced.

## Verification

Commands run:

```powershell
.\.venv\Scripts\ruff.exe check atdr\app\detection\v372_unified_detection_ml_evaluation.py atdr\scripts\run_v372_unified_detection_ml_evaluation.py atdr\tests\test_v372_unified_detection_ml_evaluation.py
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v372_unified_detection_ml_evaluation.py -q --basetemp .pytest_tmp\v372-unified-eval -p no:cacheprovider
.\.venv\Scripts\python.exe -m atdr.scripts.run_v372_unified_detection_ml_evaluation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v372_unified_detection_ml_evaluation --include-scenarios --scenario normal_allowed_traffic --scenario port_scan_like_traffic --pretty
```

All passed.
