# v3.26 SOC Assistant Evaluation And End-To-End Investigation QA

## Status

Implemented as a read-only assistant QA and validation layer.

## Purpose

v3.26 verifies that the SOC Assistant is useful across the investigation workflow without adding persisted notebooks, incident records, action execution, external LLM calls, raw-log sharing, or model activation.

The main artifact is a deterministic evaluator:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa --pretty
```

## What Changed

- Added a controlled SOC Assistant QA question set.
- Added `atdr.scripts.evaluate_assistant_qa`.
- Added a backend test that runs the evaluator.
- Validated alert/log/source/case assistant answers against a safe temporary scenario.
- Validated citations, safety wording, and no-side-effect behavior.
- Recorded v3.26 in ATDR PRD, traceability, compliance, tasklist, and change docs.

## Evaluated Assistant Coverage

- Latest critical alert summary.
- Alert explanation.
- Log explanation.
- Source health summary.
- Warning source summary.
- Recent detection run summary.
- Failed job summary.
- ML status and production-promotion explanation.
- Safe analyst next steps.
- Alert, log, source, and case investigation briefs.
- Unsafe action refusal.

## End-To-End Investigation QA

The evaluator uses an in-memory SQLite database and safe synthetic scenario data. It does not reset or mutate the user's current ATDR database.

Validation path:

1. Create a temporary ATDR schema.
2. Import `data/samples/scenarios/port_scan_like_traffic.txt`.
3. Normalize scenario logs.
4. Run rule detection with ML disabled.
5. Confirm alert, detection run, related logs, source health, and case context exist.
6. Ask assistant investigation questions against the generated context.
7. Confirm assistant answers are cited, redacted, read-only, and non-mutating.

## Safety Controls Confirmed

- External provider used: false.
- Raw log context included: false.
- Response automation allowed: false.
- Real firewall blocking enabled: false.
- No response actions created.
- No detection runs created by assistant answers.
- No ML model runs created.
- No labels changed.
- No alerts created by assistant answers.
- No logs created by assistant answers.
- Assistant questions are audited.

## Verification Snapshot

Focused v3.26 checks:

- `.\.venv\Scripts\ruff.exe check atdr\scripts\evaluate_assistant_qa.py atdr\tests\test_assistant.py atdr\tests\test_assistant_qa_evaluator.py`: pass.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py atdr\tests\test_assistant_qa_evaluator.py -q --basetemp .pytest_tmp\v326-assistant -p no:cacheprovider`: pass, `16 passed`.
- `.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa`: pass, `15` question cases, `0` failures.

## Known Limitations

- The assistant remains deterministic decision support.
- The evaluator uses a controlled synthetic scenario, not production traffic.
- Computed case/group context is not a persisted incident record.
- External LLM, raw-log context, persisted notebooks, action execution, detection execution from chat, label/model mutation, and production promotion remain future reviewed work.
