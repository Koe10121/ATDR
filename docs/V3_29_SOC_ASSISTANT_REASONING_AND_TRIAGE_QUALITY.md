# v3.29 SOC Assistant Reasoning And Triage Quality

## Status

Implemented as a deterministic, read-only assistant reasoning upgrade.

## Purpose

v3.29 improves the SOC Assistant so answers feel more like professional analyst guidance. It adds clearer triage reasoning, false-positive awareness, missing-evidence notes, source/case risk summaries, and concrete investigation checklists without enabling external LLMs, raw-log context, automatic tuning, or action execution.

## Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/scripts/evaluate_assistant_qa.py`
- `atdr/tests/test_assistant.py`
- `atdr/tests/test_assistant_qa_evaluator.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`

## What Changed

- Alert answers now include:
  - evidence strength wording
  - false-positive/noise caveats
  - missing-evidence notes
  - rule/anomaly/supervised contribution summary
  - concrete analyst checks
- Log answers now include confidence caveats and review guidance.
- Source answers now explain risky/noisy source conditions using health, parse failures, unknown app rate, and linked alerts.
- Case answers now include handoff-oriented risk interpretation and next checks.
- Investigation briefs now include risk interpretation in addition to evidence and limitations.
- The Assistant page presets are grouped around analyst workflows:
  - Alert Triage
  - False Positive Review
  - Source Health
  - Case Handoff
  - AI Governance
  - How-To
- The assistant QA evaluator now checks 20 controlled questions, including false-positive reasoning, missing evidence, source risk, case handoff, and supervisor-friendly summaries.

## Safety Controls

- Assistant remains read-only.
- External LLM provider use remains disabled by default.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Assistant cannot execute response actions.
- Assistant cannot run detection.
- Assistant cannot change labels.
- Assistant cannot create alerts/logs.
- Assistant cannot activate or promote ML models.
- Assistant feedback does not automatically tune/retrain the assistant.

## Manual Test Flow

1. Start backend and frontend normally.
2. Open `/assistant`.
3. Try these questions:
   - `Why was alert 1 flagged?`
   - `Is alert 1 likely a false positive?`
   - `What evidence is missing for alert 1?`
   - `What should I check first for this alert?`
   - `Is source 1 risky?`
   - `Summarize this case for handoff.`
   - `What should I tell my supervisor about alert 1?`
4. Confirm answers show:
   - Summary
   - Evidence
   - Risk interpretation
   - What to check next
   - Safety note
   - Citations
5. Confirm no response action, detection run, label change, model run, or data mutation is created.

## Known Limitations

- The reasoning is deterministic and evidence-template based, not a full autonomous SOC analyst.
- False-positive reasoning is cautious guidance, not a final benign/malicious decision.
- External LLM integration remains future reviewed work.
- Raw-log context sharing remains disabled unless explicitly reviewed and configured in the future.
- Persisted investigation notebooks/incidents remain future work.
