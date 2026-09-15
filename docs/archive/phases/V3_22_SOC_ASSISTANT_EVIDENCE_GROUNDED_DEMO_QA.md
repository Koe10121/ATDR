# v3.22 SOC Assistant Evidence-Grounded Demo QA

## Status

v3.22 strengthens the ATDR SOC Assistant for advisor-facing and analyst-facing demonstrations. The assistant remains deterministic, local, read-only, and decision-support only.

## Source Evidence

| Area | Source |
| --- | --- |
| Assistant router | `atdr/app/routers/assistant.py` |
| Assistant deterministic service | `atdr/app/services/assistant_service.py` |
| Assistant API schema | `atdr/app/schemas/assistant.py` |
| React assistant page | `frontend/src/pages/AssistantPage.tsx` |
| Alert handoff | `frontend/src/pages/AlertsTriage.tsx` |
| Assistant tests | `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |

## What Changed

- Assistant answers now expose structured evidence sections through the existing `details.answer_sections` payload.
- The React Assistant page renders:
  - Summary
  - Evidence
  - Safe next steps
  - Safety limitation
  - Citations
- Alert explanations include alert ID, severity, risk score, detection source, related evidence count, source context, rule/model contribution, ATT&CK-style mapping, and manual-response reminders.
- Suggested follow-up buttons now ask the assistant directly instead of only filling the text box.
- Unsafe requests still return refusal answers and create no side effects.

## Safety Rules Confirmed

- No external LLM calls by default.
- No raw log context by default.
- IP redaction remains enabled by default.
- Assistant cannot execute response actions.
- Assistant cannot run detection.
- Assistant cannot change labels.
- Assistant cannot delete data.
- Assistant cannot send email.
- Assistant cannot activate or promote models.
- Response automation remains disabled.
- Real firewall blocking remains disabled/not implemented.

## Demo Behavior

Recommended demo flow:

1. Open `/assistant`.
2. Ask `Show latest critical alerts.`
3. Ask `Why was alert 1 flagged?`
4. Click a suggested follow-up such as `Summarize source health.`
5. Ask `Why is the model not production promoted?`
6. Ask `Can you block this IP?`

Expected result: the assistant cites ATDR evidence, shows safe next steps, and refuses unsafe commands.

## Known Limitations

- The assistant is deterministic and template/context based.
- It is not an autonomous SOC agent.
- It is not an external LLM integration.
- It does not validate production detection accuracy.
- It does not replace analyst review.

## Recommended Next Phase

After advisor review, the next sensible phase is either:

- v3.23 Assistant Context Linking, if advisor wants smoother navigation from assistant answers into Alerts, Sources, Logs, and ML Governance.
- v3.23 Detection Evidence QA, if advisor wants deeper parser/detection/false-positive validation.
