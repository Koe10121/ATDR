# v3.13 SOC Assistant Alert Explainer

## Status

v3.13 upgrades the read-only SOC Assistant so analysts can ask clearer alert-specific questions and receive structured decision-support explanations.

This pass does not change detection thresholds, ML training, ML activation, response behavior, database schema, startup commands, or production readiness status.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Assistant API | `atdr/app/routers/assistant.py` |
| Assistant logic | `atdr/app/services/assistant_service.py` |
| Alert explanations | `atdr/app/detection/explanations.py` |
| Alert API and detail summary | `atdr/app/routers/alerts.py` |
| Alert dashboard | `frontend/src/pages/AlertsTriage.tsx` |
| Assistant dashboard | `frontend/src/pages/AssistantPage.tsx` |
| API client/types | `frontend/src/lib/api.ts`, `frontend/src/types/api.ts` |
| Tests | `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |

## What Changed

- Alert questions now return a structured answer with:
  - Summary
  - Why flagged
  - Evidence
  - ATT&CK mapping
  - Rule / model contribution
  - Analyst next steps
  - Safety note
  - References
- Alert-specific context includes:
  - alert ID
  - severity
  - risk score
  - attack type
  - detection source
  - rule evidence
  - anomaly evidence
  - supervised signal status as decision support only
  - ATT&CK-style mapping
  - related log and occurrence counts
  - source context
  - parser notes when available
  - response history summary
- Alert detail now includes an `Ask Assistant` affordance that opens the SOC Assistant with alert context and a prefilled prompt.
- Assistant answers cite safe references such as alert ID, source ID, explanation source, and the rule catalog.

## Safety Controls

- Assistant remains read-only.
- External LLM calls remain disabled by default.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Assistant questions are audited.
- Assistant cannot create response actions.
- Assistant cannot approve block/unblock actions.
- Assistant cannot run detection.
- Assistant cannot import logs.
- Assistant cannot retrain, activate, or promote models.
- Response automation remains disabled.
- Real firewall blocking remains unimplemented.

## Current Manual Test

1. Start backend:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

2. Start frontend:

   ```powershell
   cd frontend
   npm.cmd run dev
   ```

3. Open `http://127.0.0.1:5173`.
4. Go to Alerts.
5. Open an alert detail drawer.
6. Click `Ask Assistant`.
7. Confirm the Assistant page shows alert context and a structured explanation.
8. Confirm no response action is created automatically.

## Remaining Gaps

- The assistant is deterministic/local by default, not a full external LLM copilot.
- Full school-email/OIDC login remains future work.
- Raw-log context sharing requires explicit future privacy/security review.
- Real-source validation may reveal additional explanation wording needs.
- Assistant output remains decision support and still requires analyst judgment.
