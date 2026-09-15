# v3.68 Real LLM Assistant Quality Guard

## Summary

v3.68 hardens the external-LLM SOC Assistant path after live Gemini validation showed that a provider response can be technically successful but too short to preserve ATDR's evidence-grounded explanation.

The assistant now treats deterministic ATDR context as the source of truth. External LLM output may improve wording only when it preserves enough evidence and does not imply action execution. If the provider answer is too thin or unsafe, ATDR keeps the deterministic answer, records that the provider was contacted, and marks the response as guarded.

## Behavior

- External LLM remains configured only through private `.env`.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Assistant answers remain read-only decision support.
- Provider answers are rejected if they:
  - are empty,
  - are too short for an evidence-heavy context,
  - lose alert/evidence context,
  - imply that blocking, detection, label changes, model activation, deletion, or containment already happened.
- Guarded responses keep the deterministic answer and add `external_llm_guarded:<provider>` to `context_used`.

## Live Provider Check

Safe local provider checks showed:

- provider: Gemini
- API key configured: true
- model configured: true
- secrets exposed: false
- raw log context allowed: false
- raw log context included: false
- redaction enabled: true

An authenticated assistant endpoint smoke test called Gemini for an alert explanation. The provider response was guarded because it was too short for the evidence context. ATDR kept the deterministic evidence-grounded answer. No response actions, detection runs, labels, or model runs were created.

## Safety

- No `.env` values or API keys are printed or committed.
- No raw logs are sent by default.
- No response action can be executed by the assistant.
- No detection run, label change, model activation, account change, data deletion, or firewall change can be triggered by the assistant.
- External LLM usage is observable through response details and audit metadata.

## Verification Evidence

- `ruff check atdr/app/services/assistant_service.py atdr/tests/test_assistant.py`: passed.
- `compileall` on changed assistant files: passed.
- `pytest atdr/tests/test_assistant.py`: `31 passed`.
- `python -m atdr.scripts.test_assistant_llm_provider --pretty`: passed, status-only, no secrets exposed.
- `python -m atdr.scripts.test_assistant_llm_provider --execute --pretty`: passed, minimal provider call, no raw logs included.
- Authenticated assistant endpoint smoke: passed; provider called, answer guarded, side-effect deltas all `0`.
- Frontend lint/build/e2e: passed, Playwright `15 passed, 1 skipped`.
- Release gate: passed, backend tests `431 passed, 1 skipped`.
- Replay dry-run: passed, wrote no database rows.
- Performance smoke: passed with known cold large-SQLite warnings; cached Overview remained fast.

## Remaining Notes

The real-provider path is now safer, but provider quality still depends on model behavior and prompt design. Future work should improve provider prompt structure and answer formatting while keeping the deterministic ATDR answer as the guardrail source of truth.
