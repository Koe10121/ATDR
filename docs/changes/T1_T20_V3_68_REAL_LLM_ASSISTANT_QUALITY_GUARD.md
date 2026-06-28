# T1-T20: v3.68 Real LLM Assistant Quality Guard

## T1 Change Title

v3.68 Real LLM Assistant Quality Guard

## T2 Requirement

Validate the real LLM-powered assistant path and prevent weak or unsafe provider wording from replacing ATDR's deterministic evidence-grounded answer.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/services/assistant_llm.py`
- `atdr/app/routers/assistant.py`
- `atdr/tests/test_assistant.py`
- `atdr/scripts/test_assistant_llm_provider.py`
- `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`
- `docs/V3_66_SOC_ASSISTANT_CONTEXT_HARDENING.md`

## T4 Current Behavior

ATDR had a safe external LLM adapter and provider probe, but a live Gemini alert-answer smoke showed that a provider can return a short answer that is not good enough for a professional SOC explanation. The answer was safe but lost useful ATDR evidence.

## T5 Impacted Areas / Agents

- Backend / API
- Assistant / LLM
- Security / Response Safety
- QA
- Documentation

## T6 Scope

In scope:
- Guard external LLM answers.
- Keep deterministic evidence answers when provider output is too weak or unsafe.
- Add regression tests.
- Run safe real-provider status and minimal execution probes.

Out of scope:
- New LLM provider configuration.
- Prompt tuning for production.
- Raw log sharing.
- Action execution.
- Detection/ML logic changes.
- Schema changes.

## T7 Functional Requirements

- External LLM answers must not imply that ATDR executed actions.
- Evidence-heavy deterministic answers must not be replaced by very short provider answers.
- Alert-specific provider answers must preserve alert/evidence context.
- Guarded provider calls must still be visible in response details and audit context.
- Raw logs must remain excluded by default.

## T8 Acceptance Criteria

- Too-short provider answers are guarded.
- Provider answers implying action execution are guarded.
- Guarded responses keep deterministic answer text.
- Provider-called and answer-used fields are reported safely.
- No response actions, detection runs, labels, users, or model runs are created.

## T9 API Contract

The assistant response shape remains backward-compatible. `details.llm` now also reports:

- `provider_called`
- `answer_used`
- `answer_guard_reason`

## T10 Data Model / Migration

No database model or migration changes.

## T11 Backend Plan / Changes

Add `_llm_answer_guard_reason()` in `assistant_service.py` and use it after a provider call. If the provider answer is rejected, keep deterministic mode with a guarded LLM suffix and record the guarded provider context.

## T12 Frontend Plan / Changes

No frontend behavior changes in v3.68. Existing dashboard provider/safety badges remain valid.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Raw log context remains disabled by default.
- IP redaction remains enabled.
- Provider secrets are never returned.
- Response automation and real firewall blocking remain disabled.

## T14 Test Plan

- Add backend tests for too-short provider answers.
- Add backend tests for provider wording that implies action execution.
- Confirm mock provider success path still uses the provider answer.
- Run safe provider status and execution probes.

## T15 Implementation Summary

The assistant now evaluates external LLM output before using it. Weak or unsafe output is rejected, deterministic ATDR evidence remains visible, and the provider contact is still auditable.

## T16 Tests Run / Evidence

- Focused Ruff: passed.
- Focused compileall: passed.
- `atdr/tests/test_assistant.py`: `31 passed`.
- Provider status probe: passed, secrets exposed `false`.
- Provider execution probe: passed, raw log context included `false`.
- Authenticated endpoint smoke: passed, external provider used `true`, answer guarded, side-effect deltas all `0`.

## T17 PRD / Docs Updated

- `docs/V3_68_REAL_LLM_ASSISTANT_QUALITY_GUARD.md`
- `docs/changes/T1_T20_V3_68_REAL_LLM_ASSISTANT_QUALITY_GUARD.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- A provider can still produce low-quality wording; ATDR now guards against obvious low-evidence and unsafe outputs.
- Future prompt engineering should improve answer style, but deterministic ATDR context remains the authority.
- Real provider validation requires private `.env` and should not run in CI.

## T19 Release / Rollback

Rollback is limited to reverting `assistant_service.py`, the added tests, and v3.68 docs. No schema or data rollback is required.

## T20 Final Handoff

v3.68 makes real LLM usage safer for demos and lab operation. If provider wording is strong, ATDR can use it. If not, the assistant keeps the local evidence-grounded answer and clearly records that provider output was guarded.
