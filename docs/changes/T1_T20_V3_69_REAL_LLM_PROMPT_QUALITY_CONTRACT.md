# T1-T20: v3.69 Real LLM Prompt Quality Contract

## T1 Change Title

v3.69 Real LLM Prompt Quality Contract

## T2 Requirement

Improve the configured external LLM assistant prompt so real providers are more likely to return professional, evidence-preserving SOC answers while keeping the assistant read-only and guarded.

## T3 Source Evidence

- `atdr/app/services/assistant_llm.py`
- `atdr/app/services/assistant_service.py`
- `atdr/tests/test_assistant.py`
- `docs/V3_68_REAL_LLM_ASSISTANT_QUALITY_GUARD.md`

## T4 Current Behavior

The real provider adapter worked, and v3.68 guarded weak provider answers, but the prompt contract was still minimal. Providers were told to improve wording and structure without enough explicit guidance about SOC sections, evidence preservation, and avoiding overly terse responses.

## T5 Impacted Areas / Agents

- Assistant / LLM
- Backend / API
- Security / Response Safety
- QA
- Docs

## T6 Scope

In scope:
- External LLM prompt contract.
- Safe metadata indicating prompt contract version.
- Focused assistant tests.

Out of scope:
- New provider onboarding.
- External IAM changes.
- Detection/ML logic changes.
- Database schema changes.
- Dashboard redesign.
- Raw log sharing.
- Action execution.

## T7 Functional Requirements

- Provider prompts must request professional SOC answer sections.
- Provider prompts must preserve deterministic ATDR facts, IDs, uncertainty, counts, citations, and safety limits.
- Provider prompts must redact IPs when configured.
- Response details must expose only safe prompt-contract metadata.
- Existing v3.68 answer-quality guard must remain active.

## T8 Acceptance Criteria

- Prompt includes `soc_evidence_preserving_v1`.
- Prompt includes required sections: Summary, Evidence, Risk interpretation, Analyst checks, Safety, Sources.
- Prompt redacts IPs when `ASSISTANT_REDACT_IPS=true`.
- Mock provider success path reports the prompt contract.
- Assistant tests pass without external network calls.

## T9 API Contract

The assistant response is backward-compatible. `details.llm.prompt_contract` may appear in safe LLM details.

## T10 Data Model / Migration

No schema or migration changes.

## T11 Backend Plan / Changes

Update `assistant_llm.py` with a versioned prompt contract, stronger system prompt, structured response instructions, quality requirements, and a modest token-budget increase.

## T12 Frontend Plan / Changes

No frontend code changes in v3.69.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Provider output remains guarded by v3.68.
- No response automation or real firewall blocking is enabled.

## T14 Test Plan

- Focused Ruff.
- Assistant regression tests.
- Prompt contract and redaction unit coverage.

## T15 Implementation Summary

Added `PROMPT_CONTRACT_VERSION = "soc_evidence_preserving_v1"`, strengthened the provider prompt, included required SOC sections and quality requirements, and added tests that enforce the prompt contract.

## T16 Tests Run / Evidence

- `ruff check atdr/app/services/assistant_llm.py atdr/tests/test_assistant.py`: passed.
- `pytest atdr/tests/test_assistant.py`: `32 passed`.

## T17 PRD / Docs Updated

- `docs/V3_69_REAL_LLM_PROMPT_QUALITY_CONTRACT.md`
- `docs/changes/T1_T20_V3_69_REAL_LLM_PROMPT_QUALITY_CONTRACT.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Provider output quality can still vary; v3.68 guard remains the backstop.
- Real provider execution depends on private `.env` and should not run in CI.
- This phase improves the prompt contract but does not complete full production LLM governance.

## T19 Release / Rollback

Rollback is limited to reverting `assistant_llm.py`, the focused tests, and v3.69 docs. No data rollback is required.

## T20 Final Handoff

v3.69 makes the real LLM assistant path more professional without granting new powers. The provider gets a clear SOC response contract, while deterministic ATDR evidence and safety rules remain authoritative.
