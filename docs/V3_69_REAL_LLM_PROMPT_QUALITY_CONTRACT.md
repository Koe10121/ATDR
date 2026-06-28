# v3.69 Real LLM Prompt Quality Contract

## Summary

v3.69 improves the external LLM prompt contract for the SOC Assistant. v3.68 added a guard so weak or unsafe provider wording cannot replace ATDR's deterministic evidence. v3.69 improves the prompt itself so configured providers are asked for a professional SOC response with required sections, evidence preservation, citation discipline, and explicit safety boundaries.

This does not add new assistant powers. The assistant remains read-only.

## What Changed

- Added a versioned prompt contract: `soc_evidence_preserving_v1`.
- Strengthened the system prompt for Gemini, OpenAI-compatible providers, Claude, and mock testing.
- Added a required response format:
  - Summary
  - Evidence
  - Risk interpretation
  - Analyst checks
  - Safety
  - Sources
- Added quality requirements telling the provider to preserve IDs, counts, evidence strength, parser/source warnings, uncertainty, citations, and response-safety limits.
- Increased provider output budget from 900 to 1200 tokens for the supported external providers.
- Added prompt-contract metadata to safe LLM response details.

## Safety

- External LLM remains configured only through private `.env`.
- No API key or secret is returned.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- The assistant cannot execute response actions, run detection, change labels, activate/promote models, change accounts, delete data, or change firewall rules.
- The v3.68 answer-quality guard still rejects provider answers that are empty, too short for evidence-heavy context, lose alert/evidence context, or imply action execution.

## Verification

- Focused Ruff check passed for `assistant_llm.py` and `test_assistant.py`.
- Assistant regression suite passed: `32 passed`.
- Tests now cover:
  - prompt-contract metadata,
  - required SOC response-format instructions,
  - IP redaction inside the provider prompt,
  - too-short provider answer guard,
  - unsafe action-implying provider answer guard,
  - no response/detection/label/model/user side effects.

## Remaining Work

Future work can improve provider-specific prompt tuning and dashboard display of guarded-vs-used provider answers. The deterministic ATDR answer remains the source of truth until real-world prompt quality and privacy policies are fully validated.
