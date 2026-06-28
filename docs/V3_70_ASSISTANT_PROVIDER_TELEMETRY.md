# v3.70 SOC Assistant Provider Telemetry

## Purpose

v3.70 makes the SOC Assistant provider path understandable in the dashboard. Analysts can now tell whether an answer came from deterministic ATDR context, an external LLM answer that passed safety checks, or an external provider call that was guarded and replaced by ATDR's local evidence-grounded answer.

## What Changed

- The Assistant response panel now shows a compact Provider Status card.
- The card reports:
  - local deterministic answer
  - external LLM answer used
  - external LLM guarded
  - external fallback
  - provider name when available
  - raw-log context inclusion status
  - redaction status
  - secret-exposure status
  - prompt contract version when available
  - guard reason when ATDR rejects provider wording
- Technical JSON remains behind the existing Technical Context disclosure.

## Safety Behavior

- The assistant remains read-only.
- External LLM use is still controlled by private `.env` configuration.
- API keys and secrets are never displayed.
- Raw log context remains excluded by default.
- Response automation remains disabled.
- The assistant cannot create response actions, run detection, change labels, activate models, edit users, or delete data.

## Verification

- Frontend lint passed.
- Frontend production build passed.
- Playwright coverage now includes guarded external LLM telemetry.

## Remaining Gaps

- Live provider quality still depends on the configured provider and model.
- Real provider execution is not run in CI because it requires private `.env` secrets.
- The v3.68 answer-quality guard remains the authority for whether provider wording can be used.
