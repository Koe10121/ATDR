# T1-T20 Change Document: v3.74 MFU IAM Validation Harness

## T1 Change Title

v3.74 MFU IAM Validation Harness

## T2 Requirement

Add a safe operational harness for validating MFU IAM configuration and optional provider connectivity without enabling real external login by default, exposing secrets, changing local login, or mutating data.

## T3 Source Evidence

- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/PRODUCTIZATION_TEMPLATE_GAP_ANALYSIS.md`
- `docs/ATDR_PRODUCTIZATION_ROADMAP.md`
- `atdr/app/core/config.py`
- `atdr/app/services/mfu_iam_service.py`
- `atdr/app/routers/auth.py`
- `atdr/app/schemas/auth.py`
- Supervisor template IAM docs and integration source under `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`

## T4 Current Behavior

Before this change, ATDR had disabled-by-default MFU IAM status and token-login groundwork, plus supervisor-template env alias support. There was no dedicated CLI harness to safely validate private MFU IAM configuration or run an explicit non-mutating provider probe.

## T5 Impacted Areas / Agents

- Security / IAM
- Backend / Services
- QA
- Docs / Release-Ops

## T6 Scope

In scope:

- Non-secret MFU IAM validation report service.
- CLI command for safe status and explicit probe.
- Mock/live probe logic that does not return secrets or tokens.
- Focused tests.
- Documentation and traceability updates.

Out of scope:

- Full OAuth/Google/MFU browser login.
- Enabling MFU IAM by default.
- Creating or updating users from the validation harness.
- Schema changes.
- Response actions.
- Model activation or promotion.
- Any use of real firewall blocking.

## T7 Functional Requirements

- Default CLI status check performs no provider call.
- `--execute` is required before any mock or live provider probe.
- Provider secrets and access tokens are never printed.
- The harness can report config completeness and runtime safety issues.
- Mock mode can validate the mapping path without a real provider.
- Live mode can use client credentials or an explicit token when configured.

## T8 Acceptance Criteria

- Disabled MFU IAM does not call the provider.
- Mock mode validates a school-email identity without printing the email or secret.
- Mocked live provider path fetches a token, introspects it, checks profile availability, and hides token/secret/profile values.
- Local login behavior remains unchanged.
- Tests pass.

## T9 API Contract

No new HTTP API.

CLI:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --execute --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --execute --token "<private-token>" --pretty
```

## T10 Data Model / Migration

No schema or migration change.

## T11 Backend Plan / Changes

- Add `atdr/app/services/mfu_iam_validation.py`.
- Add `atdr/scripts/test_mfu_iam_provider.py`.
- Reuse existing `build_mfu_iam_status` and runtime validation.
- Avoid database access and mutation.

## T12 Frontend Plan / Changes

No frontend changes in this phase.

## T13 Security / Response / AI Safety

- Secrets are read only from private runtime settings and never returned.
- Access tokens are never returned.
- Provider profile values are summarized only as booleans.
- MFU IAM remains disabled unless configured.
- No response automation.
- No real firewall blocking.
- No ML model activation.

## T14 Test Plan

- Disabled IAM no-provider-call regression.
- Mock mode secret-safe validation.
- Mocked live token/introspection/profile validation.
- Ruff check for new files.
- Safe CLI status command.

## T15 Implementation Summary

Implemented a non-mutating MFU IAM validation service and CLI. The command can be used as a safe readiness check now and as an explicit live probe once private provider configuration is available.

## T16 Tests Run / Evidence

Focused commands run:

```powershell
.\.venv\Scripts\ruff.exe check atdr\app\services\mfu_iam_validation.py atdr\scripts\test_mfu_iam_provider.py atdr\tests\test_mfu_iam_validation.py
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_mfu_iam_validation.py -q --basetemp .pytest_tmp\v374-mfu-iam -p no:cacheprovider
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty
```

Results:

- Ruff: passed.
- Tests: `3 passed`.
- CLI safe status: passed, provider call not executed, secrets exposed false.

## T17 PRD / Docs Updated

- `docs/V3_74_MFU_IAM_VALIDATION_HARNESS.md`
- `docs/changes/T1_T20_V3_74_MFU_IAM_VALIDATION_HARNESS.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Live probe success depends on private `.env` and reachable MFU IAM service.
- Token/profile response shape may require adjustment after a real provider test.
- This phase intentionally does not implement the browser login/callback flow.

## T19 Release / Rollback

Rollback removes the validation service, CLI, tests, and docs. Existing local login and MFU IAM token-login groundwork remain unchanged.

## T20 Final Handoff

Recommended next phase: run the harness with private MFU IAM configuration. If the provider probe passes, implement a safe external login/callback or token handoff flow. If not, document the exact provider mismatch and request advisor/IAM support.
