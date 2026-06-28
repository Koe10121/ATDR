# T1-T20 Change Document: v3.77 MFU IAM Config Doctor Visibility

## T1 Change Title

v3.77 MFU IAM Config Doctor Visibility

## T2 Requirement

Operators need a clear, non-secret way to see whether ATDR is ready for school-email/MFU IAM validation and what remains missing.

## T3 Source Evidence

- `atdr/scripts/config_doctor.py`
- `atdr/app/services/mfu_iam_service.py`
- `atdr/tests/test_hardening_and_ingestion.py`
- `docs/V3_77_MFU_IAM_CONFIG_DOCTOR_VISIBILITY.md`

## T4 Current Behavior

Before this change, MFU IAM status was available through IAM-specific endpoints and scripts, but the general configuration doctor did not show a dedicated MFU IAM readiness block.

## T5 Impacted Areas / Agents

- Backend / API
- Security / IAM
- Release/Ops / Lab Validation
- QA/UAT

## T6 Scope

In scope:

- Add non-secret MFU IAM readiness fields to config doctor.
- Add warnings for partial/disabled/missing-domain IAM configuration.
- Add tests to prevent secret leakage.

Out of scope:

- Enabling real IAM login.
- OAuth/OIDC browser callback implementation.
- Database schema changes.
- Response automation or firewall changes.

## T7 Functional Requirements

- Config doctor must show MFU IAM readiness without secrets.
- Config doctor must warn if IAM values are present but disabled.
- Config doctor must warn if enabled IAM is missing readiness requirements.
- Existing local SQLite workflow must remain valid.

## T8 Acceptance Criteria

- Current local config still passes config doctor.
- MFU IAM readiness appears as a structured block.
- Test coverage proves secrets are not rendered.

## T9 API Contract

No API contract change.

## T10 Data Model / Migration

No schema change and no Alembic migration.

## T11 Backend Plan / Changes

- Import `build_mfu_iam_status` into config doctor.
- Add `mfu_iam` readiness block to config doctor output.
- Add IAM-specific warning codes.

## T12 Frontend Plan / Changes

No frontend change.

## T13 Security / Response / AI Safety

- No secrets printed.
- External IAM remains disabled unless explicitly configured.
- Response automation remains disabled.
- Real firewall blocking remains disabled.

## T14 Test Plan

- Config doctor ready-IAM test with supervisor-template env aliases.
- Config doctor configured-but-disabled test.
- Existing MFU IAM validation tests.

## T15 Implementation Summary

Added MFU IAM readiness visibility and warnings to `config_doctor`, plus regression tests.

## T16 Tests Run / Evidence

- `ruff check atdr/scripts/config_doctor.py atdr/tests/test_hardening_and_ingestion.py`
- `python -m pytest atdr/tests/test_hardening_and_ingestion.py::test_config_doctor_reports_mfu_iam_readiness_without_secret_leakage atdr/tests/test_hardening_and_ingestion.py::test_config_doctor_warns_when_mfu_iam_values_are_present_but_disabled atdr/tests/test_mfu_iam_validation.py -q`
- `python -m atdr.scripts.config_doctor --pretty`

## T17 PRD / Docs Updated

- `docs/V3_77_MFU_IAM_CONFIG_DOCTOR_VISIBILITY.md`
- `docs/changes/T1_T20_V3_77_MFU_IAM_CONFIG_DOCTOR_VISIBILITY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Real MFU IAM validation still requires private `.env` configuration and provider availability.
- Google/OAuth browser callback remains future work.

## T19 Release / Rollback

Rollback is script/test/docs only. No database rollback is required.

## T20 Final Handoff

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty
```

If `mfu_iam.token_login_ready` is false, configure private IAM values in `.env` before running `--execute`.
