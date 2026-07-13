# T1-T20 Change Document: v3.84 Template Shell Runtime Validation

## T1 Change Title

v3.84 Template Shell Runtime Validation

## T2 Requirement

Provide a safe way to validate whether the supervisor-template outer-shell handoff is statically present, privately configured, and optionally reachable at runtime.

## T3 Source Evidence

- `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md`
- `docs/V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md`
- `atdr/app/services/template_bridge_contract.py`
- `atdr/scripts/validate_template_bridge_contract.py`
- `atdr/scripts/validate_template_shell_runtime.py`
- `atdr/scripts/config_doctor.py`
- Official supervisor template path: `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`

## T4 Current Behavior

ATDR had a static contract checker and a template-shell session adapter, but no simple command that combined static bridge state, private config state, and optional live service reachability.

## T5 Impacted Areas / Agents

- Release / Lab Validation
- Security / IAM
- Backend / API
- QA
- Documentation

## T6 Scope

In scope:

- Add runtime validator CLI.
- Improve config doctor MFU template-shell visibility.
- Add tests for static/runtime/session validation behavior.

Out of scope:

- Full OAuth/OIDC callback.
- Real firewall blocking.
- Automatic response.
- Model activation.
- Migration to Node/Vue/MongoDB.

## T7 Functional Requirements

- Report static template/ATDR bridge readiness.
- Report MFU/template-shell config readiness.
- Optionally probe live ATDR and template services.
- Optionally use a session token from an environment variable for manual profile validation.
- Never print session tokens, emails, secrets, or raw profile payloads.

## T8 Acceptance Criteria

- Validator reports blocking config issues when template-shell IAM is disabled.
- Validator reports reachable/protected template profile endpoint when runtime probe is enabled.
- Validator can detect profile-email presence without printing the email.
- Config doctor shows template-shell readiness fields.
- Tests cover secret-safe runtime validation.

## T9 API Contract

No new HTTP API. New CLI:

```powershell
python -m atdr.scripts.validate_template_shell_runtime --pretty
python -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Added `atdr/scripts/validate_template_shell_runtime.py`.
- Updated `atdr/scripts/config_doctor.py`.
- Updated `atdr/app/services/mfu_iam_validation.py` so template-shell mode does not accidentally run a B2B probe without an explicit session token.

## T12 Frontend Plan / Changes

No new frontend behavior in this slice.

## T13 Security / Response / AI Safety

- No response automation.
- No real firewall blocking.
- No model activation.
- No raw log sharing.
- Session tokens and profile emails are not printed.

## T14 Test Plan

- Template-shell runtime static report is secret-safe.
- Runtime check detects protected template profile endpoint.
- Session probe hides token and email.
- Config doctor reports template-shell readiness.
- MFU provider helper avoids B2B probe in template-shell mode without explicit token.

## T15 Implementation Summary

Added a dedicated validation command for the advisor-template outer-shell path and improved existing config/MFU validation visibility for template-shell mode.

## T16 Tests Run / Evidence

Focused checks:

```powershell
.\.venv\Scripts\ruff.exe check atdr\scripts\config_doctor.py atdr\scripts\validate_template_shell_runtime.py atdr\app\services\mfu_iam_validation.py atdr\tests\test_hardening_and_ingestion.py atdr\tests\test_template_shell_runtime.py atdr\tests\test_mfu_iam_validation.py
.\.venv\Scripts\python.exe -m compileall -q atdr\scripts\config_doctor.py atdr\scripts\validate_template_shell_runtime.py atdr\app\services\mfu_iam_validation.py atdr\tests\test_hardening_and_ingestion.py atdr\tests\test_template_shell_runtime.py atdr\tests\test_mfu_iam_validation.py
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_template_shell_runtime.py atdr\tests\test_mfu_iam_validation.py atdr\tests\test_hardening_and_ingestion.py -q --basetemp .pytest_tmp\template-shell-runtime -p no:cacheprovider
```

Result:

- Ruff: passed
- Compileall: passed
- Focused tests: `28 passed`

## T17 PRD / Docs Updated

- `docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `docs/changes/T1_T20_V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Current local `.env` still leaves MFU/template-shell IAM disabled.
- Live login requires starting the template shell and ATDR stack.
- Manual session-token probes should use temporary environment variables only.

## T19 Release / Rollback

No schema change. The validator can be removed without affecting runtime auth. Template-shell login remains disabled unless private `.env` enables it.

## T20 Final Handoff

Operators now have a safe command to validate static and live readiness for the template-shell handoff path before trying a full school-email login flow.

