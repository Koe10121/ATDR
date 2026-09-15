# T1-T20 Change Document: v3.86 Template Shell Live Runtime Check

## T1 Change Title

v3.86 Template Shell Live Runtime Check

## T2 Requirement

Validate the advisor-template outer-shell handoff path with live local services up to the point that requires a real authenticated template browser session.

## T3 Source Evidence

- `atdr/scripts/use_template_shell_config.py`
- `atdr/scripts/validate_template_shell_runtime.py`
- `docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `docs/V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md`
- Supervisor template path: `<MFU_SHELL_ROOT>`

## T4 Current Behavior

ATDR had static bridge validation, `.env` helper support, and a runtime validator. The remaining question was whether the local services could run together and expose the expected handoff surfaces.

## T5 Impacted Areas / Agents

- Release / Lab Validation
- Security / IAM
- Frontend / Dashboard
- QA
- Documentation

## T6 Scope

In scope:

- Apply non-secret local template-shell config to private `.env`.
- Start ATDR backend/frontend.
- Start supervisor template backend/frontend.
- Run runtime validator.
- Document result and next manual login step.

Out of scope:

- Capturing or committing real session tokens.
- Full live school-email login without user interaction.
- Redis/template dependency remediation.
- Response automation.
- Model activation.

## T7 Functional Requirements

- Confirm ATDR runtime is reachable.
- Confirm template runtime is reachable.
- Confirm ATDR reports template-shell handoff mode.
- Confirm template profile endpoint is protected.
- Keep secrets and tokens out of logs/docs.

## T8 Acceptance Criteria

- Runtime validator returns `ok: true`.
- `atdr_runtime.public_status_reachable` is true.
- `template_runtime.reachable` is true.
- `template_runtime.protected_endpoint_detected` is true.
- `secrets_exposed` is false.

## T9 API Contract

No new API. Validation used existing endpoints:

- `GET /health`
- `GET /api/auth/mfu-iam/public-status`
- Template `GET /api/v1/auth/me`

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

No backend code changes in this slice. Runtime validation used existing helpers.

## T12 Frontend Plan / Changes

No frontend code changes in this slice. The template launcher and ATDR handoff receiver already exist.

## T13 Security / Response / AI Safety

- No response automation.
- No real firewall blocking.
- No model activation.
- No token printing.
- No raw log context sharing.

## T14 Test Plan

- Run `validate_template_shell_runtime --check-runtime --pretty`.
- Confirm profile endpoint is reachable and protected.
- Confirm ATDR public status reports template-shell readiness.

## T15 Implementation Summary

Local services were started and the template-shell runtime validator confirmed the bridge is reachable and configured, except for real session validation which requires a user login through the template frontend.

## T16 Tests Run / Evidence

Runtime command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

Result:

- `ok: true`
- `mfu_iam.mode: template_shell_session_handoff`
- `atdr_runtime.public_status_reachable: true`
- `template_runtime.protected_endpoint_detected: true`
- `secrets_exposed: false`

## T17 PRD / Docs Updated

- `docs/V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md`
- `docs/changes/T1_T20_V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Real school-email login still requires browser interaction.
- Template backend logged Redis connection refused; Redis-dependent template features may need follow-up.
- Template npm dependencies include vulnerability warnings; template dependency modernization remains separate work.

## T19 Release / Rollback

The only local config write was private `.env`, backed up by `use_template_shell_config`. Runtime processes can be stopped normally. No DB or schema rollback required.

## T20 Final Handoff

Open `http://localhost:8080/`, log into the template shell, and use `Open ATDR SOC Dashboard` for the next manual end-to-end validation.

