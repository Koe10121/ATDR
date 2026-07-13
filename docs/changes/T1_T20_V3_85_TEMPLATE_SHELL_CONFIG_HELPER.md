# T1-T20 Change Document: v3.85 Template Shell Config Helper

## T1 Change Title

v3.85 Template Shell Config Helper

## T2 Requirement

Reduce configuration friction for the supervisor-template outer-shell handoff by adding a dry-run-first helper that prepares private `.env` values safely.

## T3 Source Evidence

- `docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `atdr/scripts/validate_template_shell_runtime.py`
- `atdr/scripts/use_local_sqlite_config.py`
- `atdr/app/core/config.py`

## T4 Current Behavior

Template-shell handoff settings exist, but operators had to edit `.env` manually. This made it easy to forget one required field before running the runtime validator.

## T5 Impacted Areas / Agents

- Release / Lab Validation
- Security / IAM
- QA
- Documentation

## T6 Scope

In scope:

- Add a dry-run-first `.env` helper.
- Preserve backups on write.
- Avoid printing or writing secrets.
- Add tests and docs.

Out of scope:

- Real login execution.
- Session token storage.
- Admin allowlist automation.
- OAuth/OIDC callback.
- Response automation.

## T7 Functional Requirements

- Dry-run is default behavior.
- `--write` must be explicit.
- Existing `.env` must be backed up before write.
- Helper sets only non-secret template-shell values.
- Helper does not modify `MFU_IAM_ADMIN_EMAILS`.
- Output must not expose existing secret values.

## T8 Acceptance Criteria

- Dry-run does not mutate `.env`.
- Builder sets required template-shell keys.
- Write mode creates a backup.
- Existing admin mapping is preserved.
- Tests pass.

## T9 API Contract

No HTTP API. New CLI:

```powershell
python -m atdr.scripts.use_template_shell_config --dry-run --pretty
python -m atdr.scripts.use_template_shell_config --write --pretty
```

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

Added `atdr/scripts/use_template_shell_config.py`.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

- No secrets written except existing private `.env` remains private.
- No secrets printed.
- No response automation.
- No real firewall blocking.
- No model activation.
- No user creation.

## T14 Test Plan

- Dry-run safety.
- Builder output.
- Backup creation.
- Admin mapping preservation.

## T15 Implementation Summary

Implemented a `.env` helper modeled after the existing local SQLite config helper, but targeted at the template-shell handoff path.

## T16 Tests Run / Evidence

Focused tests:

```powershell
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_dev_onboarding.py -q
```

## T17 PRD / Docs Updated

- `docs/V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md`
- `docs/changes/T1_T20_V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md`
- `docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- The helper enables config but does not prove live login by itself.
- Live validation still requires running both ATDR and the template shell.
- Admin mapping remains manual.

## T19 Release / Rollback

The helper creates `.env` backups before write. To roll back, restore the backup file from `.tmp/env-backups/`.

## T20 Final Handoff

Use `use_template_shell_config --dry-run` to preview, `--write` to apply, then `validate_template_shell_runtime --check-runtime` to verify services.

