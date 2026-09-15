# T1-T20 Change Document: v3.80 Supervisor Template Runtime Bridge Validation

## T1 Change Title

v3.80 Supervisor Template Runtime Bridge Validation

## T2 Requirement

ATDR needs a source-backed, repeatable way to validate that the official supervisor template can serve as the outer login/IAM shell and hand an authenticated user into ATDR without copying secrets or migrating ATDR stacks.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Official supervisor template | `<MFU_SHELL_ROOT>` | Contains IAM docs, IAM SDK adapter, B2B middleware, Vue login, 2FA, security permissions, and env variable names. |
| Template auth store | `frontend-vue/src/store/modules/Authen/index.js` | Uses `x-access-token` and a post-sign-in route after login/2FA. |
| Template IAM adapter | `backend-node/server/integrations/iam/iam-sdk-adapter.js` | Uses token, introspection, and profile endpoints. |
| Template B2B middleware | `backend-node/server/integrations/iam/b2b-auth-middleware.js` | Validates bearer tokens through introspection and scope checks. |
| ATDR receiver | `frontend/src/pages/LoginPage.tsx` | Receives token/code-like handoff params and clears URL values. |
| ATDR token-login backend | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` | Validates token, maps school email to ATDR user, audits, and issues ATDR JWT. |

## T4 Current Behavior

Before v3.80, ATDR had the v3.79 receiver, but there was no machine-checkable command proving that the official template source still exposes the expected login/token/IAM contract.

## T5 Impacted Areas / Agents

- Security / IAM
- Backend / API
- Frontend / Dashboard
- QA/UAT
- Release/Ops
- Documentation / Governance

## T6 Scope

In scope:

- Add a safe template bridge contract scanner.
- Detect expected template IAM/login/security files.
- Detect expected token/login markers.
- Detect env variable names without values.
- Detect ATDR receiver markers.
- Add tests proving secrets are redacted.
- Document current bridge status and remaining live-provider gaps.

Out of scope:

- Starting the template app.
- Calling live IAM provider.
- Implementing a production callback/code-exchange server.
- Migrating ATDR to Node/Vue/MongoDB.
- Changing detection, ML, response, or database schema.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-V380-001 | Validate the official template path exists and contains required IAM/login files. | Must |
| FR-V380-002 | Detect template `x-access-token`, login, 2FA, introspection, and profile markers. | Must |
| FR-V380-003 | Detect ATDR handoff receiver and backend token-login markers. | Must |
| FR-V380-004 | Report env variable names only, never env values. | Must |
| FR-V380-005 | Provide a recommended local handoff URL shape. | Must |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Contract command returns `ok: true` against the current official template path. | Script run |
| AC-002 | Secret values are not present in the report. | Unit test |
| AC-003 | Missing template files are reported clearly. | Unit test |
| AC-004 | ATDR receiver markers are detected. | Script run and unit test |

## T9 API Contract

No runtime API contract changed.

The bridge continues to rely on:

```text
GET /api/auth/mfu-iam/public-status
POST /api/auth/mfu-iam/token-login
```

## T10 Data Model / Migration

No schema changes and no Alembic migration.

## T11 Backend Plan / Changes

Added read-only validation logic:

- `atdr/app/services/template_bridge_contract.py`
- `atdr/scripts/validate_template_bridge_contract.py`

The scanner reads source files and env variable names only. It does not call IAM, does not validate a live user, and does not print secrets.

## T12 Frontend Plan / Changes

No frontend runtime code changed in v3.80. The v3.79 receiver remains the frontend handoff implementation.

## T13 Security / Response / AI Safety

- Secret values are redacted by design.
- No `.env` files are committed.
- No provider token is printed.
- No response actions are created.
- No detection runs are started.
- No labels, model runs, or users are modified.
- Real firewall blocking remains disabled.
- SOC Assistant remains read-only.

## T14 Test Plan

| Test | Command / Method | Required? |
| --- | --- | --- |
| Contract command | `python -m atdr.scripts.validate_template_bridge_contract --pretty` | yes |
| Unit tests | `python -m pytest atdr\tests\test_template_bridge_contract.py -q` | yes |
| Ruff | `ruff check ...` | yes |
| Compile | `python -m compileall -q ...` | yes |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `atdr/app/services/template_bridge_contract.py` | Added safe scanner for template files, env names, markers, and ATDR receiver contract. |
| `atdr/scripts/validate_template_bridge_contract.py` | Added CLI wrapper returning a non-secret JSON report. |
| `atdr/tests/test_template_bridge_contract.py` | Added tests for positive detection, missing-file reporting, and secret redaction. |
| `docs/V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md` | Added v3.80 status and manual flow documentation. |
| `docs/changes/T1_T20_V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md` | Added completed T1-T20 record. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_bridge_contract --pretty` | pass | `ok: true`, template contract detected, ATDR receiver detected, secrets exposed `false`. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_template_bridge_contract.py -q --basetemp .pytest_tmp\template-bridge -p no:cacheprovider` | pass | `2 passed`. |
| `.\.venv\Scripts\ruff.exe check atdr\app\services\template_bridge_contract.py atdr\scripts\validate_template_bridge_contract.py atdr\tests\test_template_bridge_contract.py` | pass | Ruff passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr\app\services\template_bridge_contract.py atdr\scripts\validate_template_bridge_contract.py atdr\tests\test_template_bridge_contract.py` | pass | Compile passed. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md` | yes | New implementation/status doc. |
| `docs/changes/T1_T20_V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md` | yes | Change evidence. |
| `docs/AI-DOCS-INDEX.md` | yes | Added v3.80 link. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Added v3.80 traceability row. |
| `docs/tasks/tasklist-progress.md` | yes | Added task/progress/verification entry. |
| `docs/tasks/tasklist-progress.html` | yes | Regenerated board. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Passing source-contract validation does not prove live IAM provider login works.
- Passing local token handoff does not prove production-safe handoff.
- Query-token handoff is acceptable for controlled local validation but should be replaced with short-lived code exchange for production-like deployment when possible.

### Blockers

- Live validation still requires private provider configuration and a running template shell.
- Exact callback/code-exchange contract still requires advisor/provider confirmation.

### Assumptions

- Template `x-access-token` is an introspectable or exchangeable token after login/2FA.
- ATDR can treat the template as the outer account lifecycle owner.
- Local ATDR login remains fallback.

### Decisions

- Add source-contract validation before modifying the official template runtime.
- Do not copy template secrets.
- Do not migrate ATDR stacks.

## T19 Release / Rollback

Rollback is code/docs only. Remove the new scanner, script, test, and docs if needed. No data rollback is required.

## T20 Final Handoff

Run:

```powershell
cd <ATDR_ROOT>
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_bridge_contract --pretty
```

If it returns `ok: true`, the next runtime step is to launch the template shell, complete login/2FA, obtain the template handoff material through a safe local-only bridge, and open ATDR through the v3.79 receiver URL.
