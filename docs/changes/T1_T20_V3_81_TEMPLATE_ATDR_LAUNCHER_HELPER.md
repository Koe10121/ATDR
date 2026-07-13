# T1-T20 Change Document: v3.81 Template ATDR Launcher Helper

## T1 Change Title

v3.81 Template ATDR Launcher Helper

## T2 Requirement

ATDR needs a practical, safe way to add an ATDR launch button to the official supervisor template after login, while keeping the template as the outer IAM/account shell and ATDR as the SOC module.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Template registry page | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue\src\projects\views\mfuaidrivenlogbasedthreatdetectionandresponse\MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue` | Project-specific page where an authenticated user can launch ATDR. |
| Template auth store | `frontend-vue/src/store/modules/Authen/index.js` | Stores session as `x-access-token` and Vuex `XAccessToken`. |
| ATDR handoff receiver | `frontend/src/pages/LoginPage.tsx` | Accepts `mfu_token` and clears token-like URL values. |
| ATDR token-login backend | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` | Validates external token/handoff material and maps school email to ATDR user. |

## T4 Current Behavior

Before v3.81, ATDR could receive a handoff URL, but the official template copy did not have a ready helper to add a launch button that opens ATDR with the stored template token.

## T5 Impacted Areas / Agents

- Security / IAM
- Frontend / Template Shell
- Backend / API
- QA/UAT
- Documentation / Governance

## T6 Scope

In scope:

- Add a dry-run-first helper to patch the official template registry page.
- Add an `Open ATDR SOC Dashboard` button in the template when explicitly applied.
- Use the template `x-access-token` / `XAccessToken` as local handoff material.
- Add tests for dry-run, write mode, idempotency, and backup behavior.

Out of scope:

- Automatically modifying the template without `--write`.
- Live provider calls.
- Production-grade code-exchange flow.
- ATDR schema changes.
- Detection/ML/response changes.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-V381-001 | Helper must default to dry-run. | Must |
| FR-V381-002 | Helper must target only the known template registry page. | Must |
| FR-V381-003 | Write mode must create a backup unless disabled. | Must |
| FR-V381-004 | Patch must be idempotent. | Must |
| FR-V381-005 | Patch must not print or store token values. | Must |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Dry-run against official template reports `ok: true`, `would_change: true`, `changed: false`. | Script run |
| AC-002 | Unit tests pass for patch insertion, dry-run, write mode, and backup. | Pytest |
| AC-003 | Ruff passes. | Ruff |
| AC-004 | Secret-pattern scan remains clean. | Hygiene scan |

## T9 API Contract

No runtime API contract changed.

The launcher opens the existing ATDR handoff route:

```text
/login?mfu_token=<template-token>&next=/assistant&source=template-shell
```

## T10 Data Model / Migration

No schema changes and no Alembic migration.

## T11 Backend Plan / Changes

Added:

- `atdr/scripts/apply_template_atdr_launcher.py`

No ATDR backend behavior changed.

## T12 Frontend Plan / Changes

No ATDR frontend runtime behavior changed in v3.81.

The helper can optionally patch the external supervisor template copy when run with `--write`.

## T13 Security / Response / AI Safety

- Dry-run is default.
- No secrets are printed.
- No token values are logged by the helper.
- ATDR local login fallback remains.
- No response action can be triggered.
- No model, label, detection, user, or source mutation occurs.
- Real firewall blocking remains disabled.

## T14 Test Plan

| Test | Command / Method | Required? |
| --- | --- | --- |
| Dry-run helper | `python -m atdr.scripts.apply_template_atdr_launcher --pretty` | yes |
| Unit tests | `python -m pytest atdr\tests\test_template_atdr_launcher.py -q` | yes |
| Ruff | `ruff check atdr\scripts\apply_template_atdr_launcher.py atdr\tests\test_template_atdr_launcher.py` | yes |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `atdr/scripts/apply_template_atdr_launcher.py` | Added dry-run/write helper for patching the template registry page with an ATDR launcher. |
| `atdr/tests/test_template_atdr_launcher.py` | Added tests for patching, dry-run safety, write mode, backup, and idempotency. |
| `docs/V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md` | Added usage and safety documentation. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --pretty` | pass | Dry-run found the template target and reported `would_change: true`, `changed: false`, `secrets_exposed: false`. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_template_atdr_launcher.py -q --basetemp .pytest_tmp\template-launcher -p no:cacheprovider` | pass | `3 passed`. |
| `.\.venv\Scripts\ruff.exe check atdr\scripts\apply_template_atdr_launcher.py atdr\tests\test_template_atdr_launcher.py` | pass | Ruff passed. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md` | yes | New usage/status doc. |
| `docs/changes/T1_T20_V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md` | yes | Change evidence. |
| `docs/AI-DOCS-INDEX.md` | yes | Added v3.81 link. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Added v3.81 traceability row. |
| `docs/tasks/tasklist-progress.md` | yes | Added task/progress/verification entry. |
| `docs/tasks/tasklist-progress.html` | yes | Regenerated board. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Token-in-URL handoff is acceptable for controlled local validation but should be replaced by short-lived code exchange for production-like deployment.
- The helper modifies an external template copy only when explicitly run with `--write`; that change is not tracked by the ATDR Git repo.

### Blockers

- Live runtime validation still requires starting the template shell and configuring the private IAM/mock login path.

### Assumptions

- The template authenticated page has access to Vuex `XAccessToken` or browser `x-access-token`.
- ATDR runs at `http://127.0.0.1:5173` for local validation unless `VUE_APP_ATDR_DASHBOARD_URL` is configured.

### Decisions

- Keep the helper dry-run by default.
- Do not automatically edit the template.
- Keep ATDR as FastAPI + React + SQLAlchemy/Alembic.

## T19 Release / Rollback

No ATDR runtime rollback is needed. If `--write` is used on the template, restore the generated backup file or revert the changed Vue page in the external template copy.

## T20 Final Handoff

Dry-run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --pretty
```

Apply when ready:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --write --pretty
```
