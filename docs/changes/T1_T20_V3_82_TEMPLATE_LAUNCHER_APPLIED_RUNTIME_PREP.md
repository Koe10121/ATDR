# T1-T20 Change Document: v3.82 Template Launcher Applied And Runtime Prep

## T1 Change Title

v3.82 Template Launcher Applied And Runtime Prep

## T2 Requirement

The official supervisor template must be able to act as the outer authenticated shell and launch ATDR after successful school/IAM login, without copying secrets or migrating ATDR stacks.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Active goal | `C:\Users\User\.codex\attachments\6f0b9e08-b585-49fa-ae27-3adddc1ebc9d\goal-objective.md` | Requires supervisor template as outer application shell / IAM gateway, then open ATDR after login. |
| Template registry page | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue\src\projects\views\mfuaidrivenlogbasedthreatdetectionandresponse\MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue` | Authenticated project page now has the ATDR launcher. |
| ATDR launcher helper | `atdr/scripts/apply_template_atdr_launcher.py` | Applied the launcher with backup. |
| ATDR handoff receiver | `frontend/src/pages/LoginPage.tsx` | Receives and cleans handoff token/code URL values. |
| ATDR token-login backend | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` | Validates external token and maps a school email user into ATDR. |

## T4 Current Behavior

Before v3.82, the launcher helper existed and dry-run showed it could patch the official template, but the template copy was not yet modified. After v3.82, the external template copy has an **Open ATDR SOC Dashboard** button.

## T5 Impacted Areas / Agents

- Security / IAM
- Frontend / Template Shell
- Backend / API
- QA/UAT
- Release/Ops
- Documentation / Governance

## T6 Scope

In scope:

- Apply the v3.81 helper to the official template copy with backup.
- Verify post-write idempotency.
- Verify launcher markers exist.
- Document runtime test steps.

Out of scope:

- Committing external template files to ATDR.
- Printing/copying template secrets.
- Running live provider IAM login.
- Changing ATDR detection/ML/schema/response behavior.
- Enabling automatic response or real firewall blocking.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-V382-001 | Apply ATDR launcher to the official template registry page. | Must |
| FR-V382-002 | Create a backup of the original template page. | Must |
| FR-V382-003 | Verify the helper becomes idempotent after write. | Must |
| FR-V382-004 | Document how to start both systems and test the launcher. | Must |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Helper reports `changed: true` during write. | Script output |
| AC-002 | Backup path is created. | File listing |
| AC-003 | Post-write dry-run reports `already_installed: true` and `would_change: false`. | Script output |
| AC-004 | Template page contains launcher markers. | `Select-String` |
| AC-005 | No secrets are exposed. | Script output and hygiene scan |

## T9 API Contract

No ATDR API changed.

The launcher opens:

```text
GET /login?mfu_token=<template-session-value>&next=/assistant&source=template-shell
```

ATDR then uses the existing:

```text
POST /api/auth/mfu-iam/token-login
```

## T10 Data Model / Migration

No schema changes and no Alembic migration.

## T11 Backend Plan / Changes

No ATDR backend code changed in v3.82.

## T12 Frontend Plan / Changes

External template copy changed:

- added `Open ATDR SOC Dashboard`
- added `canOpenAtdr`
- added `getTemplateAccessToken()`
- added `openAtdrSocDashboard()`

ATDR React frontend was already updated in v3.79.

## T13 Security / Response / AI Safety

- No token values are printed.
- Backup is local to the external template copy.
- No `.env` is committed.
- No response actions are created.
- No detection/model/label/user mutation occurs in ATDR.
- Local ATDR login remains fallback.
- Real firewall blocking remains disabled.
- Response automation remains disabled.

## T14 Test Plan

| Test | Command / Method | Required? |
| --- | --- | --- |
| Apply launcher | `python -m atdr.scripts.apply_template_atdr_launcher --write --pretty` | yes |
| Idempotency | `python -m atdr.scripts.apply_template_atdr_launcher --pretty` | yes |
| Marker check | `Select-String ...` | yes |
| Task board | `node scripts/render-tasklist-progress-html.js .`; `node scripts/check-tasklist-progress-standard.js .` | yes |
| Release gate | `python -m atdr.scripts.verify_release` | yes |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| external template registry page | Added ATDR launcher button and handoff URL builder. |
| `docs/V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md` | Added runtime prep and test steps. |
| `docs/changes/T1_T20_V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md` | Added this completed change record. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --write --pretty` | pass | `changed: true`, backup path returned, secrets exposed `false`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --pretty` | pass | `already_installed: true`, `would_change: false`. |
| `Select-String` marker check | pass | Launcher button, method, URL config, handoff value, and `mfu_token` marker present. |
| `node scripts/render-tasklist-progress-html.js .` | pass | HTML board regenerated. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Progress-board check passed. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md` | yes | New runtime-prep status. |
| `docs/changes/T1_T20_V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md` | yes | Change evidence. |
| `docs/AI-DOCS-INDEX.md` | yes | Added v3.82 link. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Added v3.82 row. |
| `docs/tasks/tasklist-progress.md` | yes | Added v3.82 task and evidence. |
| `docs/tasks/tasklist-progress.html` | yes | Regenerated. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- A URL token handoff is still not the preferred production-like design.
- The template token may not be accepted by ATDR until private MFU IAM config is enabled and validated.

### Blockers

- Live runtime validation still requires starting the template app and logging in.
- If the token payload lacks user email or accepted audience, a code exchange or provider-specific adapter will be needed.

### Assumptions

- The template authenticated page has access to `XAccessToken` or `localStorage["x-access-token"]`.
- ATDR local frontend runs at `http://127.0.0.1:5173`.

### Decisions

- Patch external template copy with backup.
- Keep ATDR code unchanged in this phase.
- Keep local login fallback.

## T19 Release / Rollback

Rollback the external template page by restoring:

```text
MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue.bak-20260711T125345Z
```

No ATDR database rollback is required.

## T20 Final Handoff

Next manual runtime test:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

```powershell
cd C:\Users\User\Desktop\ATDR\frontend
npm.cmd run dev
```

```powershell
cd C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node
npm.cmd install
npm.cmd run start:local
```

```powershell
cd C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue
npm.cmd install
npm.cmd run serve:local
```

Then login through the template and click **Open ATDR SOC Dashboard**.
