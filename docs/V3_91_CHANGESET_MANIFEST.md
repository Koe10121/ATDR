# v3.91 MFU Outer-Shell Handoff Changeset Manifest

## Baseline

- Baseline checkpoint: `docs/V3_88_CHANGESET_MANIFEST.md` and `docs/CURRENT_SYSTEM_STATE_LOCK.md`.
- The ATDR worktree contained pre-existing, uncommitted productization work before v3.91. It was inspected with `git status --short --untracked-files=all`; no reset, checkout, or database deletion was performed.
- The official MFU template is an external workspace at `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`. It is not merged into ATDR or treated as an ATDR runtime dependency beyond the configured handoff boundary.

## In-Scope ATDR Changes

| Area | Intended Change |
| --- | --- |
| Authentication | Retire direct browser token handoff and add opaque-code form consumption with an ATDR HttpOnly cookie session. |
| Identity verification | Exchange the opaque code server-to-server with the template backend using a private bridge secret. |
| Authorization | Default verified external users to `analyst`; allow `admin` only for an explicit configured IAM group. |
| Routing | Validate exact template origin and allow-listed ATDR return paths; reject legacy credential URLs. |
| Diagnostics | Keep public login status minimal; make detailed IAM status admin-only and show only safe configuration/validation state. |
| Tests | Cover code rejection, origin validation, cookie session, role mapping, no side effects, route contract, and secret hiding. |
| Documentation | Record the current architecture, preproduction checklist, rollback, RBAC, traceability, and T1-T20 evidence. |

## In-Scope Official Template Changes

| Area | Intended Change |
| --- | --- |
| Backend | Add one-time-code start/exchange endpoints protected by the existing template session and a private bridge secret. |
| Storage | Store only a SHA-256 code hash, expiry, and consumed timestamp. |
| Frontend | Launch ATDR through a form POST, never a token-bearing URL. |
| Routing | Use the registered `/mfu-ai-driven-log-based-threat-detection-and-response/registry` shell route rather than an unregistered legacy path. |

## Explicitly Excluded

- Any `.env` file, client secret, bridge secret, API key, password, OTP, token value, database file, real log, model artifact, generated report, `ml_baseline_reviews/`, `demo_exports/`, or processed-data output.
- Direct ATDR-owned Google/OIDC callback implementation, IAM group creation, IAM permission bootstrap, provider account creation, and provider-side changes.
- Detection logic, ML training/promotion, response automation, real firewall blocking, and database schema changes.

## Data And Safety Impact

- No ATDR tables or migrations are changed by v3.91.
- A successful configured handoff can create or update an external ATDR user and writes an audit record. It cannot create alerts, detection runs, response actions, labels, model runs, or delete data.
- The handoff is disabled until both private environments contain matching approved configuration.

## Rollback

Set `MFU_IAM_HANDOFF_ENABLED=false` in ATDR and `ATDR_HANDOFF_ENABLED=false` in the template, then restart both services. Local ATDR login remains available. No database rollback is required.

## Evidence

- Current design: `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`
- Preproduction checklist: `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`
- Change record: `docs/changes/T1_T20_V3_91_MFU_OUTER_SHELL_IAM_HANDOFF.md`
- Contract and security tests: `atdr/tests/test_mfu_iam_handoff.py`, `atdr/tests/test_template_bridge_contract.py`, `atdr/tests/test_template_shell_runtime.py`

## Provider-Side Prerequisites Observed During Audit

The existing template source provides the required code boundary, but its preproduction/private configuration still needs administrator action: approved IAM credentials, any required Google/MFU Mail client registration, matching `ATDR_HANDOFF_*` backend settings, matching frontend consume URL settings, exact allowed origins, and explicit ATDR admin-group identifiers. These values must be supplied through private configuration only.
