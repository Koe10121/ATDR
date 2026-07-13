# ATDR IAM / RBAC Matrix

ATDR adapts the university IAM requirement as local authentication, authorization, role-based access control, response-safety permission checks, and auditability. v3.91 adds an optional MFU outer-shell secure handoff: the official template owns school sign-in and 2FA, while ATDR receives a short-lived opaque code, exchanges it server-to-server, creates its own HttpOnly session, and maps users to `analyst` by default. ATDR still does not implement a direct ATDR-owned OAuth callback, SAML, LDAP, or a general enterprise identity provider. Local email verification/dev-outbox groundwork remains disabled by default, and ATDR does not send real email by default.

ATDR is a controlled lab-ready prototype. The current IAM/RBAC model is suitable for local and lab validation, not final production identity governance.

## Source Evidence

| Area | Repository Source |
| --- | --- |
| JWT auth, active-user check, role dependencies | `atdr/app/core/security.py` |
| Login, current-user, password-change routes | `atdr/app/routers/auth.py` |
| External IAM groundwork plan | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| MFU IAM adapter plan and provider checklist | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` |
| Secure MFU outer-shell handoff | `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`, `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`, `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` |
| User model and role field | `atdr/app/db/models.py` |
| User lifecycle and demo users | `atdr/app/services/user_service.py` |
| Email verification and dev outbox groundwork | `atdr/app/services/account_verification_service.py`, `atdr/app/services/email_service.py`, `atdr/app/routers/auth.py`, `atdr/app/routers/users.py` |
| Account lifecycle and email verification UX | `frontend/src/components/AppShell.tsx`, `frontend/src/pages/UserAdmin.tsx`, `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md` |
| User admin routes | `atdr/app/routers/users.py` |
| Log import and log investigation routes | `atdr/app/routers/logs.py` |
| Alerts, cases, status, assignment, notes, timeline | `atdr/app/routers/alerts.py` |
| Source management routes | `atdr/app/routers/sources.py` |
| Detection run routes | `atdr/app/routers/detection.py` |
| ML governance, labels, model training/scoring | `atdr/app/routers/ml.py` |
| Response routes and protected-IP checks | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py` |
| Audit log route | `atdr/app/routers/audit.py` |
| Frontend protected routes and admin-only route guard | `frontend/src/App.tsx`, `frontend/src/components/ProtectedRoute.tsx`, `frontend/src/components/AdminRoute.tsx` |
| Role-aware navigation and response controls | `frontend/src/components/AppShell.tsx`, `frontend/src/pages/AlertsTriage.tsx`, `frontend/src/pages/ResponseCenter.tsx` |
| Existing auth/response tests | `atdr/tests/test_api.py`, `atdr/tests/test_response_safety.py` |

## Current Roles

| Role | Status | Purpose |
| --- | --- | --- |
| Admin | Supported now | Full lab operator role. Can manage users, sources, demo controls, log import, ML training/scoring, and simulated response actions. |
| Analyst | Supported now | SOC analyst role. Can investigate logs/alerts, update alert lifecycle, add notes, run detection, review labels, view AI Governance, and view audit evidence. |
| Viewer / read-only | Future work | Not currently implemented. A future viewer role should be read-only and must be enforced in backend dependencies, not only the UI. |

## Permission Matrix

| Capability | Admin | Analyst | Viewer / Read-only | Evidence |
| --- | --- | --- | --- | --- |
| Login and view own session | Supported now | Supported now | Future work | `atdr/app/routers/auth.py` |
| Login by local username or email | Supported now | Supported now | Future work | `atdr/app/routers/auth.py`, `atdr/app/services/user_service.py` |
| Open ATDR through approved MFU outer shell | Source implementation complete; preproduction validation pending | Source implementation complete; preproduction validation pending | Future work | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py`, `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md` |
| View OIDC status | Supported now | Supported now | Future work | `atdr/app/routers/auth.py`, `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| View detailed MFU IAM adapter status | Supported now | Not allowed | Future work | `atdr/app/routers/auth.py`, `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md` |
| View email verification status | Supported now | Supported now | Future work | `atdr/app/routers/auth.py`, `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md` |
| View account lifecycle/email status in dashboard | Supported now | Supported for own header status; full user list is admin-only | Future work | `frontend/src/components/AppShell.tsx`, `frontend/src/pages/UserAdmin.tsx` |
| Request own email verification | Supported now | Supported now | Future work | `atdr/app/routers/auth.py`, `atdr/app/services/account_verification_service.py` |
| Verify own email code | Supported now | Supported now | Future work | `atdr/app/routers/auth.py`, `atdr/app/services/account_verification_service.py` |
| Overview dashboard | Supported now | Supported now | Future work | `atdr/app/routers/dashboard.py`, `frontend/src/App.tsx` |
| Alerts / Alert Workbench list and details | Supported now | Supported now | Future work | `atdr/app/routers/alerts.py` |
| Alert lifecycle: investigating, needs context, contained, resolved, false positive | Supported now | Supported now | Future work | `atdr/app/routers/alerts.py` |
| Alert assignment to self | Supported now | Supported now | Future work | `atdr/app/routers/alerts.py` |
| Assign alert to another user | Supported now | Not allowed | Future work | `atdr/app/routers/alerts.py` |
| Alert notes, timeline, report | Supported now | Supported now | Future work | `atdr/app/routers/alerts.py` |
| Investigation / Log Explorer list and detail | Supported now | Supported now | Future work | `atdr/app/routers/logs.py` |
| Log import through API/dashboard | Supported now | Not allowed | Future work | `atdr/app/routers/logs.py` |
| Detection run and detection history | Supported now | Supported now | Future work | `atdr/app/routers/detection.py` |
| Source list/detail/health | Supported now | Supported now | Future work | `atdr/app/routers/sources.py` |
| Source create/update/disable | Supported now | Not allowed | Future work | `atdr/app/routers/sources.py` |
| AI Governance summary, ML reports, model status | Supported now | Supported now | Future work | `atdr/app/routers/ml.py` |
| Label create/update/import/export | Supported now | Supported now | Future work | `atdr/app/routers/ml.py` |
| Anomaly model training/scoring | Supported now | Not allowed | Future work | `atdr/app/routers/ml.py` |
| Supervised model training | Supported now | Not allowed | Future work | `atdr/app/routers/ml.py` |
| Supervised report/export/prediction view | Supported now | Supported now | Future work | `atdr/app/routers/ml.py` |
| Response & Audit view | Supported now | Supported now | Future work | `atdr/app/routers/response.py`, `atdr/app/routers/audit.py` |
| Simulated block/unblock response | Supported now | Not allowed | Future work | `atdr/app/routers/response.py` |
| User Admin | Supported now | Not allowed | Future work | `atdr/app/routers/users.py`, `frontend/src/components/AdminRoute.tsx` |
| User email, verified-email, provider status management | Supported now | Not allowed | Future work | `atdr/app/routers/users.py`, `frontend/src/pages/UserAdmin.tsx` |
| Send verification for managed user | Supported now | Not allowed | Future work | `atdr/app/routers/users.py`, `frontend/src/pages/UserAdmin.tsx` |
| View dev email outbox | Supported now | Not allowed | Future work | `atdr/app/routers/users.py`, `frontend/src/pages/UserAdmin.tsx` |
| Demo Controls | Supported now | Not allowed | Future work | `atdr/app/routers/demo.py`, `frontend/src/components/AdminRoute.tsx` |
| Threat Controls view suppressions/watchlists | Supported now | Supported now | Future work | `atdr/app/routers/suppressions.py`, `atdr/app/routers/watchlists.py` |
| Threat Controls create/review/disable suppressions | Supported now | Not allowed | Future work | `atdr/app/routers/suppressions.py`, `frontend/src/pages/ThreatControls.tsx` |
| Threat Controls create/disable watchlists | Supported now | Not allowed | Future work | `atdr/app/routers/watchlists.py`, `frontend/src/pages/ThreatControls.tsx` |
| Audit log viewing | Supported now | Supported now | Future work | `atdr/app/routers/audit.py` |

## Backend Enforcement Summary

- Unauthenticated protected requests are rejected through `get_current_user` in `atdr/app/core/security.py`.
- Admin-only behavior uses `require_admin`.
- Analyst/admin behavior uses `require_analyst_or_admin`.
- Inactive users are rejected before role checks.
- User Admin and Demo Controls are admin-only.
- Log import, source create/update, anomaly training/scoring, supervised training, and simulated block/unblock are admin-only.
- Alert investigation, log investigation, detection run, audit view, label review/import/export, and ML report viewing are analyst/admin.
- Response safety is enforced server-side. The UI is not the only control.

## Frontend Enforcement Summary

- `frontend/src/components/ProtectedRoute.tsx` redirects unauthenticated users to login.
- `frontend/src/components/AdminRoute.tsx` renders `AccessDenied` for non-admin users.
- `frontend/src/components/AppShell.tsx` hides admin-only navigation items from analysts.
- Response controls in `frontend/src/pages/AlertsTriage.tsx` and `frontend/src/pages/ResponseCenter.tsx` are disabled for non-admin users.
- Frontend controls are usability protections only. Backend route dependencies remain the authority.

## Response Safety Permissions

| Check | Status | Evidence |
| --- | --- | --- |
| Simulated response only by default | Supported now | `atdr/app/services/response_service.py` |
| Admin-only block/unblock API | Supported now | `atdr/app/routers/response.py` |
| Justification note required | Supported now | `atdr/app/services/response_service.py` |
| Protected/internal/management IP ranges denied | Supported now | `atdr/app/services/response_service.py` |
| Linked alert without evidence is denied | Supported now | `atdr/app/services/response_service.py` |
| Denied attempts are audited | Supported now | `atdr/app/services/response_service.py` |
| ML output cannot trigger automatic response | Supported as a safety constraint and tested | `atdr/app/routers/ml.py`, `atdr/app/routers/detection.py`, `atdr/tests/test_response_safety.py` |
| Real firewall enforcement | Not implemented | Future approved connector work only |

## Current IAM Limitations

- No direct ATDR-owned SSO/OAuth/SAML/LDAP integration.
- No provider-backed preproduction proof for the MFU outer-shell handoff yet.
- No validated external lifecycle/group synchronization, provider logout, recovery, or deprovisioning policy yet.
- No viewer/read-only role yet.
- No real SMTP sending in v3.14; dev outbox is local/admin-only testing groundwork.
- No fine-grained permission table; permissions are role dependencies in FastAPI routes.
- Demo JWT secret must be replaced before shared lab or real deployment.
- Password policy and account lockout behavior are basic and suitable only for prototype/lab use.
- Role permission review is required before any real deployment.

## Future IAM Work

1. Add a read-only `viewer` role if supervisor/demo read-only access is needed.
2. Add stronger password policy, token expiry review, and secret rotation guidance.
3. Run `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md` with approved MFU origins, group identifiers, and secret custody before enabling the handoff outside local testing.
4. Use `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` for any future direct MFU IAM or Google SSO implementation.
5. Add a permission registry if route-level role checks become hard to audit.
6. Re-run this matrix before any real device deployment or response connector implementation.
