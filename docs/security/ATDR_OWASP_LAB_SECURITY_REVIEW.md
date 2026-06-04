# ATDR OWASP Lab Security Review

This is a lightweight ATDR security review following the same security-review discipline used by the NewSystem template. It is not a penetration test and does not certify production readiness.

## Source Evidence

| Area | Source |
| --- | --- |
| App startup, CORS, security middleware | `atdr/app/main.py`, `atdr/app/core/middleware.py` |
| Runtime config validation | `atdr/app/core/config.py` |
| JWT auth and role checks | `atdr/app/core/security.py` |
| User routes | `atdr/app/routers/users.py` |
| Response safety | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py` |
| Audit behavior | `atdr/app/routers/audit.py`, `atdr/app/db/models.py` |
| IAM/RBAC matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| Response safety tests | `atdr/tests/test_response_safety.py`, `atdr/tests/test_iam_rbac.py` |

## Executive Summary

ATDR is suitable for controlled lab validation with local JWT auth, admin/analyst RBAC, simulated response, and audit logging. It is not production-hardened.

| OWASP Area | Current Lab Status | Notes |
| --- | --- | --- |
| A01 Broken Access Control | Partially mitigated | Protected routes use JWT and role dependencies. Viewer role and fine-grained external IAM remain future work. |
| A02 Cryptographic Failures | Lab-limited | JWT secret is configurable, but demo secret must be replaced before shared lab or real deployment. |
| A03 Injection | Partially mitigated | SQLAlchemy is used for DB access. File-path import workflows must remain admin-only and avoid committing real paths. |
| A04 Insecure Design | Mitigated for response automation | ML cannot trigger response; response remains simulated and approval-based. |
| A05 Security Misconfiguration | Partially mitigated | Runtime config doctor and production validation exist; local `.env` remains user-managed and ignored. |
| A06 Vulnerable Components | Needs routine review | Dependency scanning is future work. |
| A07 Authentication Failures | Lab-limited | Basic JWT auth and login rate limit exist. Strong password policy, lockout, and external IAM are future work. |
| A08 Software/Data Integrity | Partially mitigated | Release gate exists; model artifacts and real logs are ignored. Signed releases are future work. |
| A09 Logging/Monitoring Failures | Partially mitigated | Audit logs and operation run history exist. Centralized monitoring/retention are future work. |
| A10 SSRF | Low current exposure | No general URL-fetching feature is exposed. Future connectors must be reviewed. |

## Current Controls

- JWT authentication for protected APIs.
- Admin/analyst role checks in backend route dependencies.
- React route guards and role-aware navigation as secondary UX controls.
- Security headers middleware with HSTS enabled only in production mode.
- Production config validation blocks unsafe defaults.
- Simulated response only by default.
- Response actions require justification and protected-IP checks.
- Denied response attempts are audited.
- ML outputs are decision support only.
- Real logs, `.env`, DB files, and model artifacts are ignored by Git.

## Current Gaps

- No external SSO/OAuth/SAML/LDAP.
- No viewer/read-only role.
- Demo JWT secret must be replaced before shared lab or real deployment.
- Password policy and account lockout should be strengthened before shared lab use.
- No production-grade audit retention/archival policy yet.
- No dependency vulnerability scan is part of the release gate yet.
- No real firewall connector has been security-reviewed because real enforcement is not implemented.

## Required Safety Position

ATDR must continue to state:

- lab-ready prototype, not production-certified
- ML decision support only
- no automatic response
- simulated response only
- real firewall blocking is future approved work only

