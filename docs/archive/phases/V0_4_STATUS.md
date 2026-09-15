# ATDR v0.4 Status

## Scope

v0.4 keeps ATDR on the current FastAPI + React + SQLAlchemy/Alembic + Python ML stack. It does not migrate to NewSystem's Node/Vue/MongoDB stack.

## IAM Status

- Local username/password login remains active.
- Local users can now carry school-email account metadata.
- Local email login is configurable with `LOCAL_EMAIL_LOGIN_ENABLED=true`.
- School-domain enforcement is configurable with `SCHOOL_EMAIL_DOMAINS` and `REQUIRE_SCHOOL_EMAIL`.
- OIDC remains disabled by default.
- `GET /api/auth/oidc/status` exposes only non-secret status values.
- SMTP/invite email settings are placeholders only and disabled by default.

Current user fields include:

- username
- email
- role
- email_verified
- auth_provider
- external_subject
- last_login_at
- invited_at
- disabled_at

## Dashboard Status

- The dashboard uses a hybrid SOC/admin theme: dark navigation with lighter working surfaces.
- Admin / Settings shows local login, OIDC status, school-email policy, and email-login status.
- ML Governance uses concise labels such as Decision Support, Analyst Review, SOC Triage Mode, and Automation Disabled.

## Performance Status

- The Overview summary service was profiled against the large local SQLite database.
- Isolated uncached summary generation was about 0.47 seconds during this pass.
- A short TTL cache was added for the API-facing Overview summary to reduce repeated expensive refreshes under SQLite contention.
- `performance_smoke` now reports both uncached and cached Overview timings.

## Safety Status

- Response remains simulated and analyst-approved.
- Automatic response remains disabled.
- Real firewall blocking is not implemented.
- ML remains decision support only.
- No production readiness claim is made.

## Remaining Work

- Full external OIDC login flow.
- Mock-provider OIDC integration tests.
- SMTP invite/reset email flow.
- Viewer/read-only role.
- v0.6 controlled small-subnet threat detection capability validation.
- Real router/firewall syslog validation with lab hardware.
- PostgreSQL/Docker lab deployment validation.

## v0.6 Handoff

The active controlled threat detection validation phase is documented in `docs/V0_6_THREAT_DETECTION_VALIDATION.md`. It keeps v0.4 behavior intact while adding expectation-based safe scenarios, defensive detection checks, and ignored validation reports. `docs/V0_5_REAL_SOURCE_VALIDATION_PLAN.md` remains the future hardware validation plan.
