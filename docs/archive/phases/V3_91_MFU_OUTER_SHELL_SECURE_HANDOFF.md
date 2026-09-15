# v3.91 MFU Outer-Shell Secure Handoff

## Status

Implemented and verified through focused handoff tests, the full backend suite, React lint/build/Playwright, the template backend contract suite, replay dry-run, performance smoke, Alembic check, and release gate. The official MFU template is the school identity and outer application shell; ATDR remains a separate FastAPI + React SOC application behind that shell. This is a secure handoff implementation, not a production IAM certification.

The current local configuration intentionally leaves the secure handoff disabled. Its safe provider/runtime checks report the missing private provider, bridge-secret, and allowed-origin configuration without exposing a secret or attempting external authentication. That is the expected fail-closed state until the approved MFU preproduction configuration is supplied.

## Current Architecture

1. A user signs in through the official MFU template, including its configured school-email and 2FA flow.
2. The template backend verifies the existing template session and creates a cryptographically random, short-lived, single-use handoff code.
3. The template frontend submits that code in a browser form POST to ATDR.
4. ATDR checks the template origin, asks the template backend to exchange the code over a server-to-server bridge, and receives only a minimal identity payload.
5. ATDR maps the identity to a local external user, defaults new users to `analyst`, and maps `admin` only from configured IAM groups.
6. ATDR sets its own HttpOnly session cookie and redirects to the allowed React route.

The school session token, IAM client secret, bridge secret, password, and OTP never appear in a React URL, browser storage, ATDR API response, audit record, or Git-tracked file.

## Source Evidence

| Area | Evidence |
| --- | --- |
| ATDR consume route and cookie session | `atdr/app/routers/auth.py`, `atdr/app/core/security.py` |
| ATDR server-side exchange and user mapping | `atdr/app/services/mfu_iam_service.py` |
| Safe configuration/status | `atdr/app/core/config.py`, `atdr/app/schemas/auth.py`, `atdr/scripts/config_doctor.py` |
| Template one-time-code service | `backend-node/server/Project/atdr/service/atdr_handoff.js` in the official template workspace |
| Template routes and Vue form submit | `backend-node/server/Project/atdr/atdr_handoff.routes.js`, `frontend-vue/src/projects/utils/atdr-handoff.js`, `frontend-vue/src/views/Dashboard.vue` |
| Security regression tests | `atdr/tests/test_mfu_iam_handoff.py`, `atdr/tests/test_template_bridge_contract.py`, `atdr/tests/test_template_shell_runtime.py`, external `backend-node/test/atdr-handoff-service.test.js` |
| Change manifest | `docs/V3_91_CHANGESET_MANIFEST.md` |

The detailed `GET /api/auth/mfu-iam/status` diagnostic is admin-only and includes only the latest safe handoff outcome (`passed`, `failed`, or `not_run`), timestamp, and a fixed safe reason. The public login page uses the intentionally limited `GET /api/auth/mfu-iam/public-status` response, which exposes no secret or provider-response values.

## Retired Pattern

The old browser token handoff route, `POST /api/auth/mfu-iam/token-login`, is retired. It is not part of the v3.91 API surface. Old links containing token-like query or fragment values are removed from the URL and show a safe error instead of attempting sign-in.

Older v3.65-v3.86 documents are retained as historical change evidence. Their token-handoff descriptions are superseded by this document and the v3.91 T1-T20 record.

## Route And 404 Diagnosis

The template Vue router registers the ATDR shell page at `/mfu-ai-driven-log-based-threat-detection-and-response/registry`. A link to a differently spelled or legacy path resolves to the template's Vue 404 page. The current registry launcher is contract-tested against that registered route and starts the opaque-code form POST; it does not redirect a browser token to ATDR.

## Private Configuration Checklist

Do not copy secrets into source control or chat. Generate one new random bridge secret and place the same value in the two private environment files.

### Official template private environment

```text
ATDR_HANDOFF_ENABLED=true
ATDR_HANDOFF_SHARED_SECRET=<new-random-secret>
ATDR_HANDOFF_SECRET_HEADER=x-atdr-handoff-secret
ATDR_HANDOFF_TTL_SECONDS=60
ATDR_HANDOFF_CONSUME_URL=http://127.0.0.1:8000/api/auth/mfu-iam/handoff/consume
ATDR_HANDOFF_ALLOWED_DOMAINS=<approved-school-domain>
ATDR_HANDOFF_ALLOWED_RETURN_PATHS=/overview,/alerts,/logs,/assistant,/response,/audit,/ml
VUE_APP_ATDR_HANDOFF_CONSUME_URL=http://127.0.0.1:8000/api/auth/mfu-iam/handoff/consume
```

### ATDR private `.env`

```text
MFU_IAM_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_BASE_URL=http://127.0.0.1:8214
MFU_IAM_HANDOFF_ENABLED=true
MFU_IAM_HANDOFF_SHARED_SECRET=<same-new-random-secret>
MFU_IAM_HANDOFF_ALLOWED_ORIGINS=<exact-template-frontend-origin>
MFU_IAM_HANDOFF_FRONTEND_URL=http://127.0.0.1:5173
MFU_IAM_ALLOWED_DOMAINS=<approved-school-domain>
MFU_IAM_ADMIN_GROUPS=<approved-ATDR-admin-group-identifiers>
```

Generate the bridge secret locally, never in Git:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

If the official template files previously contained a real-looking IAM admin or client secret, treat it as potentially exposed and ask the provider/advisor to rotate it before preproduction use.

## Validation Sequence

1. Start the official template backend and Vue frontend using that project's documented private configuration.
2. Start ATDR normally:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

3. Run the non-mutating readiness check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

4. Sign in through the template and open ATDR from its registered dashboard/registry entry.
5. Confirm ATDR opens the requested allowed route, `/api/auth/me` succeeds with the cookie session, the user is an `analyst` unless an IAM group maps to admin, and an `mfu_iam_login_success` audit exists without credentials.

## Safety And Remaining Work

- Local ATDR username/password login remains a configurable recovery path.
- The handoff is read-only from the identity perspective: it cannot run detection, alter labels, activate models, delete data, execute response actions, or enable response automation.
- Real firewall blocking remains disabled.
- The template's actual MFU provider, 2FA enforcement, group values, account recovery, deprovisioning, HTTPS/reverse-proxy behavior, and preproduction runtime evidence still require approved environment details and live validation.
- ATDR does not claim production readiness from source-level or local validation alone.
