# v3.74 MFU IAM Validation Harness

## Purpose

v3.74 adds a safe validation harness for the MFU school-email IAM direction. It lets ATDR check whether MFU IAM configuration is complete and, only when explicitly requested, run a limited provider probe without exposing secrets or changing login behavior.

This is a productization step toward real school-email IAM. It does not enable a full OAuth browser callback flow and does not replace local login.

## What Changed

- Added `atdr/app/services/mfu_iam_validation.py`.
- Added `atdr/scripts/test_mfu_iam_provider.py`.
- Added focused tests in `atdr/tests/test_mfu_iam_validation.py`.
- The harness reports:
  - enabled/disabled status
  - B2B readiness
  - token-login readiness
  - admin API readiness
  - permission bootstrap readiness
  - allowed domains
  - Google SSO configured status
  - runtime safety issues
  - whether a provider probe was executed
  - whether secrets were exposed
- The default command performs no provider call.
- `--execute` is required for mock or live probing.

## Commands

Safe status check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty
```

Explicit provider probe:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --execute --pretty
```

Optional token introspection/profile probe:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --execute --token "<private-token>" --pretty
```

Do not paste tokens into screenshots, docs, or Git history.

## Safety Behavior

- No secrets are printed.
- No access tokens are printed.
- No provider profile email is printed.
- No database rows are created.
- No local user is created.
- No normal login behavior changes.
- MFU IAM remains disabled unless configured in private `.env`.
- Local username/password login remains the fallback.
- Response automation remains disabled.
- Real firewall blocking remains disabled.

## Supervisor Template Alignment

The harness is based on the supervisor template's IAM evidence:

- `IAM_SDK_*` / `IAM_ADMIN_*` client credential and token/introspection/profile paths.
- B2B token introspection flow.
- Permission source/bootstrap variables.
- Google/MFU Mail login direction.
- OTP/2FA direction.

ATDR implements this as a Python/FastAPI-compatible validation layer instead of copying Node/Vue/MongoDB runtime code.

## What Still Requires Provider Input

- Approved MFU IAM client ID and client secret in private `.env`.
- Approved audience and scopes.
- Confirmed token endpoint behavior.
- Confirmed introspection response shape.
- Confirmed profile response shape.
- Allowed school-email domains.
- Group-to-role mapping.
- Browser login callback/redirect details if OAuth or Google/MFU Mail login is enabled later.
- 2FA/OTP policy.

## Verification

Focused verification:

```powershell
.\.venv\Scripts\ruff.exe check atdr\app\services\mfu_iam_validation.py atdr\scripts\test_mfu_iam_provider.py atdr\tests\test_mfu_iam_validation.py
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_mfu_iam_validation.py -q --basetemp .pytest_tmp\v374-mfu-iam -p no:cacheprovider
.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty
```

Current focused result:

- Ruff passed.
- v3.74 tests: `3 passed`.
- Safe status command ran without provider call and without exposing secrets.

## Remaining Gaps

- Full external school-email login is not complete.
- Google/MFU OAuth callback is not implemented.
- Real provider probing depends on private `.env` values and live provider access.
- Path/action permission matrix is still future RBAC v2 work.
- Provider-managed 2FA/OTP remains future work.
