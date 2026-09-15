# v5.29.1 Frontend Dependency Security Closure

## Status

v5.29.1 removes the remaining React Router advisories from the ATDR React
dashboard. It preserves the existing routes, role guards, MFU shell handoff,
alert/log deep links, Assistant session state, and visible workflows. No
backend API, database schema, detection, ML, IAM-provider, or response behavior
changed.

## Advisory Evidence

The starting lock resolved `react-router-dom` and `react-router` to `6.30.4`.
`npm audit --json` reported two moderate vulnerabilities:

- `GHSA-wrjc-x8rr-h8h6`: backslash open redirect in navigation; and
- `GHSA-337j-9hxr-rhxg` / `GHSA-jjmj-jmhj-qwj2`: unsafe SSR hydration error
  deserialization and the related React Router DOM redirect/XSS range.

The first minimum upgrade candidate, `7.18.0`, fixed those findings but the
current npm advisory database then identified the newer high-severity
`GHSA-qwww-vcr4-c8h2` RSC CSRF range through `7.18.1`. The final exact version
is therefore `react-router-dom@7.18.2`, which resolves
`react-router@7.18.2`. It supports Node `>=20` and React/React DOM `>=18`,
matching ATDR's Node 20.19 and React 18 baseline.

Final result:

```text
npm audit --audit-level=moderate
found 0 vulnerabilities
```

## Compatibility Changes

- `ProtectedRoute` retains `pathname`, query parameters, and hash in its
  internal post-login return state. A protected alert/log deep link therefore
  returns to the same record after local recovery authentication.
- Login redirect validation rejects network-path references, backslashes,
  URI schemes, colons, and control characters. Invalid state fails closed to
  `/overview`.
- Existing declarative `BrowserRouter`, `Routes`, `Route`, `Navigate`,
  `NavLink`, `Outlet`, location, and search-parameter APIs remain supported.
- No route name, page, navigation label, role boundary, or dashboard workflow
  was redesigned.

## Regression Coverage

New Playwright checks prove:

- a safe protected alert deep link survives login;
- malicious redirect state cannot navigate outside the ATDR origin;
- unknown routes fail closed to authenticated Overview; and
- browser back/forward navigation preserves the Assistant investigation
  session.

Existing coverage continues to exercise local login, MFU handoff errors,
analyst/admin authorization, alert/log deep links, Assistant context and
logout clearing, dropdown click behavior, and horizontal overflow across
projector, laptop, and mobile viewports.

## Verification

- clean install: passed (`npm ci`);
- dependency audit: `0` vulnerabilities at moderate or higher;
- React lint/build: passed;
- Playwright: `31 passed, 1 skipped`;
- Ruff and compileall: passed;
- backend: `852 passed, 1 skipped`;
- Alembic: no drift; and
- release gate: `ok: true` with no failed required checks.

The browser skip is the existing external live-source scenario gate. Existing
scikit-learn sparse-feature/calibration warnings and the Windows pytest-cache
permission warning remain non-failing diagnostics.

## Safety And Remaining Risk

- Rules remain alert-authoritative.
- Supervised ML remains `shadow_observation`.
- The Assistant remains read-only decision support.
- Automatic response and real firewall blocking remain disabled.
- No database reset, migration, data deletion, model activation, or provider
  activation occurred.
- Dependency advisories can change after closure; CI and future release work
  must continue running `npm audit --audit-level=moderate`.

## Recommended Next Phase

v5.30 should return to supervised ML evidence quality: obtain legitimate
independent human-reviewed, schema-compatible, multi-source PAN-OS evidence,
then evaluate the frozen shadow candidate without treating assisted labels as
human truth or changing rule authority.
