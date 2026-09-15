# v5.53 MFU IAM And Shared Deployment Readiness

Date: 2026-09-01

## Decision

ATDR now has a fail-closed, secret-safe readiness contract for its MFU shell,
shared deployment, Assistant provider, teammate runtime, and repository
security controls. The normal entry remains the MFU template shell. Local
SQLite remains supported, while the existing PostgreSQL, worker, reverse
proxy, monitoring, backup, restore, and recovery assets remain the shared-host
path.

This phase completes the repository work that can be done without pretending
that an external owner has accepted the system. It does not certify MFU IAM,
an approved host, Gemini institutional use, a physical teammate machine, or
production readiness.

## Implemented

- Explicit CORS methods, request headers, and exposed response headers replace
  wildcard application policy.
- Template-shell callbacks, frontend origins, return paths, default role,
  mock mode, secure-cookie expectations, and private evidence-root settings
  fail closed during configuration validation.
- `GET /api/operations/release-readiness` gives admins aggregate readiness for
  IAM, database profile, migrations, workers, backups, monitoring, HTTPS,
  managed secrets, recovery evidence, Gemini, teammate runtime, and security.
- Four expiring private evidence contracts distinguish real acceptance from
  configuration:
  - MFU IAM lifecycle acceptance;
  - approved shared-host deployment and recovery;
  - Assistant-provider governance; and
  - physical teammate clean-clone acceptance.
- `run_v553_release_readiness` is read-only by default. Database probing and
  empty evidence-template generation each require a separate exact
  confirmation phrase.
- `run_v553_team_runtime_acceptance` validates an approved MFU shell source and
  can rehearse setup/start/health/stop in disposable storage after an exact
  execution confirmation. It never writes a successful acceptance manifest.
- Repository security now includes high-confidence secret/path scanning,
  CycloneDX SBOM generation, Python and npm dependency auditing, and scheduled
  Python/TypeScript CodeQL.
- The Python dependency lock is pip-compiled with hashes. The audit baseline
  moved from 70 known advisories in nine packages to zero known advisories.
- Admin and AI Governance show compact operational state without raw
  configuration, keys, provider payloads, or classroom wording.

## Current Local Result

| Area | Result |
| --- | --- |
| Template-shell mode | secure handoff configured |
| Local username login | disabled in normal shell-first mode |
| Default external role | analyst |
| Admin mapping | explicit IAM group still required in private configuration |
| Gemini adapter | configured locally; deterministic fallback available |
| Raw log provider context | disabled |
| Response automation | disabled |
| Real firewall blocking | disabled |
| Local database | SQLite supported |
| Shared database | PostgreSQL contracts and CI exist; approved-host proof pending |
| Repository secret scan | passed; no matched value exposed |
| Python dependency audit | zero known advisories |
| npm dependency audit | zero vulnerabilities |
| Source SBOM | 395 components; generated under ignored temporary storage |
| Backend regression | 1048 passed, 1 skipped |

The private local profile currently reports `local_controls_incomplete` only
because no explicit MFU admin-group mapping has been configured. This is an
honest private-configuration gate, not an application crash. The approved MFU
group identifier must come from the university owner.

## Commands

Read-only readiness report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_release_readiness --pretty
```

Create false-by-default templates in ignored private storage:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_release_readiness `
  --write-evidence-templates `
  --output-directory .atdr_runtime\acceptance `
  --confirm WRITE_EMPTY_V553_EVIDENCE_TEMPLATES `
  --pretty
```

Read-only team-machine preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_team_runtime_acceptance `
  --template-root "C:\Path\To\Approved-MFU-Shell" `
  --pretty
```

Security controls and ignored SBOM:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_security_acceptance `
  --write-sbom .tmp\atdr-source.cdx.json `
  --pretty
```

## Verification

- taskboard render/standard check: pass;
- Ruff and compileall: pass;
- focused v5.53 backend: `8/8` pass;
- full backend and release gate: `1048 passed, 1 skipped`, `ok: true`;
- Alembic: no new upgrade operations;
- React lint/build: pass;
- Playwright: `38 passed, 1 skipped`;
- controlled source: `4/4` pass;
- deterministic scenarios: `24/24` pass;
- layered validation: `288/288` pass;
- Assistant QA: `20/20` pass, all word budgets and citations pass;
- configured Gemini minimal/full synthetic probes: pass with redaction, raw-log
  exclusion, secret hiding, and zero authoritative side effects;
- replay dry-run and all measured performance budgets: pass;
- deployment artifact validation: pass with `production_ready=false`;
- Python audit: no known vulnerabilities; npm audit: zero vulnerabilities;
- source scan: zero findings; source/frontend CycloneDX SBOMs contain `395`
  and `276` components respectively.

The upgraded Starlette test client emits one deprecation warning recommending
its future `httpx2` path. It does not fail runtime or tests and remains a narrow
dependency-follow-up item rather than a reason to weaken the current lock.

## External Acceptance Required

1. The MFU owner must provide approved origins/callbacks, a real admin group,
   and evidence for login, issuer/audience, 2FA, expiry, logout, recovery, and
   deprovisioning.
2. A deployment owner must provide an approved Linux host, PostgreSQL, shared
   storage, DNS/TLS, managed secrets, monitoring, backup/restore, measured
   RPO/RTO, rollback, disaster recovery, and load-test evidence.
3. The university/provider owner must approve Gemini privacy, retention,
   quota/billing ownership, monitoring, and key rotation, then run a
   representative evaluation.
4. A teammate must perform the clean-clone shell-first exercise on a separate
   physical machine after the proposed baseline is committed and clean.
5. Detection field qualification still needs a second physical source and
   genuinely independent future evidence.

No one should mark an evidence check true merely to clear the dashboard. Each
private manifest expires and must be backed by the named owner's actual test.

## Remaining Roadmap

One substantial locally controllable closure phase remains: v5.54 Release
Candidate Truth Lock And Operator Handoff. Five external acceptance tracks can
then close only when their owners and resources exist: MFU IAM, approved shared
host, Gemini governance, physical teammate acceptance, and independent
detection field evidence.

Recommended v5.54 objective:

```text
We completed v5.53 MFU IAM And Shared Deployment Readiness.

Next phase: v5.54 Release Candidate Truth Lock And Operator Handoff.

Goal:
Create one accurate, reproducible release-candidate handoff from the verified
v5.53 baseline. Remove stale status claims, exercise all locally available
recovery paths, and produce operator/advisor checklists for the five remaining
external acceptance tracks without fabricating any result.

Constraints:
- Preserve the configured database and private evidence.
- Keep the MFU shell as the normal entry and local recovery explicit only.
- Do not activate/promote ML, enable automatic response, or enable blocking.
- Keep the Assistant read-only with raw logs disabled.
- Do not commit secrets, private evidence, generated reports, or artifacts.
- Do not commit or push without separate explicit approval.

Tasks:
1. Re-audit source, docs, CI, setup/start/stop, release, and recovery contracts.
2. Run a clean disposable install from the committed baseline when available.
3. Consolidate current-state, architecture, operator, advisor, privacy,
   accessibility, backup/restore, incident, and rollback handoffs.
4. Eliminate stale version/production claims and dead duplicate instructions.
5. Run the complete verification, security, privacy, and hygiene matrix.
6. Create v5.54 status, T1-T20, final external-owner matrix, and exact allowlist.
7. Report the release-candidate decision, substantial work remaining, every
   external gate, and exact owner commands. Do not commit or push.
```

No commit or push is authorized by this document.
