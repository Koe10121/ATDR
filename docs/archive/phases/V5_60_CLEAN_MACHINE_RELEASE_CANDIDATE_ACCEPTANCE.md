# v5.60 Clean-Machine Release Candidate Acceptance

Date: 2026-09-15

## Decision

ATDR's published v5.59 baseline passed a genuine disposable Windows
clean-machine rehearsal from `origin/main`. All 27 setup, package, lifecycle,
health, authentication-contract, recovery, analyst-workflow, safety, and
cleanup gates passed.

This is local release-candidate evidence, not production certification. The
run used a synthetic non-network provider profile only to prove component
wiring. It did not authenticate a real MFU account, use a private Gemini key,
or replace the remaining university, provider, hardware, human-evidence, or
shared-host acceptances.

## Starting State

- Published baseline: v5.59 commit
  `d020f1a973f005c192eba3256357f76618542cab`.
- Branch and `origin/main`: synchronized before implementation.
- Initial worktree and staging: clean.
- Repository surface audit: 1,411 intended paths, zero broken/nonportable
  Markdown links, zero Python parse failures, and zero missing documented
  commands or runtime documentation references.
- Repository security scan: 1,411 tracked text files, zero findings.
- Runtime authority: rules `active_authoritative`; IsolationForest
  `active_advisory` in the authoritative environment; supervised
  `unqualified`; hybrid `active_advisory`; response `simulation_only`.

## Clean-Room Method

`atdr.scripts.run_v560_clean_machine_acceptance` is preflight-only by default.
Execution requires `--execute --confirm DISPOSABLE_V560_CLEAN_MACHINE`.

The execution:

1. resolves the configured HTTPS/SSH Git remote without returning it;
2. clones `origin/main` with `--no-local` into a uniquely named directory
   directly under the Windows temporary root;
3. verifies the clone has no `.env`, database, logs, reviews, model artifacts,
   runtime tree, virtual environment, or JavaScript dependencies;
4. installs the checksum-locked MFU shell package and all Python/React/Node/Vue
   dependencies without copying the authoritative workspace;
5. proves setup works without provider secrets and startup fails closed;
6. creates a random, disposable, synthetic provider profile for lifecycle
   wiring only;
7. repeats setup and migrations without changing generated ATDR secrets;
8. validates packaged handoff source plus authenticated ATDR handoff fixtures;
9. starts, checks, repeats start, stops, repeats stop, diagnoses stale metadata
   and an occupied port, then restarts and stops;
10. verifies explicit local-recovery user bootstrap and login idempotence;
11. runs a controlled disposable ingestion-to-investigation workflow; and
12. drops its uniquely named shell database, stops processes, and deletes only
    its verified temporary directory using Windows long-path handling.

No authoritative `.env`, API key, credential, database, review, log, model,
generated evidence, username, provider payload, or private path is read into or
returned by the acceptance report.

## Acceptance Result

| Area | Result |
| --- | --- |
| Genuine remote clone | Pass |
| Pristine clone hygiene | Pass |
| Setup without private provider configuration | Pass |
| Missing-provider startup failure | Pass, fail closed and actionable |
| Synthetic lifecycle profile | Pass, disposable and non-network |
| Setup/migration idempotence | Pass |
| Isolated Python, React, shell backend, and shell frontend dependencies | Pass |
| SQLite and four-component URL/configuration contract | Pass |
| Shell-to-ATDR handoff fixtures and packaged source contract | Pass |
| First start, four-service health, and entry URLs | Pass |
| Repeated start without duplicate processes | Pass |
| Stop and repeated stop | Pass |
| Stale-process and occupied-port diagnostics | Pass |
| Restart, repeated health, and final stop | Pass |
| Explicit local recovery and idempotent user seed | Pass |
| Disposable analyst workflow | Pass |
| Runtime authority and no-side-effect checks | Pass |
| Unique MongoDB, process, and filesystem cleanup | Pass |
| **Total** | **27/27 passed** |

## Analyst Workflow Result

- records preserved: 10;
- records normalized: 10;
- expected deterministic rule alerts: 1;
- source health, why-flagged evidence, related logs, and recommendations: pass;
- deterministic Assistant turns: 3 (`alert_explanation`, `related_logs`, and
  `safe_next_step`);
- Assistant citation counts: `10/10/3`;
- external provider calls and raw-log context: 0;
- Assistant authoritative row deltas: 0;
- response actions created: 0;
- model activations or promotions: 0.

The pristine clone correctly reports IsolationForest `unavailable` and hybrid
`abstained` because ignored model artifacts are never copied or committed. Its
deterministic rules remain immediately `active_authoritative`, supervised ML
remains `unqualified`, and response remains `simulation_only`. A governed local
advisory artifact may be created later from approved evidence; setup must never
silently train or import one.

## Defects Found And Fixed

1. The initial harness expected a Node handoff test file inside the sanitized
   shell archive. The package intentionally excludes test directories. v5.60
   now runs authenticated ATDR handoff fixtures and validates the installed
   shell route/service syntax and one-time exchange security contract directly.
2. Initial cleanup encountered legacy Vue dependency paths beyond ordinary
   Windows deletion handling. v5.60 now revalidates the exact temporary parent
   and prefix, refuses symlinks/outside paths, uses the Windows extended-length
   path form, clears read-only attributes, retries boundedly, and proves the
   directory is absent.

Neither correction changes production authentication or runtime behavior.

## Exact Teammate Commands

Requirements are Windows 10/11, Python 3.11, Node.js 20.19 or newer with npm,
Git, MongoDB for the shell, the approved companion archive, and the separately
controlled real provider profile.

```powershell
git clone <ATDR_REPOSITORY_URL> ATDR
Set-Location .\ATDR
.\scripts\setup_team.cmd `
  -ShellPackage "<approved-shell-package>" `
  -ShellPrivateConfigRoot "<approved-private-provider-directory>"
.\scripts\start_system.cmd
.\scripts\check_system.cmd -RequireReady
```

Open `http://localhost:8080/#/pages/login`. To restart or stop:

```powershell
.\scripts\stop_system.cmd
.\scripts\start_system.cmd
.\scripts\stop_system.cmd
```

Preview the acceptance harness:

```powershell
py -3.11 -m atdr.scripts.run_v560_clean_machine_acceptance `
  --shell-package "<approved-shell-package>" `
  --pretty
```

The full acceptance confirmation is intentionally documented in the operator
runbook; ordinary teammates do not need to run it for daily startup.

## Safety State

- `production_ready=false`
- rules `active_authoritative`
- clean-clone anomaly state `unavailable` until a governed advisory artifact
  exists
- supervised runtime `unqualified`
- Assistant read-only, deterministic fallback verified
- external raw-log context disabled
- response `simulation_only`
- automatic response disabled
- real firewall blocking disabled
- no model activated or promoted
- no authoritative database or private workspace state touched

## Verification Result

| Check | Result |
| --- | --- |
| v5.60 focused and related backend tests | 40 passed |
| Genuine remote-clone acceptance | 27/27 stages passed |
| Ruff and compileall | Passed |
| Full backend suite | 1,091 passed, one skipped |
| Alembic drift | No new upgrade operations |
| Frontend lint and production build | Passed; 2,300 modules built |
| Playwright | 42 passed, one skipped live-hardware case |
| Controlled source scenario | Passed; 10 parsed, one expected rule alert, zero response actions |
| Layered detection validation | 288/288 mode runs passed across 24 scenarios |
| SOC Assistant QA | 30/30 cases and one follow-up sequence passed; citation pass rate 100% |
| Governed runtime inspection | Safe; rules authoritative, supervised unqualified, response simulation-only |
| Replay dry-run | Passed with zero writes and zero sends |
| Repository surface and security | Passed with zero broken references and zero secret findings |
| Performance smoke | Passed with one cold Overview timing observation |
| Release gate | Passed, including its full backend rerun and deployment checks |

The large local SQLite database returned the cold Overview summary in 1.0477
seconds against a 1.0-second advisory budget. The cached path returned in 0.014
seconds, and all other measured budgets passed. This is recorded as a small
environment-sensitive observation, not hidden as a perfect result.

## Remaining Finish Line

No broad implementation phase is required for the controlled local release
candidate. One useful Codex-owned closure remains: v5.61 should make the
optional advisory IsolationForest bootstrap and its unavailable/ready state
fully operator-guided and reproducible without committing an artifact or
claiming threat accuracy.

Five owner-backed acceptance tracks remain:

1. a second physical Windows teammate repeats setup and records usability;
2. the university validates real MFU account/group/2FA/recovery/deprovisioning;
3. the provider owner approves Gemini privacy, retention, quota, cost, and key
   rotation;
4. detection owners provide a second physical source, non-loopback forwarding,
   and fresh prediction-blind evidence; and
5. a deployment owner qualifies an approved PostgreSQL/HTTPS host, monitoring,
   backup, rollback, load, and disaster recovery.

v5.60 is complete locally. Publication requires separate explicit approval;
no commit or push is authorized by this document.
