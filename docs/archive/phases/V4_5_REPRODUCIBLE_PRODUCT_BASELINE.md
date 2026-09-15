# v4.5 Reproducible Product Baseline

## Status

v4.5 establishes a reproducible Windows baseline and an executive SOC experience for the current ATDR codebase. It does not claim production readiness, provider acceptance, model promotion, automatic response, or real firewall enforcement.

The approved 175-path source boundary is published on `main` in `dd6ff014fc09d02b224d11be2b0663c2d26c3495`. CI-only follow-up commits `a407ca09bb2f77e9e4068f26f2139591777787d4` and `1535a3182d2813b6136a2ee0073c4901fb19d675` select the explicit isolated recovery profile and expose the Linux runner's installed PowerShell Core to Windows portability tests. No product authentication default was weakened.

## What Changed

- Team setup now requires Node.js `20.19.0` or newer, reports the detected version precisely, and installs the pinned Python environment from `requirements.lock.txt`.
- A broken `.venv` is preserved under ignored runtime storage before a clean replacement is created. Existing databases are never reset.
- Installation readiness and MFU identity-provider readiness are reported independently.
- The external MFU shell is governed by `config/mfu-shell-contract.json`; its credentials and private environment files remain outside this repository.
- Overview and AI Governance now read one strict canonical evidence snapshot through `GET /api/ml/evidence-snapshot`. They do not merge historical report metrics.
- IsolationForest operational state, active supervised artifact metadata, and diagnostic candidates are displayed separately.
- Overview, Alerts, Investigation, AI Governance, and SOC Assistant now use the shared MFU-token `SocPageHeader` surface while retaining their existing queries and workflows. AI Governance also uses a reusable current-policy panel and keeps latest registered-run diagnostics explicitly separate from canonical validation evidence.
- The SOC Assistant visible answer contract is limited to two summary points, three evidence points, and three next steps. Its answer, citation, and technical-context presentation is isolated in `AssistantAnswerContent`; provider telemetry, history, and feedback remain secondary.
- `python -m atdr.scripts.prepare_safe_demo` provides a dry-run-first, idempotent synthetic scenario path for an empty database.
- Playwright now checks rendered Overview, Alerts, Investigation, SOC Assistant, and AI Governance pages at projector, laptop, and mobile sizes.

## Clean-Room Evidence

On 2026-07-15, setup was exercised in a disposable Windows path containing spaces. The copy began with:

- no `.venv`;
- no `node_modules`;
- no ATDR database;
- no private `.env`;
- no private logs or model artifacts;
- no `ml_baseline_reviews/` or `demo_exports/` output.

Using Python 3.11 and Node.js `20.19.0`, this command completed successfully:

```powershell
.\scripts\setup_team.cmd -TemplateRoot "D:\Approved MFU Shell"
```

The run installed all three JavaScript dependency trees and the Python environment, generated ignored local configuration, and migrated a new disposable SQLite database from base to Alembic head `b4c5d6e7f8a9`. Elapsed setup time was approximately 699 seconds on this workstation. The follow-up check returned:

- `installation_ready: true`;
- `provider_ready: false`;
- `database_dialect: sqlite`;
- `response_simulation: true`;
- `secrets_exposed: false`.

The provider result is expected because the clean-room shell intentionally contained no private university configuration.

The clean environment's pinned dependency set also passed a focused API, supervised-ML, and canonical-evidence test slice (`75 passed`).

## Current Provider Boundary

The approved shell copy currently used by the project has its MFU IAM proxy fields configured, but its frontend and backend Google OAuth client fields are not configured. Startup therefore fails closed before provider login. The university/provider owner must supply one approved OAuth Web client, authorize the exact local/preproduction origins, and assign an approved account/group. ATDR must not bypass this check.

The shell is separately supplied and is not versioned as an installable companion repository or archive. `config/mfu-shell-contract.json` validates structure and records a non-secret source fingerprint, but teammate distribution still requires the approved shell package and private configuration through the university channel.

## ML Evidence Contract

`GET /api/ml/evidence-snapshot` accepts only the canonical v4.1 evidence filename and version. If the ignored report is absent or invalid, the endpoint returns `available: false`; it never substitutes an older metric. When available, it reports:

- snapshot ID and generation time;
- dataset, publisher, evidence role, row count, and split count;
- metric ranges and worst split;
- calibration state;
- decision-support, activation, promotion, and response-automation state;
- explicit limitations.

Generated evaluation reports remain ignored. A fresh clone therefore shows evidence as unavailable until an authorized diagnostic run creates the canonical local report.

## Safe Demo Preparation

Preview without writes:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_safe_demo --pretty
```

Execute the bundled synthetic port-scan scenario intentionally:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_safe_demo --execute --confirm SAFE_SYNTHETIC_DEMO --pretty
```

The command is idempotent for its fixed source, never resets data, and never creates a response action.

## Safety State

- Response remains simulated and analyst-approved.
- Real firewall blocking remains disabled.
- The SOC Assistant remains read-only and excludes raw-log context by default.
- Model activation and production promotion remain manual and false for diagnostic candidates.
- The current configured database and private files were not reset, deleted, or copied into versioned source.

## Verification Result

- Ruff, compileall, PowerShell parsing, task-board rendering, and task-board standards checks passed.
- Backend verification passed: `589 passed, 1 skipped`. The skip is the hardware-dependent live-source browser scenario.
- Alembic is at head `b4c5d6e7f8a9` with no new upgrade operations.
- React lint and production build passed. Playwright passed `25 passed, 1 skipped`, including projector, laptop, mobile, dropdown, assistant-context, and overflow checks.
- Replay and safe-demo dry-runs parsed bundled synthetic evidence and wrote no database rows.
- Warm local performance was healthy: Overview `0.4065s`, cached Overview `0.0059s`, ML Governance `1.1306s`, alerts `0.0312s`, cases `0.0719s`, and feature generation `0.2692s`, with no warnings.
- One cold-disk performance run measured Overview at `9.12s`. This remains an explicit large-SQLite cold-start risk, not an SLA claim.
- `python -m atdr.scripts.verify_release` returned `ok: true` with no failed required checks.
- GitHub Actions CI #55 passed `backend-release-gate`, `frontend-dashboard`, and `postgres-persistence` at final public commit `1535a31`. The Linux backend job recorded `589 passed, 1 skipped`.
- A separate clean public clone of `1535a31` was clean, contained no tracked protected artifacts or personal-machine paths, compiled successfully, and passed `63` focused baseline/auth/assistant tests.

## Completion Audit

| Goal requirement | Authoritative evidence | Decision |
| --- | --- | --- |
| 1. Audit the v3.97-v4.4 boundary | `docs/V4_5_COMMIT_ALLOWLIST.md`, `docs/V4_5_REPO_HYGIENE_REPORT.md`, `docs/V4_5_CURRENT_STATE_MANIFEST.md`, exact `dd6ff01` commit | Complete |
| 2. Repair teammate setup | `scripts/setup_team.ps1`, lifecycle wrappers, pinned requirements, v4.3/v4.4 portability tests, clean-room path-with-spaces run | Complete |
| 3. Define the external MFU-shell contract | `config/mfu-shell-contract.json`, contract tests, and the explicit unpublished-companion-package blocker below | Complete for repository scope; external distribution gate remains |
| 4. Run clean-room Windows setup | Disposable no-environment/no-DB/no-private-input setup reached Alembic head; focused clean-room suite passed `75` tests | Complete |
| 5. Separate installation/provider readiness | Setup/check services report `installation_ready` and `provider_ready` separately; missing OAuth remains concise and fail-closed | Complete |
| 6. Use one canonical ML evidence snapshot | `GET /api/ml/evidence-snapshot`, `ml_evidence_snapshot_service.py`, Overview/AI Governance consumers, snapshot regression tests | Complete |
| 7. Separate model operating states | AI Governance distinguishes IsolationForest, active supervised metadata, and diagnostic candidates; unknown metadata is labeled unavailable/unknown | Complete |
| 8. Refactor primary SOC pages | Shared MFU-token components and `SocPageHeader` cover Overview, Alerts, Investigation, AI Governance, and SOC Assistant | Complete |
| 9. Bound and isolate assistant output | `AssistantAnswerContent`, two/three/three response contract, redacted tab persistence, read-only tests, admin QA details | Complete |
| 10. Verify projector/desktop/mobile rendering | Playwright `25 passed, 1 skipped`, including rendered content and horizontal-overflow probes at all three viewport classes | Complete |
| 11. Add safe scenario preparation | `python -m atdr.scripts.prepare_safe_demo` is dry-run first, explicit-confirmation, idempotent, and response-action free | Complete |
| 12. Run full release verification | Local release matrix passed; GitHub Actions CI #55 passed all jobs; final public clone passed compilation and `63` focused tests | Complete |

The definition of done is satisfied for versioned ATDR source: a clean clone receives the intended source, setup/start commands are documented, tracked personal paths are absent, ML metrics use explicit provenance, assistant behavior remains concise and mutation-free, protected local state was untouched, and full local/public verification passed. The external MFU shell and private provider configuration remain separately governed dependencies rather than missing ATDR source.

## Remaining Blockers

1. Publish or formally distribute a versioned approved MFU shell companion package.
2. Obtain and privately configure the university-approved OAuth client and group assignment, then run real provider acceptance.
3. Validate the shared PostgreSQL/worker/deployment profile on an approved host.
4. Obtain authorized independent multi-source firewall/syslog evidence; current supervised readiness remains candidate-only.
5. Complete organizational Gemini privacy, quota, key-custody, and real-traffic answer evaluation.
