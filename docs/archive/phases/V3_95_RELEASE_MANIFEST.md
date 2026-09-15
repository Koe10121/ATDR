# v3.95 Cumulative Release Manifest

## Boundary

The current release candidate is cumulative because v3.89-v3.95 share modified configuration, CI, backend, migrations, systemd, frontend, and governance files. Splitting it by phase now would require patch-level staging of shared files and would create a less reviewable release.

The exact path allowlist is the union of:

- `docs/V3_94_RELEASE_COMMIT_ALLOWLIST.txt` (133 historical v3.89-v3.94 paths);
- `docs/V3_95_RELEASE_ADDITIONS.txt` (v3.95-only paths).

## Approval-Gated Commands

Do not run these commands without explicit user approval:

```powershell
$base = Get-Content docs/V3_94_RELEASE_COMMIT_ALLOWLIST.txt |
  Where-Object { $_ -and -not $_.StartsWith('#') }
$v395 = Get-Content docs/V3_95_RELEASE_ADDITIONS.txt |
  Where-Object { $_ -and -not $_.StartsWith('#') }
$allowlist = @($base + $v395 | Sort-Object -Unique)

git status --short --untracked-files=all
git diff --check
git add -- $allowlist
git diff --cached --check
git diff --cached --name-only
git status --short --ignored
```

Only after reviewing the staged diff and confirming the path set exactly matches the allowlist:

```powershell
git commit -m "feat: add ATDR shared deployment operations foundation"
git push origin main
```

After push, inspect all three CI jobs, especially `postgres-persistence`. Do not describe PostgreSQL multi-worker behavior as environment-validated until that job passes.

## Approved Release Execution

The user explicitly approved the exact allowlist release on 2026-07-13. The reviewed allowlist contained 162 paths, matched the changed path set exactly, passed `git diff --cached --check`, and produced no high-confidence secret matches. The release was committed and pushed normally without force-push:

- `5711c05` - `feat: add ATDR shared deployment operations foundation`
- `7d080e9` - align `log_sources` model metadata with the PostgreSQL migration
- `274c961` - make API health regression assertions database-aware
- `a282cd7` - retain primitive job IDs in the PostgreSQL validator
- `50c37e5` - isolate CI pytest state and remove local-DB test coupling

GitHub Actions run [#49](https://github.com/Koe10121/ATDR/actions/runs/29247673505) passed all required jobs on final commit `50c37e5`:

- `backend-release-gate`: success, `525 passed, 1 skipped`, no Alembic drift, Ruff passed, and deployment/recovery validators passed;
- `frontend-dashboard`: success, including `21 passed` Playwright tests;
- `postgres-persistence`: success, including disposable PostgreSQL migrations, restore, drift checking, persistence regressions, concurrent workers/shared staging, lease recovery, and backup coordination.

This is evidence for CI-hosted PostgreSQL behavior, not proof of an approved multi-host deployment, real TLS, managed secrets, alert routing, or measured recovery objectives.

## Explicit Exclusions

- `.env` and private configuration;
- database and backup files;
- real/private logs and processed data;
- model artifacts;
- `ml_baseline_reviews/` and `demo_exports/`;
- generated runtime reports and `.tmp/`;
- credentials, tokens, certificates, private keys, and external template runtime data.

No staging, commit, or push was performed while initially creating this manifest. The later approved execution and CI evidence are recorded above.
