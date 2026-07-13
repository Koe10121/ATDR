# v3.89-v3.94 Release Commit Allowlist

## Purpose

This document records the exact source-controlled path boundary accumulated through the v3.94 checkpoint. It exists to prevent broad staging in a worktree that also contains ignored private/runtime data.

The canonical one-path-per-line list is `docs/V3_94_RELEASE_COMMIT_ALLOWLIST.txt`.

## Important Current-Worktree Warning

Several allowlisted files, including `.github/workflows/ci.yml`, environment examples, core configuration, metrics, persistence, systemd references, PRD, runbook, and task board, now also contain v3.95 edits. Therefore this list is an exact historical v3.89-v3.94 path boundary, but it must not now be used to claim a pure v3.94 commit without reviewed patch-level separation.

The safe choices are:

1. create one reviewed cumulative v3.89-v3.95 commit using the later cumulative allowlist; or
2. use carefully reviewed patch staging for mixed files.

Do not use `git add .`, `git add -A`, or directory-wide staging.

## Review Command

```powershell
$allowlist = Get-Content docs/V3_94_RELEASE_COMMIT_ALLOWLIST.txt |
  Where-Object { $_ -and -not $_.StartsWith('#') }

git status --short --untracked-files=all
git diff --check
git status --short -- $allowlist
```

Staging requires explicit user approval. If approved for an appropriately reviewed cumulative boundary:

```powershell
git add -- $allowlist
git diff --cached --check
git diff --cached --name-only
```

Before commit, compare `git diff --cached --name-only` exactly with the approved list and rerun the hygiene checks. No commit or push was performed while preparing this file.
