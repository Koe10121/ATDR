# ATDR Taskboard Workflow

`docs/tasks/tasklist-progress.md` is the only active progress source. Its HTML
view is generated and must not be edited manually.

For each non-trivial phase:

1. Record source evidence and the progress basis.
2. Keep one clear active task table.
3. Record actual verification commands and results.
4. Keep blockers, owners, and next actions explicit.
5. Add a T1-T20 change record under `docs/changes/`.
6. Render and validate the board:

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
```

Progress is evidence-backed delivery progress, not a production-readiness
percentage. External IAM, provider, host, device, reviewer, and teammate gates
remain blocked until their owners provide real evidence.

The full progress ledger through v5.58 is preserved at
`docs/archive/tasks/tasklist-progress-through-v5.58.md`.
