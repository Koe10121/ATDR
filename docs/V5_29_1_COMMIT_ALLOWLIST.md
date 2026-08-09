# v5.29.1 Exact Commit Allowlist

## Status

This is the exact tracked review boundary for the v5.29.1 frontend dependency
security closure. It contains exactly 11 paths. It is not permission to stage,
commit, or push.

## Allowed Paths

```text
docs/AI-DOCS-INDEX.md
docs/V5_29_1_COMMIT_ALLOWLIST.md
docs/V5_29_1_FRONTEND_SECURITY_CLOSURE.md
docs/changes/T1_T20_V5_29_1_FRONTEND_SECURITY_CLOSURE.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/package-lock.json
frontend/package.json
frontend/src/components/ProtectedRoute.tsx
frontend/src/pages/LoginPage.tsx
frontend/tests/smoke.spec.ts
```

## Excluded

Do not stage or commit `.env` files, credentials, databases, logs, labels,
reviews, model artifacts, generated reports, `ml_baseline_reviews/`,
`demo_exports/`, processed evidence, Playwright output, build output, npm
cache/log output, or anything outside the exact list.

## Approval Gate

Before any future Git operation, compare the complete changed-path set to this
list, confirm staging is empty, run `git diff --check`, verify private/ignored
files remain untracked, and obtain separate explicit exact-path approval. Never
force-push.
