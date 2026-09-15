# v5.17 PostgreSQL Multi-Worker Capacity And Recovery Acceptance

Date: 2026-07-30

## Decision

The repository-side v5.17 implementation is complete and locally verified.
Actual PostgreSQL execution is currently `blocked_by_environment` because this
workstation has no PostgreSQL server, Docker runtime, `pg_dump`, or
`pg_restore`. The runner does not substitute SQLite and does not report a
synthetic pass.

The existing GitHub Actions PostgreSQL job now provisions two disposable
v5.17 databases and runs a bounded 2,000-row synthetic acceptance. That job
cannot execute until a separately approved commit is published. No commit or
push is authorized by this change record.

This phase does not claim production capacity, a shared-host SLA, independent
device evidence, model readiness, or response authority.

## Audit Findings

The pre-change audit found:

- queue claims and expired-lease recovery already use PostgreSQL
  `FOR UPDATE SKIP LOCKED`;
- lease owner, private token, and claim generation already fence stale workers;
- evidence-mutating jobs already fail closed after lease expiry;
- resumable imports commit raw evidence, normalized evidence, run/source
  counters, checkpoints, lease renewal, and heartbeat at each chunk boundary;
- source counter updates already lock the source row;
- shared staging already uses a deployment storage identity and relative key;
- backup already coordinates with workers and restore already refuses the
  configured database;
- concurrent idempotent enqueue had a narrow unique-key race after the
  pre-insert lookup; and
- concurrent PostgreSQL detection transactions could both inspect the same
  unalerted evidence before either committed, creating a dedup race.

The two real gaps were repaired without changing detection meaning:

1. concurrent idempotency-key conflicts now roll back and reuse the committed
   same-actor job;
2. PostgreSQL detection alert/dedup writes now use one bounded,
   transaction-scoped advisory lock. SQLite behavior is unchanged.

Rules, thresholds, parser mappings, alert severity, dedup matching, case keys,
API routes, model lifecycle, and response behavior were not changed.

## Acceptance Runner

Command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v517_postgres_multiworker_acceptance `
  --target-rows 100000 `
  --chunk-size 1000 `
  --workers 2 `
  --synthetic `
  --run-detection `
  --test-recovery `
  --pretty
```

Private environment variables:

```text
ATDR_V517_POSTGRES_DATABASE_URL=<DISPOSABLE_POSTGRES_DATABASE>
ATDR_V517_RESTORE_DATABASE_URL=<SECOND_EMPTY_DISPOSABLE_POSTGRES_DATABASE>
```

Both targets must:

- use PostgreSQL;
- differ from the configured `DATABASE_URL`;
- have distinct identities;
- use safe names containing `v517`, `test`, `ci`, `disposable`, or `temp`;
- not be `postgres`, a template database, or the normal `atdr` database; and
- be disposable and empty.

The command never returns URLs, credentials, private paths, raw rows, IPs,
fingerprints, or secrets. Use `--preflight-only` to check readiness without
migrations or evidence writes.

Full private-file execution additionally requires the approved host to set
`ATDR_V517_PRIVATE_EVIDENCE_APPROVED=true` and pass:

```powershell
--sample-path "<PRIVATE_PANOS_LOG>"
```

That approval is intentionally not present in example environment files.

## Validation Contract

The runner validates:

- two or more workers claim distinct jobs;
- no job or source row is processed twice;
- shared staging identity and staged fingerprints remain enforced internally;
- source raw/normalized/parse counters reconcile exactly;
- stale lease tokens cannot commit;
- evidence-mutating stale leases fail closed and retain checkpoints;
- cancellation occurs at a committed boundary and verified-input resume
  completes without extra rows;
- concurrent idempotent submissions persist one job;
- concurrent source-scoped rule detection completes under bounded
  coordination with no duplicate alert-evidence pair;
- alert occurrence/related counts, computed cases, and source-linked
  detection runs reconcile;
- rule detection remains authoritative;
- labels, model runs, and response actions remain unchanged;
- pool use, process memory, chunk commit intervals, throughput, database
  growth, dashboard timings, query counts, lock state, and safe PostgreSQL
  plan node types are measured;
- `pg_dump` creates a checksum/revision/count manifest;
- `pg_restore` restores into the second empty disposable database with matching
  counts and Alembic revision; and
- staging, backup artifacts, and both disposable databases are removed.

## Local Result

```text
status: blocked_by_environment
target URL configured: false
restore URL configured: false
pg_dump available: false
pg_restore available: false
configured database modified: false
privacy findings: 0
```

This is a correct fail-closed result, not a failed SQLite workflow.

Focused repository tests pass `23 passed`, covering v5.17 safety, migration
failure cleanup, v3.94 worker behavior, and detection grouping.

No PostgreSQL throughput, lock-wait, recovery-time, query-plan, database
growth, or backup/restore result was measured on this workstation. The
100,000-row baseline thresholds therefore remain unfrozen, and the 250,000-row
and complete private-file runs were not attempted. The bounded 2,000-row
synthetic CI gate is configured but has not run because no publication is
authorized.

## Verification

- Ruff and compileall: passed.
- Focused PostgreSQL/worker/detection regressions: `23 passed`.
- Full backend through the final release gate: `771 passed, 1 skipped`.
- SQLite Alembic check: no drift.
- PostgreSQL offline Alembic SQL generation: passed through head.
- React lint and production build: passed.
- Playwright: `26 passed, 1 skipped`; the skip is hardware-dependent.
- Controlled detection scenarios: `24/24`.
- Layered validation: `288/288`, zero controlled FP/FN.
- Assistant QA: `20/20`, no response actions.
- Replay dry-run: parsed two safe rows and wrote zero.
- Performance smoke: no warnings; cold/cached Overview
  `0.2454/0.0154s`, alert list `0.0557s`, case summary `0.0975s`, and AI
  Governance `0.3950s`.
- Release gate: `ok: true`.
- Taskboard, exact 34-path allowlist, diff, privacy, staging, and tracked
  hygiene checks: passed.

## Roadmap Accounting

Start-of-phase estimate: four major external/product gates remained:

1. PostgreSQL multi-worker capacity/recovery;
2. real multi-device/live-source acceptance;
3. independent labeled Detection/ML evidence;
4. provider/deployment/security closure.

End-of-phase estimate remains four until the disposable PostgreSQL command
actually passes in CI or on an approved host. The repository implementation is
ready, but implementation readiness is not runtime evidence. The taskboard
percentage is not a production-readiness percentage.

## Safety State

- configured database reset/deletion: false;
- SQLite normal workflow changed: false;
- rules alert-authoritative: true;
- supervised lifecycle: `shadow_observation`;
- model activation/promotion: false/false;
- automatic response: disabled;
- real firewall blocking: disabled;
- private evidence committed: false; and
- production readiness claimed: false.

The exact source-controlled review boundary is listed in
`docs/V5_17_COMMIT_ALLOWLIST.md`. It grants no staging, commit, or push
permission.
