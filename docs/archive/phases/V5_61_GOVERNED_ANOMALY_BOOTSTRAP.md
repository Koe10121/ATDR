# v5.61 Governed Advisory IsolationForest Bootstrap

Date: 2026-09-16

## Decision

ATDR can now reproduce its IsolationForest capability on a fresh clone through
an explicit operator workflow. Normal setup and startup never train a model.
The resulting artifact is an advisory capability only: it is not supervised,
not threat-accuracy validated, not alert-authoritative, and cannot authorize a
response.

The published source baseline entering this phase is v5.60 commit
`da7c2434962eec10c0fd7c6bbd9266c5dbebf2c6`, with GitHub Actions and CodeQL
green. v5.61 remains uncommitted until the project owner separately approves
an exact allowlist.

## Operator Workflow

Run a read-only preflight against committed synthetic evidence:

```powershell
.\scripts\bootstrap_advisory_anomaly.cmd -UseCommittedSyntheticSample -Pretty
```

The preflight validates file count, parser quality, feature-schema
completeness, exact duplicate rate, minimum eligible low-risk rows, ignored
artifact destination, and ignored manifest destination. It writes nothing.

After reviewing a passing preflight, explicitly execute:

```powershell
.\scripts\bootstrap_advisory_anomaly.cmd `
  -UseCommittedSyntheticSample `
  -Execute `
  -Confirm GOVERNED_ADVISORY_ANOMALY_BOOTSTRAP `
  -Pretty
```

For private operator evidence, pass the path only as a runtime argument:

```powershell
.\scripts\bootstrap_advisory_anomaly.cmd `
  -EvidencePath "<private-log-file-or-directory>" `
  -Pretty
```

Never place a private path in committed configuration or documentation.
Execution uses the same explicit confirmation. An existing artifact is
protected; replacement additionally requires `-ReplaceExisting` and uses
rollback-safe installation.

## Evidence Contract

Eligible bootstrap evidence must be successfully parsed PAN-OS TRAFFIC,
`allow` action, application risk at most 3, a resolved application, and a
complete anomaly feature schema. THREAT records, denied traffic, high-risk
applications, unresolved applications, parser failures, and incomplete
feature rows are excluded from training.

Fixed gates are:

- at least 20 unique eligible rows;
- parse rate at least 95%;
- feature-schema completeness at least 95%; and
- exact duplicate rate at most 20%.

The committed capability sample contains 45 unique rows. Current preflight
accepts 41 and excludes four unresolved-application rows. This proves only
that the pipeline can train and score reproducibly. It is not evidence of
real-world malicious-traffic accuracy.

## Storage And Privacy

Training and acceptance use a temporary SQLite database that is deleted after
the run. Only these configured, Git-ignored outputs may remain:

- `atdr/models/isolation_forest.joblib`
- `atdr/models/isolation_forest.bootstrap.json`

The deterministic manifest stores protocol version, aggregate evidence
counts, algorithm settings, feature names, and governance flags. It does not
store source paths, raw logs, IP addresses, row fingerprints, identities,
provider payloads, or secrets. Pending and rollback files use the same ignored
suffix policies.

## Runtime Contract

Without an artifact, startup remains healthy and reports:

`Advisory anomaly model unavailable`

The launcher and AI Governance page show the corrective preflight command.
After a governed bootstrap they report:

`Advisory anomaly model available`

Both states explicitly say decision support only and threat accuracy not
validated. A legacy artifact without the v5.61 manifest remains usable only as
legacy advisory state and still requires governed replacement for closure.

Anomaly scoring may set `is_anomaly` and `anomaly_score` on the rows being
scored. The `ml_anomaly_detected` rule is excluded from authoritative matches,
so an anomaly-only row cannot create, classify, suppress, or change the
severity of an alert. Supervised runtime remains `unqualified`; rules remain
`active_authoritative`; response remains `simulation_only`.

## Clean-Machine Acceptance

The v5.60 harness keeps its default 27 stages. The explicit
`--exercise-anomaly-bootstrap` option adds five stages that verify:

1. a pristine clone has no anomaly artifact or manifest;
2. setup and normal startup do not train silently;
3. committed synthetic preflight passes without writing;
4. explicit bootstrap reaches governed advisory-ready state with zero model
   alerts, suppressions, labels, model runs, or response actions; and
5. the generated artifact and manifest are removed with disposable storage.

This extension can run against the genuine remote clone after v5.61 is
published. Before publication, focused tests and disposable execution validate
the same service contract without modifying the authoritative database or the
existing local ignored artifact.

## Verification Evidence

Local verification completed on 2026-09-16:

- committed synthetic preflight: 45 unique rows parsed, 41 eligible, four
  unresolved-application rows excluded, and all four evidence gates passed;
- isolated explicit bootstrap: 45 rows scored, two advisory anomaly signals,
  valid deterministic manifest, and temporary SQLite removed;
- bootstrap safety: zero model-driven alerts, suppressions, labels, model runs,
  detection runs, response actions, or supervised activations;
- focused v5.60/v5.61 tests: 18 passed; complete backend: 1,102 passed and one
  skipped through the release gate;
- controlled source scenario passed and layered detection passed 288/288 with
  zero controlled false positives, false negatives, or response actions;
- Assistant QA passed all 30 cases and its contextual follow-up sequence;
- frontend lint/build passed and Playwright passed 43 with one skipped;
- genuine published v5.60 clean-machine baseline passed 27/27 stages with the
  expected pristine anomaly-unavailable state and complete process/storage
  cleanup;
- repository/taskboard/security audits, Ruff, compileall, Alembic check,
  replay dry-run, performance smoke, deployment checks, and release gate all
  passed.

The new five-stage opt-in clean-clone extension remains a post-publication
rerun because `origin/main` intentionally does not contain unapproved v5.61
source. This does not weaken the local implementation result: the same
bootstrap executed against isolated ignored storage and the harness extension
is covered by focused tests. No publication occurred in this phase.

## Remaining Boundaries

- IsolationForest remains unusual-behavior prioritization, not a maliciousness
  classifier.
- Supervised runtime remains unqualified after the v5.49b no-candidate
  decision.
- Independent source evidence, MFU IAM acceptance, Gemini governance, a real
  teammate machine, and approved shared-host acceptance remain external.
- No response automation or real firewall blocking is enabled.
