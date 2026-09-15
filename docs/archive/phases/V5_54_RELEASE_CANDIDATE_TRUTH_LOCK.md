# v5.54 Release Candidate Truth Lock And Operator Handoff

Date: 2026-09-03

## Decision

Release-candidate decision: **`local_release_candidate_ready`**.

ATDR is a locally verified release candidate for a controlled SOC lab.
`production_ready` remains `false`.

This decision means the source, supported local profiles, safety controls,
recovery paths, documentation, and local verification are coherent. It does
not replace owner-backed evidence for MFU IAM, an approved shared host,
institutional Gemini use, a separate teammate machine, or independent physical
detection sources.

## Published Starting Point

- feature commit: `825e29dde7430cee191ab86068c05e7c5ae30bf5`
- CI repair commit: `b5761a953cf541e744fc437d4fb07be2adaec63f`
- GitHub Actions run `33585630166`: passed
- CodeQL run `33585630219`: passed

No v5.54 commit or push is authorized by this document.

## Defects Found And Fixed

### Windows Disposable Lifecycle Capture

The v5.53 team acceptance runner captured stdout/stderr while starting
long-lived processes through PowerShell. On Windows, inherited anonymous pipe
handles could remain open in child processes, so a successful startup appeared
to hang.

The runner now sends long-lived startup output to `DEVNULL`, reads the bounded
launcher report separately, waits on explicit HTTP contracts, and terminates
only the disposable processes it owns.

### Incomplete Lifecycle Coverage

The disposable runner previously stopped after one setup/start/health/stop
cycle. It now verifies:

1. package/archive validation;
2. clean setup;
3. shell-first start;
4. health;
5. secure login-handoff contract;
6. stop;
7. restart;
8. repeated health;
9. repeated handoff contract;
10. repeated stop; and
11. explicit local-recovery authentication on disposable SQLite.

The clean-baseline run passed `11/11`. It did not access the configured
database, modify the configured shell, retain its completed workspace, create
an acceptance manifest, or expose private paths or secrets.

### Readiness Semantics

The release-readiness projection previously made external acceptance look like
a local pass/fail boolean and treated the missing university admin-group value
as a failed local engineering control. The current contract distinguishes:

- `locally_verified`;
- `externally_accepted`;
- `externally_pending`;
- `unavailable`; and
- `failed`.

The admin group mapping remains visibly unconfigured, but it is an external MFU
acceptance dependency rather than a local source-code failure.

## Supported Profiles

| Profile | Current state | Boundary |
| --- | --- | --- |
| MFU shell-first local SQLite | Locally verified | Normal authentication path; real MFU lifecycle acceptance pending |
| Explicit local recovery | Locally verified in disposable storage | Recovery/development only; never a silent fallback |
| Versioned teammate shell distribution | Source/package lifecycle locally verified | Separate physical-machine acceptance pending |
| Shared PostgreSQL deployment | Source, migrations, workers, scale, and recovery assets locally verified | Approved host and operational evidence pending |

MongoDB is required for the MFU shell in the normal local profile. Redis is
optional locally because the shell has a memory-store fallback. PostgreSQL is
optional locally and required only for the shared deployment profile.

## Current Detection And AI Truth

- Deterministic rules remain alert-authoritative.
- Controlled detection passes `24/24`; layered validation passes `288/288`.
- IsolationForest remains advisory because current evidence does not support
  detector authority.
- v5.49b selected no supervised candidate; lifecycle remains
  `shadow_observation`; no artifact was activated or promoted.
- The Assistant's deterministic QA passes `20/20`, citation rate `1.0`, and
  average/max answer size `60.9/110` words.
- The privately configured Gemini minimal and full synthetic paths pass with
  IP redaction, raw-log exclusion, valid structured output, safe fallback, and
  zero detection, label, model, user, or response mutation.

## Local Readiness Projection

The safe v5.53 readiness command now reports:

- status: `local_controls_ready_external_evidence_required`;
- local controls: `locally_verified`;
- external acceptance: `externally_pending`;
- approved host: `externally_pending`;
- shared lab: `externally_pending`;
- IAM local controls: `9/9`;
- shared-deployment local controls: `7/7`;
- Assistant local controls: `8/8`;
- team-runtime local controls: `5/5`;
- repository-security local controls: `8/8`; and
- `production_ready=false`.

Configuration, a successful local probe, or a same-machine rehearsal never
counts as external acceptance.

## Operator Handoff

Use `docs/V5_54_OPERATOR_HANDOFF.md` for installation, startup, log ingestion,
detection and investigation, Assistant provenance, backup/recovery,
troubleshooting, and safety boundaries. Use
`docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md` for the exact five owner-backed
acceptance tracks.

## Verification

Closure verification results:

- taskboard render and standards check: passed;
- Ruff and compileall: passed;
- full backend: `1052 passed, 1 skipped`;
- Alembic: no new upgrade operations;
- React lint/build: passed;
- Playwright: `38 passed, 1 skipped`;
- controlled source: `4/4` scenarios and `10/10` checks;
- deterministic detection: `24/24`;
- layered detection: `288/288`;
- deterministic Assistant QA: `20/20`, citation rate `1.0`, average/max
  `60.9/110` words;
- privately configured Gemini minimal/full synthetic probes: passed with
  redaction, raw-log exclusion, structured output, and zero authoritative
  writes;
- replay dry-run: two rows parsed, zero sent/imported/written;
- large-SQLite performance: all budgets passed on `145,232` logs and `3,231`
  alerts;
- tracked-source secret scan: zero findings;
- Python/npm dependency audits: zero known vulnerabilities;
- deployment source validation: passed with `production_ready=false`.

The independent release gate passed with `ok=true`, zero failed required
checks, the same `1052/1` backend result, Alembic at head, deployment controls
valid, response simulation enabled, and `production_ready=false`.

The direct backend run initially encountered Windows global temporary-folder
ACL setup errors. Its authoritative rerun used a unique ignored repository
`.tmp` directory and passed. This was environment setup behavior, not an ATDR
test failure. The release gate independently uses its own repository-local
temporary contract and also passed.

Final repository hygiene passes: the changed set contains exactly the 27 paths
in `docs/V5_54_COMMIT_ALLOWLIST.md`, staging is empty, `git diff --check`
passes, the final tracked-source scan reports zero findings, dependency audits
report zero known vulnerabilities, and private/generated paths remain ignored.
No commit or push has occurred.

## External Acceptance Still Required

| Track | Owner-backed evidence required |
| --- | --- |
| MFU IAM | Approved callbacks/origins, real admin group, login/issuer/audience/2FA/expiry/logout/recovery/deprovisioning |
| Shared host | Linux/PostgreSQL, DNS/TLS, managed secrets, shared storage, monitoring, load, backup/restore, rollback, RPO/RTO, DR |
| Gemini governance | Privacy/retention approval, quota/billing owner, key rotation, monitoring, representative evaluation |
| Physical teammate | Clean clone/package setup, shell login handoff, stop/restart/recovery on another machine |
| Detection field evidence | Non-loopback forwarding, second physical source, prediction-blind labels, untouched future window |

## Finish Line

v5.54 ends broad local feature development. The remaining work is not a chain
of invented local versions; it is five evidence tracks owned by real people and
environments. They can run in parallel.

A controlled senior-project release can use this local release candidate while
clearly disclosing the pending tracks. A shared-lab release requires the MFU,
host, provider, and teammate tracks. A claim about supervised-model quality or
production detection additionally requires independent field evidence and a
separate activation decision.

## Safety Invariants

- Protected v5.49b evidence was not accessed or rerun.
- No database reset or destructive migration occurred.
- No supervised artifact was activated or promoted.
- Rules remain alert-authoritative.
- The Assistant remains read-only with raw-log provider context disabled.
- Automatic response and real firewall blocking remain disabled.
- Secrets, private logs, reviews, model artifacts, generated reports, SBOMs,
  provider payloads, and processed evidence remain out of Git.
