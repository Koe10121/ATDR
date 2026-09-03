# v5.54 External Owner Acceptance

Date: 2026-09-03

These checklists identify evidence ATDR cannot honestly manufacture locally.
Do not mark an item complete from source code, example configuration, mock
responses, same-machine rehearsal, or screenshots without the named owner's
approval. Private evidence belongs under an ignored absolute
`ATDR_ACCEPTANCE_EVIDENCE_ROOT`; never commit it.

## MFU IAM Owner

Owner: university IAM/Google Workspace administrator with the project advisor.

- [ ] Approve local and preproduction origins/callbacks for the registered Web client.
- [ ] Confirm issuer, audience, scopes, project account/domain policy, and token lifetime.
- [ ] Supply the real IAM group identifier that maps to ATDR `admin`.
- [ ] Prove an unprivileged school user defaults to `analyst`.
- [ ] Prove admin and analyst authorization boundaries.
- [ ] Prove provider-managed 2FA, logout, session expiry, account recovery, and deprovisioning.
- [ ] Confirm audit retention and incident-contact requirements.

Required result: a current private `mfu-iam-acceptance.json` backed by the
owner's test. Never place tokens, IDs tied to a person, client secrets, or OTP
values in the manifest.

## Approved Shared-Host Owner

Owner: authorized Linux/PostgreSQL/network operations owner.

- [ ] Provide an approved host, PostgreSQL service, and shared durable storage.
- [ ] Apply Alembic migrations and prove the database is at head.
- [ ] Run API and durable workers under least-privilege service accounts.
- [ ] Install HTTPS/TLS and validate trusted-proxy/forwarded-header handling.
- [ ] Store JWT, IAM, database, and provider secrets in the approved secret manager.
- [ ] Connect metrics, health checks, operational alerts, and retention jobs.
- [ ] Prove backup, restore, rollback, disaster recovery, and measured RPO/RTO.
- [ ] Run approved load and multiworker recovery acceptance.

Required result: host acceptance plus a current private
`shared-deployment-acceptance.json`. Repository deployment examples are not
acceptance evidence.

## Gemini Governance Owner

Owner: university/project data-protection and provider-budget owner.

- [ ] Approve the provider, model, data classification, region, and retention policy.
- [ ] Confirm raw logs remain excluded and IP redaction remains enabled.
- [ ] Assign API-key custody, rotation, revocation, quota, and billing owners.
- [ ] Configure provider-failure, latency, quota, and cost monitoring.
- [ ] Run representative answer-quality/privacy acceptance on approved evidence.
- [ ] Confirm deterministic fallback and zero action-execution behavior.

Required result: a current private `assistant-provider-governance.json`.
Configured Gemini access proves connectivity only, not institutional approval.

## Physical Teammate Owner

Owner: a teammate using a separate physical machine and fresh clone.

- [ ] Install from the approved Git revision and checksum-locked shell package.
- [ ] Supply private machine-specific configuration through the approved channel.
- [ ] Run `setup_team.cmd`, `start_system.cmd`, and `check_system.cmd` successfully.
- [ ] Reach the MFU login entry and complete the secure handoff with an approved account.
- [ ] Stop, restart, and recover without copying another user's database or `.env`.
- [ ] Confirm private logs, keys, runtime files, and evidence remain untracked.

Required result: a current private `team-runtime-acceptance.json`. The local
disposable rehearsal is supporting evidence only.

## Independent Detection Field-Evidence Owner

Owner: advisor-approved analyst/network owner with real hardware and evidence
custody authority.

- [ ] Forward from a non-loopback firewall/router and verify sender/source identity.
- [ ] Add a second independently verified physical source.
- [ ] Confirm PAN-OS fields against device/vendor records without exposing raw logs.
- [ ] Conduct prediction-blind FP/FN review on a new untouched future window.
- [ ] Measure precision, recall, F1, benign-like FPR, suspicious/malicious recall,
      queue rate, parser quality, and source/time drift.
- [ ] Decide whether a frozen supervised candidate may proceed beyond shadow.

Required result: governed independent evidence and a separate activation
decision. Rules remain alert-authoritative until that decision; no quota should
be filled by inventing labels.

## Project/Repository Owner

Owner: repository maintainer and project lead.

- [ ] Review the exact v5.54 allowlist and repository security scan.
- [ ] Give separate approval before commit/push; never force-push.
- [ ] Confirm CI, CodeQL, dependency audits, and release gate are green.
- [ ] Keep private/generated paths ignored and verify staged paths exactly.
- [ ] Refuse `production_ready=true` until every applicable external owner has
      supplied current evidence.
