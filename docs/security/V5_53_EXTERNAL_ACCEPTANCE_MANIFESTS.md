# v5.53 External Acceptance Manifests

## Purpose

ATDR separates repository readiness from external acceptance. Configuration,
source files, mocks, or a local success message are not proof that MFU IAM, an
approved host, Gemini governance, or a teammate machine has been accepted.

`ATDR_ACCEPTANCE_EVIDENCE_ROOT` may point to an absolute private directory
outside Git. The API exposes only booleans, counts, status names, and missing
check names. It never returns the directory, manifest body, identity, secret,
or provider payload.

## Private Files

| File | Required real evidence |
| --- | --- |
| `mfu-iam-acceptance.json` | provider login, exact origins, issuer/audience, school domain, group-role mapping, session expiry, logout, 2FA, recovery, deprovisioning |
| `shared-deployment-acceptance.json` | approved Linux host, PostgreSQL, multiworker, shared storage, TLS, managed secrets, monitoring, backup/restore, RPO/RTO, rollback, disaster recovery, load test |
| `assistant-provider-governance.json` | institutional privacy, retention, quota owner, billing owner, key rotation, monitoring alerts, representative evaluation |
| `team-runtime-acceptance.json` | clean clone, approved shell package, private configuration, setup, shell entry, handoff, health, shutdown, database preservation, private-data exclusion |

Every file must use schema version 1, match the current environment, set
`template_only` to false, include UTC `recorded_at` and future `expires_at`
values, name an approving role, and set every required check to true. Symlinks,
oversized files, unsafe keys, malformed JSON, expired evidence, and partial
checks fail closed.

## Workflow

1. Generate empty false-by-default templates with the confirmed CLI command in
   `docs/V5_53_MFU_IAM_AND_SHARED_DEPLOYMENT_READINESS.md`.
2. Store them only in ignored private storage.
3. Have the responsible owner execute and retain the underlying evidence.
4. Set a check true only after the real test passes.
5. Run the read-only readiness CLI or open Admin > Release Readiness.
6. Renew or remove expired evidence; never extend an expiry without rerunning
   the relevant acceptance.

Do not put passwords, tokens, client secrets, API keys, raw logs, user
identities, provider payloads, database URLs, or private paths in a manifest.
The manifest is an aggregate claim pointer, not the evidence archive itself.

## Authority Boundary

Valid manifests and an accepted host report can establish shared-lab
acceptance for the named environment. They do not establish production
certification, supervised-model promotion, response automation, or permission
to perform real blocking.
