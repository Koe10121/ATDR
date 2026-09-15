# ATDR External Acceptance

ATDR is locally reproducible, but configuration and local tests cannot prove
these owner-backed acceptance tracks.

## MFU Identity Owner

Provide approved preproduction/prod origins and callbacks, the allowed account
scope, the private group mapped to ATDR admin, provider-managed 2FA, recovery,
deprovisioning, and audit requirements. Validate a real school-account handoff
without exposing tokens or secrets.

## Gemini Governance Owner

Approve data sharing, retention, region, model, quota, billing, key custody,
rotation, incident response, and monitoring. Confirm raw-log context remains
disabled and redaction is appropriate for institutional traffic.

## Shared-Host Owner

Provide an approved Linux/PostgreSQL host, DNS/TLS, reverse proxy, managed
secrets, shared staging/storage, worker ownership, monitoring/alerts, backup,
restore, rollback, load evidence, and measured RPO/RTO.

## Physical Source Owner

Validate non-loopback forwarding from at least two genuine firewall/router
sources across distinct future windows. Preserve provenance and obtain
prediction-blind human truth without committing raw evidence.

## Teammate And Usability Owner

Run a clean-clone setup on a separate physical machine with the approved shell
package and private provider profile. Validate sign-in, ingestion,
investigation, Assistant continuity, accessibility, stop/restart, and recovery.

## Repository Owner

Approve exact changed paths before every commit/push and review all GitHub
Actions and CodeQL jobs. Do not force-push the shared default branch.

## Closure Rule

Each owner must produce current, reviewable evidence. Missing evidence remains
pending; it cannot be replaced by a feature flag, localhost test, synthetic
source, AI-generated label, or written claim. Until every required track is
accepted, `production_ready=false`.
