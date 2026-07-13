# ATDR Managed Secret Contract

ATDR deployment secrets must be supplied through a private environment file with mode `0600` or an approved secret manager. They must never be placed in Git, command-line arguments, browser storage, API responses, metrics, logs, screenshots, or support messages.

## Ownership And Rotation

| Secret class | Environment names | Owner | Rotation trigger | Failure behavior |
| --- | --- | --- | --- | --- |
| ATDR session signing | `JWT_SECRET_KEY` | ATDR deployment administrator | Scheduled rotation or suspected disclosure | Readiness fails for known placeholder values in production; existing sessions may require re-login after rotation. |
| Database credential | `DATABASE_URL` | Database administrator | Password policy, staff change, or suspected disclosure | API readiness fails and mutating operations stop; never fall back to another database silently. |
| MFU handoff | `MFU_IAM_HANDOFF_SHARED_SECRET` and approved IAM client secrets | MFU IAM owner | Provider rotation or suspected disclosure | Disable external handoff and retain local recovery login; never downgrade an external identity to an unverified one. |
| Assistant provider | `ASSISTANT_LLM_API_KEY` or provider-specific credential | AI service owner | Provider policy, quota incident, or suspected disclosure | Deterministic read-only fallback remains; no action capability is enabled. |
| SMTP | `SMTP_PASSWORD` | Mail service owner | Mail policy or suspected disclosure | Email delivery fails closed; account access must not silently bypass configured verification policy. |
| TLS private key | Deployment-managed certificate key | Platform administrator | Certificate renewal or suspected disclosure | Reverse proxy must not start with an unreadable/invalid key; do not expose FastAPI publicly as a fallback. |

## Operating Rules

- Separate local, preproduction, and future deployment credentials.
- Grant the service account read access only to the secrets it needs.
- Record rotations in the protected operations log without recording values.
- Run config doctor and readiness after rotation.
- Revoke and replace any value pasted into chat, issue trackers, source control, or presentation material.
- Keep `RESPONSE_SIMULATION=true` and `ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false` independent of secret availability.

The committed environment examples contain names and placeholders only. They are not deployable secret files.
