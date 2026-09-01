# v5.52 Analyst Experience And SOC Assistant Closure

Date: 2026-08-31

## Decision

The locally controllable alert-investigation and SOC Assistant experience is
closed for the controlled shared-lab target. Alert, log, source, and case
questions now keep one explicit primary entity; ordinary follow-ups retain it,
while reset prompts and explicit entity switches start a clean conversation.
Four sanitized turns persist in the current browser tab across dashboard
navigation.

This phase does not certify universal answer accuracy, institutional Gemini
approval, production operations, or autonomous response. Deterministic rules
remain alert-authoritative, ML remains advisory, the Assistant remains
read-only, and automatic response and real firewall blocking remain disabled.

## Defects Closed

1. Generic text such as `source ID 35` could be parsed as alert 35. IDs now
   require an explicit alert, log, source, sensor, row, event, or `#` context.
2. Related citations were promoted into active context. A source answer could
   therefore acquire a related alert as conversational state. Citations now
   remain evidence while only the primary entity drives follow-ups.
3. A reset question could reuse prior provider history. Reset requests now send
   zero prior turns, and the frontend rotates the conversation identifier.
4. Explicit entity switches reused the previous thread. Switching from alert
   1717 to alert 35, or from an alert to a source, now starts a clean thread and
   removes stale URL directives.
5. Browser state retained only one response. It now retains at most four
   sanitized turns, bounded to 180,000 characters, in `sessionStorage` only.
6. Answer origin was hidden in technical details. Every answer now shows
   deterministic versus external-LLM synthesis, evidence scopes, citation
   count, rules authority, ML advisory status, and raw-log exclusion.
7. Answer budgets were unnecessarily broad. Intent limits are now 55-120 words
   with at most two suggested follow-ups.

## Answer Sources

The deterministic context builder reads bounded ATDR service data and emits
citations. Provenance distinguishes:

- ATDR database records for alerts, normalized logs, sources, jobs, and runs;
- deterministic detection-rule and explanation evidence;
- advisory anomaly or supervised-ML governance evidence;
- operational health and job telemetry;
- approved ATDR documentation and runbooks; and
- optional external LLM synthesis over that bounded evidence.

Gemini is a synthesis layer, not a source of security facts. ATDR creates the
deterministic answer and citation allowlist first. Provider output is accepted
only after structured-output, grounding, citation, safety, ID, and word-budget
guards pass. A rejected or unavailable provider falls back to the deterministic
answer.

## Measured Result

| Check | Result |
| --- | --- |
| Controlled Assistant questions | `20/20` passed |
| Required citation pass rate | `1.0000` |
| Average answer length | `60.9` words |
| Maximum answer length | `110` words |
| Intent word budgets | all passed |
| Unsafe request refusal | passed |
| Provider status | Gemini configured; key/model configured without exposure |
| Minimal real provider probe | passed; structured response; 1 attempt |
| Full synthetic Gemini chat | passed; external answer used; 6 citations |
| Raw log context | disabled and not included |
| IP redaction | enabled and applied |
| Secret exposure | false |
| Provider/full-chat side effects | labels/models/detections/responses `0/0/0/0` |
| Complete backend suite | `1040 passed, 1 skipped` |
| React lint and production build | passed |
| Playwright | `38 passed, 1 skipped` |
| Controlled source workflows | `4/4` passed |
| Controlled detection corpus | `24/24` passed |
| Layered detection matrix | `288/288`; controlled FP/FN `0/0` |
| Replay and performance | dry-run zero-write; all budgets passed |
| Release gate | `ok: true`; no required check failed |

The real provider checks used private configuration without printing the key.
The full-chat probe used a synthetic temporary database. Provider payloads and
generated reports are not committed.

The release gate independently repeated the complete backend suite and passed
configuration safety, compilation, Alembic drift, and deployment-operations
checks. The exact cumulative v5.50-v5.52 change set is 42 tracked paths in
`docs/V5_52_COMMIT_ALLOWLIST.md`; no path is staged and no commit or push is
authorized.

## Analyst UI

- Ctrl+Enter submits a question; normal buttons remain keyboard accessible.
- Loading state is exposed with `aria-busy` and response updates use a polite
  live region.
- Previous turns are collapsed and show only bounded summaries.
- Evidence reasoning, citations/provider telemetry, feedback, activity, and
  technical context remain progressively disclosed.
- Provenance is visible without opening technical JSON.
- Long text uses wrapping and the tested Assistant view has no horizontal
  overflow.

## Safety And Privacy

- No Assistant endpoint can import logs or labels, run detection, alter users,
  train/activate/promote a model, delete data, or create a response action.
- Raw log lines are excluded from provider context by default.
- IP redaction remains enabled before external-provider context.
- API keys and provider payloads are absent from API, audit, UI, and Git.
- Conversation persistence is tab-scoped, sanitized, bounded, and cleared on
  logout or explicit context clear.
- Protected v5.49b evidence was not accessed or reused.

## Remaining External Gates

Institutional Gemini privacy approval, quota/billing ownership, key rotation,
and operational monitoring remain external. Independent field evidence and
human usability/accessibility acceptance also remain open. These do not change
the local v5.52 implementation decision.

## Roadmap

Two substantial shared-lab phases remain:

1. v5.53 MFU IAM And Shared Deployment Acceptance.
2. v5.54 Release Candidate Closure.

The parallel v5.51 physical-source and prediction-blind field-evidence gate
remains open until hardware and genuine reviewers are available.

No commit or push is authorized by this document.
