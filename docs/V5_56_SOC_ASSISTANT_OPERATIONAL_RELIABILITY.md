# v5.56 SOC Assistant Operational Reliability And Analyst Quality Lock

Date: 2026-09-04

## Decision

ATDR's locally controllable SOC Assistant reliability work is complete for the
controlled-lab release candidate. Answers are more intent-specific, concise,
and evidence-focused; provider failures fail safely to deterministic output;
Gemini citations are constrained to the request's ATDR allowlist; and the UI
shows aggregate provider health and usage warnings outside the answer.

This does not establish institutional Gemini approval, representative field
accuracy, persistent production monitoring, or production readiness. The
Assistant remains read-only. Deterministic rules remain alert-authoritative,
supervised ML remains in `shadow_observation`, and automatic response and real
firewall blocking remain disabled.

## Defects Closed

1. Alert explanations could repeat one long aggregate narrative instead of
   leading with the actual detection reason. The alert contract now gives a
   direct verdict, bounded atomic evidence, and one focused check.
2. Semantic deduplication collapsed distinct related logs when their text
   differed mainly by record ID. Explicit record IDs are now preserved and at
   most three related rows are shown.
3. Alert next-step answers used generic checks. They now consume the alert's
   prioritized explanation checks and show at most three.
4. Source-health answers could describe a healthy state as the main issue.
   They now select the first material parser, ingestion, or source warning.
5. ML governance answers could present artifact presence as a blocker. They
   now lead with advisory status, the actual validation limitation, and its
   operational consequence.
6. Provider-output limits confused the intent target with the absolute safety
   ceiling. Output targets remain mode-specific; any answer over 120 words
   fails to deterministic fallback, while valid content is centrally rendered
   to the narrower intent budget.
7. Gemini could invent a citation spelling even when all security facts were
   grounded. Gemini's response schema now enumerates the exact per-request
   citation allowlist. Unambiguous formatting aliases are canonicalized, while
   unknown or ambiguous references are still rejected.
8. The concise ML-governance rendering described ML as advisory but dropped
   the established `decision support` wording required by the independent
   review-pack contract. The summary now states both concepts explicitly.

## Response Contract

- Lead with the direct answer.
- Target 40-100 words; controlled no-data answers may be shorter.
- Enforce a 120-word absolute provider ceiling unless a future explicitly
  governed investigation-brief contract permits more.
- Show at most three findings and at most three checks.
- Preserve one explicit alert, log, source, or case through follow-ups.
- Do not repeat classroom, advisor, supervisor, or presentation wording.
- Do not expose raw JSON, raw logs, provider payloads, secrets, or numeric IPs.

The deterministic answer remains the source-of-truth fallback. Gemini may
rephrase only the bounded ATDR context and exact allowlisted citations.

## Operational Telemetry

`GET /api/assistant/status` exposes aggregate, payload-free process telemetry:

- attempted, successful, failed, guarded-fallback, and total fallback counts;
- latest, maximum, and average provider latency;
- timeout, rate-limit, quota, and provider-unavailable event counts;
- circuit state, open count, and cooldown remaining;
- aggregate input, output, and total tokens when the provider returns usage;
- configured token-warning threshold, warning state, and remaining allowance;
- aggregate estimated cost only when private rates are configured; and
- explicit `prompts_stored=false`, `answers_stored=false`, and
  `secrets_exposed=false` safety status.

The telemetry is intentionally process-local and resets on backend restart.
It is useful for the local release candidate but is not a substitute for an
approved persistent monitoring, billing, or quota system.

## Failure Behavior

The external provider fails to the deterministic answer for timeout, rate
limit, quota, provider outage, malformed structure, unsupported citation,
oversized output, unsafe action recommendation, missing grounding, or
unredacted IP content. IP redaction is a mandatory precondition for any
external call. The Assistant never retries an action because it has no action
interface.

## Evaluation Corpus

`data/samples/assistant/v556_quality_corpus.json` is synthetic and
privacy-safe. It covers alert reason, related logs, false-positive assessment,
alert-specific next checks, source health, failed jobs, AI governance,
investigation briefs, controlled workflow guidance, malicious action refusal,
and a four-turn contextual alert investigation.

The corpus contains no raw logs, identities, provider payloads, private paths,
or protected review evidence.

## Measured Quality

| Measure | Result |
| --- | ---: |
| Independent deterministic questions | `30/30` passed |
| Four-turn contextual sequence | `4/4` steps passed |
| Required citation pass rate | `1.0000` |
| Average answer length | `56.0` words |
| Maximum answer length | `110` words |
| 40-100-word target rate | `0.7333` |
| Word-budget violations | `0` |
| Authoritative side effects | `0` |

The target-rate denominator includes intentionally short no-data and direct
fact answers. All modes satisfy their fixed budgets.

## Private Gemini Checkpoint

Private, synthetic, secret-safe probes confirmed:

- provider/model/key configured without exposing values;
- minimal structured call: one attempt, `2,114 ms`, `824` aggregate tokens;
- full chat: provider answer used, one attempt, `3,720 ms`, `4,043` aggregate
  tokens, six allowlisted citations;
- raw-log context allowed/included: `false/false`;
- redaction enabled and applied;
- raw line and secret exposure: `false/false`; and
- detection runs, labels, model runs, and response actions changed: `0/0/0/0`.

These numbers are a connectivity checkpoint, not a latency SLO or cost
forecast. Provider latency and token usage vary between calls.

## UI Changes

The Assistant status band now shows aggregate provider health, successful and
failed calls, fallback count, average latency, and total tokens. A compact
warning appears when the private token threshold is reached. Conversation
persistence, provenance, citations, MFU styling, wrapping, and read-only safety
badges remain unchanged.

## Verification

- Taskboard render and standard checks pass.
- Ruff and Python compile checks pass.
- The first complete backend run exposed the missing `decision support`
  governance wording; the focused repair passes `11/11`, and the final release
  rerun passes `1062` backend tests with `1` external/live skip.
- Alembic reports no new upgrade operations.
- React lint/build pass; Playwright passes `39` tests with `1` live-hardware
  skip.
- Deterministic Assistant QA passes `30/30` plus the `4/4` contextual sequence.
- Private minimal and full-chat Gemini probes pass with raw logs excluded,
  redaction enabled, secrets hidden, and zero authoritative side effects.
- Controlled source `4/4`, deterministic detection `24/24`, and layered
  detection `288/288` pass.
- The tracked-source security scan reports zero findings; replay dry-run,
  all measured performance budgets, deployment operations, and the release
  gate pass.
- The cumulative changed-path set matches the exact `28`-path allowlist,
  staging is empty, and private/generated evidence remains ignored.

## Remaining External Gates

1. MFU/provider approval for privacy, retention, region, and approved evidence.
2. Named billing, quota, key-custody, rotation, and revocation owners.
3. Persistent monitoring and operational alert delivery on an approved host.
4. Representative privacy-approved field evaluation by independent analysts.
5. Formal usability and assistive-technology acceptance.

The five v5.54 owner-backed acceptance tracks remain open. v5.56 improves the
local Assistant but does not close any external acceptance contract.

## Publication Boundary

The exact proposed path boundary is in `docs/V5_56_COMMIT_ALLOWLIST.md`. No
staging, commit, push, deployment, model activation, or external acceptance is
authorized by this document.
