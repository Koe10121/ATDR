# v5.37 Blind Evidence Review And Assistant Acceptance Workspace

## Status

v5.37 adds an authenticated React workspace at `/evidence-review` for the two
human gates that remained outside the dashboard:

- the 40-row sealed detection blind review; and
- the eight-case SOC Assistant acceptance review.

The workspace reuses the existing v5.28 detection working copy and v5.33
Assistant acceptance worksheet under ignored `ml_baseline_reviews/`. It does
not create a second evidence format, persist review evidence in the database,
or alter the sealed source packs.

Supervised lifecycle remains `shadow_observation`. Deterministic rules remain
alert-authoritative. No model was trained, activated, or promoted. Automatic
response and real firewall blocking remain disabled.

## Access And Ownership

The API requires an authenticated `analyst` or `admin`. The first genuine
human reviewer who starts a workspace becomes its server-side owner. That
reviewer can save and resume the private evidence. Other analysts and admins
receive aggregate progress only; they cannot open another reviewer's items or
see the owner identity.

Usernames associated with automated reviewers, including AI assistants and
model identities, are rejected. Every save requires explicit
`human_confirmed=true`. Reviewer identity and timezone-aware timestamps are
written by the server from the authenticated session.

## Detection Blind Review

The browser receives only the approved v5.28 structured fields:

- evidence role, pattern, review priority, and event time;
- log type, subtype, application, action, protocol, and ports;
- zones, bytes, packets, elapsed time, risk, and threat severity;
- parser/schema quality aggregates; and
- bounded source/destination behavior counts.

The browser never receives the immutable review token, frozen predictions,
model scores, expected class, rule scores, IP addresses, fingerprints, source
path, raw log, hidden ground truth, or reviewer identities.

The reviewer selects one review category and a compatible existing five-class
decision:

| Review category | Allowed final decisions |
| --- | --- |
| `benign_like` | `benign`, `benign_unusual` |
| `needs_context` | `needs_context` |
| `threat_positive` | `suspicious`, `malicious` |

Confidence uses the sealed contract's `1-100` scale. A rationale of at least
eight characters is required. Threat decisions also require a meaningful
attack type. Completed decisions are immutable through the API.

## Assistant Acceptance

The Assistant tab displays the existing protected question, answer, citation,
and context type. It does not call Gemini when the pack is opened, scored, or
completed. The reviewer scores eight dimensions from 1 to 5:

- factual correctness;
- evidence grounding;
- citation correctness;
- relevance;
- concision;
- actionable usefulness;
- privacy; and
- unsafe-action refusal.

The reviewer chooses `accept`, `revise`, or `reject`. Revise and reject require
a note. The protected digest is checked before every open and save. Raw-log
context and action execution must both remain false.

## Integrity And Persistence

Private session ownership, revision, and pack digests are kept in the ignored
file `ml_baseline_reviews/v5_37_evidence_review_workspace_state.json`. Writes
use atomic replacement. An optimistic revision prevents stale browser writes.
Pack changes, duplicate or malformed review contracts, protected Assistant
content changes, and stale revisions fail closed.

The API returns zero authoritative mutations for labels, model runs, detection
runs, alerts, and response actions. Completion records only that every current
row satisfies its human-review contract. It does not import detection labels,
tune the Assistant, call Gemini, retrain a model, or authorize activation.

## Audit

ATDR records safe audit events for review start, save, completion, reject, and
integrity failure. Audit details contain workspace, row index, revision, and a
bounded reason code only. They exclude questions, answers, evidence values,
review tokens, reviewer notes, predictions, raw logs, paths, fingerprints, and
secrets.

## Manual Test

1. Start ATDR through the normal supported shell workflow.
2. Sign in as an analyst or admin.
3. Open **AI Governance > Evidence Review**, or browse to
   `http://127.0.0.1:5173/evidence-review` when using the direct React dev
   server.
4. Confirm the Detection tab shows `0/40` or current saved progress and the
   `Predictions Withheld` badge.
5. Record one genuine independent decision, confirm it, and save.
6. Navigate away and return; verify progress and the immutable saved decision.
7. Open Assistant Acceptance, score one protected answer, confirm it, and
   save.
8. Confirm no response, detection, model, or import control exists on the page.

If the private detection pack is absent, the page shows a clear unavailable
state. The Assistant pack can be prepared from current bounded ATDR records
without an external provider call. A real human must still perform every
decision.

## Verification

- Focused v5.37 backend: `8 passed`.
- Full/release backend: `910 passed, 1 skipped`.
- Alembic: no schema drift.
- React lint/build: passed.
- Playwright: `33 passed, 1 skipped`.
- Controlled detection: `24/24` passed.
- Layered detection: `288/288` passed with zero controlled false positives or
  false negatives.
- Assistant QA: `20/20` passed with zero authoritative side effects.
- Replay: dry-run only, zero writes.
- Performance smoke: all fixed budgets passed with no warnings.
- Release gate: `ok: true`.

The first direct backend run used an unnecessarily deep pytest temporary path
and encountered one Windows filename-length error in an unrelated template
backup test after `909` tests had passed. That test passed immediately under a
short ignored path, and the authoritative release run then passed the complete
suite under the repository's standard short temp contract.

## Remaining Gates

v5.37 removes CSV editing as an operational obstacle but does not close the
human evidence gate by itself. Meaningful phases still remaining are:

1. genuine independent completion of 40 detection decisions and eight
   Assistant acceptance decisions;
2. one read-only v5.36 locked evaluation after those decisions are complete;
3. second verified physical-device/native-source evidence;
4. institutional Gemini privacy, retention, quota, cost, and key-rotation
   approval; and
5. MFU/shared-preproduction security and operations acceptance.

No commit or push is authorized by this document.
