# ATDR Deep System Analysis

Date: 2026-09-22

## Scope and method

This is a full-system review across UI/UX, backend, data model, security, and
AI/ML, done to answer one question directly: **what is actually wrong or weak
right now, and how much work is it to get to the best honest state before
presentation.**

Four independent audits were run in parallel (frontend/UI-UX, backend
ingestion/ops/deployment, data model/architecture, security/IAM/privacy),
each reading the real source and citing file:line. Findings below merge those
four reports with this session's own firsthand knowledge of the detection
rules, the Assistant, and the supervised-ML qualification campaign. The two
highest-stakes new findings (the `_AI_REVIEWER_PATTERN` drift and the broken
IPv6 check in `v514_large_file_runtime_service.py`) were independently
re-verified against the live source before being written up here — both are
real, confirmed by direct inspection, not just cited.

This document intentionally excludes presentation-prep work. It is about the
system itself.

## Overall verdict

The system is materially stronger than a typical capstone in three places —
backend-enforced RBAC, ingestion durability/parsing, and frontend UI
consistency — and has one real, structural, unfixable-by-effort limitation:
the supervised ML detector cannot be honestly qualified without a second
independent data source, and it says so rather than hiding it. What's
actually wrong is a short list of concrete, fixable bugs (most under a day of
work total) plus a known and disclosed maintainability debt (dead code,
config sprawl) that doesn't affect correctness but affects how the codebase
reads to a reviewer.

---

## 1. UI/UX

Source: automated frontend audit, cross-checked against this session's own
`AlertsTriage.tsx` / `AppShell.tsx` / `RouteErrorBoundary.tsx` work.

**Strength**: this reads as one coherent product, not bolted-together pages.
Every page shares the same `SocPageHeader` / `hero-panel` / `MetricCard` /
`Badge` / `EmptyState` / `ErrorBanner` / `LoadingPanel` vocabulary. Loading,
error, and empty states are handled almost everywhere. The "decision support
only, response automation disabled" governance language is repeated verbatim
across Overview, ML Governance, Threat Controls, and User Admin — real design
discipline for a security-review capstone. The route-level error boundary
added this session (`RouteErrorBoundary.tsx`) is now the backstop for exactly
this class of failure app-wide, not just on the one page that crashed.

**Real bugs found:**

1. **Same bug class as the AlertsTriage crash, latent in 5 more places.**
   `Object.entries(item.evidence).map(([key, value]) => <dd>{value}</dd>)`
   renders `value` as a raw JSX child with no `String()` coercion, in:
   `EvidenceReviewPage.tsx:344`, `:630`, `:940`, `SupervisedEvidenceExpansionPanel.tsx:254`,
   `SupervisedQualificationReviewPanel.tsx:261`. It's not actively broken
   today because those specific backend endpoints type `evidence` as
   `dict[str, str]` — but sibling fields in the *same backend file*
   (`SupervisedQualificationStatusResponse.evidence`,
   `SupervisedExpansionStatusResponse.evidence`) are typed `dict[str, Any]`,
   so the backend team doesn't treat "evidence dict" as reliably string-only.
   One future backend change reproduces the exact white-screen crash fixed
   this session, just on a different page.
2. **Privilege-escalation-by-misclick.** `UserAdmin.tsx:483` fires the
   "Make admin / Make analyst" role-change mutation with no confirmation,
   while every other destructive action in the app (`:495` Disable, block/
   unblock IP, disable suppression/watchlist) uses `window.confirm()` first.
3. **Unstyled native dialogs for a security-sensitive action.**
   `UserAdmin.tsx:463,489` use raw `window.prompt()` for editing a user's
   email and resetting a password — no validation, out of step with the rest
   of the UI.
4. **Accessibility sweep gap.** The Playwright axe-core sweep only covers
   8 of 13 routes — missing `/controls`, `/tuning`, `/users`, `/demo`,
   `/login`. `/users` is the biggest miss: densest table, custom dropdowns,
   the `window.prompt` flows above.
5. **`ErrorBanner.tsx:4`** does `String(error.detail)` where FastAPI 422
   errors return `detail` as an array of `{loc, msg, type}` objects —
   renders as `"[object Object],[object Object]"` instead of a real message.
   Not a crash, just useless error text on every validation failure.
6. Two files have outgrown single-component form: `MLGovernance.tsx`
   (2,341 lines, one ~2,270-line component) and `ExecutiveOverview.tsx`
   (1,040 lines, one component). Functionally fine, structurally
   unreviewable/untestable as a unit.

---

## 2. Backend — ingestion, parsing, ops, deployment

Source: automated backend audit.

**Strength**: this is not "demo-only" in the usual capstone sense. There's a
genuine durable job architecture — leases, fencing tokens, checkpointed chunk
commits, cooperative cancellation, backpressure — plus a dialect-aware DB
layer that already supports Postgres multi-worker, structured JSON logging
with request-id correlation, and Prometheus metrics. Migration hygiene is
good (27 linear migrations, CI-enforced `alembic check`). The PAN-OS parser
anchors on the high-resolution timestamp rather than brittle tail-indexing,
never drops raw evidence on parse failure, and stamps rich diagnostics — the
strongest-engineered part of the whole backend.

**Real gaps:**

1. **The "quick" ingestion path is the unsafe one, and it's the one people
   reach for first.** `POST /api/logs/import` (`logs.py:90-168`) has no
   upload size limit and commits the entire import as one transaction — a
   large or slow file blocks the request thread and any failure rolls back
   every log already parsed. The actually-hardened path
   (`/api/jobs/import` + worker, byte limits, resumable chunk commits) is one
   API call further away and isn't even the documented default —
   `OPERATIONS_RUNBOOK.md` still recommends the CLI for large files.
2. **O(n) per-line duplicate check** on the synchronous import path
   (`log_service.py:92-93`, `RawLog.raw_line == line`) vs. the batched
   hash-lookup already used on the resumable path.
3. **Docker Compose doesn't serve the real product.** `docker-compose.yml`
   still wires up the legacy Streamlit dashboard on port 8501 and never
   builds/serves the React frontend. Anyone who runs `docker compose up`
   gets a stale UI.
4. No tracing, no external alerting on job-failure spikes — health is a
   field a human has to poll.

The project's own runbooks already say `production_ready` must stay false
until named external owners supply real evidence — that's correct
self-grading, not a gap to fix.

---

## 3. Data model and architecture

Source: automated data-model audit, cross-referencing `models.py`, all 27
migrations, and the full `detection/`+`services/` import graph (179 files).

**Strength**: indexing is genuinely well-matched to real query patterns
(`ix_alert_status_severity_updated` etc.), `joinedload`/`selectinload` used
deliberately in 13 service files — no real N+1 risk found. Migrations are
linear, every `downgrade()` is real, nothing does an unsafe `alter_column`.

**Real gaps:**

1. **Done 2026-09-22** (migration `ff5e3639ceb0`): `OperationJob.resume_of_job_id`
   / `original_job_id` were plain `Integer`, inconsistent with sibling
   fields that use real FKs — now proper self-referential `ForeignKey`s.
   `AlertEvidence` now has a real `UniqueConstraint(alert_id,
   normalized_log_id)`, with both bulk-insert paths guarded against the new
   constraint via `on_conflict_do_nothing`.
   `RawLog.source_id`'s equivalent fix was **deliberately deferred** — it's
   a documented SQLite ALTER-TABLE workaround with no currently-reachable
   exploit path (no `LogSource` delete function exists anywhere in the
   codebase), and fixing it would mean rebuilding the largest table in the
   system with a migration pattern this repo had never used before. See the
   Consolidated Findings section below for the full reasoning.
2. **Done 2026-09-22**: `config.py`'s 200 `Field(...)` settings, previously
   one flat class with zero section comments, now have 18 section headers
   grouping them by purpose (database, auth, MFU IAM, assistant, etc.) —
   purely additive, no behavior change.
3. **Maintainability, not correctness — corrected and closed out 2026-09-22**:
   of 177 files under `detection/` + `services/`, a full verified
   import-graph trace (not the rough estimate originally reported here)
   found **130 live / 47 historical (26.6%)**. The original "~45-50 dead
   files in contiguous version ranges" framing was directionally right on
   count but **wrong on membership** — roughly 31 of the ~49 files this
   section originally named as dead (the v330-v362 and v514-540 ranges)
   turned out to be live, entangled inside two active import chains rooted
   in `dashboard.py` and `evidence_review.py`. The real historical
   population is scattered abandoned side-branches inside those chains,
   plus a few self-contained dead islands — including a second, more
   consequential example beyond the already-known `v564_window_aware_anomaly.py`
   (not wired into `main.py`; `v561_anomaly_bootstrap_service.py` is the
   live anomaly module): the `v565`/`v567` evidence-expansion tiers from
   this session's own supervised-ML qualification campaign were run as
   one-time CLI/CSV-worksheet tools, never wired into the live Evidence
   Review web UI the way the earlier `v562`/`v563` tiers were — their
   *output* feeds the live gate (`v530_supervised_evidence_closure.py`
   reads a shared evidence-pool file), but their own modules aren't live
   code paths. Full verified file-by-file table now published at
   `docs/MODULE_INDEX.md`.

---

## 4. Security, IAM, privacy

Source: automated security audit, two findings independently re-verified
against live source this turn.

**Strength**: genuinely stronger than most professional MVPs for a lab
prototype. RBAC is backend-dependency-enforced, not UI-only — sampled across
`users.py`, `demo.py`, `response.py`, `logs.py`, `suppressions.py`,
`watchlists.py`, `ingestion.py`, every mutating route gated by
`Depends(require_admin)`/`require_analyst_or_admin)`. The project's own
`ATDR_IAM_RBAC_MATRIX.md` claims were spot-checked and matched exactly — the
doc is honest, not aspirational. The MFU handoff SSO flow has real
anti-open-redirect and anti-CSRF-origin checks. `config.py` actively blocks
startup in production on a placeholder JWT secret, wildcard CORS, or
`AUTO_CREATE_TABLES` left on. The Assistant's rate limiter is DB-backed and
survives restarts; the login rate limiter is in-process only (a real but
minor gap, undocumented).

**Real bugs found — same duplicated-pattern-drift class as two bugs already
fixed this session, now confirmed by direct re-inspection:**

1. **`_AI_REVIEWER_PATTERN` has drifted across the 3 files that use it to
   gate whether an evidence-review sign-off counts as human vs. AI-generated.**
   `evidence_review_service.py:26-29` includes `"language model"` as a match
   term. `v541_governed_blind_evidence.py:84-87` and
   `v551_field_qualification_service.py:61-64` do not. Confirmed directly:
   ```
   evidence_review_service.py: ...heuristic|language model|llm|model...
   v541_governed_blind_evidence.py: ...heuristic|llm|model...   (missing term)
   v551_field_qualification_service.py: ...heuristic|llm|model... (missing term)
   ```
   A reviewer string like `"reviewed via language model"` is rejected by one
   gate and silently accepted as human by the other two. This is a real,
   exploitable integrity gap in the exact evidence chain this project's
   supervised-ML qualification claims rest on.
2. **A third, broken IP-redaction variant.**
   `v514_large_file_runtime_service.py:79-82` defines its own `_IP_PATTERN`
   for the privacy pre-flight check that asserts
   `"private_identifiers_returned": False` on acceptance-evidence exports.
   Confirmed directly: its IPv6 branch
   (`(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}`) has no `::` handling, so
   `fe80::1`, `::1`, `2001:db8::8a2e:370:7334`, `fd00::abcd` all evade
   detection — only fully-expanded IPv6 matches. The privacy check this
   function exists to enforce would miss real compressed IPv6 addresses.
   Notably, `v551_field_qualification_service.py:65-81` copy-pastes the
   *correct* canonical pattern from `assistant_llm.py` verbatim with a
   comment admitting it's a deliberate duplicate — proving even the
   "faithful" copies are one refactor away from drifting, because nothing
   forces them to stay in sync.
3. No JWT revocation — logout only clears the cookie; a bearer token
   survives up to its 8-hour lifetime regardless. Compounded by the
   `local_recovery` fallback path storing its token in `localStorage`
   (XSS-exfiltrable) rather than an HttpOnly cookie like the primary path.

This is now the **fourth** instance of the same root cause found this
session (after the zone-classification substring bug, the IPv4-only
redaction bug already fixed, and this): logic that must stay identical
across files is copy-pasted instead of shared, and it silently drifts. The
fix is the same every time — extract to one module, import everywhere, add
a test that asserts every call site references the same object.

---

## 5. AI / ML — detection rules, Assistant, supervised-ML qualification

This section is from this session's own firsthand work, not a subagent.

**Deterministic rules**: alert-authoritative, source-scoped, the actual
detection backbone. Coverage-group stratification is now empirically
grounded — `unknown_transport_context`, `incomplete_transport_context`, and
`high_activity_context` are the only strata with real threat-positive signal
(14.0% / 10.0% / 7.9%); the other four strata are ≈0%, which the v565 tier
of the evidence campaign initially over-weighted and the v567 tier corrected.

**Advisory anomaly model** (`v561_anomaly_bootstrap_service.py`, the one
actually wired into `main.py`): decision-support only, explicitly not a
threat-accuracy-validated model. `v564_window_aware_anomaly.py` (per §3) is
unpromoted research code, not a live replacement — worth being precise about
this distinction if asked in defense, since the two are easy to conflate by
name alone.

**Supervised ML qualification — the second-source situation.**
`FIXED_PROMOTION_GATES` (`v530_supervised_evidence_closure.py`) requires
5 conditions; 5 of 6 pass as of the v567 tier close-out
(`threat_positive_rows: 115/100`, closed 2026-09-19). The one that doesn't,
`minimum_real_source_identities: 2` (currently 1), is **categorical, not
volume-based** — no amount of additional rows from the same dataset can close
it, because it's specifically testing whether the model generalizes beyond
one data-generating source. This was tested directly this session: the user
asked to weaken the gate, and the request was declined, because doing so
would have produced a qualification claim the evidence doesn't support. A
public-dataset search for a usable second source was also run this session
and came back empty — nothing found met the bar (comparable schema, genuine
incident ground truth, compatible licensing).

This is not a bug and not something more engineering time fixes. It is a
structural limitation, and it's already the most honestly and thoroughly
documented part of the whole system (`CURRENT_AI_ML_PRODUCT_STATUS.md`,
`CURRENT_SYSTEM_STATE_LOCK.md` both carry a "Second-Source Requirement —
Final Decision" section). The correct move before presentation is not to try
to close it, but to be ready to explain it in exactly these terms: the gate
is categorical, the system fails closed rather than fabricating
qualification, and that's a design decision, not an oversight.

**Assistant**: deterministic keyword-routed intent handling (~25 branches)
with an optional LLM rewrite layer that never adds facts, only rephrases,
plus per-mode word budgets. This session fixed the one place it silently
gave a wrong-shaped answer (unmatched questions now honestly say so instead
of returning a generic fallback). It is not itself open-ended-question
capable beyond its routed intents — if the goal from the "make it the best"
request was a true open-domain Q&A assistant, that would be a larger
architecture change (routing unmatched questions to the LLM layer with
retrieved system context, still redaction-guarded) rather than a tuning pass.
Worth a explicit decision on scope if that's still wanted before
presentation, since it wasn't picked back up after the initial "both" answer.

---

## 6. Consolidated findings, prioritized

**Fix before presentation — small, high value, matches the class of bug
already fixed twice this session:**

| # | Finding | Effort | Status |
|---|---|---|---|
| 1 | `_AI_REVIEWER_PATTERN` drift (3 files) + broken IPv6 in v514 — extract both into one shared redaction/gating module | 2-3h | **Done** — `atdr/app/core/redaction.py` |
| 2 | 5x unguarded raw-evidence rendering in frontend — shared `String(value ?? "-")`-guarded component | 1h | **Done** — `MetaGrid.safeDisplayValue` |
| 3 | No-confirm role-change button in UserAdmin | 15m | **Done** |
| 4 | `AlertEvidence` UniqueConstraint + `RawLog.source_id`/`OperationJob` self-ref FKs | 2-3h | **Done, scoped** — see note below |
| 5 | `ErrorBanner` array-detail stringification | 30m | **Done** |

**Subtotal: ~6-8 hours — all 5 items closed 2026-09-22.**

**Scope note on item 4**: `OperationJob`'s self-referential FKs and
`AlertEvidence`'s unique constraint were added (migration
`ff5e3639ceb0`, verified up/down against a copy of the dev DB, `alembic
check` clean, full test suite green). `RawLog.source_id`'s foreign key was
**deliberately deferred**, per an explicit decision at plan time: it's a
documented SQLite workaround (`migrations/versions/c4f1a8d9e2b6_add_log_sources.py:56-58`,
"SQLite cannot add a foreign key constraint to an existing table with ALTER
TABLE"), no code path in the entire codebase currently deletes a
`LogSource` (no delete endpoint or service function exists), and fixing it
would mean rebuilding `raw_logs` — the largest table in the system
(600+MB in this project's own dev DB) — via `batch_alter_table`, a
migration pattern this repo has never used before. The risk-to-benefit
ratio didn't justify it for a gap with no reachable exploit path. Revisit
if a `LogSource` delete feature is ever added.

Adding the `AlertEvidence` unique constraint also surfaced a real, separate
finding: 4 tests across 3 files (`test_v47_overview_performance.py`,
`test_v532_analyst_workflow_product_acceptance.py`,
`test_v535_overview_stabilization.py`) had test setup code that
deliberately inserted literal duplicate `(alert_id, normalized_log_id)`
rows — a data shape the new constraint now correctly rejects. Traced each
one: in every case the duplication was incidental to what the test actually
asserted (distinct-alert counting, evidence-count reflecting multiple
rows), not the thing under test, so the fix was to remove the redundant
duplicate row rather than weaken the constraint — all original assertions
still hold with valid data.

**Worth doing if time allows — real but lower stakes:**

| # | Finding | Effort | Status |
|---|---|---|---|
| 6 | `window.prompt()` → styled modal in UserAdmin | 2h | **Done** — reuses `DetailDrawer`, new regression test |
| 7 | Add 5 missing routes to axe-core sweep | 30m | **Done** — caught and fixed a real crash in `DetectionTuning.tsx` along the way |
| 8 | `config.py` section comments | 1-2h | **Done** — 18 sections, purely additive |
| 9 | Fix `docker-compose.yml` to serve React, not stale Streamlit | 3-4h | Not started — low priority, demo doesn't use Docker |
| 10 | MODULE_INDEX.md mapping live vs. historical vNNN modules (cheaper alternative to archiving ~45-50 files outright) | 3-4h | **Done** — full verified table at `docs/MODULE_INDEX.md`; corrected the membership errors in §3 above |

**Subtotal: ~10-13 hours — 4 of 5 items closed 2026-09-22; only the Docker fix remains, and it's low-priority since the demo doesn't run through Docker.**

Item 6's build-out surfaced one more real bug, same class as the others this
session: the new drawer's input `value` state wasn't reset between opens,
so submitting "Reset password" right after "Edit email" would have carried
the email's typed text into the password field's validation check. Found by
the new regression test failing on first run, fixed with a `useEffect` keyed
on the edit target.

**Explicitly defer — real production-hardening, out of scope for a capstone
demo, belongs in Limitations/Future Work rather than a pre-presentation
scramble:** JWT revocation, moving the recovery-login token out of
`localStorage`, durable multi-worker rate limiting, OpenTelemetry tracing, a
job-failure alerting hook, delegating `/api/logs/import` to the queued path,
batched-hash dedup on the sync path, archiving (vs. just indexing) the dead
vNNN modules, splitting `MLGovernance.tsx`/`ExecutiveOverview.tsx`. None of
these change what the system does today; they're about running it somewhere
real, at scale, unattended — not about the capstone demo being correct and
honest.

---

## 7. How far, and how long

**Status as of 2026-09-22**: all 5 "fix before presentation" items and 4 of
5 "worth doing if time allows" items are done and verified (full backend
suite green, full Playwright suite green, both builds clean). Only the
Docker-serves-stale-Streamlit fix remains from the original ~16-21 hour
estimate, and it's low priority since the demo runs through
`start_system.cmd`, not `docker compose up`. Two real bugs were caught and
fixed along the way that weren't in the original finding list: a missing
optional-chain guard in `DetectionTuning.tsx` (found by the expanded
accessibility sweep) and a state-persistence bug in the new UserAdmin
drawer (found by its own new regression test).

**What does not get fixed no matter how much time is spent**: the
second-source gate. That's not a gap in the plan — it's the correct outcome
of a gate that's designed to fail closed rather than be gamed by volume. It
should be presented as evidence the governance model works, not apologized
for.

**Recommended order**: Tier 0 first (it's the integrity bug, and it's cheap),
then decide per-item on Tier 1 based on remaining time. Tier 2/defer items
are legitimate future-work entries, not gaps to close before presenting.
