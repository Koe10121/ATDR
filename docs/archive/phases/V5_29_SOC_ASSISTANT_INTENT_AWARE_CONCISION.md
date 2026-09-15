# v5.29 SOC Assistant Intent-Aware Concision

## Status

v5.29 replaces the SOC Assistant's universal report shape with concise,
intent-specific response contracts. The Assistant remains authenticated,
read-only decision support. Deterministic fallback remains available, raw log
context remains disabled, IP redaction remains enabled, and no answer can
execute detection, response, label, model, user, or deletion operations.

Human blind review remains deferred. This change does not alter detection or
supervised-model authority.

## Root Cause

Three behaviors made unrelated answers look the same:

1. The provider schema required Summary, Evidence, Risk Interpretation,
   Analyst Checks, Safety Notice, Follow-ups, and Citations for every question.
2. The deterministic normalizer injected the same sections even when a direct
   answer, list, or short procedure was sufficient.
3. The provider guard rejected answers shorter than 180 characters whenever
   local context was long, regardless of factual coverage.

The React page then displayed the entire result, evidence trail, citations,
provider telemetry, and repeated safety wording at once.

## Response Contracts

| Mode | Intended shape | Hard word limit |
| --- | --- | ---: |
| `direct_fact` | One direct fact or up to three short sentences | 80 |
| `alert_explanation` | Verdict, key evidence, one next check | 110 |
| `safe_next_step` | Two to four prioritized checks | 100 |
| `related_logs` | Compact linked-log summary | 120 |
| `source_health` | Status, main issue, one next check | 100 |
| `list_summary` | Short ranked list | 100 |
| `investigation_brief` | Full structured brief only when explicitly asked | 300 |
| `how_to` | Concise numbered procedure | 180 |
| `governance` | Status, blocker, consequence | 100 |

Every mode allows no more than three follow-up suggestions. Follow-ups include
the active alert, log, source, or case identifier where applicable.

## Measured Result

The fixed 20-question deterministic Assistant QA suite reports:

| Measure | Before | v5.29 |
| --- | ---: | ---: |
| Average answer length | 283.8 words | 73.1 words |
| Maximum answer length | 697 words | 184 words |
| QA cases passing | not measured by v5.29 contract | 20/20 |
| Citation pass rate | not changed | 100% |
| Word-budget pass rate | not available | 100% |

The explicit investigation brief remains the longest answer class. Routine
triage questions stay within 100 to 120 words.

## Follow-Up Behavior

A single conversation now preserves the active record while changing only the
answer requested:

1. `Why was alert 1 flagged?` returns `alert_explanation`.
2. `What logs are related?` returns `related_logs` for alert 1.
3. `What should I check next?` returns `safe_next_step` for alert 1.

The second and third answers do not repeat the complete first explanation.
Explicit IDs replace stale or ambiguous context, and unsupported provider IDs
fail closed.

## Provider And UI Result

The Gemini prompt uses `soc_intent_aware_concise_v4`, receives the requested
mode and budget, and returns only direct answer, relevant evidence, next steps,
limitations, follow-ups, and citations as needed. Accurate short provider
answers are accepted; invented records, lost primary citations, missing
requested coverage, over-budget output, secret-like content, or implied action
execution are rejected to the concise deterministic fallback.

The configured bounded Gemini suite passed 12/12 checks over six calls:

- median and p95 latency: 2,105 ms and 2,828 ms;
- aggregate input/output/total tokens: 19,332 / 1,238 / 20,570;
- correct record context and citations: passed;
- raw logs, IPs, private paths, and secrets returned: none; and
- configured-database and authoritative-state mutations: zero.

The React response panel shows the direct answer first. Detailed evidence and
provider/citation information are collapsed by default. The visible response
safety state is limited to `Read Only`, `Decision Support Only`, and
`Response Automation Disabled`. Conversation state still survives dashboard
navigation and clears on logout or explicit context reset.

## Safety And Limitations

- Rules remain alert-authoritative.
- Supervised ML remains `shadow_observation`.
- Gemini and deterministic Assistant output remain decision support only.
- Raw log context is disabled and IP redaction is enabled.
- Automatic response and real firewall blocking remain disabled.
- The automated suite does not prove universal semantic correctness or human
  usefulness.
- Qualified human semantic/privacy review and approved-host provider
  governance remain future evidence phases.

## Verification

Focused verification completed during implementation:

- Assistant-focused backend: `59 passed`;
- deterministic Assistant QA: `20/20`, all budgets and citations passed;
- configured Gemini bounded quality: `12/12`;
- React lint/build: passed; and
- focused Assistant Playwright: `6 passed`.

Complete closure verification also passed:

- Ruff and compileall;
- full backend: `852 passed, 1 skipped`;
- Alembic: no drift;
- React lint/build;
- Playwright: `27 passed, 1 skipped`;
- replay dry-run: two safe rows parsed with zero sends or writes;
- performance smoke: no warnings, cached Overview `0.0118s`, alert list
  `0.0433s`, case summary `0.0272s`, and ML Governance `0.3908s`; and
- official release gate: `ok: true` with no failed required checks.

The Playwright skip is the existing external live-source scenario gate. During
closure, an initial custom pytest temp root under `.pytest_tmp/` correctly
triggered ATDR's backup-output containment guard. The final full run used the
approved ignored `.tmp/` boundary; all affected persistence and integrated
acceptance tests then passed without weakening that guard.
