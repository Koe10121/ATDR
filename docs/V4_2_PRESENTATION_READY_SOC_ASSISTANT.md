# v4.2 Presentation-Ready SOC Assistant

Date: 2026-07-14

## Status

v4.2 makes the existing read-only SOC Assistant easier to trust and use during investigation. It does not change detection logic, model activation state, response behavior, database schema, or startup commands.

ATDR remains a controlled security-operations system under active development. The assistant is decision support, not an autonomous responder.

## Where Answers Come From

The deterministic assistant routes a question to bounded ATDR services in `atdr/app/services/assistant_service.py`. Those services query structured records through the existing alert, log, source, case, job, detection-run, and ML-governance services. Each answer returns structured citations from `atdr/app/schemas/assistant.py` through `atdr/app/routers/assistant.py`.

Examples of grounded sources:

- alert records: `/api/alerts/{alert_id}`;
- normalized log records: `/api/logs/{log_id}`;
- managed source records: `/api/sources/{source_id}`;
- case groups: `/api/alerts/cases`;
- operation jobs and detection runs: `/api/jobs/{job_id}` and `/api/detection/runs/{run_id}`;
- governance summaries: `/api/ml/report` and `/api/ml/supervised/report`;
- ATDR runbooks and rule documentation under `docs/`.

`atdr/app/services/assistant_service.py` now adds a non-secret `details.grounding` summary to every answer. The React page renders the exact returned citations as **Grounded In** references. If no citation is available, the page says that no record-specific ATDR evidence was available rather than inventing a source.

## Gemini Boundary

Gemini is an optional explanation layer implemented in `atdr/app/services/assistant_llm.py`.

- ATDR first builds a deterministic evidence-grounded answer.
- Only bounded, structured, redacted context is supplied to Gemini.
- Raw-log context remains disabled.
- Gemini may summarize or improve wording; it may not create database facts.
- Returned citation references are restricted to citations supplied by ATDR.
- Invalid, unsafe, incomplete, or unavailable provider output falls back to the local evidence assistant.
- The assistant cannot execute response actions, detection runs, label changes, user changes, model activation, deletion, or firewall changes.

The 2026-07-14 private configuration check found Gemini enabled with provider, model, and key configured. The safe synthetic provider probe completed in one attempt with structured output, no raw-log context, IP redaction enabled, and `secrets_exposed=false`. No key value was printed or stored.

The dashboard uses truthful wording:

- **Gemini Configured** means private configuration is ready but the visible answer has not yet used Gemini.
- **Gemini Assisted** appears only when that answer reports `external_provider_used=true` and passed ATDR guards.
- **Local Evidence Assistant** appears for deterministic answers.
- A provider failure or guard displays a local-evidence fallback state.

## Persistent Investigation Context

Root cause: `frontend/src/App.tsx` unmounts the lazy `AssistantPage` when the analyst navigates to another route, while React Query mutation data is page-local. The question, answer, and active context therefore disappeared on remount.

`frontend/src/lib/assistantSession.ts` now stores a versioned, session-scoped, whitelisted snapshot in `sessionStorage`. It preserves:

- current question and bounded rendered answer;
- returned citations and follow-up suggestions;
- alert, log, source, or case context;
- conversation ID and safe provider telemetry.

It explicitly excludes raw-log context, arbitrary response details, tokens, secrets, keys, and model paths. Malformed storage is removed safely. `Clear Context` removes the snapshot and creates a new conversation. `frontend/src/hooks/useAuth.tsx` clears it on logout or session expiry. Returning to the Assistant page restores the snapshot without resending a provider request.

## Concise Analyst View

The default response in `frontend/src/pages/AssistantPage.tsx` now shows:

1. Summary: at most three short items.
2. Why flagged / evidence: at most five items.
3. Analyst next steps: at most five items.
4. Safety: one line.
5. Grounded In: compact source citations.

Risk interpretation, related context, limitations, narrative text, provider telemetry, raw technical response details, assistant activity, and feedback quality review are expandable. Additional playbooks are collapsed behind **More analyst playbooks**.

The provider prompt contract in `atdr/app/services/assistant_llm.py` is now `soc_evidence_grounded_concise_v3`, with bounded section sizes and explicit anti-repetition instructions.

## MFU Visual Alignment

The official supervisor shell was used only as a visual reference. Its source establishes MFU burgundy `#8c1515`, dark burgundy, and gold accents in:

- `frontend-vue/src/assets/scss/_variables.scss`;
- `frontend-vue/src/projects/styles/shared-page-shell.scss`;
- `frontend-vue/src/projects/components/layout/AppSectionHero.vue`.

ATDR keeps React and its existing routes. Shared tokens in `frontend/tailwind.config.ts`, global components in `frontend/src/styles.css`, and the shell in `frontend/src/components/AppShell.tsx` now use a restrained burgundy/gold university visual language, a dark navigation rail, compact header, consistent surfaces, and clearer focus states.

## Manual Presentation Check

1. Start the backend and React frontend with the normal commands.
2. Open **SOC Assistant**.
3. Confirm **Read Only**, **Decision Support Only**, **Response Automation Disabled**, and **Raw Logs Disabled**.
4. Ask `Why was alert 1717 flagged?` using an alert ID that exists locally.
5. Confirm the answer shows concise sections and **Grounded In** citations.
6. Click a follow-up such as `What logs are related?` and confirm the same alert ID remains active.
7. Navigate to **Alerts**, then return to **SOC Assistant**. Confirm the answer remains and no question is resent.
8. If the answer used Gemini, confirm **Gemini Assisted**. If it did not, present the exact local/fallback status shown.
9. Click **Clear context** and confirm the answer and active context disappear.
10. Confirm there are no response-action controls on the Assistant page.

## Safety And Remaining Limits

- Raw logs are not sent to Gemini by default.
- IP redaction remains enabled by default.
- Browser persistence is tab/session scoped, not a server-side chat archive.
- Gemini quality and availability depend on private provider configuration and quota.
- Citations prove which ATDR references were supplied; they do not convert an inference into a verified incident fact.
- Response automation and real firewall blocking remain disabled.
- No model was activated or promoted by v4.2.

## Verification Result

- Ruff and compileall: passed.
- Backend: `568 passed, 1 skipped`.
- Alembic: no drift on the already migrated disposable database.
- React lint and production build: passed.
- Playwright: `23 passed, 1 skipped`.
- SOC Assistant focused Playwright: `6 passed`.
- Gemini status and one bounded live probe: passed; structured output valid, raw-log context excluded, and no secret exposed.
- Live authenticated assistant request: `external_llm_gemini`, provider answer used, ten returned citations, redaction applied, raw-log context false, and no secret field returned.
- Live side-effect comparison on the disposable copy: response actions `0 -> 0`, detection runs `31 -> 31`, labels `2672 -> 2672`, model runs `41 -> 41`.
- Replay dry-run: passed with two safe sample rows and zero writes.
- Read-only performance smoke on the migrated disposable copy: no warnings; Overview `0.4549s`, cached Overview `0.0074s`, ML Governance `1.1866s`, alerts `0.0307s`, cases `0.0729s`.
- Release gate: `ok: true`.

The configured local database was not reset, migrated, deleted, or written. It remains one additive migration behind (`raw_logs.raw_line_hash`), so current-model queries against that configured DB require the operator to run `alembic upgrade head` before normal dashboard use. This is an inherited v3.97 operational step, not a v4.2 schema change.
