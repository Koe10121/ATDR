# v5.47 Prediction-Blind Manual-Anchor Acquisition

## Status

v5.47 is implemented and measured against the private PAN-OS evidence through
disposable SQLite storage. It created one immutable sealed pack and one
editable working copy containing 120 development-only rows. The pack is ready
for genuine human review; it is not import-ready and contains no model
prediction or assisted label.

- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- pack status: `ready_for_human_review`
- selected rows: `120/120`
- represented coverage strata: `7`
- human review: `0/120`
- candidate frozen or activated: no
- automatic response and real firewall blocking: disabled
- supervised phases remaining after human review begins: 4

## Evidence Selection

The acquisition revalidates the v5.39-v5.46 custody chain before reading the
private source. Only `development_fit`, `calibration`, and `threshold` roles
are eligible. Reserved-future roles remain sealed. Selection is deterministic
and independent of predictions and assisted labels.

The measured pack contains:

| Coverage stratum | Rows |
| --- | ---: |
| High-risk or threat context | 20 |
| Incomplete / allow / 80 | 20 |
| Low-signal suspicious boundary | 15 |
| QUIC / 443 control | 15 |
| Routine benign control | 10 |
| Scan-like behavior | 20 |
| Unknown transport | 20 |

The acquisition found 220,982 eligible unique families. It excluded 18,994
duplicate families, 44,741 future or reserved-role families, and 706 existing
manual-anchor families. No future-role row was selected.

## Review Contract

The sealed pack and working copy remain under the ignored
`ml_baseline_reviews/` workspace. Review columns are blank at creation. A row
counts as reviewed only when a real reviewer supplies a supported decision,
confidence from 1 through 100, rationale, reviewer identity, timestamp, and
explicit confirmation. Reviewer identities that claim an automated system,
assistant, Codex, Gemini, or another model are rejected.

The validator requires complete review plus minimum support of 20 benign-like,
15 suspicious, and 10 malicious decisions before fixed revalidation can run.
It never imports labels automatically, never retrains, and never changes model
or alert authority.

## Privacy And Safety

The review pack omits raw log text, IP addresses, source/device identities,
private paths, fingerprints, predictions, model scores, and assisted labels.
The authenticated API and AI Governance panel expose aggregate counts only.

The measured run changed zero configured database rows, labels, model runs,
detection runs, alerts, response actions, protected workspaces, or active model
artifacts. It created no human-reviewed label and opened no reserved-future
label. The private source still represents only one identified real device;
source-generalization remains unproven.

## Verification Result

- Private preflight passed every custody, availability, privacy, and
  no-mutation check.
- The measured disposable pass parsed `773,551/773,551` rows with zero parser
  failures in `220.4093s`; the sealed 120-row workspace was reused unchanged
  after the reporting-contract regression fix.
- Taskboard render/standard, Ruff, canonical compileall, and Alembic no-drift
  checks passed.
- Backend and release-gate testing passed `997 passed, 1 skipped`.
- React lint/build passed; Playwright passed `35`, with one intentional
  live-source skip.
- The isolated port-scan scenario parsed `10/10`, created one critical alert
  and one case, and created zero response actions.
- Layered detection passed `288/288` with zero controlled false positives and
  false negatives.
- Assistant QA passed `20/20`, all answer budgets, citations, unsafe refusal,
  and zero-side-effect checks.
- Replay dry-run parsed `2/2` and wrote zero rows.
- Performance smoke passed without warnings: Overview `0.1777s`, cached
  Overview `0.0102s`, ML Governance `0.2506s`, alert list `0.0309s`, and case
  summary `0.0635s`.
- The final canonical release gate completed successfully in `459.6s`.

## Repository Hygiene

The cumulative v5.43-v5.47 worktree contains exactly the 50 paths listed in
`docs/V5_47_COMMIT_ALLOWLIST.md`. Staging is empty and `git diff --check`
passes. No tracked `.env`, database, private log, model artifact, generated
review/report workspace, or processed evidence is present. The private file
name appears only as an intentional `.gitignore` rule; no private path or
credential appears in changed content. The v5.47 generated workspace remains
ignored. No commit or push is authorized.

## Operator Commands

Custody and private-file preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v547_manual_anchor_acquisition `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --preflight-only --no-report --pretty
```

Create or revalidate the sealed 120-row workspace:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v547_manual_anchor_acquisition `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --review-limit 120 --pretty
```

Read safe aggregate progress:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v547_manual_anchor_acquisition `
  --status-only --pretty
```

Authenticated dashboard status:
`GET /api/evidence-review/manual-anchor-acquisition/status`.

## Next Decision

Complete genuine prediction-blind review of the private working copy. Do not
replace that work with AI-generated labels or reinterpret the pack as
independent evidence. After the review and class-support gates pass, run one
fixed development-only revalidation without changing the v5.42 quality gates.
A second genuine source is still required before source-generalization or
activation can be reconsidered.
