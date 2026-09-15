# v5.57 End-to-End Analyst Workflow, Accessibility, And Startup Reliability Lock

Date: 2026-09-04

## Decision

ATDR's locally controllable analyst journey now has an integrated disposable
acceptance path, automated accessibility coverage, predictable keyboard and
focus behavior, five-viewport layout coverage, and an idempotent four-service
launcher. The local release-candidate decision remains
`local_release_candidate_ready`; `production_ready=false`.

This phase changes neither detection authority nor AI lifecycle. Deterministic
rules remain alert-authoritative, supervised ML remains in
`shadow_observation`, the Assistant remains read-only, and response remains an
analyst-approved simulation. Real firewall blocking and automatic response are
disabled.

## Proven Defects Closed

1. Re-running the supported launcher against a healthy system returned an
   error. It now recognizes all four tracked healthy components and returns a
   successful, actionable status without creating duplicate processes.
2. Partial runtime state did not clearly describe recovery. Startup now fails
   closed with exact check and stop commands; stale metadata is removed only
   when no tracked process remains active.
3. Setup and recovery messages mixed direct PowerShell scripts with supported
   command wrappers. Operator guidance now consistently uses the `.cmd`
   entrypoints.
4. Machine-specific project and template paths appeared in status JSON. The
   status contract now reports configuration booleans and a sanitized error
   code instead of absolute paths.
5. SPA route changes did not announce or focus the new main region. The shell
   now provides a skip link, a separately labelled main landmark, and bounded
   route-title announcements and focus movement.
6. Detail drawers lacked complete dialog keyboard behavior. Drawers now have
   dialog semantics, initial close-button focus, Tab containment, Escape and
   backdrop close behavior, body-scroll containment, and focus restoration.
7. Custom selects did not provide complete keyboard movement. Arrow keys,
   Home, End, Enter, Space, Escape, focus tracking, and listbox naming are now
   explicit.
8. Several form controls and progress indicators had incomplete accessible
   names or invalid ARIA. Filters, date inputs, response justification,
   progress bars, loading state, and toolbar commands now expose valid
   semantics.
9. Amber, success, and sidebar text combinations failed automated contrast
   checks. Accessible palette values replace those combinations without
   removing MFU red, gold, and neutral visual identity.
10. Loading placeholders and motion did not consistently respect assistive
    technology or reduced-motion preferences. Loading regions now expose
    status/busy state and decorative skeletons are hidden; global motion is
    disabled when requested.
11. The integrated Assistant sequence interpreted "Which logs are related?"
    as another alert explanation. Intent matching now recognizes that wording
    as `related_logs` while preserving the selected alert through the next-step
    follow-up.
12. The legacy v5.38 source-backed reliability gate matched the previous
    three-viewport Playwright title literally. It now recognizes the renamed
    desktop/tablet/mobile contract, so expanding coverage to five viewports no
    longer creates a false backend-suite failure.

## Integrated Analyst Acceptance

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v557_analyst_workflow_acceptance --pretty
```

The command uses temporary in-memory SQLite and deterministic Assistant mode.
It does not access the configured database or write a report. The measured
scenario passed `24/24` checks:

| Stage | Measured result |
| --- | --- |
| Ingestion | 10 raw records preserved |
| Parsing and normalization | 10 normalized; 0 parse failures |
| Detection | 10 evaluated; 1 rule-authoritative alert |
| Explanation and related evidence | 10 linked evidence rows |
| Case investigation | 1 case; `case_handoff` Assistant contract |
| Assistant continuity | `alert_explanation`, `related_logs`, then `safe_next_step` |
| Assistant citations | 10, 10, and 3 references across the three turns |
| Assistant writes | 0 alert, detection-run, label, model-run, or response-action deltas |
| Simulated response | approved simulation plus two guarded denials; firewall unchanged |
| Audit | four Assistant events and both response targets represented |

The scenario is controlled synthetic evidence. It verifies workflow contracts
and safety, not field accuracy or production behavior.

## Accessibility And Responsive Coverage

Automated axe checks cover unauthenticated login plus authenticated Overview,
Alerts, Logs, Assistant, Response, Audit, AI Governance, and Evidence Review.
The tested WCAG 2 A/AA and WCAG 2.1 A/AA rules report zero violations.

Keyboard regression covers the skip link, SPA route focus, custom-select
navigation, detail-drawer focus containment, Escape close, and focus return.
Responsive regression covers `1920x1080`, `1440x900`, `1366x768`, `768x1024`,
and `390x844` without page-level horizontal overflow.

Automated axe and viewport checks are engineering evidence, not a formal WCAG
certification or an independent assistive-technology usability study.

## Startup And Recovery Evidence

The supported command remains:

```powershell
.\scripts\start_system.cmd
```

An actual local lifecycle verified:

- initial start reached all four services;
- repeated start recognized the healthy runtime and exited successfully;
- `check_system.cmd -RequireReady -Json` reported four reachable services and
  `secrets_exposed=false`;
- `stop_system.cmd` stopped exactly four launcher-owned processes; and
- the following status check reported no runtime metadata or reachable
  service and recommended the supported start command.

The status contract does not return the project root, MFU shell root, secret
values, provider identifiers, or private configuration values.

## Verification

- Focused v5.57 backend/startup/Assistant tests pass `34/34`.
- The repaired legacy v5.38 reliability suite passes `8/8`.
- Full backend verification passes `1067 passed, 1 skipped`; the independent
  release gate repeats the same result successfully.
- Disposable integrated acceptance passes `24/24` checks.
- Ruff, compileall, React lint, and production build pass.
- Playwright passes `42` tests with `1` intentional physical/live skip.
- Controlled source validation passes `4/4` scenarios and `10/10` checks;
  deterministic detection passes `24/24`; layered validation passes `288/288`
  with controlled false-positive/false-negative counts `0/0`.
- Assistant QA passes `30/30` with citation rate `1.0`, average/max answer size
  `56/110` words, contextual continuity, privacy, and zero side effects.
- Alembic reports no pending upgrade operations. Replay dry-run parses `2/2`
  sample rows and writes nothing.
- The repository security scan finds zero issues across `1,376` tracked or
  intended text paths; Python and npm audits find zero known vulnerabilities.
- The read-only performance smoke passes. Cached Overview is `0.0163s`; cold
  Overview is `1.0875s` and records one soft warning against the `1.0s` local
  target. No functional performance gate fails.
- Release verification returns `ok=true` with no failed required checks, and
  deployment-operation source validation passes with `production_ready=false`.
- The cumulative changed-path set reconciles exactly `61/61`, staging is empty,
  private/generated outputs remain ignored, and `git diff --check` passes.

## Remaining External Gates

1. A teammate must execute the shell-first lifecycle on a separate physical
   machine.
2. MFU must accept real callbacks, account scope, group-role mapping, provider
   2FA, recovery, and deprovisioning.
3. A second physical log source and untouched future window must provide
   independently reviewed detection evidence.
4. The provider owner must approve Gemini privacy, retention, quota, billing,
   key rotation, and representative field use.
5. An approved shared host must provide DNS/TLS, managed secrets, monitoring,
   PostgreSQL, shared storage, load, backup/restore, and measured recovery.
6. Independent analysts and assistive-technology users must complete formal
   usability acceptance.

## Publication Boundary

No commit, push, deployment, external acceptance, model activation, response
automation, or real blocking is authorized by this document. The exact
cumulative review boundary is recorded in `docs/V5_57_COMMIT_ALLOWLIST.md`.
