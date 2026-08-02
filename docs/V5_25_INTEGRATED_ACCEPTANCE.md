# v5.25 Integrated Acceptance

## Status

`v5_25_integrated_acceptance_passed_external_gates_open` on 2026-08-02.

The detection-centered v5.20-v5.25 local product-closure roadmap is complete.
This is a controlled, disposable acceptance result. It is not production
readiness, real-device validation, or supervised-model promotion.

## Integrated Result

The privacy-safe runner passed `14/14` fixed local gates:

- 5,000 attempted rows produced exactly 5,000 raw and 5,000 normalized rows;
- raw evidence and source links were complete;
- three intentional raw-fallback parse failures and 19 duplicates were
  accounted for;
- committed-boundary interruption, cancellation/resume, stale lease recovery,
  queue backpressure, file import, API upload, and local UDP replay passed;
- deterministic rules remained alert-authoritative and alert deduplication,
  source linkage, case linkage, `Why flagged?`, and analyst next steps passed;
- the bounded v5.24 Gemini lock supplied six real provider answers and passed
  `11/11` grounding, citation, context, concision, fallback, privacy, and
  read-only gates;
- missing-justification and protected-target response attempts were denied;
- one approved action remained simulated and all three response records were
  audited inside disposable storage;
- no configured-database change, label, model run, model activation,
  automatic response, or real firewall change occurred; and
- no raw evidence, private path, address, credential, or secret was returned.

## Gemini Evidence Policy

v5.25 accepts either a fresh bounded provider run or the validated ignored
`v5_24_investigation_gemini_quality_latest.json` lock. The measured run reused
the existing v5.24 lock because a fresh repeat encountered external provider
throttling. It did not weaken any quality gate or substitute deterministic
fallback answers for a provider pass.

Fresh provider revalidation remains available:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v525_integrated_acceptance --use-temp-db --execute-provider --log-count 5000 --pretty
```

Quota-independent integrated acceptance using the existing validated lock:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v525_integrated_acceptance --use-temp-db --log-count 5000 --pretty
```

Both commands use disposable databases. Generated diagnostics remain ignored.

## External Gates Still Open

| Gate | Current state | Required before claim |
| --- | --- | --- |
| Non-loopback sender | Owner-deferred | External transport acceptance |
| Real firewall/router | Not observed | Real-device interoperability |
| Independent human-reviewed native labels | Not provided | Supervised promotion reconsideration |
| MFU IAM preproduction | Not evaluated by v5.25 | Provider-backed university IAM acceptance |
| Approved shared host | Not evaluated by v5.25 | Deployment and recovery acceptance |
| Gemini privacy/quota/key governance | Quality lock passed; governance open | Shared external-assistant deployment |

## Lifecycle Lock

- Rules: alert-authoritative.
- IsolationForest: advisory anomaly signal.
- Supervised ML: `shadow_observation`, not activated or promoted.
- Gemini: read-only evidence-grounded decision support.
- Response: simulated and analyst-approved only.
- Automatic response: disabled.
- Real firewall blocking: disabled.
- Production readiness: not claimed.

## Final Local Verification

The complete local closure matrix passed on 2026-08-02:

- taskboard render and standard checks;
- Ruff and compileall;
- backend and release suites: `824 passed, 1 skipped`;
- Alembic: no drift;
- React lint and production build;
- Playwright: `27 passed, 1 skipped` (the skipped test is the intentionally
  deferred external live-source scenario);
- controlled detection: `24/24`;
- layered detection: `288/288` with zero controlled false positives or false
  negatives;
- deterministic Assistant QA: `20/20` with zero authoritative side effects;
- v5.25 integrated acceptance: `14/14`;
- replay dry-run: two safe sample rows parsed and zero rows written;
- warning-free performance smoke at 145,232 raw/normalized rows: Overview
  `0.1712s`, cached Overview `0.0099s`, Alerts `0.0425s`, Cases `0.0217s`, and
  ML Governance `0.3232s`; and
- official release gate: `ok: true`.

The exact cumulative review boundary reconciles `75/75` paths with zero
missing or extra entries. `git diff --check`, staging, private-marker,
credential-pattern, ignored-path, and forbidden-tracked-file checks pass.

Existing scikit-learn sparse-feature and calibration warnings remain diagnostic
evidence. They do not change the passing test result or the required
`shadow_observation` lifecycle.

No commit or push is authorized by this phase.
