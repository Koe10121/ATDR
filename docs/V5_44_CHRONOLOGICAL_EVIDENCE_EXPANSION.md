# v5.44 Chronological Evidence Expansion And Label-Coverage Qualification

## Status

v5.44 is implemented and measured. It revalidates every v5.39-v5.43 custody
boundary, streams the complete private PAN-OS source through disposable
SQLite, quarantines prior/overlapping evidence, creates three disjoint
development cohorts, and keeps the newest cohort sealed.

The result supports another **development-only** model-repair cycle. It does
not provide independent validation or justify model activation.

- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- supervised model activated or promoted: no
- automatic response and real firewall blocking: disabled
- supervised phases remaining: 5

## Measured Evidence

| Measure | Result |
| --- | ---: |
| Rows streamed | 773,551 |
| Parser successes / failures | 773,551 / 0 |
| Observed chronology | 22 minute windows over 1,249 seconds |
| Eligible chronology | 19 minute windows |
| Configured-database overlap | 120,000 rows |
| Near-duplicate rows | 52,881 |
| Excluded or quarantined | 120,626 rows |
| Usable development rows | 540,921 |
| Usable development near families | 503,752 |
| Sealed future-validation rows | 112,004 |
| Identified genuine device sources | 1 |

Development roles are fixed before assisted decisions are calculated:

| Cohort | Rows | Representative families | Windows |
| --- | ---: | ---: | ---: |
| Fit | 352,312 | 327,464 | 10 |
| Calibration | 113,519 | 105,955 | 3 |
| Threshold | 75,090 | 70,333 | 2 |
| Untouched future validation | 112,004 | 104,759 | 4 |

Exact and propagation-family equivalents cross no cohort boundary under the
v5.44 lock. The future cohort was partitioned but its assisted labels were not
calculated or opened. The later v5.45 label-blind audit found broader
`candidate_near_hash` overlap across roles and quarantined it in disposable
storage; see `docs/V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`.

## Quarantine

Final exclusion reasons are:

- configured-database overlap: 120,000 rows
- family containment after quarantine: 573 rows
- v5.40 near-family overlap: 53 rows

The workflow also rechecked v5.39 protected tokens, v5.40 exact/near
boundaries, the v5.41 candidate store, and v5.42/v5.43 freeze state. Protected
labels and predictions were never opened.

## Label Coverage

The existing governed development population remains 1,467 rows: 918
manual/reviewed anchors and 549 assisted/weak rows. No existing decision was
rewritten.

The private source produced 360,886 high-confidence assisted representative
groups and 133,373 ambiguous represented events. These are **weak/assisted
evidence only**. They are not human ground truth.

| Assisted decision | Representative groups |
| --- | ---: |
| Benign | 134,340 |
| Benign unusual | 4,337 |
| Suspicious | 220,694 |
| Malicious | 1,515 |
| Needs context | 131,324 |

Dominant pattern groups are scan-like behavior (317,061),
suspicious/malicious boundary (95,412), benign QUIC/443 (56,274), unknown
UDP/TCP (12,572), routine known applications (9,731), incomplete/allow/80
(672), denied high-risk service (287), and vendor THREAT records (201). No
separate C2/exfil-specific rule pattern was observed in this source under the
current taxonomy; this absence is not proof that C2 traffic is absent.

## Assisted Review Pack

A compact 200-row assisted preview was generated in ignored private storage.
Every row states:

- `human_must_confirm=true`
- `human_reviewed=false`
- `import_ready=false`
- no raw log or IP address included

The pack is optional evidence for future human work. It must not be imported
or described as reviewed labels.

## IsolationForest Audit

The unchanged active IsolationForest artifact was sampled over 1,800
development representatives. It produced FPR `0.0056`, queue recall `0.0056`,
F1 `0.0110`, suspicious recall `0.0111`, and malicious recall `0.0000`.

This is a low-noise but severely under-sensitive result. IsolationForest
remains advisory and cannot create, suppress, or change authoritative alerts.
No future-validation row was scored and no artifact was written.

## Sufficiency Decision

All fixed development-evidence checks pass: parser quality, chronology,
three populated development roles, duplicate isolation, assisted class
support, training volume, existing manual anchors, assisted-only provenance,
and sealed future labels.

Therefore:

- development-only model repair ready: **yes**
- candidate freeze ready: **no**
- independent validation ready: **no**
- independent labeled evidence sufficient: **no**

Remaining blockers are one genuine device source, no new human ground truth,
and no supervised candidate that has passed unchanged temporal gates.

## Safe Commands

Preflight without reading rows:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v544_chronological_evidence_expansion `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --preflight-only --no-report --pretty
```

Full aggregate-only qualification:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v544_chronological_evidence_expansion `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --use-temp-db --pretty
```

The CLI never returns the private path, filename, raw rows, IP addresses,
source tokens, fingerprints, or secrets. Generated evidence remains ignored
under `ml_baseline_reviews/`.

## Remaining Supervised Phases

1. Rerun fixed development-only model repair on the new locked cohorts.
2. Freeze at most one candidate only if every unchanged development gate
   passes.
3. Acquire future evidence from at least two genuine devices and complete
   prediction-blind human review.
4. Run one frozen independent evaluation without tuning.
5. Make a separate governance decision and complete shadow observation.

Software can complete phases 1 and the engineering portion of phase 2. A
second physical source, genuine human labels, provider/advisor acceptance,
and any authority decision remain external evidence.

## Verification

- taskboard render and standard check: pass
- Ruff and source-tree compileall: pass
- backend: `970 passed, 1 skipped`
- Alembic: no drift
- React lint/build: pass
- Playwright: `35 passed, 1 skipped` (live source intentionally skipped)
- controlled port-scan scenario: 10/10 parsed, one alert, one case, zero response
- layered detection: `288/288`, zero controlled FP/FN
- deterministic Assistant QA: `20/20`, citation pass rate `1.0`
- replay: dry-run only, zero writes
- performance smoke: pass with no warnings
- release gate: `ok: true`

Performance on 145,232 normalized rows is Overview cold/cached
`0.1766s/0.0102s`, AI Governance `0.2494s`, Alerts `0.0302s`, and Cases
`0.0552s`.

An initial broad compileall traversed intentionally malformed ignored pytest
fixtures under `atdr/data/processed`; the canonical source-only command and
release-gate exclusion both pass. An initial full pytest run used an overly
long Windows temp root and produced five path-construction failures; the
affected tests passed `7/7` and the complete suite passed after using a short
temp root. Neither issue was an ATDR runtime failure.
