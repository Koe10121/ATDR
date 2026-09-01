# v5.51 Fresh Evidence Protocol

## Evidence Namespace

Protocol: `v5.51-post-v5.49b-fresh-evidence-v1`.

The public temporal boundary is `2026-09-01T00:00:00+07:00`. It follows the
published v5.49b/v5.50 closure and is deliberately derived without opening any
protected review, label, prediction, fingerprint, claim, or result.

Rows before the boundary and rows without a usable event time are excluded.
They cannot be moved into a role by an operator override.

## Collection Eligibility

A collection is admitted only when:

- a versioned private human attestation matches its source and window;
- the source is a physical firewall or router;
- non-loopback device transport passes;
- collection start and event times are post-boundary;
- raw rows remain outside Git and only private hashes/tokens enter the ignored
  manifest.

Synthetic fixtures and second-laptop senders remain controlled transport
evidence only. They do not increase the physical-source count.

## Duplicate Containment

Exact row hashes remove repeated rows across admitted collections. A
normalization-derived near-family key groups semantically repeated traffic.
Near families are sorted chronologically and assigned as a unit so one family
cannot cross roles. Public output exposes only counts, never hashes.

## Fixed Roles

Families are assigned chronologically using fixed proportions:

| Role | Family interval | Label access | Use |
| --- | --- | --- | --- |
| Development fit | first 60% | governed development labels may be added later | Future model fitting only |
| Calibration | next 15% | governed development labels may be added later | Probability calibration only |
| Threshold | next 15% | governed development labels may be added later | Queue threshold selection only |
| Untouched future evaluation | final 10% | closed until a separately approved one-shot protocol | Final independent decision only |

The v5.51 phase does not train a model or open any role's labels. It creates
custody and aggregate readiness only.

## Sufficiency

The fixed minimum is:

- two independently attested physical source tokens;
- four disjoint collection-window tokens;
- 240 exact-deduplicated post-boundary rows;
- 40 rows in the untouched future role;
- human field confirmation and at least 40 complete prediction-blind rule
  reviews.

Meeting these minimums permits a later development phase; it does not qualify a
model, certify production accuracy, or authorize response.

## v5.49b Separation Proof

- The v5.51 module does not import or call the v5.49b evaluation service.
- No protected path is accepted as an input contract.
- The manifest requires `protected_v549b_accessed=false`.
- Every admitted timestamp is at or after the public boundary.
- Public status fixes `v549b_overlap_rows_admitted=0` and returns no
  fingerprints.
- The consumed v5.49b result is never reused for feature, threshold,
  calibration, split, or candidate selection.

## Failure Policy

Integrity mismatch, malformed private input, public-data leakage, missing
temporary-storage acknowledgement, unsupported source kind, invalid bounds, or
failed transport causes a safe failure. Missing hardware, reviewer work, or
evidence volume produces an explicit non-ready status rather than a fabricated
pass.
