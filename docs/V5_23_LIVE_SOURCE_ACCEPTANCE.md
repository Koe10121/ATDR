# v5.23 Live-Source Acceptance

Date: 2026-08-02

## Decision

ATDR's local collection and investigation paths pass one consolidated,
privacy-safe disposable acceptance run. File import, authenticated multipart
API upload, queued/resumable import, queue backpressure, replay to an actual UDP
socket, source health, parser quality, source-scoped rule detection,
deduplication, case linkage, explanations, recommendations, and audit history
were exercised together.

The phase is not yet complete. The measured UDP sender and receiver were on the
same laptop, so this is local transport evidence rather than second-laptop or
real firewall/router evidence. The result therefore reports
`phase_complete=false`, `real_device_validated=false`, and
`v5_23_local_acceptance_passed_external_sender_pending`.

Rules remain alert-authoritative. The supervised lifecycle remains
`shadow_observation`. No model was activated or promoted, no response action
was created, and automatic response and real firewall blocking remain disabled.

## Measured Local Acceptance

The complete run supplied the private PAN-OS file only through `--sample-path`
and used 20 bounded rows as UDP replay payload. The path, raw rows, addresses,
and fingerprints were not returned or written to tracked files.

| Channel / contract | Result |
| --- | ---: |
| Controlled direct file import | 20 raw / 20 normalized / 0 parse failures |
| Authenticated multipart API import | 5 raw / 5 normalized |
| Queued generic-syslog import | 8 raw / 8 normalized |
| Queue pressure | second queued upload rejected with HTTP 429 |
| Graceful worker interruption | released at a committed chunk boundary |
| Worker recovery | resumed to 8 / 8 with 8 chunk commits |
| Private bounded replay over UDP loopback | 20 sent / 20 received / 20 parsed |
| Total disposable raw / normalized rows | 53 / 53 |
| Logical sources | 4 |
| Detection runs | 2, both source scoped and rule authoritative |
| Port-scan alerts | 1 created, then 1 deduplicated update |
| Alert occurrence / related-log counts | 20 / 20 |
| Cases | source-linked case available |
| Explanation | why flagged, missing context, and next steps available |
| Required audit actions | present |
| Response / label / model / user writes | 0 / 0 / 0 / 0 |
| Configured database modified | false |
| Disposable artifacts removed | true |

The generic-syslog source correctly reports a limited parser-quality warning;
this is evidence preservation with limited structured fields, not parser
failure. The firewall, API file, and UDP sources report healthy parser quality.

## CLI

Local preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v523_live_source_acceptance `
  --sample-path "<PRIVATE_PANOS_PATH>" --use-temp-db --preflight-only --pretty
```

Local disposable acceptance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v523_live_source_acceptance `
  --sample-path "<PRIVATE_PANOS_PATH>" --use-temp-db `
  --transport-mode local_loopback --message-count 20 --timeout 20 --pretty
```

Generated aggregate reports stay ignored under `ml_baseline_reviews/`. The
configured database is never an acceptance target.

## External Sender Gate

On the ATDR laptop, allow the chosen UDP port through the private/lab firewall
only for the test, then run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v523_live_source_acceptance `
  --use-temp-db --transport-mode external_sender --bind-host 0.0.0.0 `
  --port 5515 --message-count 5 --timeout 60 `
  --external-sender-kind second_laptop --pretty
```

On a second laptop with the repository's Python environment:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog `
  --host <ATDR_LAPTOP_LAN_IP> --port 5515 --count 5 --delay 0.1
```

A non-loopback second laptop satisfies the phase's transport gate but does not
prove a firewall parser/device integration. For a real configured firewall or
router, run the receiver with `--external-sender-kind firewall` or `router`
only when that description is true. The CLI records operator attestation and
safe sender counts, never sender addresses.

## Verification Status

- taskboard render and supervisor-standard checks pass;
- whole-repository Ruff and compilation pass;
- focused v5.23 plus UDP tests pass `5/5`;
- full backend and release-gate suites pass `812 passed, 1 skipped`;
- Alembic reports no drift;
- React lint/build pass and Playwright passes `27 passed, 1 skipped`;
- controlled detection passes `23/23` and layered validation passes `288/288`;
- deterministic Assistant QA passes `20/20` with zero side effects;
- Gemini status and one bounded provider probe pass without raw-log context or
  secret exposure;
- replay dry-run passes and performance smoke reports no warnings;
- local safe and private-input preflights pass;
- local disposable acceptance passes every implemented check;
- release verification reports `ok=true`; and
- the 55 changed paths exactly match the cumulative allowlist, nothing is
  staged, and privacy/ignore/diff checks pass.

An initial full pytest run used an unnecessarily long workspace-local temporary
path and hit the Windows legacy path-length ceiling in the template launcher
backup test. The isolated test and complete suite both pass with a short temp
root; this was test-environment path construction, not an ATDR regression.

## Remaining Gate

One external sender run remains. Until it passes, v5.23 is locally accepted but
not complete. On 2026-08-02 the owner explicitly deferred this hardware/network
gate so work could continue on v5.24 without misrepresenting the result. The
deferral does not convert local loopback evidence into non-loopback or
real-device evidence: `phase_complete=false` and `real_device_validated=false`
remain authoritative. A real firewall/router forwarding run remains stronger
future evidence even after second-laptop transport succeeds.

No commit or push is authorized by this phase.
