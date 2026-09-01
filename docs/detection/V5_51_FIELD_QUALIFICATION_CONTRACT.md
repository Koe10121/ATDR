# v5.51 Field Qualification Contract

## Purpose

This contract is the operator boundary between ATDR's controlled local tests
and a real firewall/router qualification. It never turns a synthetic sender
into field evidence and never imports review decisions into the database.

## Required Inputs

### Physical Source Attestation

Store the following JSON outside Git and pass it with
`--source-attestation`:

```json
{
  "schema_version": "v5.51-source-attestation-v1",
  "source_name": "operator-private-source-name",
  "source_kind": "firewall",
  "collection_window": "operator-private-window-name",
  "physical_device_confirmed": true,
  "attested_by": "Genuine Human Reviewer",
  "attested_at": "2026-09-02T09:00:00+07:00",
  "collection_started_at": "2026-09-02T08:00:00+07:00"
}
```

`source_kind` must be `firewall` or `router`. The CLI source name, source kind,
and window must match the file. The collection must begin at or after the v5.51
boundary. AI, automated, assisted, model, or synthetic reviewer identities are
invalid. The identity is never returned by the CLI or API.

### Human Field Expectations

Store the following JSON outside Git and pass it with
`--field-expectations`:

```json
{
  "schema_version": "v5.51-field-expectations-v1",
  "source_name": "operator-private-source-name",
  "reviewed_by": "Genuine Human Reviewer",
  "reviewed_at": "2026-09-02T10:00:00+07:00",
  "independent_human_confirmed": true,
  "rows": [
    {
      "line_number": 1,
      "expected": {
        "log_type": "TRAFFIC",
        "app": "ssl",
        "action": "allow",
        "protocol": "tcp",
        "dst_port": 443,
        "app_risk": 2,
        "generated_time_present": true,
        "high_res_timestamp_present": true
      }
    }
  ]
}
```

Allowed fields are log type/subtype, application, action, protocol, ports,
zones, bytes, packets, application risk, timestamp-presence flags, PAN-OS
THREAT severity, and SYSTEM event/module/severity. At least eight fields must
be checked with zero mismatches for the fixed field-accuracy gate to pass.
Only counts and aggregate accuracy are public.

### Prediction-Blind Rule Review

The generated `v5_51_prediction_blind_rule_review.csv` contains normalized,
non-address evidence and no rule/model prediction. A private prediction seal is
written separately. The reviewer completes:

- `human_decision`: `benign`, `benign_unusual`, `needs_context`, `suspicious`,
  or `malicious`;
- `human_confidence`: integer `1` through `100`;
- `human_rationale`: at least eight characters;
- `human_attack_type`: required for `suspicious` or `malicious`;
- `human_reviewer` and `human_reviewed_at`;
- `independent_human_confirmed=true` and `human_reviewed=true`.

`human_must_confirm` and `prediction_blind` must remain true.
`import_ready` must remain false. Forty complete rows are required. Metrics are
computed only after the whole sealed pack validates. No labels are imported.

## Physical Run

Use a private evidence path and private contract paths:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v551_detection_field_qualification `
  --use-temp-db `
  --transport-mode external_sender `
  --source-kind firewall `
  --source-name "operator-private-source-name" `
  --collection-window "operator-private-window-name" `
  --sample-path "C:\private\firewall.log" `
  --source-attestation "C:\private\source-attestation.json" `
  --field-expectations "C:\private\field-expectations.json" `
  --pretty
```

Start the command, then configure/send the requested datagrams from the
physical device to the displayed host and selected UDP port. A second-laptop
sender can test network transport but cannot satisfy the physical-device gate.

After the private review is complete, rerun with
`--rule-review "C:\private\completed-review.csv"`. Never place these paths or
files in Git.

## Fixed Readiness Gates

- Disposable local acceptance passes and configured DB remains unchanged.
- PAN-OS parser success is at least `0.99`, accounting balances, and no
  partial/unsupported layout is admitted to a passing run.
- UDP loss and parse failures are zero for the acceptance messages.
- Source health and parser quality are available.
- Physical source and human attestation both pass.
- Field expectations pass and the prediction-blind review is complete.
- At least two physical sources, four windows, 240 fresh rows, and 40 untouched
  future rows exist after duplicate containment.

## Privacy And Authority

Public output contains aggregates only. It cannot contain a raw row, IP
address, private path, source/reviewer identity, row fingerprint, prediction
seal, token salt, or secret. Private outputs remain ignored. The service writes
no labels, model runs, active artifacts, alerts, detection runs, or response
actions. Rules stay alert-authoritative and response remains disabled.
