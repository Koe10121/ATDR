# v5.23 Live-Source Acceptance Contract

Date: 2026-08-02

## Purpose

This contract prevents ATDR from confusing local replay, external transport,
and real-device evidence. It also fixes the minimum end-to-end evidence needed
before the collection path can be called accepted.

## Required Channels

The disposable acceptance must exercise all of the following in one run:

1. direct file import with exact raw and normalized counts;
2. authenticated multipart `/api/logs/import` upload;
3. authenticated queued `/api/jobs/import` upload;
4. queue backpressure with an explicit HTTP 429 outcome;
5. interruption at a committed ingestion chunk and successful worker resume;
6. replay through a real UDP socket into the syslog receiver;
7. source health and parser-quality summaries;
8. source-scoped deterministic detection and detection-run history;
9. alert creation followed by deduplication/occurrence growth;
10. alert evidence, case linkage, why-flagged explanation, and analyst next steps;
11. import, syslog, queue, worker-completion, and detection audit events; and
12. zero response, label, model-run, or user writes.

## Evidence Classes

| Class | Required observation | Allowed claim |
| --- | --- | --- |
| Local loopback | sender and receiver on `127.0.0.1` | local UDP software path validated |
| External second laptop | non-loopback datagrams plus `second_laptop` operator attestation | external transport validated; not a firewall/device claim |
| Firewall/router | non-loopback datagrams plus truthful firewall/router attestation | real device transport observed; parser/device depth still depends on payload quality |

`phase_complete=true` requires the second or third class. Local-loopback success
alone must return `phase_complete=false` and an external-sender-pending status.

## Privacy Contract

Public CLI/report output may include aggregate counts, parser states, source
types, HTTP status, job progress, and boolean evidence classifications. It must
not include raw rows, source/destination/sender addresses, private paths,
fingerprints, staging paths, database URLs, credentials, or secrets.

## Authority Contract

- deterministic rules remain alert-authoritative;
- anomaly and supervised results remain advisory/shadow evidence;
- the acceptance may not activate or promote a model;
- the acceptance may not create a response action;
- automatic response and real firewall blocking remain disabled; and
- transport acceptance is not a production-readiness claim.
