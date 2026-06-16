# ATDR Final Screenshot Capture Plan

## Safety Rules

Before capturing:

- Use safe synthetic scenario data.
- Close unrelated browser tabs and notifications.
- Do not show `.env`, passwords, tokens, private file paths, real log payloads,
  personal email addresses, database files, or model/review artifacts.
- Do not commit the screenshot folder unless each image is sanitized and
  intentionally approved.
- Store working screenshots outside Git, for example:

```text
C:\Users\User\Pictures\ATDR-Final-Defense\
```

Recommended capture resolution: 1440x900 or 1920x1080.

## Capture Preparation

1. Start the backend.
2. Start the React dashboard.
3. Run the temporary-database preflight.
4. Run the dashboard-visible scenario using source
   `final-demo-firewall-live`.
5. Log in as the intended demo user.
6. Refresh Overview once before capture.

## Screenshot 1: Overview Final Status

**Slide**

Slide 1 and Slide 17.

**Page**

Overview.

**What should be visible**

- Final Controlled Validation Candidate
- Decision Support Only
- Response Automation Disabled
- Not Production Promoted
- Real firewall blocking disabled
- Operations Health

**Capture guidance**

For Slide 1, crop a wide dashboard detail rather than the full browser chrome.
For Slide 17, crop the readiness/status area more tightly.

**Do not show**

- Real/private source names
- User email if unnecessary
- Browser bookmarks or notifications

## Screenshot 2: Healthy Source

**Slide**

Slide 6 and Slide 16.

**Page**

Overview -> Log Sources.

**Filter/search**

Find `final-demo-firewall-live`.

**What should be visible**

- Source name
- Source type: firewall
- Status: healthy
- Last seen
- Logs received
- Parse success/failure

**Do not show**

- Private IP/host values from other sources
- Unrelated historical source errors

## Screenshot 3: Source Detail And Run Attack Type

**Slide**

Slide 6 or Slide 16.

**Page**

Overview -> Log Sources -> open `final-demo-firewall-live`.

**What should be visible**

- Parser profile: `palo_alto`
- Source health
- 10 logs received for the clean run, or the current accumulated total if the
  scenario was repeated
- Recent ingestion run
- Recent detection run
- `Run attack types: port_scan (1)`
- Unknown/incomplete app data-quality note

**Capture guidance**

Crop the detail drawer to include health and recent detection run. If the
source has accumulated more than ten logs after repeated demonstrations,
explain that the run itself still evaluated ten records.

**Do not show**

- Full private input paths
- Other source parser errors

## Screenshot 4: Log Explorer / Normalized Logs

**Slide**

Slide 6, Slide 7, or Slide 16.

**Page**

Investigation / Log Explorer.

**Filter/search**

- Source: `final-demo-firewall-live`
- Source IP: `203.0.113.44`, if needed

**What should be visible**

- Timestamp
- Source IP
- Destination IP
- Destination port
- Action
- Application
- Source name/parser status

**Capture guidance**

Show 5-8 rows. Keep the table header visible.

**Do not show**

- Real logs from unrelated sources
- Long raw payloads containing sensitive values

## Screenshot 5: Alert List

**Slide**

Slide 10 or Slide 16.

**Page**

Alerts.

**Filter/search**

- Source: `final-demo-firewall-live`
- Attack type: port scan, if available

**What should be visible**

- Critical severity
- Port-scan alert title
- Source IP
- Risk score
- Status
- Occurrence count or evidence count

**Capture guidance**

Crop the table to the alert row and relevant columns.

**Do not show**

- Unrelated alerts with real/private source information

## Screenshot 6: Why Flagged Panel

**Slide**

Slide 10 and Slide 16.

**Page**

Alerts -> open the critical port-scan alert.

**What should be visible**

- `Why flagged?`
- Repeated deny/incomplete behavior
- Multiple destination ports or hosts
- Detection source/rule
- Risk score
- Related evidence
- Recommended analyst action

**Capture guidance**

This is one of the most important screenshots. Use a large crop and add at most
three numbered callouts in PowerPoint.

**Do not show**

- Technical JSON output
- Private unrelated raw evidence

## Screenshot 7: Case / Investigation View

**Slide**

Slide 11 and Slide 16.

**Page**

Alert case section or case detail.

**What should be visible**

- Case title
- Related alert count
- Total related logs
- Source IP
- First/last seen
- Top destination ports
- Top actions
- Recommended analyst focus

**Capture guidance**

If the scenario has been repeated, use the increased related-log count to
explain deduplication honestly.

**Do not show**

- Analyst personal notes not intended for the defense

## Screenshot 8: Simulated Response Confirmation

**Slide**

Slide 12.

**Page**

Response & Audit or alert response action.

**What should be visible**

- Simulated Response
- Target preview
- Justification field
- Requires Analyst Approval
- Confirmation dialog

**Do not execute**

Do not use a real operational target.

**Do not show**

- Credentials
- Real user identities unless approved

## Screenshot 9: Protected-IP Denial

**Slide**

Slide 12.

**Page**

Response & Audit.

**Safe target**

Use a protected local test address such as `127.0.0.1`.

**What should be visible**

- Denial result
- Protected-IP reason
- No real enforcement wording

**Privacy warning**

Do not use an actual management address from the university network.

## Screenshot 10: Audit Trail

**Slide**

Slide 12 or backup slide.

**Page**

Response & Audit -> Audit.

**Filter/search**

Filter to the latest simulated or denied response attempt.

**What should be visible**

- Actor role/name, sanitized if needed
- Action
- Target
- Result
- Timestamp
- Justification or denial context

**Do not show**

- Email address or account identifiers not needed for the proof

## Screenshot 11: AI Governance Readiness

**Slide**

Slide 9, Slide 14, Slide 15, or Slide 17.

**Page**

AI Governance.

**What should be visible**

- Candidate: `independent_fpr_stabilized`
- Final Controlled Validation Candidate
- Readiness v8: 22/22
- 700 rows / 7 sources / 16 scenarios
- Threat F1: 0.9174
- Benign-like FPR: 0.1303
- Suspicious recall: 0.8556
- Malicious recall: 0.9000
- Decision Support Only
- Response Automation Disabled
- Not Production Promoted

**Capture guidance**

Use one wide screenshot or two focused crops. Do not force unreadable full-page
content onto one slide.

## Screenshot 12: Release Gate

**Slide**

Backup slide or Slide 15.

**Source**

PowerShell output from:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release --pretty
```

**What should be visible**

- `ok: true`
- Failed required checks: empty
- Pytest passed
- Alembic check passed

**Capture guidance**

Crop to the summary. Do not show the entire JSON output.

## Screenshot 13: Performance Smoke

**Slide**

Backup slide or Slide 15.

**Source**

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
```

**What should be visible**

- `ok: true`
- Overview timing
- ML Governance timing
- Alert list timing
- Case summary timing
- Warnings: empty

## Final Screenshot Selection

Recommended core deck set:

1. Overview final status
2. Healthy source
3. Source detail with `port_scan (1)`
4. Filtered normalized logs
5. Alert list
6. `Why flagged?`
7. Case detail
8. Response confirmation/protected denial
9. AI Governance readiness

Use release-gate and performance screenshots as backup evidence rather than
crowding the core presentation.
