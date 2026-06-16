# ATDR Final Defense Rehearsal Checklist

## One Day Before

- [ ] Read `docs/FINAL_DEMO_SCRIPT.md` aloud once.
- [ ] Practice the 5-minute and 10-minute scripts.
- [ ] Review `docs/FINAL_DEFENSE_QA.md`.
- [ ] Confirm the laptop power adapter is available.
- [ ] Confirm Node.js 20.x and the Python virtual environment still work.
- [ ] Confirm the final PowerPoint opens without missing fonts or media.
- [ ] Export a PDF backup of the slides.
- [ ] Store screenshots and the deck outside ignored/private project data.
- [ ] Confirm no private logs or credentials appear in the slides.
- [ ] Disable notification popups.

## Before The Demo

- [ ] Open PowerShell in `C:\Users\User\Desktop\ATDR`.
- [ ] Check Git state:

```powershell
git status --short
```

- [ ] Confirm `.env`, `atdr.db`, `ml_baseline_reviews/`, `demo_exports/`, and
      processed logs are not staged.
- [ ] Close duplicate backend, importer, and syslog processes.
- [ ] Confirm port 8000 is available.
- [ ] Confirm port 5173 is available.
- [ ] Open the final PowerPoint and speaker notes.
- [ ] Keep `docs/FINAL_DEMO_SCRIPT.md` open as backup.

## Start Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- [ ] Wait for successful startup.
- [ ] Check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Start Frontend

Open a second PowerShell window:

```powershell
cd C:\Users\User\Desktop\ATDR\frontend
npm.cmd run dev
```

- [ ] Open `http://127.0.0.1:5173`.
- [ ] Log in.
- [ ] Confirm Overview loads.

## Run Safe Preflight

Open a third PowerShell window:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall-live --source-type firewall --parser-profile palo_alto --run-detection --use-temp-db --pretty
```

Expected:

- [ ] `ok: true`
- [ ] source healthy
- [ ] 10 received
- [ ] 10 normalized
- [ ] 10 parsed
- [ ] 0 failures
- [ ] 10 evaluated
- [ ] `port_scan (1)`
- [ ] 1 alert
- [ ] 1 case
- [ ] 0 automatic responses
- [ ] real firewall blocking false

## Run Dashboard-Visible Scenario

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall-live --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Expected:

- [ ] 10 new raw logs imported
- [ ] 10 parsed successfully
- [ ] source remains healthy
- [ ] run attack type is `port_scan (1)`
- [ ] one alert is created or an existing alert is deduplicated
- [ ] one case is available
- [ ] automatic response count is 0

## If The Alert Deduplicates

Say:

"This scenario has been demonstrated before. ATDR preserved the ten new raw
logs, recognized that the detection matched an existing alert pattern, and
updated occurrence and related-log counts instead of creating duplicate alert
noise."

Do not say that one new alert was created if `alerts_created` is zero.

## Dashboard Navigation Order

1. Overview
2. Log Sources
3. Source detail
4. Investigation / Log Explorer
5. Alerts
6. `Why flagged?`
7. Case view
8. Response & Audit
9. AI Governance

## Speaking Checkpoints

### Overview

- [ ] Say "Final Controlled Validation Candidate."
- [ ] Say "Decision Support Only."
- [ ] Say "Not Production Promoted."
- [ ] Say "Response Automation Disabled."

### Source Detail

- [ ] Explain source health.
- [ ] Show `port_scan (1)` in the recent run.
- [ ] Explain run-scoped versus historical counts.

### Unknown-App Warning

Say:

"The synthetic scan uses rapidly denied or incomplete sessions, so the
firewall does not establish a full application identity. All ten records were
still parsed successfully. The dashboard shows this as a data-quality note,
not a source failure."

### Alert

- [ ] Explain repeated ports/destinations.
- [ ] Explain deny/incomplete behavior.
- [ ] Show raw and normalized evidence.
- [ ] State that detection recommends investigation.

### Response

- [ ] State that the action is simulated.
- [ ] Show confirmation and justification.
- [ ] Show protected-IP denial if time allows.
- [ ] State that ML cannot trigger response.

### AI Governance

- [ ] Explain the fresh blind holdout.
- [ ] State that the profile was frozen before evaluation.
- [ ] State that blind labels were not used for threshold tuning.
- [ ] State that metrics are controlled validation, not production accuracy.

## If Asked Why It Is Not Production Ready

Say:

"The prototype passed controlled academic validation, but production requires
real-device forwarding over time, high availability, production IAM, TLS and
secret management, backup and retention, independent security assessment,
larger independently reviewed real-source labels, and a vendor-approved
response connector with rollback. Therefore ATDR remains Decision Support Only
with Response Automation Disabled."

## Failure Recovery

### Backend fails

1. Check port:

```powershell
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
```

2. Stop the duplicate process if appropriate.
3. Restart the backend command.
4. Recheck `/health`.

### Frontend fails

1. Confirm the terminal is in `frontend`.
2. Run:

```powershell
npm.cmd install
npm.cmd run dev
```

3. Confirm the backend remains available on port 8000.

### Dashboard says `Failed to fetch`

- Refresh only after `/health` succeeds.
- Confirm frontend API configuration targets `http://127.0.0.1:8000`.

### SQLite says database is locked

- Stop duplicate backend/import/detection processes.
- Do not delete or reset the database.
- Restart one backend process and rerun the scenario.

### Scenario already exists

- Explain deduplication, or use a new clearly labeled source:

```powershell
--source-name final-demo-firewall-live-2
```

Do not create many unnecessary sources immediately before presenting.

### Live demo cannot be recovered

Use the sanitized screenshots and describe the already validated expected
workflow. Do not improvise unsupported claims.

## Timing Rehearsal

### 5-minute version

- Opening/problem: 45 seconds
- Architecture/detection: 75 seconds
- Validation: 60 seconds
- Demo transition/highlights: 60 seconds
- Limitations/conclusion: 60 seconds

### 10-minute version

- Opening/problem/objectives: 90 seconds
- Architecture/ingestion: 90 seconds
- Detection/AI: 120 seconds
- Validation results: 120 seconds
- Demo flow: 120 seconds
- Limitations/future/conclusion: 60 seconds

## Final Cleanup

- [ ] Stop the frontend with `Ctrl+C`.
- [ ] Stop the backend with `Ctrl+C`.
- [ ] Do not delete the database.
- [ ] Do not commit screenshots unless explicitly approved.
- [ ] Recheck Git status.
- [ ] Confirm private/generated artifacts remain ignored.
- [ ] Keep the final deck, PDF backup, and sanitized evidence copy available.

