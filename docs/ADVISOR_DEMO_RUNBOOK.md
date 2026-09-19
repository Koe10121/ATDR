# ATDR Advisor Demonstration Runbook

## Preflight

From `C:\Users\User\Desktop\ATDR`:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_advisor_demo_acceptance `
  --use-temp-db `
  --execute-provider-probe `
  --pretty
```

Require `advisor_demo_acceptance_passed` and all ten stages `true`. The check
uses disposable storage and leaves the configured database unchanged.

Start the product through its normal MFU shell entry:

```powershell
.\scripts\start_system.cmd
```

Open the entry URL printed by the launcher. If processes are already running:

```powershell
.\scripts\check_system.ps1
```

## Five-Minute Walkthrough

### 1. Overview

Show that ATDR receives logs, preserves evidence, normalizes fields, tracks
source/parser health, and presents the current alert queue.

Say: "ATDR turns firewall logs into normalized evidence and explainable SOC
alerts. The dashboard separates operational health from detection findings."

### 2. Alert Investigation

Open a High or Critical alert. Show:

- matched deterministic rule;
- evidence strength and parser limitations;
- related normalized logs;
- source and case context; and
- recommended analyst checks.

Say: "Rules create alerts. Every alert explains the evidence and what the
analyst should verify before any response."

### 3. SOC Assistant

Ask: `Why was alert <visible-alert-id> flagged?`

Then ask: `What should I verify next for this alert?`

Show citations and the safety badges. Keep the visible answer concise.

Say: "Facts come from bounded ATDR context. Gemini improves the wording, raw
logs are not sent, IPs are redacted, and deterministic fallback remains
available. The Assistant cannot execute actions."

### 4. AI Governance

Show these exact states:

- Rules: `active_authoritative`
- IsolationForest: advisory only
- Supervised ML: `unqualified`
- Response: `simulation_only`

Explain that anomaly rate is now measured among scored rows and scoring
coverage is shown separately.

Say: "We use ML honestly as decision support. The current unsupervised model
can prioritize unusual traffic, but it does not decide that traffic is
malicious. Supervised activation remains blocked until its evidence gates
pass."

### 5. Response And Audit

Show that response requires analyst justification and, by default, remains
simulated. Show the audit history.

Say: "ATDR recommends and records response decisions. By default nothing
real is changed. An operator can explicitly opt this machine into a real,
host-scoped Windows Firewall block — it only ever affects this machine, never
a real network firewall or another device."

If you want to demonstrate real enforcement, do it deliberately and
separately from the main walkthrough: confirm `RESPONSE_PROVIDER=windows_firewall`
and `RESPONSE_SIMULATION=false` are set, run the backend as Administrator,
and use a test IP you fully control. Do not toggle this mid-demo.

## Current Proof Points

- controlled source scenario: 10/10;
- layered detection: 288/288;
- advisor workflow: 24/24 checks and 10/10 stages;
- Assistant: 30 quality cases plus follow-up continuity;
- live Gemini structured probe: pass;
- v5.64 anomaly redesign: 0/32 candidates qualified (28 distinct, 4 a
  disclosed duplicate); current artifact unchanged;
- automatic (unattended) response: disabled in every profile;
- real blocking: simulation by default; explicit opt-in local/lab
  host-scoped Windows Firewall enforcement implemented and tested.

## Questions To Answer Honestly

**Is supervised ML active?** No. The pipeline exists, but the governed
evaluation selected no qualified candidate. Rules remain the detector of
record.

**Does IsolationForest detect attacks?** It identifies unusual rows for
analyst review. v5.64 improved controlled suspicious capture but stayed at 50%
malicious scenario capture, so no replacement qualified and no threat-accuracy
claim is made.

**Where do Assistant facts come from?** Bounded ATDR database/service context
and approved documentation. Gemini is a synthesis layer, not the evidence
source.

**Is this production-ready?** It is a controlled local release candidate.
University IAM acceptance, physical-device validation, and approved shared
infrastructure remain external.

## Recovery

If Gemini is unavailable, continue the demonstration with deterministic
fallback. If the dashboard is already running, do not launch a second copy;
use `scripts/check_system.ps1`. Do not enable real blocking mid-demo or on an
IP you do not fully control; if demonstrating it, do so deliberately per the
note in step 5.
