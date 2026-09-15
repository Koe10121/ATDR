# Weekly Progress Presentation Handoff

Date: 2026-06-24

Project: MFU AI-Driven Log-Based Threat Detection and Response System (ATDR)

## 1. Short Explanation For The Team

ATDR is a controlled defensive SOC lab prototype. It helps analysts ingest firewall/syslog logs, parse and normalize them, detect suspicious behavior, explain why an alert was created, review AI/ML model status, and use a read-only SOC Assistant chatbot for investigation help.

Important wording:

- ATDR is a controlled lab prototype, not production software.
- ML is AI-assisted decision support only.
- Response actions are simulated and require analyst approval.
- Real firewall blocking is disabled.
- Automatic response is disabled.

## 2. Can A Friend Open The System Easily?

Yes, if they receive the current project files and follow the Windows quickstart.

The current local environment check passes on this machine:

- Python 3.11.15: supported
- Node 20.11.1 and npm 10.2.4: supported
- Backend dependencies: importable
- Database: local SQLite profile works with `sqlite:///./atdr.db`
- Alembic: no migration drift
- Safe sample file: available
- Response mode: simulation
- Config doctor: no critical warnings

The only expected warning is that `/health` is not reachable when the backend is not running yet. That is not a code failure.

Important repo-sync note:

- If a teammate clones from GitHub, they only get committed and pushed files.
- The current local folder has many uncommitted/untracked development files from recent phases.
- Before teammates clone GitHub, commit and push the current working version.
- Alternative: share a sanitized zip of the project, but do not include `.env`, `atdr.db`, real logs, model artifacts, `ml_baseline_reviews/`, `demo_exports/`, or processed logs.

## 3. Fresh Setup For A Teammate

Use Windows PowerShell.

### Backend Setup

```powershell
cd C:\Path\To\ATDR
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\alembic.exe upgrade head
python -m atdr.scripts.seed_users
```

Default local demo users:

```text
admin / admin123
analyst / analyst123
```

Optional setup check:

```powershell
python -m atdr.scripts.check_dev_environment --pretty --no-api
python -m atdr.scripts.config_doctor
```

### Start Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

### Frontend Setup

Open another PowerShell window:

```powershell
cd C:\Path\To\ATDR\frontend
Copy-Item .env.example .env
npm.cmd install
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

Recommended Node.js: 20.x. Node 16 may fail with the current Vite/Playwright frontend tooling.

## 4. What To Show In The Dashboard

Recommended demo order:

1. Login
   - Show local admin login.
   - Mention school email/IAM groundwork exists, but real external IAM is not enabled yet.

2. Overview
   - Show total logs, alerts, system health, source health, operations health.
   - Explain this is the main SOC summary page.

3. Log Sources / Operations Health
   - Show source management and source health.
   - Explain sources can be file import, replay, syslog-style lab source, firewall/router source, or fallback/raw source.

4. Investigation / Log Explorer
   - Show normalized logs.
   - Explain raw evidence is preserved and normalized fields are extracted for investigation.

5. Alerts
   - Open an alert detail.
   - Show severity, risk score, attack type, detection source, evidence, related logs, and "Why flagged?"

6. AI Governance
   - Show ML status.
   - Say ML remains decision support only.
   - Explain current ML work is focused on safe SOC review-queue diagnostics, not production promotion.

7. SOC Assistant
   - Ask about an alert, source health, ML model status, safe next steps, or how to run a scenario.
   - Show citations and safety badges.
   - Mention the assistant is read-only and cannot execute actions.

8. Response & Audit
   - Show simulated response workflow.
   - Explain response requires analyst confirmation and justification.
   - Protected IPs cannot be blocked.
   - Denied/simulated attempts are audited.

## 5. How ATDR Works Internally

### Log Ingestion

ATDR can ingest logs through:

- dashboard import
- direct file import
- replay mode
- syslog-style local test flow
- safe synthetic scenarios

Raw logs are stored first so evidence is preserved.

### Parsing And Normalization

The parser reads firewall/syslog lines and extracts useful fields:

- timestamp
- source IP
- destination IP
- ports
- protocol
- app
- action
- bytes/packets
- zones
- rule or evidence fields when available

Parser profiles:

- `palo_alto`
- `generic_syslog`
- `raw_fallback`

If a line is malformed, the parser should not crash. It preserves raw evidence and records parse failures/data-quality warnings.

### Detection

ATDR uses multiple detection layers:

1. Rule-based detection
   - Examples: port-scan-like traffic, repeated deny/drop/reset behavior, rare service attempts, incomplete traffic, suspicious external-to-internal behavior.

2. Anomaly scoring
   - IsolationForest helps flag unusual traffic patterns.

3. Supervised ML diagnostics
   - Current supervised experiments compare different candidate classifiers and label policies.
   - ML is not production-promoted.
   - ML output does not trigger response actions.

4. Hybrid scoring
   - Combines rules, anomaly evidence, model signals, and behavior-window features.

### Alert Quality

Alerts include:

- severity
- risk score
- attack type
- detection source
- why flagged explanation
- top evidence
- related logs
- case grouping
- recommended analyst action
- response/audit history

Deduplication prevents repeated identical logs from creating endless duplicate alerts. Instead, it increases occurrence count and related log count.

## 6. Current AI/ML Status

Current supervised ML work is diagnostic only.

Current v3.59 status:

- The safest supervised output is a `binary_soc_review_queue` signal.
- The review-queue signal estimates whether a log or alert should be reviewed by a SOC analyst.
- Exact severity or attack labels are explanation/ranking support only, not authoritative production classifications.
- Queue validation: `5/5` evaluated splits passed.
- Queue F1 minimum: `0.9725`.
- Queue recall minimum: `0.948`.
- Queue precision minimum: `0.9907`.
- Benign-like false-positive rate maximum: `0.04`.
- Calibration status: passed, ECE `0.007`.
- Queue-vs-rule/hybrid agreement is usable with review: `4/5` splits passed.
- Exact severity policies are still unstable: `0/6` stable policies.
- Readiness remains `candidate_only`.
- No model was activated.
- No model artifact was written.
- No response automation was enabled.

What this means for the presentation:

Say: "We are improving ML responsibly. The latest diagnostics show that supervised ML is most reliable as a SOC review-queue assistant. Exact severity labels are still treated as supporting explanation only. The system is useful for triage support, but ML remains decision support."

Do not say: "The model is production ready."

## 7. What The SOC Assistant Can Do Now

The SOC Assistant is a read-only analyst helper inside the React dashboard.

It can answer questions like:

- What are the latest critical alerts?
- Why was this alert flagged?
- What should an analyst check next?
- Summarize open alerts.
- Summarize source health.
- Which sources have warnings?
- Summarize recent detection/operation jobs.
- Explain why the model is not production promoted.
- How do I import logs?
- How do I import reviewed labels?
- How do I run a safe scenario?
- Build a compact investigation brief for an alert/log/source/case.

It includes:

- prompt presets, including a **SOC Playbook** group
- alert/log/source/case context links
- citations back to dashboard records or docs
- feedback controls
- assistant history
- admin/analyst feedback review
- safety badges

Safety boundaries:

- read-only
- deterministic/local by default
- external LLM disabled by default
- raw log context disabled by default
- IP redaction enabled by default
- audited questions
- cannot execute response actions
- cannot run detection
- cannot change labels
- cannot activate/promote models
- cannot delete data
- cannot send email

## 8. Chatbot Future Plan

Current presentation hardening:

- use the **SOC Playbook** preset group first
- demonstrate Latest Critical Alert, Explain Alert, Investigation Brief, Source Health, AI Governance Summary, Controlled Validation Scenario, and Response Safety
- show that missing alerts/sources get clean fallback guidance instead of invented answers
- show unsafe requests are refused
- use feedback for manual QA, not automatic tuning

Short-term improvements after the presentation:

- keep improving answer quality for alert investigation
- improve evidence ranking and missing-evidence notes with more real lab examples
- make "what should I check next?" guidance more source-aware
- keep improving links from assistant answers to dashboard records
- expand the assistant evaluation question set
- use feedback for manual QA, not automatic tuning

Medium-term:

- optional external LLM support only after privacy/security review
- approved school email/IAM identity integration
- stricter redaction and context filtering
- retrieval over approved docs and sanitized alert summaries
- role-aware assistant behavior

Not allowed yet:

- no automatic response through chat
- no raw logs sent to external providers by default
- no autonomous SOC agent behavior

## 9. Current Stack

Backend:

- Python
- FastAPI
- SQLAlchemy
- Alembic
- SQLite for local development
- optional PostgreSQL planned for shared lab/future deployment

Frontend:

- React
- TypeScript
- Vite
- TanStack Query
- TanStack Table
- Recharts
- Playwright for UI tests

Detection / ML:

- rule-based detection
- IsolationForest anomaly scoring
- supervised ML diagnostics using scikit-learn models
- feature engineering over normalized logs and behavior windows
- calibration and split-stability diagnostics

Security / account:

- local JWT authentication
- admin/analyst RBAC
- email verification/dev outbox groundwork
- MFU IAM / Google SSO / OIDC adapter planning only
- no real external IAM login enabled yet

Ops / validation:

- Alembic migrations
- release gate
- performance smoke
- replay dry-run
- source scenarios
- no-hardware validation
- university workflow docs and T1-T20 change records

## 10. What Is Complete

Completed:

- backend API foundation
- React SOC dashboard
- local login and RBAC
- log ingestion/import/replay
- parser profiles and raw fallback
- normalized log explorer
- source management and health
- rule-based detection
- anomaly scoring
- alert deduplication
- case grouping
- "Why flagged?" explanations
- AI Governance and label workflow
- simulated response controls and audit logs
- SOC Assistant MVP through feedback/reasoning upgrades
- assistant investigation briefs, feedback review, citations, and safe dashboard handoffs
- email verification/account lifecycle groundwork
- MFU IAM adapter planning
- performance and release verification
- university process documentation

## 11. What Is Not Complete Yet

Not complete / future work:

- real external MFU IAM/Google/OIDC login
- real SMTP email sending
- real firewall/router device validation
- real firewall blocking
- automatic response
- PostgreSQL shared-lab validation as default
- production security hardening
- production deployment
- final stable supervised ML promotion
- active deployment of the stable SOC queue candidate
- richer rule/hybrid/ML agreement diagnostics

## 12. Recommended Next Development Plan

Immediate next technical phase:

- v3.61 SOC Assistant Presentation Hardening
- Goal: make the SOC Assistant reliable for analyst walkthrough questions with SOC playbook presets, clean missing-context fallbacks, and direct response-safety answers.
- Why: this lets the team show the chatbot confidently without fake data, unsafe actions, or confusing ML claims.
- Keep diagnostic-only.
- No model activation.
- No automatic response.

Advisor-facing next phase:

- show the SOC Assistant answering alert/source/ML/how-to questions
- show that assistant answers include citations and safety boundaries
- explain future path to school email IAM after provider details are available

## 13. Quick Demo Questions For The SOC Assistant

Use these in the dashboard:

```text
Explain the latest critical alert.
```

```text
Why was alert 1 flagged?
```

```text
Create investigation brief for alert 1.
```

```text
Summarize source health.
```

```text
What supervised ML output is safe?
```

```text
How do I run a controlled validation scenario?
```

```text
What are response safety rules?
```

## 14. One-Minute Presentation Script

"Our project is ATDR, an AI-assisted log-based threat detection and response system. It takes firewall/syslog logs, preserves the raw evidence, parses and normalizes the important fields, detects suspicious behavior using rules, anomaly scoring, and supervised ML diagnostics, and then shows explainable SOC-style alerts in a React dashboard.

The system now has source health, run history, alert deduplication, case grouping, AI Governance, simulated response controls, audit logging, and a read-only SOC Assistant chatbot. The chatbot can explain alerts, summarize sources and jobs, help with ML governance questions, and give safe next steps, but it cannot run actions or change data.

For safety, response automation and real firewall blocking are disabled. ML is decision support only. Our current ML work shows that a binary SOC review-queue signal is stable for analyst prioritization, while exact severity classification is still explanation-only. For this walkthrough, the SOC Assistant has a SOC Playbook preset group so we can show alert explanation, investigation brief generation, source health, AI governance, controlled validation guidance, and response safety clearly."
