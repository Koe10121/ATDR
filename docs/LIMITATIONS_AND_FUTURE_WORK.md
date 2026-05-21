# Limitations And Future Work

ATDR is intentionally defensive and lab-pilot oriented. It is stronger than a simple senior-project prototype, but it is not yet a fully certified production SOC platform.

## Current Limitations

- Detection thresholds need validation against a longer MFU baseline window.
- IsolationForest is unsupervised and should be treated as assistive evidence only.
- Response actions are simulated and do not integrate with a real firewall API.
- User management is local JWT-based auth, not campus SSO.
- The Streamlit UI is suitable for prototype operations but not a hardened multi-tenant web frontend.
- Live syslog ingestion is a lab service, not a high-availability collector.
- PostgreSQL deployment is scaffolded but should be verified on the target Docker host.
- PDF incident reports are available for presentation use, but should be reviewed before formal compliance reporting.

## Production-Stage Roadmap

1. Validate PostgreSQL Docker Compose on the deployment host.
2. Put FastAPI behind an HTTPS reverse proxy.
3. Integrate with institutional identity management.
4. Add password policy, session revocation, and persistent rate limiting.
5. Add role-separated approval for real blocking.
6. Build a firewall connector with allowlist protection, dry-run preview, and rollback.
7. Add scheduled retention and backup jobs.
8. Run dashboard smoke tests in CI or on a dedicated lab workstation.
9. Add persistent SLA reporting and ticket-system integration.
10. Add PDF incident report export.

## ML Maturity Roadmap

1. Define a baseline traffic window with supervisor approval.
2. Train only on reviewed low-risk allowed traffic.
3. Compare model versions over repeated scoring runs.
4. Track drift signals for app, action, source zone, baseline size, and anomaly rate.
5. Add a second model family for comparison, such as Local Outlier Factor or robust statistical baselines.
6. Create a model acceptance checklist before using ML evidence in response decisions.

## SOC Maturity Roadmap

1. Review suppressions on a fixed schedule.
2. Maintain watchlists for known risky or high-priority indicators.
3. Expand computed SLA indicators into formal escalation reporting.
4. Add ticket references and report exports to every confirmed incident.
5. Add after-action notes for contained and resolved incidents.
6. Measure false-positive rate and tune rules from review outcomes.
