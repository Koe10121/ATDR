# ATDR Final 10-Minute Speaking Script

## Opening

Good morning. My project is the AI-Driven Log-Based Threat Detection and
Response system, or ATDR.

ATDR is a controlled lab-scale cybersecurity prototype designed to help
analysts monitor firewall and syslog logs. It preserves original evidence,
normalizes important fields, detects suspicious behavior, explains alerts,
groups related activity into cases, and records simulated analyst-approved
response actions.

The final engineering status is Final Controlled Validation Candidate. This
means the system passed its configured controlled academic validation gates.
It does not mean production promotion. The final labels are
`Decision Support Only`, `Response Automation Disabled`,
`Not Production Promoted`, and `Real firewall blocking disabled`.

## Problem Background

Firewalls generate a large number of logs. These logs can contain evidence of
port scanning, repeated denied access, unusual applications, brute-force-like
attempts, data-transfer anomalies, and command-and-control-like behavior.
However, manually reviewing every record is impractical.

Rule-based systems help because their logic is understandable. For example, a
rule can identify one source contacting many destination ports in a short
period. However, static rules cannot represent every unusual behavior.

Machine learning can add value, but it introduces risks. An anomaly is not
automatically an attack. A supervised model can inherit weak labels, class
imbalance, or source-specific patterns. A model that catches many threats may
still be operationally unusable if it creates too many false positives.

The project problem was therefore to create an AI-assisted workflow that is
useful without giving uncertain predictions automatic authority.

## Objectives And Scope

The first objective was to preserve raw evidence. Parsing is useful, but the
original line must remain available for investigation.

The second objective was to normalize useful fields, including timestamps,
source and destination IP addresses, ports, actions, applications, zones, and
risk indicators.

The third objective was to combine explainable rules, behavior-window
features, anomaly scoring, supervised predictions, and hybrid risk.

The fourth objective was to provide a SOC workflow for source health, alert
triage, investigation, case grouping, human label review, response approval,
and audit.

The fifth objective was to validate not only classification metrics, but also
parser safety, false positives, confidence, source handling, response safety,
performance, and release stability.

The current scope includes file import, replay, controlled syslog testing, and
safe source scenarios. It does not include real firewall enforcement,
automatic response, production IAM, or completed real-device forwarding.

## Architecture

The backend is implemented in Python with FastAPI. SQLAlchemy manages the data
model, Alembic manages migrations, and SQLite is the default local database.
The primary dashboard is React with TypeScript and Vite. scikit-learn supports
anomaly and supervised model experiments.

The main pipeline is:

source, raw evidence, parser, normalized log, detection signals, hybrid risk,
alert, case, analyst investigation, simulated response, and audit.

ATDR supports three parser profiles. The Palo Alto profile extracts structured
firewall fields. The generic syslog profile captures limited common context.
The raw fallback profile preserves unmatched evidence and clearly records that
structured fields are limited.

Each source has health and quality information, including last seen, logs
received, parse success, parse failure, unknown application rate, recent
ingestion runs, and recent detection runs.

## Detection Layers

The first layer is rule-based detection. It identifies explainable patterns
such as scanning, repeated denied access, suspicious applications,
brute-force-like behavior, connection floods, policy violations, and possible
exfiltration or command-and-control behavior.

The second layer is behavior-window analysis. A single log can be harmless in
isolation, so ATDR calculates features over time, including event count, unique
destination addresses, unique ports, deny ratio, repeated attempts, traffic
direction, and scanning-like behavior.

The third layer is IsolationForest anomaly scoring. It identifies behavior
that appears unusual relative to the available feature distribution. It is an
assistive signal only.

The fourth layer is supervised SOC triage. The workflow uses assisted labels,
human-reviewed labels, active learning, time-based validation, class-support
warnings, model comparison, threshold profiles, false-positive analysis, and
confidence assessment.

Hybrid scoring combines these signals, but the explanation remains visible.
The analyst can inspect the detection source, matched rule, behavior-window
evidence, anomaly or supervised support, risk score, ATT&CK-style context, and
recommended next checks in the `Why flagged?` panel.

## Human Review And Governance

One important part of the project is that assisted weak labels are not treated
as perfect ground truth. Review samples can be exported, completed by analysts,
and imported through AI Governance.

Active-learning samples prioritize uncertain predictions, model disagreement,
rare patterns, important threat boundaries, and underrepresented classes.
Model reports distinguish weak-label, reviewed-label, mixed-label, benchmark,
and blind-holdout results.

Earlier validation showed that threat detection could be strong while benign
false positives were unacceptable. The project therefore focused on reducing
noise rather than only improving accuracy. The final frozen profile,
`independent_fpr_stabilized`, preserves threat evidence while routing ambiguous
patterns toward analyst review.

## Response Safety

Response is separated from detection. ML cannot create a response action.

An authorized analyst must select the action, review the target, enter a
justification note, and confirm. Protected internal and management addresses
are denied. Both accepted simulations and denied attempts are recorded in the
audit trail.

There is no real firewall connector. This prevents the controlled prototype
from disrupting a real network.

## Validation Journey

Validation was completed in stages.

First, fixed synthetic scenarios tested normal traffic, port scanning,
repeated deduplication, generic syslog, malformed input, and other threat
behaviors.

Second, generated variants checked whether the rules depended on one exact
sample.

Third, layered tests compared rule, anomaly, supervised, and hybrid
contributions.

Fourth, end-to-end tests validated ingestion, detection, investigation,
response simulation, and audit.

Later phases added reviewed labels, benchmark adapters, temporal support,
false-positive reduction, calibration, separate holdouts, and independent
revalidation.

For the final phase, the candidate profile was frozen before a new fresh blind
holdout was generated. Thresholds were not tuned on this blind set.

## Final Results

The fresh blind holdout contained 700 rows from seven source identities and
sixteen scenario families.

Threat precision was 0.8906. Threat recall was 0.9459. Threat F1 was 0.9174.
The benign-like false-positive rate was 0.1303. Suspicious recall was 0.8556,
and malicious recall was 0.9000. Macro F1 was 0.8680, and weighted F1 was
0.8753.

Confidence assessment passed without fitting a calibrator on blind labels.
Expected calibration error was 0.0757, the threat-positive Brier score was
0.0751, and the maximum confidence gap was 0.1878.

Readiness v8 passed 22 out of 22 configured checks. The decision was
`final_controlled_validation_candidate`.

A separate controlled-source workflow processed 28 raw logs, recorded 25
successful parses and three tracked failures, created two alerts and two
cases, verified deduplication, verified `Why flagged?`, denied a protected-IP
response, recorded audit evidence, and created zero automatic responses.

## Demo Transition

For the live demonstration, I use a safe port-scan scenario with ten synthetic
records and source name `final-demo-firewall-live`.

The temporary-database preflight proves the expected outcome without changing
the dashboard. The dashboard-visible run then imports ten raw logs, creates ten
normalized records, and evaluates all ten.

The source is healthy. The detection run reports `port_scan (1)`. The system
creates one critical alert or deduplicates an existing matching alert. The
alert links the evidence and appears in a lightweight case. No response action
is created.

If the occurrence count is greater than ten, that means the scenario has been
run before. ATDR preserved the new logs and updated the existing alert instead
of creating duplicate noise.

The source may show an unknown-application note because the scan sessions are
rapidly denied or incomplete. This is expected data-quality context, not a
parser failure.

## Limitations

The controlled datasets cannot represent all real network behavior. The fresh
blind set still contains near-pattern overlap, which is reported honestly. The
system has not completed a sustained real router or firewall forwarding pilot.

SQLite is useful for local setup but is not validated as a shared production
database. Local JWT roles are not enterprise identity management. There is no
high-availability collector, production retention policy, independent
penetration test, or vendor-approved response connector.

For these reasons, the system is not production promoted.

## Future Work

The next meaningful technical phase is a controlled real-device syslog pilot.
One approved firewall or router should forward logs to ATDR over multiple days.
The study should measure parser quality, source stability, false positives,
drift, and analyst workload while response remains simulated.

Later work can validate PostgreSQL, TLS, secret management, backup, retention,
monitoring, university OIDC, and an approved response connector with rollback
and separate authorization.

## Conclusion

ATDR demonstrates a complete controlled SOC workflow. It preserves evidence,
uses layered and explainable detection, supports human-reviewed AI Governance,
groups alerts into cases, and records safe simulated responses.

The project achieved strong controlled threat-positive results while keeping
the final boundary clear: Final Controlled Validation Candidate,
`Decision Support Only`, `Response Automation Disabled`,
`Not Production Promoted`, and `Real firewall blocking disabled`.
