# ATDR Final 5-Minute Speaking Script

## Opening

Good morning. My project is the AI-Driven Log-Based Threat Detection and
Response system, or ATDR. It is a controlled lab-scale SOC prototype that
helps analysts review firewall and syslog data. The system preserves raw
evidence, detects suspicious behavior, explains why an alert was created, and
supports simulated analyst-approved response actions.

The project is not presented as production security software. Its final status
is Final Controlled Validation Candidate. The final status labels are
`Decision Support Only`, `Response Automation Disabled`,
`Not Production Promoted`, and `Real firewall blocking disabled`.

## Problem

Firewalls generate more logs than an analyst can inspect manually. Traditional
rules are useful because they are explainable, but they may miss unfamiliar
behavior. Machine learning can assist prioritization, but it may also create
false positives or appear more reliable than its training labels justify.

The main problem was therefore not only how to detect threats. It was how to
build a trustworthy workflow that keeps evidence visible and keeps security
decisions under human control.

## Objectives

ATDR has five main objectives. First, it preserves raw log evidence. Second, it
normalizes useful fields for search and detection. Third, it combines
rule-based, anomaly, supervised, and hybrid detection. Fourth, it supports
alert investigation and case grouping. Finally, it records simulated response
actions with approval and audit instead of performing automatic blocking.

## Architecture

The backend uses Python, FastAPI, SQLAlchemy, Alembic, and SQLite. The primary
dashboard uses React and TypeScript. Machine-learning experiments use
scikit-learn.

The data flow begins with a file, replay source, or controlled syslog input.
ATDR stores the raw line before parsing. It then creates a normalized record
using a Palo Alto, generic syslog, or raw fallback parser profile. Detection
signals produce an explainable alert, related alerts can form a lightweight
case, and any response remains a human-approved simulation recorded in the
audit trail.

## Detection And AI

The rule layer detects known behaviors such as repeated denied access,
scanning-like activity, brute-force-like attempts, suspicious applications,
and other policy or behavior patterns.

Behavior-window features summarize repeated activity, including event counts,
unique destinations and ports, deny ratios, and repeated attempts.

IsolationForest provides anomaly scoring. It identifies unusual behavior but
does not prove an attack. The supervised model learns from assisted and
human-reviewed labels and supports SOC triage. Hybrid scoring combines these
signals while the `Why flagged?` panel shows the evidence behind the alert.

## Validation Results

The final frozen profile is called `independent_fpr_stabilized`. It was tested
on a fresh blind holdout of 700 rows from seven sources and sixteen scenario
families. The profile was not tuned on the blind labels.

The final threat precision was 0.8906, threat recall was 0.9459, and threat F1
was 0.9174. The benign-like false-positive rate was 0.1303. Suspicious recall
was 0.8556, and malicious recall was 0.9000. Confidence assessment also passed
without fitting calibration on the blind labels. Readiness v8 passed 22 out of
22 configured checks.

These are controlled validation metrics. They are not production accuracy.

## Demo Transition

In the demonstration, I use a safe ten-log port-scan scenario. ATDR registers
the source, parses all ten records, reports the source as healthy, evaluates
the ten logs, and creates or deduplicates one critical port-scan alert. The run
attack type is correctly shown as `port_scan (1)`. The alert links the ten
evidence records and appears in one case.

The source may show an unknown-application note because the synthetic scan
uses rapidly denied or incomplete sessions. This is a data-quality note, not a
parser failure.

## Limitations And Conclusion

ATDR has not completed a real router or firewall forwarding pilot, a
high-availability deployment, production IAM, or a real response connector.
SQLite is suitable for local testing but not yet validated for shared
production scale.

The next meaningful phase is controlled real-device validation over multiple
days while keeping response simulated.

In conclusion, ATDR demonstrates a complete evidence-preserving SOC workflow
that combines explainable rules, anomaly scoring, supervised learning, human
review, and audited response safety. The project is complete for controlled
academic demonstration, while production deployment remains future work.
