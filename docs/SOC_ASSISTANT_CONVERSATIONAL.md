# Conversational SOC assistant

The SOC Assistant page can now hold a normal conversation, like a chat
assistant, instead of only recognising fixed phrasings. A language model reads
the analyst's question and answers in plain words, in the language the analyst
used (Thai works). Questions about ATDR's data are looked up through ATDR's own
read-only tools; general questions (security concepts, IT advice, writing help,
small talk) are answered from the model's own knowledge and labelled as such.
Before an answer is shown, ATDR checks it. If the check fails, or the model is
unavailable, the page falls back to the old built-in answers.

## How it works

1. The question goes to the model together with a list of 12 tools. Every tool
   wraps a service the dashboard already uses, so the facts are the same ones
   the other pages show:

   | Tool | What it looks up |
   |---|---|
   | security_overview | Alerts by severity and status, top attack types and sources, the open alerts to look at first, stored logs, latest detection run |
   | query_alerts | Count, rank, per-day trend or list of alerts, with filters |
   | query_logs | Count, rank or trend of firewall logs (apps, ports, countries, IPs) |
   | get_alert | One alert: why it was flagged, rules, MITRE ATT&CK, evidence, SLA, what to check |
   | get_alert_playbook | The response steps for one alert (triage, investigate, contain, close) |
   | get_log | One log and why it was or was not flagged |
   | explain_detection_rules | The rule catalog |
   | explain_concept | Security terms and ATDR concepts (severity, SLA, MITRE, ML, data sources) |
   | dashboard_how_to | The dashboard guides (block, suppress, notes, import logs, and so on) |
   | system_status | ML status, detection runs, jobs, source health |
   | behavior_model_view | What the MFU behaviour model sees in a five-minute window: its findings, their non-normal estimates, its experimental alerts and each attack type's standing against the quality bar |
   | watchlist_lookup | Whether an address is on ATDR's watchlist (Feodo Tracker, ThreatFox or the team's own entries) and which alerts it appears in |

2. The model calls the tools it needs (several calls, up to 5 rounds) and writes the answer.
3. ATDR decides from the question whether it is about ATDR (alerts, logs, rules, severity, SLA, the dashboard, blocking, an IP, and so on). Such a question must be answered from the tools: an answer from memory is sent back once to look it up, and rejected if it still is not. Other questions may be answered from general knowledge, and the page then says "general knowledge (not from ATDR records)".
4. ATDR checks the answer before showing it (`verify_answer` in `atdr/app/services/assistant_agent.py`):
   - in an answer built from the tools, every number and every alert or record number must appear in a tool result; a number that only the analyst's question contains does not count, so "we have 500 alerts, right?" cannot be confirmed by repeating it. The assistant's own earlier answers in the conversation do count, since they were checked when given; a follow-up that points back at them ("tell me more about the second one") is sent to look the item up again rather than answered from memory. Any named page, button, menu or tab must appear in the tool results;
   - the answer stays within the conversation word limit (220 words);
   - in a general-knowledge answer, ordinary facts are allowed ("at least 12 characters"), but figures about ATDR's own data ("41 alerts", "alert #3676") are not;
   - no IP address from ATDR's records (they stay redacted), and no configured secret;
   - no claim that the assistant did something ("I have blocked…"): it can only read;
   - ATDR dashboard directions only if a guide tool was used;
   - requests for raw logs, passwords or keys must be refused;
   - internal tool names and leaked model markup are removed from the text.
5. If a check fails, the model gets one chance to correct the answer. If it still fails, the built-in answer is shown instead and the page says why. The whole exchange, every model call and tool call together, has one time limit (`ASSISTANT_AGENT_TIMEOUT_SECONDS`, 120 seconds by default); past it, the built-in answer is used.
6. With a hosted engine such as Gemini, ATDR removes IP addresses, secrets, email addresses and pasted log lines from the question, the earlier turns and the tool results before they leave the laptop. An IP the analyst typed is replaced by a placeholder, which ATDR swaps back only inside its own lookups. The local model sees the question as typed, since nothing leaves the laptop. The audit trail stores the question with secrets, email addresses and IP addresses removed.
7. Requests to *do* something ("block 10.1.1.1", "close these alerts") get the real dashboard guide fetched before the model answers, and the answer always says the assistant did not do it.
8. Investigation briefs, empty questions and unsafe or prompt-injection requests still go straight to the built-in handlers.

Nothing the assistant can call writes to the database, and raw log lines are never sent to the model. It has no internet access, so it says so when asked about the weather, news or sports.

## Turning it on

The recommended engine runs on the same computer, so no data leaves it:

1. Install Ollama (`winget install Ollama.Ollama`) and download the model: `ollama pull qwen3:8b` (5.2 GB).
2. In `.env` set `ASSISTANT_AGENT_ENGINE=ollama` and restart ATDR (`scripts/stop_system.cmd`, then `scripts/start_system.cmd`).
3. The first answer after the model has been unloaded takes about a minute while it loads into the graphics card. After that, answers take 6 to 8 seconds on average. The model stays loaded for 30 minutes after the last question (`ASSISTANT_AGENT_KEEP_ALIVE`).

`ASSISTANT_AGENT_ENGINE=off` (the default) keeps the old built-in answers only.

Configured is not the same as running. `scripts/start_system.cmd` starts the
Ollama app when it is installed but not running, and prints "SOC Assistant
model: ready (qwen3:8b)" or what is wrong; `scripts/check_system.cmd` prints
the same line. On the SOC Assistant page the Answer Provider card says "Local
model offline: built-in answers" with the fix when Ollama is down or the model
is not downloaded, and AI Governance marks the assistant "Model offline".
Gemini is also supported (`ASSISTANT_AGENT_ENGINE=gemini`, reusing
`ASSISTANT_LLM_API_KEY`), but see the free-tier note below.

## How good it is

Measured with the assistant scoreboard on a copy of the real database
(3,676 alerts, 151,242 logs) on 2026-09-27. A question passes only if its
automatic checks pass, for example "the answer contains the real count of
High alerts today" or "the how-to answer names the real page".

| | Built-in answers only | Conversational (qwen3:8b, local) |
|---|---|---|
| Main question set (82 questions) | 40 (49%) | 79 (96%) |
| Held-out set (27 questions not used while building it), automatic checks | 10 (37%) | 27 (100%) |
| Held-out set, judged by reading every answer | | 25 of 27 |
| Average answer time | 0.3 s | 6.3 s (8.4 s on the held-out set) |

How to read these numbers:

- The main set was used to find and fix problems, so its score is partly tuned. The held-out set is the fairer estimate. Held-out questions that were later used to fix something were moved to the main set and replaced before the final run.
- The two held-out misses, found by reading the answers:
  - "What should an analyst do first when a brute force alert comes in?" gets general advice instead of the concrete first step (check the login system for successful sign-ins).
  - "How many alerts are still waiting for someone to take them?" reports all open alerts. No tool can filter by owner yet, and the model should have said so.
- The main-set misses change a little from run to run (the model is not fully deterministic). In the final run: "Is anything scanning our network?" gave a general overview without mentioning scans, the audit-trail answer was vaguer than the guide, and the ML answer was correct but did not use the word "rule" the check wanted.
- The checks are automatic and fairly lenient, which is why every answer was also read by hand. Earlier versions scored well on the checks while answering ATDR questions from memory and inventing dashboard steps; each such finding became one of the checks above.
- Gemini could not be compared: the free tier's daily quota ran out after a few questions, and every later call was refused. A free tier is not enough for a chat assistant used through the day.

### 29 September fix and re-run

A browser check found "How many critical alerts are open right now, and what
attack types are they?" answered "0 open Critical alerts" while 35 were open.
The model had read "right now" as "created today", and the tool's "0 created
today" as "none open". The alert tools now give the all-time count beside an
empty period, the overview says a quiet period is not an all-clear, and the
instructions say "right now" means open now and forbid calling the network
safe. Re-run on the 181-alert database: main set 84 of 85 (was 83),
held-out 25 of 27 (was 26). The held-out misses were a Thai summary that
passed 6 of 7 re-asks and a concept question that called no tool; neither
touches the fix.

### 30 September: external review and re-run

An outside code review found the checks trusted numbers that appeared in the
analyst's own question, that answers could run past the word limit, that
there was no time limit across a whole exchange, and that a hosted engine
received questions and history unredacted. All four are fixed (see the rules
above). Tightening the checks exposed four side effects, each fixed with a
test: a word the analyst typed ("critical") counted as an invented screen
name; a follow-up such as "tell me more about the second one" was answered
from memory and rejected; a rewrite a few words over the limit was thrown
away instead of cut at a whole sentence; and "5 minutes" was rejected when
the tool said "five-minute window". The model's instructions gained routing
lines for the watchlist and model tools, and the description of the older
models now says the supervised classifier is not used at all. One held-out
expectation was corrected: "explain the latest Critical alert" expected login
words, written when that alert was a brute force; it now accepts the plain
words for each attack type.

Final run on the 178-alert database: main set 84 of 85 (the brute-force
threshold question, which misses in every run), held-out 26 of 27 (the Thai
summary, which passes most re-asks). The model answered every question itself;
none fell back to the built-in answers. Average answer time 7.5 s on the main
set and 8.9 s on the held-out set.

### 1 October: the brute-force rule and the Thai summary

Asked "What does the brute force rule check?", the model called the concept
tool and answered from its first line, a textbook definition. It left out the
rule's threshold and added a check ATDR cannot make ("failed logins from one IP
or user account"; firewall logs have no accounts). The concept tool now gives
"How ATDR detects it:" with each rule's ID and condition straight after the
one-line definition, and the answer names ATDR-NET-009: at least 5
denied/reset attempts to the same host and service port in five minutes. The
port-scan answers now keep their "at least 10" thresholds too.

The Thai summary was right all along: on a day with no new alerts it says so
in words ("ไม่มีการแจ้งเตือนใหม่", there are no new alerts), and the checker
only accepted the digit 0. A zero count now also accepts a phrase about that
same count; a narrower phrase ("no critical alerts") does not stand in for all
alerts.

Run on the 178-alert database: main set 85 of 85, held-out 27 of 27, no
fallbacks; average answer time 7.0 s and 9.0 s. A full score means every
check passed on this run, not that every question is answered well: scores
have moved by a question or two between runs.

### 1 October, later: questions a reviewer would ask

Fifteen questions a reviewer might ask, read by hand, found four weak answers:

- "How accurate is ATDR?" gave no figures and called the rules "highly
  reliable". A new concept topic gives the official blind result first (F1
  62.7%) and marks the later figures as a second look. When the second look
  came first, the model quoted only that, as "the blind check". A test keeps
  the topic's figures identical to `docs/EVIDENCE_SUMMARY.md`.
- "Why should I trust your answers?" was answered without a lookup ("real-time
  insights"). Questions about trusting the assistant now count as questions
  about ATDR, and a new topic, in the first person, explains the checks every
  answer passes. The instructions also say the assistant is not the detector:
  asked "how do you work?", it had described ATDR's job as its own.
- "Can the AI create alerts by itself?" said no and expanded ATDR as
  "Automated Threat Detection and Response". The overview text itself had that
  name and said machine learning only gives advisory scores. It now has the
  project's name, and a new topic says the rules raise almost all alerts, the
  MFU model raises experimental ones where no rule alerted (with the live
  count), and the assistant cannot create alerts.
- "Explain alert 3738 like I'm a manager" listed rule names, scores and ATT&CK
  codes. The instructions now ask for plain words when someone wants an alert
  explained simply. A broader first version (any simple explanation, "for a
  manager") made the model round 151,002 logs to 151,000 for "a quick overview
  for my boss" and count alerts by type wrongly for "any critical stuff I
  should worry about?". The checks rejected both, so the rule now covers only
  explaining an alert.

The main set gained three questions for these, so it now has 88 checks.

One more safety gap showed up in these runs. When the model's answer to "close
all critical alerts for me" failed the checks (it named statuses the dashboard
guide calls "Resolve" and "Needs context" as "Resolved" and "Needs More
Context"), the built-in fallback listed the Critical alerts without saying it
cannot close them. Any request that starts with an action verb now gets the
read-only refusal from the fallback too.

Asked "Why should I trust your answers?", the model looked up the right topic
and still answered generically ("I am designed to provide accurate
information"). Tracing every call showed why: it first answered from memory,
was sent back to look the facts up, and then repeated that unchecked first
draft word for word, because the draft stayed in the conversation. The draft
is no longer sent back, so the answer is built from the lookup. "How do you
work?" also stopped describing ATDR's detection as the assistant's own job.

Run on the 178-alert database: main set 88 of 88, held-out 27 of 27, no
fallbacks; average answer time 7.0 s and 8.2 s. Every change to the
instructions moved a few unrelated answers, so each version was scored on both
sets before it was kept.

### 1 October, afternoon: a second round of reviewer questions

Sixteen more questions, four of them in Thai, found these; each is fixed:

- "Is MFU under attack right now?" was answered "MFU is not currently under
  attack" from a quiet day. The overview now opens with "ATDR cannot tell
  whether MFU is under attack right now" and the date of its newest log, and an
  answer that says MFU is, or is not, under attack is sent back.
- "What's the difference between the rules and the AI model?" compared the old
  rules' official F1 (62.7%) with the new rules plus the model (90.1%), and said
  the model adapts over time. The accuracy topic now sets 90.1% against 85.2%
  for the same rules, and the model topic says it does not learn after
  training.
- "Show me alerts from China" searched for an IP address called "China" and
  reported none. Alerts carry no country, so the tools now say so and give the
  logs' counts for that country (640 from China, 981 to it).
- "How many logs, and from when?" left out the dates, and then called a
  three-minute export from May "up to date". The count now gives the span and
  says nothing newer has been imported.
- Thai: "how accurate is this system?" was answered in English, and Thai
  answers were rejected for Buddhist-era years (2569 for 2026) and for quoted
  Thai translations of English terms. An answer to a Thai question must now be
  in Thai, a Buddhist-era year counts as its Gregorian year, and quoted Thai is
  not taken for a screen name. "What can the AI model do?" in Thai is now looked
  up instead of answered from memory.
- "Block the IP in alert 3738" was rejected for naming an alert that no tool
  had returned. A request to act now also looks up the alert it names, so the
  answer gives the dashboard steps for that alert.

Scoring these changes found two more. "Why can't the ML model create alerts?"
was answered "it cannot create alerts on its own": the model text mentioned the
experimental alerts only after the quality bar, so they now come second. The
Thai daily summary turned "no new alerts today is not an all-clear" into "not
100% safe", a figure no tool gave, and called the newest alert's date "today".
The overview now says "no new alerts were created today, but N are still open"
and states today's date.

Three multi-turn conversations found two more. "Show me the top 3 critical
alerts" ranked alerts by severity while keeping only Critical, a single group,
and the answer named alert numbers no tool had returned; "explain the first one"
then went to an unrelated alert. Ranking by a field already kept to one value
now lists the highest-scoring alerts instead (#3839, #3838, #3792), and the
follow-ups explain and plan for #3839. "Why is it only experimental?" was
answered from memory ("still in development"); "experimental" now marks a
question about ATDR, so it is looked up ("it has not passed its quality bar").

Final run on the final code: main set 88 of 88, held-out 26 of 27, no
fallbacks; average answer time 7.6 s and 10.5 s (a Thai answer sometimes needs
a second pass to come back in Thai). The miss, "What does the ML model do in
ATDR?", leaves out how the model relates to the rules in some runs and passes
in others; the run before scored 27 of 27. A run that shared the laptop with
the test suite scored 25 of 27: part of the model runs on the CPU, so heavy
CPU load changes its wording slightly, and scores move by a question or two
between runs.

## Measuring it again

```
python -m atdr.scripts.assistant_scoreboard                    # built-in answers only
python -m atdr.scripts.assistant_scoreboard --engine ollama    # conversational, local model
python -m atdr.scripts.assistant_scoreboard --engine ollama --questions data/evaluation/assistant_questions_holdout.json
```

Reports are saved under `.tmp/assistant_scoreboard/`. When a held-out question
is used to fix something, move it to the main set and write a new held-out one.

## Known limits

- An 8-billion-parameter model sometimes phrases things loosely or stays general when the tool gave specifics. Numbers and screen names are checked; wording is not.
- General-knowledge answers are the model's own knowledge and can be wrong or out of date, like any chat assistant; they are labelled so the analyst knows.
- Long overview answers can take 10 to 25 seconds, most of it the model writing the answer.
- It only knows what ATDR's tools return about MFU. It cannot see the internet or other MFU systems, and it cannot yet filter alerts by who they are assigned to.
