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

1. The question goes to the model together with a list of 10 tools. Every tool
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

2. The model calls the tools it needs (several calls, up to 5 rounds) and writes the answer.
3. ATDR decides from the question whether it is about ATDR (alerts, logs, rules, severity, SLA, the dashboard, blocking, an IP, and so on). Such a question must be answered from the tools: an answer from memory is sent back once to look it up, and rejected if it still is not. Other questions may be answered from general knowledge, and the page then says "general knowledge (not from ATDR records)".
4. ATDR checks the answer before showing it (`verify_answer` in `atdr/app/services/assistant_agent.py`):
   - in an answer built from the tools, every number must appear in a tool result, the question or the conversation, and any named page, button, menu or tab must appear in the tool results;
   - in a general-knowledge answer, ordinary facts are allowed ("at least 12 characters"), but figures about ATDR's own data ("41 alerts", "alert #3676") are not;
   - no IP address from ATDR's records (they stay redacted), and no configured secret;
   - no claim that the assistant did something ("I have blocked…"): it can only read;
   - ATDR dashboard directions only if a guide tool was used;
   - requests for raw logs, passwords or keys must be refused;
   - internal tool names and leaked model markup are removed from the text.
5. If a check fails, the model gets one chance to correct the answer. If it still fails, the built-in answer is shown instead and the page says why.
6. Requests to *do* something ("block 10.1.1.1", "close these alerts") get the real dashboard guide fetched before the model answers, and the answer always says the assistant did not do it.
7. Investigation briefs, empty questions and unsafe or prompt-injection requests still go straight to the built-in handlers.

Nothing the assistant can call writes to the database, and raw log lines are never sent to the model. It has no internet access, so it says so when asked about the weather, news or sports.

## Turning it on

The recommended engine runs on the same computer, so no data leaves it:

1. Install Ollama (`winget install Ollama.Ollama`) and download the model: `ollama pull qwen3:8b` (5.2 GB).
2. In `.env` set `ASSISTANT_AGENT_ENGINE=ollama` and restart ATDR (`scripts/stop_system.cmd`, then `scripts/start_system.cmd`).
3. The first answer after the model has been unloaded takes about a minute while it loads into the graphics card. After that, answers take 6 to 8 seconds on average. The model stays loaded for 30 minutes after the last question (`ASSISTANT_AGENT_KEEP_ALIVE`).

`ASSISTANT_AGENT_ENGINE=off` (the default) keeps the old built-in answers only.
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
