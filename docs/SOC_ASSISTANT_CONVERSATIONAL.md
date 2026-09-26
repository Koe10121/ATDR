# Conversational SOC assistant

The SOC Assistant page can now hold a normal conversation, like a chat
assistant, instead of only recognising fixed phrasings. A language model
reads the analyst's question, looks the facts up through ATDR's own read-only
tools, and answers in plain words, in the language the analyst used (Thai
works). Before an answer is shown, ATDR checks it. If the check fails, or the
model is unavailable, the page falls back to the old built-in answers.

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

2. The model calls the tools it needs (it can make several calls, up to 5 rounds) and writes the answer.
3. ATDR checks the answer before showing it (`verify_answer` in `atdr/app/services/assistant_agent.py`):
   - every number must appear in a tool result, the question or the conversation (alert IDs included);
   - no IP address the analyst did not type (IPs stay redacted);
   - no configured secret;
   - no claim that the assistant did something ("I have blocked…"): it can only read;
   - dashboard directions ("click…", "open the…") only if a guide tool was used;
   - internal tool names are removed from the text.
4. If the model answers from general knowledge without checking a tool, it is sent back once to check. If a check fails, it gets one chance to correct the answer. If it still fails, the built-in answer is shown instead and the page says why.
5. Requests to *do* something ("block 10.1.1.1", "close these alerts") get the real dashboard guide fetched before the model answers, and the answer always says the assistant did not do it.
6. Investigation briefs, empty questions and unsafe or prompt-injection requests still go straight to the built-in handlers.

Nothing the assistant can call writes to the database, and raw log lines are never sent to the model.

## Turning it on

The recommended engine runs on the same computer, so no data leaves it:

1. Install Ollama (`winget install Ollama.Ollama`) and download the model: `ollama pull qwen3:8b` (5.2 GB).
2. In `.env` set `ASSISTANT_AGENT_ENGINE=ollama` and restart the backend (`scripts/stop_system.cmd`, then `scripts/start_system.cmd`).
3. The first answer after a restart loads the model into the graphics card (about a minute). After that, answers take about 6 seconds on average. The model stays loaded for 30 minutes after the last question (`ASSISTANT_AGENT_KEEP_ALIVE`).

`ASSISTANT_AGENT_ENGINE=off` (the default) keeps the old built-in answers only.
Gemini is also supported (`ASSISTANT_AGENT_ENGINE=gemini`, reusing
`ASSISTANT_LLM_API_KEY`), but see the free-tier note below.

## How good it is

Measured with the assistant scoreboard on a copy of the real database
(3,676 alerts, 151,242 logs) on 2026-09-26. A question passes only if its
automatic checks pass, for example "the answer contains the real count of
High alerts today" or "the how-to answer names the real page".

| | Built-in answers only | Conversational (qwen3:8b, local) |
|---|---|---|
| Main question set (76 questions, v2 checks) | 40 (53%) | 76 (100%) |
| Held-out set (22 questions not used while building it), automatic checks | 10 (45%) | 21 (95%) |
| Held-out set, judged by reading every answer | | 20 of 22 |
| Average answer time | 0.3 s | 6 s (7.6 s on the held-out set) |

How to read these numbers:

- The main set was used to find and fix problems, so its 100% is partly tuned. The held-out set is the fairer estimate. Two of its questions were later used to fix problems (the "hello" reply and country names for internal addresses); they moved to the main set and two new held-out questions replaced them before the final run.
- The two held-out misses, found by reading the answers:
  - "What should an analyst do first when a brute force alert comes in?" got a general "follow the playbook" instead of the concrete first step (check the login system for successful sign-ins).
  - "How many alerts are still waiting for someone to take them?" reported all open alerts. No tool can filter by owner yet, and the model should have said so.
- The checks are automatic and fairly lenient, which is why every answer was also read by hand. The first version scored 70/74 but often answered from general knowledge and invented dashboard steps. That is why the check-first rule and the dashboard-direction check exist, and why the question set was tightened (version 2).
- Gemini could not be compared: the free tier's daily quota ran out after a few questions, and every later call was refused. A free tier is not enough for a chat assistant used through the day.

## Measuring it again

```
python -m atdr.scripts.assistant_scoreboard                    # built-in answers only
python -m atdr.scripts.assistant_scoreboard --engine ollama    # conversational, local model
python -m atdr.scripts.assistant_scoreboard --engine ollama --questions data/evaluation/assistant_questions_holdout.json
```

Reports are saved under `.tmp/assistant_scoreboard/`. When a held-out question
is used to fix something, move it to the main set and write a new held-out one.

## Known limits

- An 8-billion-parameter model sometimes phrases things loosely (for example calling a count "in total" when it was today's). Numbers are checked; wording is not.
- Long overview answers can take 10 to 25 seconds, most of it the model writing the answer.
- It only knows what ATDR's tools return. It cannot see the internet or other MFU systems, and it cannot yet filter alerts by who they are assigned to.
