# ATDR finish list

Everything left to do on ATDR, written 23 October 2026. Claude works through it from the top in terminal
sessions with `/goal`. Each item says when it counts as done; the proof has to appear in the session's output
(test counts, the release line "ATDR runs version ...", check results), because the goal's checker only reads
the conversation.

How Claude uses this list:

- Work top to bottom. Tick an item as `[x]` with the date and commit when its "Done when" holds, and print the
  proof.
- An item that needs Koe (a decision, or a step the safety check blocks) is marked `[needs you]` with the exact
  question or commands, and Claude moves on to the next item it can do.
- A real design choice is asked with the question tool before building, with options and a recommendation.
  Live data or settings change only with Koe's OK, after a rehearsal on a copy and a backup.
- After each item, print this list's status (done / needs you / left).

## 1. Finish what is in flight

- [x] **Live rebuild follow-up.** Needs Koe first: run the rebuild (the five lines in
      `project_atdr_production_phase.md`, 23 Oct evening). Done when: the live list matches the rehearsal
      (92 new alerts plus #2049 and #2637 kept; open Critical 16, High 19, Medium 37, Low 21; #4163 is now
      #4255); the route check and the scanning check (`.tmp\claude-tools`), updated to the new numbers, print
      "PROBLEMS: none" on live; `docs/detection/ALERT_REBUILD.md` has a 23 Oct section with the old-to-new
      numbers; the runbook line about #4210 and #4215 is corrected; released.
      Done 23 Oct (aa3288b): Koe rebuilt at 17:31 (audit 4392, backup `atdr-sqlite-20261023T103108Z-f29103ee`);
      live = rehearsal alert for alert (94 of 94), open Critical 16, High 19, Medium 37, Low 21, #4163 -> #4255,
      #4225 -> #4317; route check 68/68 PROBLEMS: none, scanner check (#4317) and System panel PROBLEMS: none;
      assistant on the rebuilt copy main 126/126, held-out 26/27 (h-30: new item below); ATDR runs aa3288b.
- [x] **Push what is not on GitHub** (34ea7b5, 4801fcd and later). Done when: origin/main equals the live
      version and CI and CodeQL are green. Done 23 Oct (4801fcd): the safety check blocked my push, Koe pushed
      it; origin/main = live = 4801fcd; CI run 39939658699 green (postgres-persistence, backend-release-gate,
      security-controls, frontend-dashboard), CodeQL 39939658701 green. Later commits are pushed after their
      release checks.

## 2. Claude can do these

- [x] **Readiness check false alarm.** `production_readiness_doctor` is blocked only because
      `.env.preproduction.example` and `.env.shell.example` (placeholders only) count as tracked secrets. Done
      when: example templates holding only placeholders pass and a real secret in one is still caught, with a
      test that fails without the fix; the doctor on live shows no blocker; released.
      Done 23 Oct (896360f + 4e5a8ac, live in aa3288b): the doctor uses the repository scan (its own list had
      drifted); example files must hold placeholders for every secret-named setting; 14 of 14 breaks caught;
      230 related tests local + UTC; doctor on live: status warnings, blockers []. 896360f turned CI's
      security-controls red (the scan imported pydantic, which that job does not install): fixed in 4e5a8ac
      with a test that runs the scan without site-packages; CI 39948415253 + CodeQL green on aa3288b.
- [x] **Restore drill.** Restore the newest daily backup from `D:\ATDR-backups` into a scratch folder with
      `restore_database` / `run_backup_restore_drill` (dry run first), and compare integrity and counts with
      live. Done when: the drill's output shows integrity ok and matching counts, and the runbook has the steps
      and the measured time.
      Done 23 Oct (36e509f, live): newest daily backup atdr-sqlite-20261023T025258Z-3c658d85 verified (size,
      checksum, 11.5 h old); dry run, then restored into a scratch file in 3.8 s: restore_validated, checksum
      valid, integrity_ok, row_counts_match (33 tables vs the manifest), revision f1a3c5e7b9d2; against live 20
      tables equal and the 13 others matched the day's audit entries after the backup (synthetic log removed,
      note, 6 service alerts, rebuild, 59 audit rows). Runbook "Restore drill" with the steps and the time.
- [x] **Production profile, on a copy.** Run ATDR with `ENVIRONMENT=production`, `AUTO_CREATE_TABLES=false` and
      migrations (`alembic upgrade head`) on a fresh database; fix what breaks so that switching live is only a
      settings change. Done when: the doctor for that profile lists only what needs a server (PostgreSQL, TLS);
      tests pass; the runbook has a "Production profile" section; released. Live stays in development until
      item 12.
      Done 23 Oct (bff3a28, live; CI green on 3e4d0bf): rehearsed on PostgreSQL 16 over HTTPS with the
      MFU-shell sign-in settings: 0 start-up issues, 9 of 9 checks (ready, local login refused, session token,
      uploads, worker, detection, Overview, alerts), cookie `HttpOnly; SameSite=lax; Secure`; doctor on
      PostgreSQL: no blocker, warnings = PostgreSQL lab validation, TLS, restore and performance (items 4, 7);
      on SQLite only PostgreSQL itself; live schema = migrations (`alembic check` on a copy). Found: the
      three sign-in addresses must be HTTPS (so not only a settings change on this laptop), and the syslog
      receiver made tables whatever AUTO_CREATE_TABLES said (fixed, 2 of 2 breaks). Runbook "Production
      profile".
- [x] **Database portability audit.** Run `database_portability_audit` and fix SQLite-only code it finds, with
      tests. Done when: its output shows no unhandled finding (or each finding with its fix); released.
      (Corrected 23 Oct: the audit reads settings and column types, not code, so it cannot find SQLite-only code,
      and CI's PostgreSQL job ran ATDR's API tests on SQLite. The check that the code works on PostgreSQL is a
      run of ATDR's own flow on PostgreSQL compared with SQLite: `atdr/tests/test_postgres_smoke.py`, on a
      portable PostgreSQL 16 here and in CI.)
      Done 23 Oct (0dab41c, fb06262, 6ccef0b, 4105acf, 3e4d0bf; live = origin/main = 3e4d0bf, CI 39969502947
      green including "Compare ATDR on PostgreSQL with ATDR on SQLite"): the audit's findings on SQLite and
      PostgreSQL, each handled: no blockers; "PostgreSQL validation pending" -> the comparison test; "JSON
      fields" -> pages filtering on JSON gave the same answers; "timezone and ordering" -> found and fixed:
      on a server not in UTC every time came back off by the server's offset (connections now in UTC),
      missing values sorted first on PostgreSQL (now said), ties in 6 rankings (now by name); 8 of 8 breaks
      caught. Also fixed: the audit, doctor and 4 old answers named removed scripts (guard test, 4 of 4).
- [x] **Performance smoke.** Run `performance_smoke` on a copy of live and after a large import. Done when: cold
      and cached Overview timings are printed and recorded in the runbook.
      Done 23 Oct (59dd6de + 36e509f, live): live copy (120,000 logs): Overview cold 0.22 s, cached first
      0.17 s, cached 0.015 s; after importing 199,643 more logs (319,643): 0.45 s, 0.44 s, 0.028 s; alert list
      0.012 s. Found: the smoke timed the alert list with every evidence log (4.1 s), which no page does;
      fixed (1 of 1 break). Model features 2.6 s -> 6.9 s per call (mostly fixed cost): recorded. Runbook
      "Performance".
- [x] **Detection evidence under catalog v5.38.0.** Run the detection scoreboard (team labels; 381 right
      expected after the synthetic log was removed) and the blind check on the held-out lines. Done when: both
      outputs are printed and `docs/EVIDENCE_SUMMARY.md` has them.
      Done 23 Oct (36e509f): scoreboard 1,414 labeled records, 381 of 384 threats, precision 97.9%, recall
      99.2%, false alarms 0.8%, F1 98.6%; blind second look under v5.38.0 (453,908 held-out logs re-run):
      80.6% / 81.8% / 1.5% / 81.2%, human-checked 93.5% / 78.2% / 0.5% / 85.2% (as under v5.36.0; no Threat
      sample lost its flag). Rows in EVIDENCE_SUMMARY.md, section in BLIND_CHECK.md, second_look_v5_38.json.
- [x] **Assistant: "if I had ten minutes, what should I look at?"** The last item of Known limits in
      `docs/SOC_ASSISTANT_CONVERSATIONAL.md`: such wordings do not single out the alert the Overview opens
      first. Done when: the question is in the main set, 6 fresh asks of 6 pass, main and held-out show no
      regression, released.
      Done 24 Oct (32cb843, with eaed567). "What first" now covers:
      - time-boxed and "where do I start" wordings, in English and Thai;
      - a worry question, which gets the situation summary when the model's answer fails;
      - a fallback of ATDR's own when the model's answer fails its checks: it names the alert to open
        first, with a Thai lead line when asked in Thai.

      Results:
      - the probe went from 0 of 6 to 6 of 6 fresh; dev rewordings 4 of 4;
      - main 129 of 129; held-out (v8) 28 of 28;
      - 12 of 12 deliberate breaks caught; 237 assistant tests pass in local time and UTC.

      Release eaed567: backend 1,865 passed, browser 98 passed. On live:
      - route check, System panel check and scanner check: PROBLEMS: none;
      - "If I had ten minutes, what should I look at?" names #4255 (3.5 s); the Thai question names #4255
        (11.4 s).

      Pushed: origin/main = live = eaed567. CI run 40056507501 green (all 4 jobs); CodeQL green.
- [x] **Repo documents current.** README, runbook, `EVIDENCE_SUMMARY.md` and `IMPROVEMENT_PHASE_REPORT.md` give
      today's figures (catalog v5.38.0, alert counts, test counts) wherever they describe the present. Done
      when: no document states an old figure as current; committed.
      Done 24 Oct, committed together with this list, then released and pushed.
      - README "Current State (24 Oct 2026)": v5.38.0; 94 alerts, 93 open (Critical 16, High 19, Medium 37,
        Low 21) on 120,000 logs; the 23 Oct rebuild; 381 of 384 on the team's labels; ATDR starts with the
        machine.
      - `EVIDENCE_SUMMARY.md`: as of 24 Oct (v5.38.0), 120,000 logs, and a paragraph on the 23 Oct list.
      - `IMPROVEMENT_PHASE_REPORT.md` "Where we are now (24 October)": team labels 97.9 / 99.2; assistant
        129/129 and 28/28; tests 1,865 backend and 98 browser; the live list's figures; #4163 is #4255.
      - Runbook: already current (23 Oct rebuild line, restore drill, performance, production profile).
        Its older figures are dated measurements and stay as they are.
      - A search of the current docs finds old figures only in dated sections.
- [x] **Assistant: "which alert first?" in Thai when that alert is new** (found 23 Oct, item 1). On the rebuilt
      list, h-30 (held-out) fails 6 of 6 fresh asks: with the alert to open first created that day the model
      fetched its playbook, answered in English, and the Thai rewrite turned "May 2024" into a wrong
      Buddhist-era year (2577), so the answer check fell back to the built-in answer, which names no alert.
      The same code passes 6 of 6 on the list from before the rebuild and on the rebuilt list dated a day
      earlier. Also h-01 ("any critical stuff I should worry about?", held-out): 0 of 6 fresh on the rebuilt
      list with the code before item 6 and after it alike (draft 277 words, over the 220 limit, and a "1,000
      connections" no tool gave), while it passed on the list before the rebuild.
      Done with item 9 (same question family), without tuning on h-30 or h-01: Done when a fresh probe of dev
      wordings on a copy where the top alert is new passes 6 of 6, h-30 is re-measured fresh, and main and
      held-out show no regression; released.
      Done 24 Oct (32cb843, with eaed567), as part of the item above. h-30 and h-01 were re-measured fresh
      and moved to the main set as open-15 and open-16. Both pass 6 of 6 fresh on a list whose alerts are
      new. New held-out questions h-32 to h-34 were written before any run. Main 129 of 129, held-out
      28 of 28. Same release, live checks, push and CI as the item above.
- [x] **Code clean-up, phase 3.** Remove modules and scripts nothing runs, the way 342e94b did. Done when: the
      removed files are listed, the full suite passes, released.
      Decided 24 Oct (Koe, question tool): keep all 34 (32 scripts nothing imports, plus
      `mfu_iam_validation` and `template_bridge_contract`) and list them; nothing removed. Done 24 Oct
      (05a39d3): `docs/MODULE_INDEX.md` "Operator tools" lists them by group, with a warning that
      `reset_demo`, `seed_demo`, `seed_demo_labels`, `register_log_source` and `send_sample_syslog` must
      never run against live. Its stale lines are fixed: audit and staged-input retention have been live
      since 22 Oct, through the worker's housekeeping. Reach check re-run on today's tree: scripts 124,
      unreached 0 (it was 32). App modules 257, unreached 2, and both are one-line package `__init__`
      files. The docs-name guard (`test_named_scripts_exist`) passes in local time and UTC. Released with
      the documents commit below.

## 3. Needs a decision from Koe (Claude asks, then does it)

- [x] **Switch live to the production profile** (after the profile item above): yes or no.
      Decided 23 Oct (Koe, question tool): no, live stays in development. The production profile needs HTTPS
      for the three sign-in addresses, and live serves one person on 127.0.0.1 over HTTP; the profile is
      rehearsed for a server (item above, runbook "Production profile").
- [x] **Where ATDR runs:** stay on this laptop (one person, local only), or a server for the team (PostgreSQL,
      HTTPS, network access). Claude can write and rehearse the move; the server itself needs MFU or Koe.
      Decided 23 Oct (Koe): the laptop, with a server guide. Done (36e509f): runbook "Moving to a server"
      (PostgreSQL, HTTPS, settings, migrations, processes, the feed, backups, data, checks); rehearsed parts:
      the production profile and PostgreSQL. Gaps named in it: no unit for the syslog receiver, no SQLite to
      PostgreSQL copy tool.
- [x] **Team documents** (Team Guide, explainer, Presentation Script, decks on claude.ai, school account): Koe
      said this comes last. Decided 23 Oct: figures and alert numbers only.
      Done 24 Oct, after Koe switched to the school account. Seven documents were updated:
      - Team Guide, ATDR Explained for the Team, How ATDR Works, ATDR after the presentation, Presentation
        Script: figures, alert numbers and as-of dates.
      - Main deck (v42) and Q&A Practice deck (v6): figures and alert numbers.
      What changed:
      - #4033 / 3738 is #4255, #4067 is #4271, #4134 is #4311, #4145 is #4328, and #4143-#4148 are
        #4326-#4331, all checked on live by the route check.
      - The counts now read 94 alerts, 93 open (Critical 16, High 19, Medium 37, Low 21), on 120,000 logs.
      - The MFU model panel reads 98 / 92 / 6, with 6 experimental alerts (4 malware / C2, 2 port scan).
      - Unclassified is 19%; team labels give precision 97.9%, recall 99.2%; the assistant scores 129/129
        and 28/28; tests are 1,865 + 98.
      - The Assistant slide quotes the real 24 Oct answer: 16 open Critical.
      Decided 24 Oct (Koe, question tool): recreate the demo files and re-measure, and retake the backup
      screenshots.
      - `Downloads\mfu-demo-import.log` (export lines 120,001-123,000) and `mfu-practice-import.log`
        (200,001-203,000) were recreated.
      - Stop 8 rehearsed on a copy of live with live's code: 3,000 logs in 2.9 s, re-import 3,000
        duplicates, check 21.4 s, 4 new alerts, evidence added to 8. The Overview then shows 97 open
        (17 Critical) and still opens #4255.
      - "Undo a practice import" rewritten for `C:\ATDR-live` (backup_now, stop, restore_database, swap,
        alembic, start). Rehearsed: the restore validated with 94 alerts and 120,000 logs.
      - Nine backup screenshots retaken from live with every address shown as [redacted-ip]; the capture's
        check found no visible address.
      Not touched: the four documents teammates shared (ATDR Live Demo Guide, Presentation Slides, their
      Presentation Script, ATDR at a Glance). The Team Guide says it replaces them.
- [x] **Chat notifications:** built but not set up; needs a chat webhook address from Koe.
      Decided 24 Oct (Koe, question tool): not needed. Chat would only repeat what email already sends: a new
      Critical alert, the daily summary, ATDR's own problems. Live has sent 10 notification emails (the daily
      summary at 09:33 on 24 Oct the newest) and 20 Windows notifications. More people can get them by adding
      their addresses to `ATDR_NOTIFY_EMAIL_TO`. The chat channel stays built and off; setting
      `ATDR_NOTIFY_CHAT_WEBHOOK_URL` turns it on later.

## 4. Not for Claude

- MFU's firewall sending its logs to ATDR, then one to two weeks of watching and tuning on real traffic. This
  needs MFU IT; once the feed is connected, the tuning becomes new items here.
- A USB drive with an `ATDR-backups` folder (every daily summary asks for it), and deleting the two leftover
  files on `D:`.
- The cold-start test: switch the laptop on from off, leave it at the sign-in screen for 3 minutes, then check
  that the dashboard answers without anyone signing in. The runbook says this has not been done ("With the
  machine, before anyone signs in"). Restart and power loss already passed.
- The open items in `docs/PROFESSOR_DEFENSE_PREP.md` (AI-usage disclosure, programme policy).
- The documents the professor asked for, when the team presents to committees.
