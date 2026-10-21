# TheHive: practice run, demo and evidence

Owner: TheHive (Park). How to rehearse triage (BACKLOG T3.4), TheHive's part of the team demo (TD.5) and what to capture for the delivery (TD.4). Procedure: [TRIAGE.md](TRIAGE.md). Alert format and rules: [ALERT-FORMAT.md](ALERT-FORMAT.md).

Never paste `.env` contents, `soc.sh info` output, keys or passwords into a chat, a screenshot or a commit. Crop them out of screenshots.

## 1. Practice run (T3.4), in `cases` mode

Takes about an hour. Uses the test alerts, so nothing real is touched; `--cleanup` removes them at the end.

1. Start and create the alerts **without** `--promote` (you promote them yourself):
   ```bash
   cd ~/asox-soc
   scripts/soc.sh up cases
   nodes/cases/thehive/scripts/thehive-test-alert.sh all
   nodes/cases/thehive/scripts/thehive-test-alert.sh ssh       # a second SSH alert, to practise a merge
   ```
2. Open http://localhost:9000 and log in as the **analyst** (login from `scripts/soc.sh info cases`, never `admin` for daily work).
3. **Alerts** → filter status **New** → sort by severity. Work them top-down with TRIAGE.md. Suggested verdicts, so every action gets practised once:

   | Alert (template) | Practise | Close the case as |
   |---|---|---|
   | `login` (suspicious-login, Critical) | Promote at once (R2), assign to yourself, work all tasks | True positive, with impact |
   | `ioc` (ioc-match, Critical) | Promote; run the MISP analyzer on the IP observable; mark it IOC only after checking | True positive, with impact |
   | `malware` (malware-detection) | Promote; run analyzers on the hash | True positive, no impact |
   | `ssh` (ssh-bruteforce) + the second `ssh` | Promote the first; **merge** the second into that case (R4) | True positive, no impact |
   | `sudo`, `newuser`, `fwlogin`, `web` | Promote, work the tasks, write a summary | True positive, no impact (or Indeterminate) |
   | `portscan`, `ids` | Promote; set `containment-action` = `ip-blocked` and describe it in a comment | True positive, no impact |
   | `fim` (file-integrity) | Treat as expected admin work: **Ignore** the alert with the reason "planned change, confirmed by host owner" | (no case: ignored = false positive) |
   | `generic` (wazuh-generic) | **Ignore** with the reason "vulnerability scanner of the IT team" | (no case: ignored = false positive) |

4. For every case: close each task with a short log, write the **summary** (what happened, impact, actions, follow-ups), set the **resolution status**, close.
5. Take the screenshots listed in section 3 while you go.
6. Try the false-positive report on what you ignored (test objects are left out by design, so expect "No false positives" unless you also ignored a non-test alert):
   ```bash
   nodes/cases/thehive/scripts/thehive-fp-report.sh --days 1
   ```
7. Clean up and note anything that felt wrong (unclear task, missing field) as a fix for the templates or TRIAGE.md:
   ```bash
   nodes/cases/thehive/scripts/thehive-test-alert.sh --cleanup
   ```

## 2. TheHive's part of the team demo (TD.5), in `full` mode

Runs on the machine that hosts `full` (the build instance), after Daniel's `demo.sh` / `DEMO.md` (WD.5) starts the attack. About 5 minutes. Suggested scenario: `ioc-ip` (rule 108000 → `ioc-match`, Critical), because it shows the whole chain including MISP; backup scenario: `ssh-success-after-fail` (40112 → `suspicious-login`, Critical).

| Step | Show | Say |
|---|---|---|
| 1 | Alerts list: the new alert at the top, severity Critical, template `ioc-match` | n8n turned the Wazuh alert into a TheHive alert in seconds, deduplicated by `sourceRef` |
| 2 | Open the alert: description table, tags (`rule:`, `agent:`, `attack.`), custom fields | Everything the analyst needs without opening Wazuh |
| 3 | Observables: the IP with `asox:verdict=suspicious` and `analyzer:MISP_2_1`; a `warninglist` tag if any | Enrichment at intake (C6); a MISP hit is suspicious, the analyst decides if it's an IOC |
| 4 | n8n's writeback comment `[asox-n8n writeback] …` | What the playbook did, with its execution ID |
| 5 | Promote to case (or show it auto-promoted, R2): the template's tasks appear | Case templates = the procedure built into the case |
| 6 | Run a Cortex analyzer by hand on the IP (C5) | Analysts can re-run enrichment any time |
| 7 | Close tasks with logs, write the summary, close as True positive | Resolution status feeds Grafana's metrics (C11) |
| 8 | Hand over to Grafana: MTTA / MTTR panels | Measured from the same alert |

Before the demo: `thehive-import.sh` on that instance (templates current), `thehive-test-alert.sh --cleanup` (no leftover test alerts), and one dry run.

## 3. Evidence for the delivery (TD.4)

Keep these in a folder outside the repo (screenshots can show hostnames); put only the final, cropped ones in the delivery.

- [ ] Alerts list with several templates and severities
- [ ] One alert opened: description table, tags, custom fields, observables
- [ ] An observable with enrichment tags (`asox:verdict=…`) and one with `warninglist`
- [ ] A case with its template tasks, half worked (some tasks closed with logs)
- [ ] A merged alert (R4) shown in the case
- [ ] A closed case: summary and resolution status
- [ ] An ignored alert with its reason
- [ ] Terminal output: `thehive-import.sh` (all unchanged), `thehive-test-alert.sh all --promote` (all PASS), `thehive-export.sh` + `git status` (no diff)
- [ ] Terminal output: `scripts/healthcheck.sh cases` and `scripts/contracts-check.sh --only C5`
- [ ] `thehive-fp-report.sh` output (from the end-to-end run, TD.3)
- [ ] README: the templates and fields tables are current (12 templates, 9 fields)
