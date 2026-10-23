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

Runs on the instance that hosts `full` for the demo, after Daniel's `demo.sh` / `DEMO.md` (WD.5) starts the attack. About 5 minutes.

**Scenario: SSH brute force, then a login** (`ssh-success-after-fail`: 5763 → `ssh-bruteforce`, then 40112 → `suspicious-login`, Critical). It runs n8n's `pb-ssh-bruteforce`, the only playbook that can propose a response (C9 v0, demo interim). Backup: `ioc-ip` (108000 → `ioc-match`), which shows MISP but has no response step.

| Step | Show | Say |
|---|---|---|
| 1 | Alerts list, sorted by severity: the SSH alerts at the top, the 40112 one Critical, all tagged `ssh-campaign:<ip>` | n8n turned each Wazuh alert into a TheHive alert in seconds, deduplicated, and linked the ones from the same attacker |
| 2 | Open the 40112 alert: description table, tags (`rule:`, `agent:`, `attack.`, `ssh:login-after-bruteforce` on the brute-force alerts), custom fields | Everything the analyst needs without opening Wazuh; the brute force was raised to Critical because a login followed |
| 3 | Observables: the attacker IP with `asox:verdict=…` (and `warninglist` if any) | Enrichment at intake (C6); the analyst decides if it's an IOC |
| 4 | n8n's writeback comment `[asox-n8n writeback] …` with **"Proposed: firewall-drop `<ip>` on `<agent>` for 300 s"** | The playbook proposes blocking the attacker; nothing runs without the analyst |
| 5 | Check the IP (it's the `src`, not a SOC host), then add the tag **`approve:firewall-drop`** to the **40112** alert only (the 5763 carries a proposal too) | Human approval, recorded in TheHive (TRIAGE.md, "Interim for the physical-lab demo") |
| 6 | n8n's comment `[asox-n8n response] firewall-drop … (live): sent`, the tag `asox:response=firewall-drop`, `containment-action` = `ip-blocked` | Wazuh blocks the IP on the attacked host for 5 minutes and removes the block by itself |
| 7 | Create case from the 40112 alert (template "Successful login after failures"), merge the brute-force alerts into it (R4), close a task with a log | One attacker, one case; the template is the procedure |
| 8 | Close the case: summary, True Positive; hand over to Grafana (MTTA / MTTR) | The resolution and times feed the metrics (C11) |

Wait at least 60 s between two SSH tests (rules 5763 / 5712 stay quiet for 60 s), and log in within 4 minutes of the failures, or no 40112 is raised (n8n's `asox-lab-test-guide.md` §1.3, §3.3).

Before the demo: `thehive-import.sh` on that instance (templates current), `thehive-test-alert.sh --cleanup` (no leftover test alerts), the analyst login ready (never shown on screen), and one dry run of steps 1–6 with n8n and Wazuh. Ask whether n8n runs in `live` or `dry_run`: in `dry_run` step 6 says `not sent (dry_run)` and nothing is blocked.

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
- [ ] README: the templates and fields tables are current (12 templates, 10 fields)
