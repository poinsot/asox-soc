# Wazuh demo: the attack, step by step (WD.5)

**Owner:** Daniel (@dmelgar1110). **For:** whoever presents the Wazuh part of the ASOX demo.
**Runs with:** `nodes/core/wazuh/tests/demo.sh`. It runs the steps, lists each step's alerts, and waits for Enter.
**Length:** about 10 minutes when presented, 4 minutes with `--auto`.

The story: an attacker scans the lab, breaks into an SSH account, adds a backdoor user, plants persistence, attacks a web server, and finally comes from an address MISP already knows. Each step is detected by a different source, and every alert at level 7 and above reaches n8n.

## Before the demo

**The day before**
1. `git pull` on the demo machine, then `scripts/soc.sh up core` and `scripts/soc.sh up intel`. MISP is only needed for step 7; on a `low` machine, start it last and only if RAM allows.
2. Rehearse once: `nodes/core/wazuh/tests/demo.sh --auto`. Every step should list alerts.

**30 minutes before**
1. `scripts/healthcheck.sh`: everything `PASS`.
2. Don't run `e2e.sh` or `demo.sh` in the last 5 minutes. The brute-force rules (5763, 5712, 31152) stay quiet for 60–120 s after they fire, and step 3 would show nothing.
3. Open three browser tabs (`scripts/soc.sh info core` prints the URLs and logins):
   - Grafana: **SOC Status**, time range "Last 15 minutes", refresh 10 s;
   - Grafana: **Attack Scenarios**;
   - n8n: workflow `recv-wazuh-alert`, **Executions** tab.
4. Open a terminal at the repo root with a large font.

**Fallbacks**
- **No internet:** nothing in `demo.sh` needs it. `ids-test` does, and is left out on purpose.
- **MISP not running:** step 7 is skipped by itself. Show `docs/EVIDENCE.md` (C14) instead.
- **A step shows no alerts:** wait 10 s and look in Grafana; indexing can lag. Then go on with `--from <next step>`.
- **Nothing works:** the screenshots and outputs in `docs/EVIDENCE.md` (`evidence/2026-10-10/`, `evidence/2026-10-19/`).

## The steps

Start with `nodes/core/wazuh/tests/demo.sh`. Each step begins with the attack-start marker (rule 100101). It is the red mark in Grafana's Attack Scenarios dashboard, and the gap between that mark and the alert is the detection time (MTTD).

| Step | What happens | Detected by | Alerts (level) | What to show |
|---|---|---|---|---|
| 1 | Recon: an nmap SYN scan of the lab host | Suricata (network IDS) on the lab agent's traffic, `eve.json` → Wazuh | **101010** (10, T1046) | SOC Status → Top rules; n8n → a new execution |
| 2 | The same kind of scan hits the firewall | OPNsense syslog to the manager's 514/udp | **103000** (10, T1046), from 203.0.113.77 | Top source IPs. "Same detection, different source: the firewall's own log" |
| 3 | SSH brute force, then a successful login | Linux auth log (agent) | 5763 (10), then **40112** (12, critical) | Attack Scenarios → Login after failures. "Ten failures, then a success: likely a stolen password" |
| 4 | The attacker adds `svc-backup` and puts it in `sudo` | Linux auth log | 5901 / 5902 (8), **100211** (10); often **40501** (15): "attacks, then a user added" | Critical (24h) goes up; Top targeted users |
| 5 | Persistence: a sudoers file, an SSH key for root, a cron job | Real-time file integrity monitoring (FIM) | **100300**, **100301**, **100302** (10), with MITRE IDs | File changes (FIM), Most changed files. "Real files changed on the host, not a log line" |
| 6 | SQL injection against a web server | Apache access log, Wazuh's `web-accesslog` decoder | 31103 (7) for each request, **31152** (10) after 8 | Recent alerts: open one and show `data.srcip` and `data.url` |
| 7 | A login attempt from an address in MISP | Threat intel: MISP IOCs synced into Wazuh lists (C14) | 5712 (10) and **108000** (12) | Attack Scenarios → IOC IP (MISP). "Wazuh knew the address was malicious from MISP, before any analyst looked" |

Rules in bold are ASOX's own, or the built-ins the story relies on. All of them are in the README's detection catalog.

**The closing line:** in n8n, every alert of level 7 or higher became an execution of `recv-wazuh-alert` (contract C1). From there n8n enriches it and creates the TheHive alert (the next part of the demo).

## Points that usually come up

- **Why levels matter:** 7 and above goes to n8n; 12 and above is critical, and is reserved for precise detections (README "Alert levels").
- **False positives:** 21 hours of lab traffic produced none at level 7 or above (W2.4). The noisy built-ins are tuned in `rules/1090-tuning.xml`, each with its reason.
- **Real devices:** the lab sends OPNsense lines as real syslog. A real firewall or sensor is enrolled the same way (`ENROLLMENT.md`), and syslog is only accepted from the manager's own networks or listed devices (W1.1).
- **Is this tested?** `tests/run.sh` (rules, 63 cases) and `tests/e2e.sh` (13 scenarios, through to n8n) run on every change; see `docs/EVIDENCE.md`.
