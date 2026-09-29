# Wazuh owner backlog

Owner: Daniel (@dmelgar1110). Branch `wazuh`. Folders `nodes/core/wazuh/` and `nodes/lab/`. Plan as of 2026-09-29.

Priorities: P1 needed for a working component, P2 should have, P3 nice to have. Contracts: PROJECT.md section 5.

Tick a box (`[x]`) when its "done when" check passes, and commit this file with the work. The interactive version of this list can regenerate it with **Copy as Markdown**.

## Done when (100% functional)

- `soc.sh init core` from a fresh clone reaches a green `healthcheck.sh` with your changes merged.
- `contracts-check.sh --only C1,C2,C8` passes, and C1–C8 pass in `full` after each checkpoint merge.
- Every custom rule and decoder has a test case, and the rule test runner passes.
- Custom rules carry MITRE ATT&CK IDs, and the level policy is agreed with the n8n owner.
- Syslog accepts only known sources; enrollment of real Linux and Windows endpoints is documented and tested.
- Network logs (pfSense, router) and MISP IOCs (CDB lists) produce alerts that reach n8n through C1.
- The README, its local patches table and this backlog are up to date, and each milestone reached `main` through a checkpoint pull request.

## M0 · Setup and baseline check (target: 2026-10-02)

Your machine runs the `core` mode and passes the Wazuh contracts before you change anything.

- [ ] **W0.1** Accept the GitHub invite and check SSH access from WSL · P1
  - Done when: `ssh -T git@github.com` greets @dmelgar1110; `git fetch origin` works.
  - With: Inigo (integrator), if the invite is missing
- [ ] **W0.2** Complete the teammate gate of CHECKLIST.md · P1
  - Done when: Sections 1–5, 7 and 9 checked; `scripts/preflight.sh` passes.
  - Files: `CHECKLIST.md`
- [ ] **W0.3** Bring main into the `wazuh` branch · P1
  - Done when: `git checkout wazuh && git pull --no-rebase --no-edit origin main` without conflicts.
- [ ] **W0.4** Set up topology.env for your machine · P1
  - Done when: `topology.env` copied from the example; `MEM_PROFILE` matches your RAM (`low` on 8 GB); `DEPLOY_MODE=single`.
  - Files: `topology.env`
- [ ] **W0.5** Run `./scripts/soc.sh init core` · P1
  - Done when: Ends with an all-green `healthcheck.sh` (5–15 min the first time; ~19 GB of disk).
- [ ] **W0.6** Verify the baseline you now own · P1, C1, C2, C8
  - Done when: `contracts-check.sh --only C1,C2,C8` passes; `id=$(nodes/lab/trigger.sh) && scripts/wazuh-query.sh --rule 100100 --match "$id"` finds the alert; it shows in Grafana.
- [ ] **W0.7** Read the contracts and the Wazuh chapter · P2
  - Done when: Read PROJECT.md 5, 6.1, 11 and 13, `nodes/core/wazuh/README.md`, CONTRIBUTING.md; run `scripts/ci-checks.sh all` once.
  - Files: `PROJECT.md`, `CONTRIBUTING.md`, `nodes/core/wazuh/README.md`
- [ ] **W0.8** Tell the integrator your RAM and Windows version · P3
  - Done when: Inigo has the answer to PROJECT.md 16, questions 1 and 3.
  - With: Inigo (integrator)

## M1 · Hardening and working tools (target: 2026-10-09)

Close the known gaps before core is exposed on a LAN, and build the tools the later milestones depend on.

- [ ] **W1.1** Restrict syslog sources on 514/udp · P1
  - Done when: `<allowed-ips>` is no longer `0.0.0.0/0`. Because the allowed range differs per machine, write it from an env var (e.g. `WAZUH_SYSLOG_ALLOWED_IPS`) in a new `config/entrypoint-scripts/30-syslog-allowed-ips.sh`. A message from an allowed source produces an alert; one from another source does not.
  - Files: `nodes/core/wazuh/config/ossec.conf`, `nodes/core/wazuh/config/entrypoint-scripts/`
  - With: Inigo: add the variable to `nodes/core/.env.example` and `render-env.sh` (shared files)
- [ ] **W1.2** Remove upstream placeholders from ossec.conf · P2, C1
  - Done when: The cluster block (disabled, but it carries upstream's public default `<key>`) and the `smtp.example` email values are removed or neutralised; `wazuh-analysisd -t` shows no errors; C1 still passes.
  - Files: `nodes/core/wazuh/config/ossec.conf`
- [ ] **W1.3** Define the rule ID plan and the rule file layout · P1
  - Done when: README lists ID ranges inside 100000–120999 (e.g. 1001xx tests, 1002xx–1009xx Linux, 101xxx pfSense, 102xxx router, 103xxx MISP lists, 109xxx tuning). One file per source, named for good from the start, since removing a file later needs the manual `rm` procedure.
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/README.md`
- [ ] **W1.4** Build a rule test runner · P1
  - Done when: `nodes/core/wazuh/tests/` holds sample log lines with the expected rule ID and level; `tests/run.sh` sends each one through the manager's logtest (`wazuh-logtest` in the container, or the API `PUT /logtest`) and prints one PASS/FAIL line per case with a non-zero exit on failure; `shellcheck` clean.
  - Files: `nodes/core/wazuh/tests/`
- [ ] **W1.5** Add attack scenarios to the lab trigger · P1, C1
  - Done when: `nodes/lab/trigger.sh --scenario <name>` writes realistic lines, for example `ssh-bruteforce` (enough `sshd` failures for built-in rule 5763), `ssh-success-after-fail`, `sudo-fail`, `new-user`, `ioc-ip` (seed IOC 203.0.113.66). The default without `--scenario` stays the C1 test event.
  - Files: `nodes/lab/trigger.sh`
  - With: Tell Inigo and Jesus: they get realistic data for playbooks and dashboards

## M2 · Detection content v1 (target: 2026-10-23)

The first real detections, tuned and mapped, merged at checkpoint 1 (milestone tag `v1.1-detections`).

- [ ] **W2.1** Write the alert level policy and agree the forwarding threshold · P1, C1
  - Done when: README table: what levels 0–15 mean in ASOX, and which levels reach n8n. `WAZUH_ALERT_MIN_LEVEL` agreed with the n8n owner (default 7).
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo (n8n owner)
- [ ] **W2.2** Linux authentication detections · P1
  - Done when: Rules (or checks that built-ins already fire) for SSH brute force, a successful login after failures (correlation), sudo failures, new user or group, direct root login. Each has test cases in the runner and a lab scenario.
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/tests/`
- [ ] **W2.3** Map every custom rule to MITRE ATT&CK · P1
  - Done when: Each custom rule has `<mitre><id>T…</id></mitre>`; `wazuh-query.sh -j` shows `rule.mitre.id` on the alerts.
  - Files: `nodes/core/wazuh/rules/`
- [ ] **W2.4** Tune false positives from the lab · P2, C1
  - Done when: After 24–48 h of lab data, the noisiest rules at level 7+ are listed (aggregate by `rule.id`), and overrides with a reason per rule live in the tuning file. Alerts forwarded to n8n per hour drop; before/after numbers in the pull request.
  - Files: `nodes/core/wazuh/rules/`
- [ ] **W2.5** Document the alert fields playbooks can rely on · P1, C1
  - Done when: README section listing the fields in the C1 payload (`id`, `timestamp`, `rule.id/level/description/groups/mitre`, `agent.id/name/ip`, `data.srcip/srcuser`, `full_log`, `location`) with an example alert. Documenting is not a contract change; changing the payload is.
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo (n8n owner)
- [ ] **W2.6** Checkpoint 1 pull request · P1, C1, C2, C8
  - Done when: `git pull --no-rebase --no-edit origin main`, `healthcheck.sh` green, `contracts-check.sh --only C1,C2,C8` passes, `ci-checks.sh all` passes, pull request `wazuh` → `main` opened and merged by the integrator.
  - With: Inigo (review and merge)

## M3 · Network sources: pfSense and routers (target: 2026-11-06)

Syslog from network devices is decoded and classified, ready for the real devices of Phase 2.

- [ ] **W3.1** Collect sample logs · P1
  - Done when: Sanitized samples in `tests/samples/`: pfSense `filterlog`, pfSense web GUI and SSH logins, configuration changes, and the router's logs. Router vendor and model confirmed with the team.
  - Files: `nodes/core/wazuh/tests/samples/`
  - With: Team: which router and pfSense version
- [ ] **W3.2** Check built-in coverage, then write decoders for the gaps · P1
  - Done when: Every sample run through logtest; the result of the built-in ruleset noted; custom decoders only where fields are missing (`srcip`, `dstip`, `dstport`, `action`, `protocol`).
  - Files: `nodes/core/wazuh/decoders/`
- [ ] **W3.3** pfSense rules · P1
  - Done when: Port scan (many blocked ports from one source, frequency rule), bursts of blocked connections, failed GUI logins, configuration changes. Test cases and MITRE IDs.
  - Files: `nodes/core/wazuh/rules/`
- [ ] **W3.4** Router rules · P2
  - Done when: Login failures, interface or configuration changes, and whatever the samples show matters. Test cases and MITRE IDs.
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/decoders/`
- [ ] **W3.5** End-to-end syslog test · P1, C1
  - Done when: A sample sent over UDP to the manager's 514 (e.g. a `--scenario pfsense-scan` in trigger.sh that sends from the lab container) is decoded, indexed, and above the threshold forwarded to n8n. The lab network is in the allowed sources from W1.1.
  - Files: `nodes/lab/trigger.sh`
- [ ] **W3.6** Hand the new rule groups to Grafana · P3, C8
  - Done when: Jesus has the rule groups and fields for network panels.
  - With: Jesus (Grafana owner)

## M4 · Agents and endpoints (target: 2026-11-20)

Real endpoints can enroll into groups with policies that fit them.

- [ ] **W4.1** Agent groups as code · P1
  - Done when: Groups `linux-servers`, `windows-desktops`, `network-sensors` with their `agent.conf` in the repo, mounted from `compose.yml` and copied into `etc/shared/<group>/` at start (like the rules). Groups created at start if missing.
  - Files: `nodes/core/wazuh/groups/`, `nodes/core/wazuh/compose.yml`, `nodes/core/wazuh/config/entrypoint-scripts/`
- [ ] **W4.2** Policies per group · P1
  - Done when: FIM paths (Linux `/etc`, binaries; Windows System32 and Run registry keys), log collection (journald / auth.log; Windows Security and Sysmon channels), SCA per OS.
  - Files: `nodes/core/wazuh/groups/`
- [ ] **W4.3** Lab agent joins `linux-servers` · P2, C1
  - Done when: `nodes/lab/entrypoint.sh` enrolls with the group; `agent_groups -l` shows it; C1 still passes after `soc.sh reset lab` and `up`.
  - Files: `nodes/lab/entrypoint.sh`
- [ ] **W4.4** Enrollment guide for real endpoints · P1
  - Done when: `nodes/core/wazuh/ENROLLMENT.md`: Linux (apt) and Windows (MSI) with `WAZUH_MANAGER`, `WAZUH_REGISTRATION_PASSWORD` and `WAZUH_AGENT_GROUP`; agent version equal to the manager (4.14.8); ports 1514/1515; what distributed mode needs; removing an old registration.
  - Files: `nodes/core/wazuh/ENROLLMENT.md`
- [ ] **W4.5** Enroll your own Windows host · P1
  - Done when: Following the guide exactly: the Windows agent is `active` in `windows-desktops`, and a failed Windows logon shows up as an alert. With mirrored networking the ports on 127.0.0.1 are reachable from Windows.
- [ ] **W4.6** Alert on disconnected agents · P2
  - Done when: `agents_disconnection_alert_time` set (it is 0 now); stopping the lab agent produces an alert at the agreed level.
  - Files: `nodes/core/wazuh/config/ossec.conf`

## M5 · Threat intel: MISP IOCs as CDB lists (target: 2026-12-04)

Wazuh flags events that match IOCs kept in MISP (joint work with the Cortex + MISP owner).

- [ ] **W5.1** Agree the design as a new contract · P1
  - Done when: With Diego: which attributes (IPs, domains, MD5/SHA-256), which events (published, `to_ids`, a tag), refresh cadence, a read-only MISP key for core (a new `__from:intel__` value). Written up and sent to Inigo, who adds the contract to PROJECT.md 5 and the shared env files.
  - With: Diego (Cortex + MISP) and Inigo (shared files)
- [ ] **W5.2** MISP to CDB export script · P1
  - Done when: `nodes/core/wazuh/lists/misp-sync.sh` writes `misp-ip`, `misp-domain`, `misp-hash` in CDB `key:value` format; the generated lists are git-ignored (IOCs are data); PASS/FAIL output; `shellcheck` clean.
  - Files: `nodes/core/wazuh/lists/`
- [ ] **W5.3** Load the lists in the manager · P1
  - Done when: Lists mounted and copied at start, declared as `<list>` in ossec.conf; a list update plus a manager restart applies it.
  - Files: `nodes/core/wazuh/config/ossec.conf`, `nodes/core/wazuh/compose.yml`
- [ ] **W5.4** IOC match rules · P1, C1
  - Done when: Rules with `<list field="srcip" lookup="address_match_key">` (and dstip, domains, FIM hashes). The seed IOC 203.0.113.66 in a lab event fires the rule at level 12 and reaches n8n through C1.
  - Files: `nodes/core/wazuh/rules/`
- [ ] **W5.5** Schedule the sync and measure memory · P2
  - Done when: How and where the sync runs is decided and documented; `scripts/mem-report.sh` shows the manager still fits `WAZUH_MANAGER_MEM` (700m) with the lists loaded.
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo, if a limit must change

## M6 · Phase 2 preparation (target: when Phase 2 opens)

Designs ready for response actions (C9) and Snort, so Phase 2 starts from agreed plans.

- [ ] **W6.1** Design C9 with the n8n owner · P2, C2, C9
  - Done when: Allowed commands (`firewall-drop`, `host-deny`, `disable-account`), timeouts, a whitelist that protects the SOC's own hosts, and the exact permissions to add to `n8n-api`. Agreed and handed to Inigo (role in `scripts/lib/wazuh.sh`, check in `contracts-check.sh`).
  - With: Inigo (n8n owner and integrator)
- [ ] **W6.2** Active response in the lab · P3, C9
  - Done when: `<active-response>` blocks prepared; the lab image can run `firewall-drop` (iptables, NET_ADMIN); a manual API call blocks and then unblocks a test IP.
  - Files: `nodes/core/wazuh/config/ossec.conf`, `nodes/lab/Dockerfile`, `nodes/lab/docker-compose.yml`
- [ ] **W6.3** Snort ingestion design · P3
  - Done when: Snort sensor with a Wazuh agent in `network-sensors` (or syslog to 514); sample Snort alerts decoded and classified in the test runner.
  - Files: `nodes/core/wazuh/tests/samples/`

## OPS · Every session and every checkpoint (target: ongoing)

Habits that keep your work safe and mergeable.

- [ ] **WO.1** Push at the end of every work session · P1
  - Done when: `git add -A && git commit -m "…" && git push` on `wazuh`; only your folders changed (`git diff --stat origin/main`).
- [ ] **WO.2** Open a checkpoint pull request about every two weeks · P1
  - Done when: Pull main, re-test, open the pull request; mention any `rm` a teammate must run for deleted rule files.
  - With: Inigo
- [ ] **WO.3** Keep the README current · P2
  - Done when: Backlog, contracts table and the local patches table reflect what you changed.
  - Files: `nodes/core/wazuh/README.md`
- [ ] **WO.4** Raise the Wazuh items in the integrator's backlog · P2
  - Done when: Asked Inigo about excluding the vulnerability feed (~9.5 GB) from core backups and about the lab agent's brief `pending` after `soc.sh up` (docs/handoff.md). Offer to test a core restore.
  - With: Inigo (integrator)
- [ ] **WO.5** Re-check local patches on any Wazuh upgrade · P3, C8
  - Done when: Each row of the README's local patches table re-checked; Wazuh 5 renames the alert indices, which affects Grafana (Jesus) and `grafana-ro`.
  - Files: `nodes/core/wazuh/README.md`
  - With: Jesus, Inigo
