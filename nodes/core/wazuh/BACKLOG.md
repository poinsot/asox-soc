# Wazuh owner backlog

Owner: Daniel (@dmelgar1110). Branch `wazuh`. Folders `nodes/core/wazuh/` and `nodes/lab/`. Plan as of 2026-10-01.

**Delivery: 2026-12-01.** Feature freeze 2026-11-24. Priorities: P1 is the delivery, P2 should have, P3 nice to have; if behind, drop P3 first, then P2. M7 is after the delivery. Contracts: PROJECT.md section 5. X-, R- and D- references: `docs/integration-backlog.md` and PROJECT.md section 15. Task IDs are cited by other owners: never renumber, only append.

Tick a box (`[x]`) when its "done when" check passes, and commit this file with the work. The interactive version of this list can regenerate it with **Copy as Markdown**.

## Done when (100% functional)

- `soc.sh init core` from a fresh clone reaches a green `healthcheck.sh` with your changes merged.
- `contracts-check.sh --only C1,C2,C8` passes, and C1–C8 pass in `full` after each checkpoint merge.
- Every custom rule and decoder has a test case, and the rule test runner passes.
- Custom rules carry MITRE ATT&CK IDs; levels follow the shared cut-offs (0–6 low, 7–9 medium, 10–11 high, 12+ critical) agreed with n8n, TheHive and Grafana.
- Your rule groups and rule IDs are the routing key n8n and TheHive use (X-04), and the alert fields are documented (X-01).
- Syslog accepts only known sources; enrollment of real Linux and Windows endpoints is documented and tested.
- Suricata IDS alerts, pfSense logs and MISP IOCs (C14) produce alerts that reach n8n through C1, and lab scenarios mark their start for Grafana's MTTD (X-32).
- Your acknowledgements of C9, C11, C12 and C13 are recorded in `docs/integration-backlog.md`.
- The README, its local patches table and this backlog are up to date, and each milestone reached `main` through a checkpoint pull request.

## M0 · Setup and baseline check (target: 2026-10-02)

Your machine runs the `core` mode and passes the Wazuh contracts before you change anything.

- [x] **W0.1** Accept the GitHub invite and check SSH access from WSL · P1
  - Done when: `ssh -T git@github.com` greets @dmelgar1110; `git fetch origin` works.
  - With: Inigo (integrator), if the invite is missing
- [x] **W0.2** Complete the teammate gate of CHECKLIST.md · P1
  - Done when: Sections 1–5, 7 and 9 checked; `scripts/preflight.sh` passes.
  - Files: `CHECKLIST.md`
- [x] **W0.3** Bring main into the `wazuh` branch · P1
  - Done when: `git checkout wazuh && git pull --no-rebase --no-edit origin main` without conflicts.
- [x] **W0.4** Set up topology.env for your machine · P1
  - Done when: `topology.env` copied from the example; `MEM_PROFILE` matches your RAM (`low` on 8 GB); `DEPLOY_MODE=single`.
  - Files: `topology.env`
- [x] **W0.5** Run `./scripts/soc.sh init core` · P1
  - Done when: Ends with an all-green `healthcheck.sh` (5–15 min the first time; ~19 GB of disk).
- [x] **W0.6** Verify the baseline you now own · P1, C1, C2, C8
  - Done when: `contracts-check.sh --only C1,C2,C8` passes; `id=$(nodes/lab/trigger.sh) && scripts/wazuh-query.sh --rule 100100 --match "$id"` finds the alert; it shows in Grafana.
- [x] **W0.7** Read the contracts and the Wazuh chapter · P2
  - Done when: Read PROJECT.md 5, 6.1, 11 and 13, `nodes/core/wazuh/README.md`, CONTRIBUTING.md; run `scripts/ci-checks.sh all` once.
  - Files: `PROJECT.md`, `CONTRIBUTING.md`, `nodes/core/wazuh/README.md`
- [x] **W0.8** Tell the integrator your RAM and Windows version · P3
  - Done when: Inigo has the answer to PROJECT.md 16, questions 1 and 3.
  - With: Inigo (integrator)
- [x] **W0.9** Re-sync your machine after the n8n merge (2026-10-01) · P1
  - Done when: `./scripts/render-env.sh` (adds `THEHIVE_ENABLED`, `false` on your core-only machine, A79), `./scripts/soc.sh up core`, `./scripts/bootstrap.sh core` (recreates n8n with the new env), `./scripts/n8n-import.sh` (bootstrap never overwrites existing workflows, so the new `pb-generic` and `lib-` workflows arrive only this way). Then `contracts-check.sh --only C1,C2,C8` passes; C1 now prints an INFO line about the TheHive test-alert cleanup, which is expected without `cases`.
  - Refs: R-18, A79, R-02

## M1 · Hardening and working tools (target: 2026-10-09)

Close the known gaps before core is exposed on a LAN, and build the tools the later milestones depend on.

- [x] **W1.1** Restrict syslog sources on 514/udp · P1
  - Done when: After W1.9: `<allowed-ips>` is no longer `0.0.0.0/0`. Because the allowed range differs per machine, write it from an env var (e.g. `WAZUH_SYSLOG_ALLOWED_IPS`) in a new `config/entrypoint-scripts/30-syslog-allowed-ips.sh`. A message from an allowed source produces an alert; one from another source does not. The entrypoint script splits the comma-separated list from R-06.
  - Files: `nodes/core/wazuh/config/ossec.conf`, `nodes/core/wazuh/config/entrypoint-scripts/`
  - With: Inigo: R-06 (the variable in `nodes/core/.env.example` and `render-env.sh`), needed by 2026-10-09
  - Refs: R-06
- [x] **W1.2** Remove upstream placeholders from ossec.conf · P2, C1
  - Done when: The cluster block (disabled, but it carries upstream's public default `<key>`) and the `smtp.example` email values are removed or neutralised; `wazuh-analysisd -t` shows no errors; C1 still passes.
  - Files: `nodes/core/wazuh/config/ossec.conf`
- [x] **W1.3** Define the rule ID plan, rule groups and file layout · P1
  - Done when: README lists ID ranges inside 100000–120999 (e.g. 1001xx tests, 1002xx–1009xx Linux, 101xxx Suricata, 104xxx pfSense, 102xxx router, 103xxx MISP lists, 109xxx tuning). One file per source, named for good from the start, since removing a file later needs the manual `rm` procedure. The rule groups double as the routing key for n8n's router (N8N-1.3, D-N2) and TheHive's `caseTemplate` routing (T2.6, ALERT-FORMAT.md §3): the three of you agree on them by checkpoint 1 (2026-10-20).
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/README.md`
  - With: Inigo (router), Park (case templates)
  - Refs: X-04, D-N2
- [x] **W1.4** Build a rule test runner · P1
  - Done when: `nodes/core/wazuh/tests/` holds sample log lines with the expected rule ID and level; `tests/run.sh` sends each one through the manager's logtest (`wazuh-logtest` in the container, or the API `PUT /logtest`) and prints one PASS/FAIL line per case with a non-zero exit on failure; `shellcheck` clean.
  - Files: `nodes/core/wazuh/tests/`
- [x] **W1.5** Add attack scenarios to the lab trigger · P1, C1
  - Done when: `nodes/lab/trigger.sh --scenario <name>` writes realistic lines, for example `ssh-bruteforce` (enough `sshd` failures for built-in rule 5763), `ssh-success-after-fail`, `sudo-fail`, `new-user`, `ioc-ip` (seed IOC 203.0.113.66). The default without `--scenario` stays the C1 test event. n8n has no fixtures for sshd, sudo, FIM, rootcheck or rules with `rule.mitre` until these exist; tell Inigo when they land so he captures them in `nodes/core/n8n/fixtures/` (`replay.sh`). Every scenario uses attacker IPs from documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`), and `ioc-ip` uses exactly the MISP seed IOC `203.0.113.66`: the lab's own `172.18.x.x` addresses are internal, so n8n would never send them to Cortex or MISP (memo item 7).
  - Files: `nodes/lab/trigger.sh`
  - With: Inigo (fixtures for playbooks), Park (TheHive's end-to-end test uses `ssh-bruteforce`), Jesus (dashboard data)
  - Refs: X-05
- [x] **W1.6** Attack-start marker for lab scenarios · P1, C11
  - Done when: Every `trigger.sh --scenario` first writes `ASOX_ATTACK_START scenario=<name> id=<uuid>`, and the scenario's own events carry the same id. A dedicated low-noise rule (ID in the 1001xx test range, level agreed with Jesus and Inigo) catches it; Grafana draws it as an annotation. It is C11's `t_attack_start`: without it there is no MTTD.
  - Files: `nodes/lab/trigger.sh`, `nodes/core/wazuh/rules/`
  - With: Jesus (GRAF-2.2, D-G3), Inigo (C11 writer)
  - Refs: X-32
- [x] **W1.7** Answer the contract decisions (by 2026-10-16) · P1, C9, C11, C12, C13
  - Done when: Your answer reaches Inigo for `docs/integration-backlog.md`. C9 (D44): accept the separate `n8n-response` user instead of widening `n8n-api` (W7.1 already updated). C11 (D46): the `asox-metrics` index lives in your indexer; agree a retention and check it fits the indexer on `low` (heap 512 MB, limit 1.15 GB). C12 (D47): noted as rejected. C13 (D48): confirm the field map against real alerts (W2.5); you are the last owner to acknowledge (n8n and Diego have). Then update the README's contracts table: C9 row per D44, and rows for C11, C13 and C14.
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo (integrator)
  - Refs: X-20, X-26, X-27, X-33
- [x] **W1.8** Record C1's "send once, no retries" (X-10) · P3, C1
  - Done when: Inigo answered (memo item 8): n8n accepts C1's send-once behaviour and answers 200 on receipt, so no retries are added. Record it in the README's contracts section: any future retry in `custom-n8n.py` needs the n8n owner's agreement first, because TheHive's duplicate refusal isn't atomic and overlapping copies create two alerts (A78). Also note that `custom-n8n.py` must keep sending valid JSON (`json.dumps`): n8n rejects anything else with HTTP 422 before a workflow runs, so only `integrations.log` would show it.
  - Files: `nodes/core/wazuh/integrations/custom-n8n.py`
  - With: Inigo (n8n owner)
  - Refs: X-10, A78
- [x] **W1.9** Test syslog source IPs, then send Inigo the R-06 spec (by 2026-10-07) · P1
  - Done when: First test which source IP the manager sees for UDP syslog sent to the published port (`${BIND_ADDR}:514:514/udp`): from the WSL host to `127.0.0.1`, from the lab container over `soc-net`, and, if you can, from another machine. Traffic through Docker's userland proxy may show every sender as the bridge gateway (`172.x.0.1`); if so, any `172.16.0.0/12` default lets every source through and W1.1's negative check can't pass. Then reply to Inigo (memo item 10) by 2026-10-07 so R-06 is on `main` by 2026-10-09: format comma-separated IPv4 addresses or CIDRs, no spaces, one `<allowed-ips>` per entry; a default chosen from the test result (Inigo proposes `172.16.0.0/12`; the narrower alternative is `127.0.0.1` plus the `soc-net` subnet); per machine, the optional `SYSLOG_ALLOWED_IPS` in `topology.env`. Record the test in `nodes/core/wazuh/docs/n8n-requests-2026-09-30.md`.
  - With: Inigo (integrator)
  - Refs: R-06
- [x] **W1.10** Answer n8n's memo of 2026-09-30 · P1, C1, C14
  - Done when: Every item in `nodes/core/wazuh/docs/n8n-requests-2026-09-30.md` has a status and an answer in its reply column, sent to Inigo: items 6, 7, 8, 9 and 10 by their dates (10 by 2026-10-07, 9 by 2026-10-16), the rest at checkpoint 1 (2026-10-20). The tasks that deliver each item are listed there.
  - Files: `nodes/core/wazuh/docs/n8n-requests-2026-09-30.md`
  - With: Inigo (n8n owner)
  - Refs: X-01, X-05, X-09, X-10, X-24, X-32, R-06

## M2 · Detection content v1 (target: 2026-10-20)

The first real detections, tuned and mapped, merged at checkpoint 1 (milestone tag `v1.1-detections`).

- [x] **W2.1** Write the alert level policy and agree the forwarding threshold · P1, C1
  - Done when: README table: what levels 0–15 mean in ASOX, with the shared cut-offs (0–6 low, 7–9 medium, 10–11 high, 12–15 critical) that TheHive's severity mapping (ALERT-FORMAT.md §2) and Grafana's buckets (D-G4) already use; which levels reach n8n. `WAZUH_ALERT_MIN_LEVEL` agreed with the n8n owner (default 7). Level 12+ is Critical, and D-N4 lets n8n auto-promote Critical alerts of named playbooks straight to TheHive cases: reserve 12+ for detections that deserve a case without an analyst looking first.
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo (n8n), Park (ALERT-FORMAT.md §2), Jesus (D-G4)
  - Refs: X-09, D-N4, D-G4
- [x] **W2.2** Linux authentication detections · P1
  - Done when: Rules (or checks that built-ins already fire) for SSH brute force, a successful login after failures (correlation), sudo failures, new user or group, direct root login. Each has test cases in the runner and a lab scenario. Decoders use Wazuh's standard field names (`srcip`, `dstip`, `srcuser`, `dstuser`), which n8n, C13 and TheHive rely on (memo item 3).
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/tests/`
  - With: Inigo (`pb-ssh-bruteforce` needs the success-after-failures rule, N8N-4.2), Park (a template per detection, T3.5)
- [x] **W2.3** Map every custom rule to MITRE ATT&CK · P1
  - Done when: Each custom rule has `<mitre><id>T…</id></mitre>`; `wazuh-query.sh -j` shows `rule.mitre.id` on the alerts. Tell n8n the convention (its WAZUH-FIELDS.md question 2): custom rules carry `rule.mitre.id`; built-in SCA rules only have `rule.mitre_techniques`, so n8n reads `rule.mitre.id` first and falls back to the other.
  - Files: `nodes/core/wazuh/rules/`
  - With: Inigo (n8n)
- [x] **W2.4** Tune false positives from the lab · P2, C1
  - Done when: After 24–48 h of lab data, the noisiest rules at level 7+ are listed (aggregate by `rule.id`), and overrides with a reason per rule live in the tuning file. Alerts forwarded to n8n per hour drop; before/after numbers in the pull request. A second pass follows in W5.7 with TheHive's false-positive report.
  - Files: `nodes/core/wazuh/rules/`
  - Refs: X-11
- [x] **W2.5** Agree n8n's alert-field draft, then write the detection catalog and C13's field map · P1, C1, C13
  - Done when: (1) Review `nodes/core/n8n/docs/WAZUH-FIELDS.md`, n8n's draft of the C1 fields verified against real alerts, instead of writing the list from scratch: answer its "To agree with the Wazuh owner" questions and correct anything wrong, so Inigo can mark it agreed. Promise stable types: `id` and `rule.id` as strings, `rule.level` as a number, `rule.groups` as an array, the same `timestamp` format (memo item 1) (the file is n8n's; your README links to it). Fields marked "not seen yet" (`data.*`, `syscheck.*`, `rule.mitre.*`) get confirmed as your scenarios produce them. (2) README: a detection catalog, one row per custom rule (ID, group, level, MITRE ID, lab scenario), used by n8n's router, TheHive's templates and Grafana's panels. (3) C13's field map (PROJECT.md 5) checked against real alerts (`data.srcip`/`data.dstip`, Suricata's `data.src_ip`/`data.dest_ip`, `agent.ip`, `agent.name`, `data.srcuser`/`dstuser`, `syscheck.*_after`); Diego asked to keep it stable. Documenting is not a contract change; changing the payload is.
  - Files: `nodes/core/wazuh/README.md`, `nodes/core/n8n/docs/WAZUH-FIELDS.md (review only)`
  - With: Inigo (n8n), Park (templates), Jesus (panels), Diego (C13 analyzer)
  - Refs: X-01, X-26
- [x] **W2.6** Checkpoint 1 pull request (by 2026-10-20) · P1, C1, C2, C8
  - Done when: `git pull --no-rebase --no-edit origin main`, `healthcheck.sh` green, `contracts-check.sh --only C1,C2,C8` passes, `ci-checks.sh all` passes, pull request `wazuh` → `main` opened and merged by the integrator. The first slice of `v1.1-detections` (alert → enriched TheHive alert) depends on it, together with TheHive's T2.7.
  - **2026-10-19:** `main` merged into `wazuh`; `healthcheck.sh` all PASS; `contracts-check.sh --only C1,C2,C8` passes; `ci-checks.sh all` passes; rule tests 63/63, `e2e.sh` 33/34 (`EVIDENCE.md`). Left: Daniel opens the PR, Inigo merges.
  - **Done:** merged with PRs #31 (2026-10-20) and #38 (2026-10-22).
  - With: Inigo (review and merge)
- [x] **W2.7** Answer X-09: should SCA alerts reach n8n? · P1, C1
  - Done when: Decided with Inigo by 2026-10-20 and written in the README. Each agent start sends ~130 level-7 SCA alerts (rules 19007, 19004), and n8n excludes group `sca` only temporarily. Inigo's options (memo item 6): raise their level threshold, exclude the `sca` group from `custom-n8n`, or let n8n aggregate them (N8N-1.4). Recommendation: fix it at the source with overwrite rules in your tuning file that lower 19007/19004 below `WAZUH_ALERT_MIN_LEVEL` (e.g. level 5). They stay in the indexer for Grafana's compliance panels, never flood n8n or TheHive, and Inigo can then remove the temporary exclusion from `lib-config`. Also answer TheHive's question whether SCA needs a compliance template (ALERT-TO-THEHIVE.md, question 4).
  - Files: `nodes/core/wazuh/rules/`
  - With: Inigo (n8n), Park (template question), Jesus (compliance panels)
  - Refs: X-09

## M3 · Network IDS: Suricata (target: 2026-11-03)

A Suricata sensor watches the lab traffic and its alerts arrive in Wazuh through an agent, then reach Grafana and n8n like any other alert. Chosen over Snort: EVE JSON output that Wazuh reads natively, built-in Wazuh rules for Suricata, free ET Open rules with no account, multi-threaded.

- [x] **W3.1** Record the decision: Suricata instead of Snort · P1
  - Done when: Done on `main` 2026-09-30 as D49 (PROJECT.md sections 1, 2, 6.1, 13). The pinned tag `jasonish/suricata:8.0.7` is in `docs/decisions.md` (images table and A96, recorded by the integrator with R-07).
  - With: Inigo (integrator), team
  - Refs: D49, X-34
- [x] **W3.2** Suricata container in the lab node · P1
  - Done when: Service `suricata` in `nodes/lab/docker-compose.yml`: pinned image, `network_mode: service:lab-agent` so it sees the lab agent's traffic, capabilities `NET_ADMIN`, `NET_RAW`, `SYS_NICE`, ET Open rules loaded by `suricata-update`, `healthcheck`, `mem_limit` = `memswap_limit`, `restart: unless-stopped`. `soc.sh up core` starts it and `healthcheck.sh` stays green.
  - Files: `nodes/lab/docker-compose.yml`, `nodes/lab/suricata/`
  - With: Inigo: R-07 (memory variable in `nodes/lab/.env.example` and `render-env.sh`)
  - Refs: R-07
- [x] **W3.3** EVE JSON into Wazuh · P1, C1
  - Done when: Suricata writes `eve.json` (alert events only, to keep the volume low) to a volume shared with the lab agent, which reads it with `<localfile><log_format>json</log_format>`. Built-in rule 86601 ("Suricata: Alert - …") fires and the alert is in the indexer with `data.alert.signature`, `data.src_ip`, `data.dest_ip`. Keep Suricata's own names (`data.src_ip`, `data.dest_ip`, `data.dest_port`); don't rename them in custom rules or decoders (memo item 3).
  - Files: `nodes/lab/docker-compose.yml`, `nodes/lab/entrypoint.sh`
- [x] **W3.4** Test traffic in the lab trigger · P1
  - Done when: `trigger.sh --scenario ids-test` (a `curl http://testmynids.org/uid/index.html` from the lab agent, ET rule 2100498) and `--scenario ids-scan` (an `nmap` scan against a lab target) produce Suricata alerts in Wazuh within a minute. `curl` and `nmap` added to the lab image.
  - Files: `nodes/lab/trigger.sh`, `nodes/lab/Dockerfile`
- [x] **W3.5** ASOX rules on top of Suricata · P1, C1
  - Done when: Custom rules map Suricata severity to Wazuh levels (severity 1 → 12, 2 → 10, 3 → 6, the mapping TheHive's ALERT-FORMAT.md already cites), add MITRE IDs by category, and silence noisy signatures (e.g. `SURICATA STREAM`) with a reason each. Sample `eve.json` lines in the test runner.
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/tests/`
- [x] **W3.6** Measure memory with Suricata running · P2
  - Done when: `scripts/mem-report.sh` in mode `core` on your profile; Suricata's limit sized with the D40 formula; `core` on `low` still fits a 6 GB WSL allocation.
  - With: Inigo, if a limit changes
  - Refs: R-07, D39
- [ ] **W3.7** Hand the IDS fields to n8n, TheHive and Grafana (by 2026-11-03) *(in progress)* · P2, C1, C8
  - Done when: Inigo (`pb-ids-alert`, N8N-4.4), Park (T3.6, ALERT-FORMAT.md §3, `ids-network-alert` template) and Jesus (GRAF-2.3) have the rule groups (`suricata`, `ids`), rule 86601 and your custom IDs, and the fields `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port`, all in the W2.5 catalog.
  - With: Inigo (n8n), Park (TheHive), Jesus (Grafana)
  - Refs: X-23, X-34

## M4 · Network sources: OPNsense and routers (target: 2026-11-10)

Syslog from network devices is decoded and classified, ready for the real devices of Phase 2.

  - **2026-10-22:** `docs/handoff-ids-fields-w37-2026-10-22.md` (rules and levels, fields confirmed on new alerts, who the attacker is, grouping per source, lab vs physical sensor). Done when the three acknowledge.
- [ ] **W4.1** Collect sample logs *(in progress)* · P1
  - Done when: Sanitized samples in `tests/samples/`: OPNsense `filterlog`, OPNsense web GUI and SSH logins, configuration changes, and the router's logs. Router vendor and model confirmed with the team.
  - Files: `nodes/core/wazuh/tests/samples/`
  - With: Team: which router and pfSense version
  - **2026-10-21:** real OPNsense 26.7 captures (remote syslog, BSD): filterlog, scan, sshd-session, noise; pinned in `tests/cases/1030-opnsense.cases`. Still to capture: web GUI logins, SSH failures, Cisco lines.
- [x] **W4.2** Check built-in coverage, then write decoders for the gaps · P1
  - Done when: Every sample run through logtest; the result of the built-in ruleset noted; custom decoders only where fields are missing (`srcip`, `dstip`, `dstport`, `action`, `protocol`). Decoders use Wazuh's standard field names (`srcip`, `dstip`, `srcuser`, `dstuser`), which n8n, C13 and TheHive rely on (memo item 3).
  - Files: `nodes/core/wazuh/decoders/`
- [x] **W4.3** OPNsense rules · P1
  - Done when: Port scan (many blocked ports from one source, frequency rule), bursts of blocked connections, failed GUI logins, configuration changes. Test cases and MITRE IDs.
  - Files: `nodes/core/wazuh/rules/`
- [x] **W4.4** Router rules · P3
  - **2026-10-21:** Cisco IOS (router Cisco 2900, switch Catalyst 2960): `decoders/1020-cisco.xml` (user, source on logins), `rules/1020-router.xml` (102000 brute force, 102001 device login block, 102010 port security), 4724 lowered to 5; `router-bruteforce` scenario; 10 cases. Documented format; confirm with the real devices (W4.1).
  - Done when: Login failures, interface or configuration changes, and whatever the samples show matters. Test cases and MITRE IDs.
  - Files: `nodes/core/wazuh/rules/`, `nodes/core/wazuh/decoders/`
- [x] **W4.5** End-to-end syslog test · P1, C1
  - Done when: A sample sent over UDP to the manager's 514 (e.g. a `--scenario opnsense-scan` in trigger.sh that sends from the lab container) is decoded, indexed, and above the threshold forwarded to n8n. The lab network is in the allowed sources from W1.1.
  - Files: `nodes/lab/trigger.sh`
- [ ] **W4.6** Hand the OPNsense fields to n8n, TheHive and Grafana (by 2026-11-10) *(in progress)* · P2, C1, C8
  - Done when: The OPNsense rule IDs, groups and fields are in the W2.5 catalog, and Inigo (`pb-ids-alert`'s OPNsense branch), Park (a template for the port scan, T3.5) and Jesus (network panels) know.
  - With: Inigo, Park, Jesus
  - Refs: X-23

## M5 · Agents and endpoints (target: 2026-11-17)

Real endpoints can enroll into groups with policies that fit them.

- [x] **W5.1** Agent groups as code · P1
  - Done when: Groups `linux-servers`, `windows-desktops`, `network-sensors` (the lab agent reading Suricata belongs here) with their `agent.conf` in the repo, mounted from `compose.yml` and copied into `etc/shared/<group>/` at start (like the rules). Groups created at start if missing.
  - Files: `nodes/core/wazuh/groups/`, `nodes/core/wazuh/compose.yml`, `nodes/core/wazuh/config/entrypoint-scripts/`
- [x] **W5.2** Policies per group · P2
  - Done when: FIM paths (Linux `/etc`, binaries; Windows System32 and Run registry keys), log collection (journald / auth.log; Windows Security and Sysmon channels), SCA per OS.
  - Files: `nodes/core/wazuh/groups/`
- [x] **W5.3** Lab agent joins `linux-servers` · P2, C1
  - Done when: `nodes/lab/entrypoint.sh` enrolls with the group; `agent_groups -l` shows it; C1 still passes after `soc.sh reset lab` and `up`.
  - Files: `nodes/lab/entrypoint.sh`
- [x] **W5.4** Enrollment guide for real endpoints · P1
  - Done when: `nodes/core/wazuh/ENROLLMENT.md`: Linux (apt) and Windows (MSI) with `WAZUH_MANAGER`, `WAZUH_REGISTRATION_PASSWORD` and `WAZUH_AGENT_GROUP`; agent version equal to the manager (4.14.8); ports 1514/1515; what distributed mode needs; removing an old registration.
  - Files: `nodes/core/wazuh/ENROLLMENT.md`
  - Refs: D33
- [x] **W5.5** Enroll your own Windows host · P1
  - Done when: Following the guide exactly: the Windows agent is `active` in `windows-desktops`, and a failed Windows logon shows up as an alert. With mirrored networking the ports on 127.0.0.1 are reachable from Windows.
- [x] **W5.6** Alert on disconnected agents · P3
  - Done when: `agents_disconnection_alert_time` set (it is 0 now); stopping the lab agent produces an alert at the agreed level.
  - Files: `nodes/core/wazuh/config/ossec.conf`
- [ ] **W5.7** Second tuning pass from TheHive's false-positive report · P2, C1
  - Done when: Once TheHive's `thehive-fp-report.sh` exists (T4.4, 2026-11-10): rules closed as False positive or Ignored three times or more (ALERT-FORMAT.md R5) are tuned or justified in the tuning file, with the counts in the pull request.
  - Files: `nodes/core/wazuh/rules/`
  - With: Park (T4.4)
  - Refs: X-11

## M6 · Threat intel: MISP IOCs as CDB lists (C14) (target: 2026-11-20)

Wazuh flags events that match IOCs kept in MISP. This is contract C14 (proposed); its design with Diego is the earliest cross-owner deadline of the whole team (2026-10-16).

- [x] **W6.1** Design C14 with Diego (by 2026-10-16) · P1, C14
  - Done when: Written and sent to Inigo for PROJECT.md 5: which attributes (IPs, domains, MD5/SHA-256), which events (published, `to_ids`, a tag), refresh cadence, and who runs the sync. Inigo prefers (a) (memo item 9): if n8n ran it, it would need write access to Wazuh's CDB lists, a new permission and a contract change like C9. Options: (a) a Wazuh-side script with its own read-only MISP key (R-08, a new `__from:intel__` value), or (b) an n8n scheduled workflow reusing C10's key (D45) (R-08 dropped; C10 waits for MISP's warninglist memory fix, R-14). Either way the CDB lists and the rules live in your folder.
  - With: Diego (Cortex + MISP), Inigo (PROJECT.md; R-08 or the n8n side)
  - Refs: X-24, R-08, R-14, D45
- [x] **W6.2** MISP to CDB export · P1, C14
  - Done when: Per the C14 design, either `nodes/core/wazuh/lists/misp-sync.sh` (option a) or Inigo's n8n workflow (option b) writes `misp-ip`, `misp-domain`, `misp-hash` in CDB `key:value` format into your folder; the generated lists are git-ignored (IOCs are data). A script of yours has PASS/FAIL output and is `shellcheck` clean.
  - Files: `nodes/core/wazuh/lists/`
- [x] **W6.3** Load the lists in the manager · P1, C14
  - Done when: Lists mounted and copied at start, declared as `<list>` in ossec.conf; a list update plus a manager restart applies it.
  - Files: `nodes/core/wazuh/config/ossec.conf`, `nodes/core/wazuh/compose.yml`
- [x] **W6.4** IOC match rules · P1, C1, C14
  - Done when: Rules with `<list field="srcip" lookup="address_match_key">` (and dstip, Suricata's `src_ip`/`dest_ip`, domains, FIM hashes). The seed IOC 203.0.113.66 in a lab event fires the rule at level 12 and reaches n8n through C1. Detection only: a match raises an alert, and any blocking stays an n8n playbook (D12).
  - Files: `nodes/core/wazuh/rules/`
  - Refs: D12
- [x] **W6.5** Schedule the sync and measure memory · P2, C14
  - Done when: How and where the sync runs is decided and documented; `scripts/mem-report.sh` shows the manager still fits `WAZUH_MANAGER_MEM` (700m) with the lists loaded.
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo, if a limit must change

## DL · Delivery (target: 2026-12-01)

Everything merged into `main`, tested end to end and ready to show one day early. No new features after the freeze.

- [ ] **WD.1** Feature freeze (2026-11-24) · P1
  - Done when: Every P1 task of M1–M6 is done, or dropped with the integrator's agreement and noted in the README and the integration register. From here on, only fixes.
  - Files: `nodes/core/wazuh/README.md`
  - With: Inigo (integrator)
- [ ] **WD.2** Final checkpoint pull request merged (by 2026-11-26) · P1, C1, C2, C8
  - Done when: `wazuh` → `main` merged; CI green; teammates told about any rule file they must `rm` on their machines.
  - With: Inigo (review and merge)
- [ ] **WD.3** End-to-end run in `full` (by 2026-11-27) · P1, C1, C2, C8
  - Done when: On the 32 GB machine or the shared instance, from `main`: `healthcheck.sh` green, C1–C8 pass, and `trigger.sh --scenario ssh-bruteforce`, `ioc-ip` and `ids-test` each show up in Grafana (with the attack-start annotation), as n8n executions and as TheHive alerts with the right severity and template (TheHive's end-to-end test).
  - With: Inigo (runs `full`), Jesus (Grafana), Park (TheHive)
- [ ] **WD.4** Evidence for the delivery (by 2026-11-30) *(in progress)* · P1
  - Done when: README final; a table of custom rules with level and MITRE ID; test runner output; screenshots of the alerts in Grafana and of an n8n execution; the enrolled Windows agent.
  - Files: `nodes/core/wazuh/README.md`
- [ ] **WD.5** Rehearse the demo (by 2026-11-30) *(in progress)* · P1
  - Done when: A short script that runs start to finish without surprises: attack scenario → Wazuh alert → Grafana → n8n; IOC from MISP → alert; syslog from pfSense → alert; Suricata detection → alert.
  - **2026-10-19:** `tests/demo.sh` (7 steps, `--auto` for a rehearsal, `--from N`) and `DEMO.md` (checklist, talk track, fallbacks). Rehearsed on `low`: steps 1–6 pass; step 7 needs intel. Left: a rehearsal with the team in `full`, after WD.3.
  - With: Team

## M7 · After the delivery (target: after 2026-12-01)

Not part of the 1 December delivery. C9 as decided in D44 (useful once Phase 2 brings real endpoints), Suricata on a dedicated sensor, custom response scripts.

- [ ] **W7.1** Build C9 with the n8n owner (D44) · P3, C2, C9
  - Done when: Separate Wazuh API user and role `n8n-response` (`active-response:command` plus `agent:read`, limited to actionable agent groups, never the SOC's own hosts), created by Inigo in `scripts/lib/wazuh.sh` (R-17); `n8n-api` stays read-only, so C2 still passes. Catalog v1 = built-in `firewall-drop`, `host-deny`, `disable-account`, each with a timeout; Wazuh's `<white_list>` matches n8n's allowlist of protected hosts.
  - With: Inigo (n8n owner and integrator)
  - Refs: X-20, X-21, R-17, D44, D12
- [ ] **W7.2** Active response in the lab · P3, C9
  - Done when: `<active-response>` blocks prepared; the lab image can run `firewall-drop` (iptables, `NET_ADMIN`); C9's check `chk-wazuh-response` passes: `firewall-drop` of `192.0.2.1` on the lab agent with a 60 s timeout succeeds, and a non-AR call as `n8n-response` gets 403.
  - Files: `nodes/core/wazuh/config/ossec.conf`, `nodes/lab/Dockerfile`, `nodes/lab/docker-compose.yml`
  - Refs: X-22
- [ ] **W7.3** Suricata on a dedicated sensor · P3
  - Done when: Guide and test for Suricata plus a Wazuh agent (`network-sensors`) on its own machine, fed by a mirror (SPAN) port of the router, as planned for Phase 2.
  - Files: `nodes/core/wazuh/ENROLLMENT.md`
- [ ] **W7.4** Custom active-response scripts for isolation and file removal · P3, C9
  - Done when: Scripts for host isolation and file removal, so TheHive's `containment-action` values `host-isolated` / `file-removed` stop being manual-only. Adding them to C9's catalog is a contract change with the n8n owner. They run only when an n8n playbook calls them (D12).
  - Files: `nodes/core/wazuh/`
  - With: Inigo (n8n), Park (TheHive)
  - Refs: X-21, D12

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
- [ ] **WO.4** Raise the Wazuh items in the integrator's backlog *(in progress)* · P2
  - Done when: Asked Inigo about excluding the vulnerability feed (~9.5 GB) from core backups and about the lab agent's brief `pending` after `soc.sh up` (docs/handoff.md). Offer to test a core restore.
  - With: Inigo (integrator)
- [ ] **WO.5** Re-check local patches on any Wazuh upgrade · P3, C8
  - Done when: Each row of the README's local patches table re-checked; Wazuh 5 renames the alert indices, which affects Grafana (Jesus) and `grafana-ro`.
  - Files: `nodes/core/wazuh/README.md`
  - With: Jesus, Inigo
- [ ] **WO.6** Keep your task IDs stable and the integration register current · P2
  - Done when: PROJECT.md and `docs/integration-backlog.md` cite your W IDs, so never renumber a task (add new ones at the end). When a task another owner depends on changes status or date, tell Inigo so the register's X row follows; answer your row of section G at each checkpoint.
  - Files: `nodes/core/wazuh/BACKLOG.md`
  - With: Inigo (integrator)
