# n8n payload fixtures (N8N-0.2)

Real payloads as n8n receives them, for building and testing the normalizer, the routers and the playbooks without waiting for live alerts. Nothing in `wazuh/` and `thehive/` is invented: every file there is a Wazuh alert from the lab's indexer or a C1 body recorded by `recv-wazuh-alert`, or a TheHive webhook payload recorded by `recv-thehive-event`. `invalid/` and `synthetic/` hold the only constructed files, each derived from a real one and listed below. Captured on 2026-09-30 from the build instance (Wazuh 4.14.8, TheHive 5.7.6 with a Community license); the scenario alerts on 2026-10-09 (below).

- **Wazuh files** (`wazuh/<rule-id>-<short-name>.json`) are the alert JSON, the same object `custom-n8n` POSTs to `/webhook/wazuh-alert` (C1). Files read from the indexer carry two extra fields the indexer adds (`@timestamp`, `input.type`); `100100-asox-test-c1.json` is the exact C1 body of the same alert, for comparison.
- **TheHive files** (`thehive/NN-<object>-<action>-<detail>.json`) are the request body TheHive POSTs to `/webhook/thehive-event` (C4, webhook version 1). They are numbered in the order they happened, as one flow on one alert and its case.
- **Headers are not kept.** In n8n, a webhook item is `{headers, params, query, body, webhookUrl, executionMode}` and the payload is under `.body`. The recorded headers included the webhook token (`x-asox-token` for C1, `authorization` for C4), so only the body is saved. The other headers TheHive sends: `accept`, `content-type`, `content-length`, `context-tags`, `host`, `user-agent`, `x-b3-traceid`, `x-b3-spanid`, `x-b3-parentspanid`.
- Payloads contain lab data only (agent `lab-agent`, its Docker IP, the lab accounts `n8n@asox.local` and `analyst@asox.local`), no credentials.

## Wazuh alerts

| File | Rule | Level | Groups | Sent by C1? | How obtained | Alert time (UTC) |
|---|---|---|---|---|---|---|
| `wazuh/100100-asox-test.json` | 100100 ASOX test rule (`nodes/lab/trigger.sh`) | 10 | `asox`, `test` | yes | `scripts/wazuh-query.sh -r 100100 -n 1 -s 30d -j` | 2026-09-26 22:20:41 |
| `wazuh/100100-asox-test-c1.json` | same alert, exact C1 body | 10 | `asox`, `test` | yes | `recv-wazuh-alert` execution 96 (API, `includeData=true`), `.body` only | 2026-09-26 22:20:41 |
| `wazuh/19007-sca-check-failed.json` | 19007 SCA check failed (CIS Ubuntu 24.04), agent start-up scan. **Predates Wazuh's W2.7 tuning:** a live 19007 is level 5 now and is never sent; replaying this level-7 file creates a `wazuh-generic` TheHive alert since n8n dropped its `sca` exclusion (2026-10-09). Kept unchanged as captured | 7 | `sca` | yes then (none reached n8n: they fired before C1 existed); no longer | `wazuh-query.sh -r 19007 -n 1 -s 30d -j` | 2026-09-25 23:15:32 |
| `wazuh/19004-sca-summary.json` | 19004 SCA summary: score < 50 %. Same as 19007: level 5 since W2.7; this file creates a `wazuh-generic` alert when replayed | 7 | `sca` | yes then (same); no longer | `wazuh-query.sh -r 19004 -n 1 -s 30d -j` | 2026-09-25 23:15:39 |
| `wazuh/503-agent-started.json` | 503 Wazuh agent started. **Below threshold, not sent by C1** (level 3 < `WAZUH_ALERT_MIN_LEVEL` 7); kept as a sample of the `ossec` group and of `data.extra_data` | 3 | `ossec` | **no** | `wazuh-query.sh -r 503 -n 1 -s 30d -j` | 2026-09-30 20:30:42 |

### From the Wazuh lab scenarios (2026-10-09)

Exact C1 bodies, one per rule: the Wazuh owner's scenarios (`nodes/lab/trigger.sh --scenario <name>`, W1.5) run on the build instance, each body read from its `recv-wazuh-alert` execution through the API (`GET /api/v1/executions/<id>?includeData=true`, node `Wazuh alert`, `.body` only: no headers, so no token). Attacker addresses are documentation ranges; lab accounts only. Log lines (and sudo's `data.command`) end with ` asox_run=<run id>`, the scenario's run ID (W1.6): not part of the real message. Route = n8n's routing row (`lib-config` `routing` 2026-10-09); each was checked live on the TheHive alert's `caseTemplate` and the writeback's `Route:` line.

| File | Rule | Level | Groups | MITRE | Scenario | Route | recv execution | Alert time (UTC) |
|---|---|---|---|---|---|---|---|---|
| `wazuh/100200-ssh-root-login.json` | 100200 ASOX: SSH login as root | 10 | `asox`, `linux`, `sshd`, `authentication_success` | T1078.003 | `root-login` | `suspicious-login` | 1293 | 2026-10-09 20:38:28 |
| `wazuh/40112-login-after-bruteforce.json` | 40112 multiple authentication failures followed by a success | 12 | `syslog`, `attacks` (no `sshd`) | T1078, T1110 | `ssh-success-after-fail` | `suspicious-login` | 1438 | 2026-10-09 20:39:54 |
| `wazuh/5763-sshd-bruteforce.json` | 5763 sshd brute force (existing user `root`, in `data.dstuser`) | 10 | `syslog`, `sshd`, `authentication_failures` | T1110 | `ssh-bruteforce` | `ssh-bruteforce` | 1301 | 2026-10-09 20:38:32 |
| `wazuh/5712-sshd-bruteforce-invalid-users.json` | 5712 sshd brute force with invalid users (name in `data.srcuser`), from `203.0.113.66`, the MISP seed IOC until 2026-10-14 | 10 | `syslog`, `sshd`, `authentication_failures` | T1110 | `ioc-ip` | `ssh-bruteforce` (MISP hit, `suspicious`, then; the seed changed since, X-36) | 1309 | 2026-10-09 20:38:32 |
| `wazuh/5404-sudo-three-failures.json` | 5404 three failed attempts to run sudo (`srcuser` ran it, `dstuser` target, `command`, `pwd`, `tty`) | 10 | `syslog`, `sudo` | T1548.003 | `sudo-fail` | `privilege-escalation` | 1297 | 2026-10-09 20:38:30 |
| `wazuh/5901-new-group.json` | 5901 new group (`data.dstuser` is the **group** name, plus `gid`) | 8 | `syslog`, `adduser` | — | `new-user` | `account-change` | 1281 | 2026-10-09 20:38:28 |
| `wazuh/5902-new-user.json` | 5902 new user (`dstuser`, `uid`, `gid`, `home`, `shell`) | 8 | `syslog`, `adduser` | T1136 | `new-user` | `account-change` | 1286 | 2026-10-09 20:38:28 |
| `wazuh/100211-user-added-to-privileged-group.json` | 100211 ASOX: user added to a privileged group (usermod; `dstuser`, `group`) | 10 | `asox`, `linux`, `adduser`, `account_changed` | T1098 | `new-user` | `account-change` | 1289 | 2026-10-09 20:38:28 |
| `wazuh/100100-asox-test-syslog-c1.json` | 100100 test rule **received over syslog** (514/udp): `agent.id` `"000"`, `agent.name` `wazuh-manager`, no `agent.ip`, `location` = sender address (`172.19.0.1`, core's network gateway behind the published port), `predecoder.hostname` = the sending machine | 10 | `asox`, `test` | — | `logger -n 127.0.0.1 -P 514 -d --rfc3164 -t asox-test "ASOX_TEST_EVENT id=…"` from the WSL host | `wazuh-generic` | 1539 | 2026-10-09 20:42:26 |

### From the Wazuh lab scenarios (2026-10-14): OPNsense over syslog

Same method as above (the `recv-wazuh-alert` execution's `.body`, no headers). Both scenarios send real syslog lines from the lab container to the manager's 514/udp (W4.5), so these are syslog alerts: `agent.id` `000`, `agent.name` `wazuh-manager`, `predecoder.hostname` `opnsense`, `location` the lab container's address. Their `rule.description` contains the source address (Wazuh fills it in from the event). Route = `lib-config` `routing` version `2026-10-14`, checked live and by replay (TheHive `caseTemplate`, writeback `Route:` line, host `opnsense` in the title, `agent:` tag and `wazuh-agent-name`).

| File | Rule | Level | Groups | MITRE | Scenario | Route | recv execution | Alert time (UTC) |
|---|---|---|---|---|---|---|---|---|
| `wazuh/103011-opnsense-gui-bruteforce.json` | 103011 OPNsense web GUI brute force (decoder `solaris_bsm`; `data.srcip` `203.0.113.51`, `data.dstuser` `root`) | 10 | `asox`, `opnsense`, `pfsense`, `authentication_failures` (no `sshd`) | T1110 | `opnsense-gui-bruteforce` | `login-bruteforce` | 25504 | 2026-10-14 19:33:48 |
| `wazuh/103000-opnsense-port-scan.json` | 103000 OPNsense port scan (decoder `pf`; `data.srcip` `203.0.113.77`, `data.dstip` `192.168.1.1`, ports, action `block`) | 10 | `asox`, `opnsense`, `pfsense`, `firewall_block`, `recon` | T1046 | `opnsense-scan` | `network-scan` | 25505 | 2026-10-14 19:33:51 |

### From the Wazuh lab scenarios (2026-10-15): MISP IOC, FIM, Suricata

Same method (the `recv-wazuh-alert` execution's `.body`, no headers, no token). Route = `lib-config` `routing` version `2026-10-15`, checked live on the TheHive alert (`caseTemplate`, writeback `Route:` line) and by a `--fresh-id` replay of the saved file (one alert, `caseTemplate` `ioc-match`, severity 4, one writeback, `metrics: ok`).

| File | Rule | Level | Groups | MITRE | Scenario | Route | recv execution | Alert time (UTC) |
|---|---|---|---|---|---|---|---|---|
| `wazuh/108000-misp-ioc-source-ip.json` | 108000 ASOX IOC: source `101.99.75.184` (the MISP seed IOC, X-36) is a MISP indicator (C14, `misp-ip` CDB list); decoder `sshd`, `data.srcip` the IOC, `data.srcuser` `admin` (an invalid user) | 12 | `asox`, `misp_ioc` (the source's `sshd` groups are **not** kept) | — | `ioc-ip` | `ioc-match` | 29389 | 2026-10-15 19:32:21 |

`ioc-ip` gave only 108000 (one a minute; it absorbs that minute's events, so no 5712 this time). Its `full_log` is the sshd line, ending with ` asox_run=<run id>`.

**Not captured in that first run** (no alert reached Wazuh): FIM and Suricata. The lab agent then had a stale enrollment (agent `001`, group `default` only, no `/etc/sudoers.d`), so no FIM alert fired and Suricata's `eve.json` alerts weren't read. Captured later the same day, after the lab node was reset (below).

### From the Wazuh lab scenarios (2026-10-15, after the lab reset): FIM and Suricata

The lab node was reset and re-initialised on 2026-10-15: `lab-agent` is now agent `002` in group `linux-servers` (real-time FIM), `/etc/sudoers.d` exists, and the agent's own `ossec.conf` reads `/var/log/suricata/eve.json` (localfile, `log_format json`), so Suricata alerts don't depend on the `network-sensors` group. Same method as above (the `recv-wazuh-alert` execution's `.body`, no headers, no token). Route = `lib-config` `routing` version `2026-10-15`, checked live on the TheHive alert (`caseTemplate`, writeback `Route:` line, `metrics: ok`); `100300` and `101010` also by a `--fresh-id` replay of the saved file (one alert each, `privilege-escalation` / `ids-network-alert`, severity 3, one writeback, `metrics: ok`).

| File | Rule | Level | Groups | MITRE | Scenario | Route | recv execution | Alert time (UTC) |
|---|---|---|---|---|---|---|---|---|
| `wazuh/100300-fim-sudoers-added.json` | 100300 ASOX: sudoers changed (`/etc/sudoers.d/90-svc-backup-<run>`, `syscheck.event` `added`; decoder `syscheck_new_entry`, `location` `syscheck`, no `data`) | 10 | `asox`, `linux`, `syscheck` | T1548.003 | `persistence` | `privilege-escalation` | 29741 | 2026-10-15 19:53:28 |
| `wazuh/100301-fim-authorized-keys-added.json` | 100301 ASOX: SSH authorized_keys changed (`/root/.ssh/authorized_keys`, `added`: the file didn't exist on the fresh agent; a later run appends, so `modified`, not captured) | 10 | `asox`, `linux`, `syscheck` | T1098.004 | `persistence` | `wazuh-generic` | 29737 | 2026-10-15 19:53:28 |
| `wazuh/100302-fim-cron-added.json` | 100302 ASOX: system cron job added or changed (`/etc/cron.d/asox-update-<run>`, `added`) | 10 | `asox`, `linux`, `syscheck` | T1053.003 | `persistence` | `wazuh-generic` | 29740 | 2026-10-15 19:53:28 |
| `wazuh/101001-suricata-id-check-root.json` | 101001 ASOX IDS (Suricata 2100498 "GPL ATTACK_RESPONSE id check returned root", severity `2`); decoder `json`, `location` `/var/log/suricata/eve.json`; `data.src_ip` `172.22.0.2` (the lab agent itself, on the lab network), `data.dest_ip` `104.20.23.154` (example.com, Cloudflare), `data.dest_port` `"80"` | 10 | `asox`, `suricata`, `ids` | — | `ids-test` | `ids-network-alert` | 29813 | 2026-10-15 19:54:02 |
| `wazuh/101010-suricata-nmap-syn-scan.json` | 101010 ASOX IDS scan (Suricata 2009582 "ET SCAN NMAP -sS window 1024"); `data.src_ip` `172.22.0.3` (the throwaway nmap container), `data.dest_ip` `172.22.0.2` (the lab agent) | 10 | `asox`, `suricata`, `ids`, `recon` | T1046 | `ids-scan` | `ids-network-alert` | 29848 | 2026-10-15 19:54:27 |

- `ids-test`'s alert reached n8n within the poll (no need to fall back on `eve.json`). `ids-scan` gave four 101010 alerts in the same second (ET SCAN 2009582 nmap -sS, 2010935 MSSQL, 2010936 Oracle, 2010937 MySQL; recv 29847–29850), all routed `ids-network-alert`; only the nmap one is kept.
- FIM and Suricata lines carry **no ` asox_run=<run id>`** (`full_log` is Wazuh's FIM text, or Suricata's raw EVE line), so these alerts get no `t_attack_start` in `asox-metrics` (C11, MTTD null): finding in `../BACKLOG.md` N8N-0.2.
- The Suricata `full_log` is the raw EVE line (numbers as JSON numbers), while the decoded `data.*` values are all strings; `data.flow_id` arrives float-formatted (`"472442805756262.000000"`): never use it as an identifier.
- These are real alerts from a reset lab: the sudoers and cron file names end with the run id's first 8 characters, the authorized_keys line contains a fake key (`AAAAC3...ASOXlabTESTkeyNOTreal`, not in the alert). No credentials.

### From the Wazuh lab scenarios (2026-10-20): FIM tamper and web attack

The Wazuh owner's two new scenarios (`trigger.sh --scenario fim-tamper` / `web-attack`, X-05, `nodes/core/wazuh/docs/request-n8n-2026-10-19.md`). Same method (the `recv-wazuh-alert` execution's `.body`, no headers, no token). Route = `lib-config` `routing` version `2026-10-15`, checked live on the drain execution (`lib-route-alert`: `default (no row matched)`), the TheHive alert (`caseTemplate`) and the writeback's `Route:` line; every alert had one TheHive alert, one writeback and `metrics: ok`. `553` and `31103` also by a `--fresh-id` replay of the saved file (2026-10-20, after the webhook token rotation): HTTP 200, one alert each, `wazuh-generic`, severity 2, one writeback (`Route: wazuh-generic (default (no row matched))`), `metrics: ok`, and the same observables as live (below). `100302` and `31152` were not replayed (live only): 100302 takes the same path as `100302-fim-cron-added.json`, and 31152 the same `data.url` / `data.srcip` path as 31103.

| File | Rule | Level | Groups | MITRE | Scenario | Route | recv execution | Alert time (UTC) |
|---|---|---|---|---|---|---|---|---|
| `wazuh/100302-fim-cron-modified.json` | 100302 ASOX: system cron job added or changed (`/etc/cron.d/asox-tamper-<run>`, `syscheck.event` `modified`; decoder `syscheck_integrity_changed`; `changed_attributes` `size`, `mtime`, `md5`, `sha1`, `sha256` and the matching `*_before`) | 10 | `asox`, `linux`, `syscheck` | T1053.003 | `fim-tamper` | `wazuh-generic` | 31030 | 2026-10-20 18:26:30 |
| `wazuh/553-fim-file-deleted.json` | 553 File deleted (built-in; the same file 3 s later, `deleted`; decoder `syscheck_deleted`; `*_after` = the file's last known state, no `*_before`, no `changed_attributes`; `rule.description` is just `File deleted.`, no path) | 7 | `ossec`, `syscheck`, `syscheck_entry_deleted`, `syscheck_file` | T1070.004, T1485 | `fim-tamper` | `wazuh-generic` | 31038 | 2026-10-20 18:26:33 |
| `wazuh/31103-web-sql-injection.json` | 31103 SQL injection attempt (built-in; decoder `web-accesslog`, Apache combined line in the lab's test log; `data.srcip` `198.51.100.30`, `data.url` path and query only, `data.protocol` `GET`, `data.id` `"500"`) | 7 | `web`, `accesslog`, `attack`, `sql_injection` | T1190 | `web-attack` | `wazuh-generic` | 31100 | 2026-10-20 18:26:57 |
| `wazuh/31152-web-sql-injection-repeated.json` | 31152 multiple SQL injection attempts from the same source (built-in frequency rule, `rule.frequency` 8; carries **`previous_output`**: the 7 earlier access log lines, attacker-written like `full_log`) | 10 | `web`, `accesslog`, `attack`, `sql_injection` | T1055 (Wazuh's own mapping) | `web-attack` | `wazuh-generic` | 31107 | 2026-10-20 18:26:57 |

- `fim-tamper` gave the three expected alerts (100302 `added`, `modified`, then 553); the `added` one is not saved (`100302-fim-cron-added.json` already covers it). The FIM `full_log` is Wazuh's text (`File '<path>' modified`, then the changed attributes and old/new values), with no ` asox_run=` (X-43).
- `web-attack` gave **10** alerts, not 11: nine 31103 and one 31152. The request that completed the 8 tries fired 31152 **instead of** 31103 (Wazuh reports one rule per event). Its lines end with ` asox_run=<run id>` inside the user agent (`sqlmap/1.8.4#stable (https://sqlmap.org) asox_run=…`), so `full_log` has it but no `data.*` field does. The URL contains `username,password` as SQL text: an injection string, no credential.
- **Observables, as `lib-extract-observables` made them** (input for X-44; extractor unchanged):
  - **553, deleted file:** `syscheck.sha256_after` became a `hash` observable tagged `sha256` only, exactly like the `modified` alert's (the same digest: the content the file had when it was removed). Nothing marks it as the hash of a deleted file; MISP_2_1 enriched it (`info`). Plus `filename` (`path`) and the agent's `ip` / `hostname`. **Replay:** the same four observables, the hash tagged `sha256` (then `asox:verdict=info`, `analyzer:MISP_2_1`); no `t_attack_start` in the metrics document (no marker, X-43).
  - **31103 / 31152, `data.url`:** **not sent.** The writeback says `Observable not sent: url /products.php?id=1%27%20UNION… (invalid: not a valid URL)`: a path without scheme and host fails the extractor's `new URL()` check, so it is listed in `skipped`. There is no length limit in the extractor: a 500+ character path is skipped the same way, and its **full value is copied into `skipped` and into the writeback comment, untruncated**; a 500+ character absolute URL (`http(s)://host/…`) would be sent as a `url` observable unchanged. The 500-character `untrusted` rule is Jev's (`../jev/untrusted-fields.json`), not applied here. **Replay (31103):** the same `Observable not sent: url … (invalid: not a valid URL)` line; `t_attack_start` set (the line's ` asox_run=` marker).
  - **`data.srcip` `198.51.100.30`:** `ip` tagged `src`, `range:documentation` and `warninglist` (MISP's "List of RFC 5735 CIDR blocks", in the observable's `message`). **Enrichment not skipped:** MISP_2_1 ran on it (`MISP:Search="0 events"`, `info`; the 31152 alert got Cortex's cached answer), because the range tag only flags it (N8N-2.3) and a warninglist match only allows skipping quota-limited online analyzers (C10). **Replay (31103):** the same tags and warninglist `message`, MISP_2_1 run again (`info`).

Also produced, not saved: the attack-start marker 100101 (level 3, never sent by C1), and 5710 / 5760 (single failures, level 5). A syslog line in RFC 5424 format (`logger` without `--rfc3164`) arrives with no `predecoder` at all: n8n then has only `location`.

These are all the rule types at level 7 or above in the indexer on 2026-09-30 (last 30 days: 100100 ×17, 19007 ×130, 19004 ×1). The 130 SCA alerts of one agent start-up were a sample of the flood the router must absorb (N8N-1.4, X-09); since W2.7 they stay at level 5 and only SCA regressions (19011, 19014) and a score below 30% (19005) reach n8n. `replay.sh --all --only wazuh` therefore creates TheHive alerts for the two SCA files too: delete them afterwards.

### Missing (to come from Wazuh)

Not produced by the lab yet at any level (or not on the build instance), so not captured and **not invented**. sshd, sudo, account changes and `rule.mitre.id` arrived with the scenarios (2026-10-09), OPNsense on 2026-10-14, the MISP IOC rule 108000, FIM and Suricata on 2026-10-15, FIM `modified` / `deleted` and web access logs on 2026-10-20 (above).

| Needed for | Rule type (built-in examples) | Comes with |
|---|---|---|
| ~~`syscheck.*`~~ captured 2026-10-15 (100300–100302, `added`, above); ~~a `modified` and a `deleted` event~~ captured 2026-10-20 (100302 `modified`, built-in 553); still missing for `pb-malware-hash` (N8N-4.3): built-in 550 / 554, a hash on a MISP list (108020/108021) | FIM / syscheck | Wazuh M5 |
| ~~`data.url`, web access logs~~ captured 2026-10-20 (31103, 31152, decoder `web-accesslog`); still missing: a real web server's logs (and an absolute URL, which this decoder never produces) | web / access logs | later (Jev's web cases), X-44 |
| `malware-detection` template | rootcheck (e.g. 510), VirusTotal (87105), YARA / ClamAV | Wazuh M5 |
| ~~`data.alert.*`, `data.src_ip`, `data.dest_ip`, `data.dest_port`~~ captured 2026-10-15 (101001, 101010, above); still missing for `pb-ids-alert` (N8N-4.4): a severity-1 signature (level 12), a Suricata alert from a MISP IOC (108010/108011), a sensor on its own machine (group `network-sensors`, Phase 2) | Suricata | Wazuh M3 / Phase 2 |
| ~~`network-scan` row, `data.dstip`, syslog device alerts~~ captured 2026-10-14 (103000, 103011, above); still missing: routers (102xxx), a real OPNsense (the lab sends the lines itself) | pfSense / router (103xxx, 102xxx) | Wazuh M4 (2026-11-10) |
| ~~`ioc-match` row~~ captured 2026-10-15 (108000, above); still missing: 108001 (destination), 108010/108011 (Suricata), 108020/108021 (hash) | MISP IOC matches (108xxx, C14) | 108000 done; the others with their sources |
| C11 `t_attack_start` | the attack-start marker 100101 (level 3: read from the indexer, never sent by C1) | in the lab now; captured by N8N-2.9 from the indexer |

### Constructed invalid payloads (`invalid/`)

The only files here that are **not** real payloads: test inputs for the malformed-alert path (N8N-1.2, lib-error). `replay.sh --all` doesn't pick them up; replay them with `--file`.

| File | Built from | Defect | Expected |
|---|---|---|---|
| `invalid/100100-no-id.json` | `wazuh/100100-asox-test-c1.json` without `id` | required `id` missing | passes the level filter, `lib-normalize-wazuh-alert` hands it to `lib-error`, parked as `malformed_input`; nothing in TheHive |

### Synthetic payloads (`synthetic/`)

**Synthetic, not captured:** copies of `wazuh/100100-asox-test-c1.json` (the real C1 body) with only the `data` field added, to exercise observable paths the lab doesn't produce yet (X-05). Everything else, `id` included, is the real alert, so replay them with `--fresh-id`. `replay.sh --all` doesn't pick them up.

| File | Changed from `wazuh/100100-asox-test-c1.json` | Exercises | Expected |
|---|---|---|---|
| `synthetic/100100-misp-hit.json` | `data.srcip = "101.99.75.184"` (the MISP seed IOC since 2026-10-14, X-36; `203.0.113.66` before) | enrichment (N8N-2.4): `MISP_2_1` hit (`suspicious`, `ioc` false); without analyzer keys AbuseIPDB, OTX, URLhaus and VirusTotal `skipped (not enabled in Cortex)`; with keys they run, and VirusTotal too (the MISP hit opens D-N7's severe path); needs `full` (MISP) | `asox-test` alert, route `wazuh-generic`; `101.99.75.184` (tag `src` only: a public address, no range tag) enriched by `MISP_2_1`: `MISP:Search="2 event(s)"` (the seed event and Botvrij's Loki-Bot event), tags `asox:verdict=suspicious`, `analyzer:MISP_2_1`, `ioc` false; **no warninglist tag** (writeback: `0 of 1 checked value(s) on a warninglist`); agent IP and hostname skipped; all in the writeback. Checked 2026-10-14 |
| `synthetic/100100-warninglist-demo.json` | `data.srcip = "8.8.8.8"`, `data.dstip = "185.220.101.1"`, `data.hostname = "github.com"` (the Cortex + MISP owner's C10 demo) | warninglist check (C10, N8N-2.11; needs `full`) | `asox-test` alert; `8.8.8.8` (`src`), `185.220.101.1` (`dst`) and `github.com` (`fqdn`) each tagged `warninglist` only (answer G revised, 2026-10-15), with a `message` "On MISP warninglists (common, not safe):" listing every list: `8.8.8.8` the public DNS resolvers and vpn-ipv4 lists, `185.220.101.1` the Tor exit nodes and vpn-ipv4 lists, `github.com` 17 lists; all three still enriched by `MISP_2_1` (`info`), `ioc` false; since 2026-10-21 (`skip_online_analyzers: false`) the online analyzers take them too, so without analyzer keys each shows `skipped (not enabled in Cortex)`, not a warninglist skip (checked 2026-10-21); `lab-agent` and the agent IP unchanged, no message; writeback: `Warninglists (MISP, C10): 3 of 3 checked value(s) ...` and three `On warninglist: ...; tagged warninglist.` lines. The `message` survives promotion to a case. The list names depend on MISP's warninglist version. Checked 2026-10-15 |
| `synthetic/100100-user-account.json` | `data.srcuser = "asox-test-src"`, `data.dstuser = "asox-test-target"` | `user-account` observables (N8N-2.3; needs TheHive's `entities/` loaded, T1.3) | `asox-test` alert with `user-account` observables `asox-test-src` (tag `src`) and `asox-test-target` (tag `target`), besides the agent's `ip` and `hostname` |

**Seed IOC (X-36, decided 2026-10-14):** the old seed IOC `203.0.113.66` is on MISP's "List of RFC 5735 CIDR blocks" (a documentation range), so n8n tagged it as a common value. The owners replaced it with **`101.99.75.184`** (`ip-dst`, `to_ids: true`, from a Botvrij event; on no enabled warninglist, which `misp-config.sh apply` now enforces), and the old seed event is deleted. `synthetic/100100-misp-hit.json` uses the new address. `wazuh/5712-sshd-bruteforce-invalid-users.json` keeps `203.0.113.66` as captured (a real alert of 2026-10-09); with the old seed event deleted, MISP should no longer report a hit for it (not replayed), and its route is unchanged.

## TheHive events

One flow, produced on 2026-09-30 between 20:50 and 20:53 UTC on the build instance, then deleted: n8n's key created the alert (`source: asox-test`, from the 100100 alert) and added a tag; `analyst@asox.local` did everything else through the API. The recorded bodies were read from the `recv-thehive-event` executions (IDs 114–135) through the API. Events of the same HTTP request share `requestId`.

| File | `action` / `objectType` | Actor (`_createdBy`) | What happened | `details` keys |
|---|---|---|---|---|
| `01-observable-create-on-alert-by-n8n.json` | create / Observable | n8n | observable created with the alert (one event per observable, before the alert's own event) | full observable |
| `02-alert-create-by-n8n.json` | create / Alert | n8n | alert created | full alert |
| `03-alert-update-tags-by-n8n.json` | update / Alert | **n8n** | n8n added a tag: **the event loop prevention must ignore** (N8N-1.5) | `tags` |
| `04-alert-update-assignee.json` | update / Alert | analyst | alert assigned | `assignee` |
| `05-alert-update-status-inprogress.json` | update / Alert | analyst | alert status New → InProgress (MTTA `t_ack`, C11) | `status`, `stage` |
| `06-comment-create-on-alert.json` | create / Comment | analyst | comment on the alert (`object.alert` set, `object.case` null) | `author` |
| `07-case-update-share-on-promote.json` | update / Case | analyst | promotion, part 1: case shared with the org | `share` |
| `08-alert-update-caseid-on-promote.json` | update / Alert | analyst | promotion, part 2: alert gets `caseId`, status Imported | `caseId` |
| `09-observable-create-on-case-from-alert.json` | create / Observable | analyst | promotion, part 3: alert observables copied to the case | full observable |
| `10-case-create-from-alert.json` | create / Case | analyst | promotion, part 4: the case (arrived ~3 s after parts 1–2) | full case |
| `11-task-create.json` | create / Task | analyst | task added to the case | full task |
| `12-task-update-inprogress.json` | update / Task | analyst | task started | `status`, `startDate` |
| `13-case-update-status-inprogress-auto.json` | update / Case | analyst | case New → InProgress, done by TheHive because a task started | `status`, `stage` |
| `14-log-create.json` | create / Log | analyst | task log | full log |
| `15-task-update-completed.json` | update / Task | analyst | task completed | `status`, `endDate`, `timeToHandle` |
| `16-comment-create-on-case.json` | create / Comment | analyst | comment on the case | `author` |
| `17-observable-create-on-case.json` | create / Observable | analyst | observable added to the case (`192.0.2.10`, documentation range) | full observable |
| `18-case-update-closed-falsepositive.json` | update / Case | analyst | case closed as FalsePositive (C11 `t_closed`, `resolution`; N8N-5.3) | `status`, `stage`, `endDate`, `summary` |
| `19-case-delete.json` | delete / Case | analyst | case deleted: **no `object`**, `details` has only `number`, `title` | `number`, `title` |
| `20-alert-delete.json` | delete / Alert | analyst | alert deleted: **no `object`, empty `details`** | none |

Observations (details in `../docs/ALERT-TO-THEHIVE.md`):
- The actor of every event, deletes included, is the top-level `_createdBy` (the audit record's author). `object._updatedBy` exists only when there is an `object`.
- Delete events have no `object`, so a deleted alert's `sourceRef` (the Wazuh alert ID) can't be read from the payload.
- Deleting the case put the alert back to InProgress with `caseId` null **without any event** for the alert.
- Not captured: `User` events (skipped on purpose; they carry `details.key: "<hidden>"` on key renewals, not the key), alert merge into a case, alert status Ignored/FalsePositive, case template applied (no templates are loaded on the build instance), approval tasks (N8N-7.x).

## Replaying (`replay.sh`, N8N-0.6)

```bash
nodes/core/n8n/fixtures/replay.sh --file nodes/core/n8n/fixtures/wazuh/100100-asox-test-c1.json
nodes/core/n8n/fixtures/replay.sh --all --only wazuh --times 2   # idempotency test (N8N-3.3)
nodes/core/n8n/fixtures/replay.sh --all --no-token               # every POST must get 403 (N8N-1.6)
nodes/core/n8n/fixtures/replay.sh --fresh-id --times 2 --delay 5 --file nodes/core/n8n/fixtures/wazuh/100100-asox-test-c1.json
                                  # new unique alert id, sent twice 5 s apart: one TheHive alert, one writeback,
                                  # second run = duplicate (N8N-3.3)
```

With playbooks attached, a replayed Wazuh fixture creates a real TheHive alert (source `asox-test` for rule 100100, `wazuh` otherwise), and TheHive refuses a second alert with the same `sourceRef`. Use `--fresh-id` to replay a fixture as a new alert; the id is replaced once per file and run, so `--times N` still tests deduplication. Give `--delay` so the first run finishes first: **without it, the copies reach TheHive concurrently and TheHive creates one alert per copy** (its duplicate refusal isn't atomic; `../docs/ALERT-TO-THEHIVE.md` §2). Delete the test alerts afterwards (source `asox-test`).

It picks the webhook and the auth header from the payload (Wazuh → `wazuh-alert` + `X-ASOX-Token`, TheHive → `thehive-event` + `Authorization: Bearer`), reads the token from `nodes/core/.env` without printing it, and reaches n8n on its published port (`N8N_URL`, default `http://127.0.0.1:5678`, as the other scripts). Once playbooks are attached, a replay runs them for real.

Verified 2026-09-30: `--all --no-token` → 25 × HTTP 403; `100100-asox-test-c1.json` → HTTP 200 and `recv-wazuh-alert` execution 136 recorded alert `1790461241.14189`; a TheHive fixture `--times 2` → 2 × HTTP 200.
