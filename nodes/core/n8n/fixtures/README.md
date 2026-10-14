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
| `wazuh/5712-sshd-bruteforce-invalid-users.json` | 5712 sshd brute force with invalid users (name in `data.srcuser`), from the MISP seed IOC `203.0.113.66` | 10 | `syslog`, `sshd`, `authentication_failures` | T1110 | `ioc-ip` | `ssh-bruteforce` (MISP hit, `suspicious`) | 1309 | 2026-10-09 20:38:32 |
| `wazuh/5404-sudo-three-failures.json` | 5404 three failed attempts to run sudo (`srcuser` ran it, `dstuser` target, `command`, `pwd`, `tty`) | 10 | `syslog`, `sudo` | T1548.003 | `sudo-fail` | `privilege-escalation` | 1297 | 2026-10-09 20:38:30 |
| `wazuh/5901-new-group.json` | 5901 new group (`data.dstuser` is the **group** name, plus `gid`) | 8 | `syslog`, `adduser` | — | `new-user` | `account-change` | 1281 | 2026-10-09 20:38:28 |
| `wazuh/5902-new-user.json` | 5902 new user (`dstuser`, `uid`, `gid`, `home`, `shell`) | 8 | `syslog`, `adduser` | T1136 | `new-user` | `account-change` | 1286 | 2026-10-09 20:38:28 |
| `wazuh/100211-user-added-to-privileged-group.json` | 100211 ASOX: user added to a privileged group (usermod; `dstuser`, `group`) | 10 | `asox`, `linux`, `adduser`, `account_changed` | T1098 | `new-user` | `account-change` | 1289 | 2026-10-09 20:38:28 |
| `wazuh/100100-asox-test-syslog-c1.json` | 100100 test rule **received over syslog** (514/udp): `agent.id` `"000"`, `agent.name` `wazuh-manager`, no `agent.ip`, `location` = sender address (`172.19.0.1`, core's network gateway behind the published port), `predecoder.hostname` = the sending machine | 10 | `asox`, `test` | — | `logger -n 127.0.0.1 -P 514 -d --rfc3164 -t asox-test "ASOX_TEST_EVENT id=…"` from the WSL host | `wazuh-generic` | 1539 | 2026-10-09 20:42:26 |

Also produced, not saved: the attack-start marker 100101 (level 3, never sent by C1), and 5710 / 5760 (single failures, level 5). A syslog line in RFC 5424 format (`logger` without `--rfc3164`) arrives with no `predecoder` at all: n8n then has only `location`.

These are all the rule types at level 7 or above in the indexer on 2026-09-30 (last 30 days: 100100 ×17, 19007 ×130, 19004 ×1). The 130 SCA alerts of one agent start-up were a sample of the flood the router must absorb (N8N-1.4, X-09); since W2.7 they stay at level 5 and only SCA regressions (19011, 19014) and a score below 30% (19005) reach n8n. `replay.sh --all --only wazuh` therefore creates TheHive alerts for the two SCA files too: delete them afterwards.

### Missing (to come from Wazuh)

Not produced by the lab yet at any level, so not captured and **not invented**. sshd, sudo, account changes and `rule.mitre.id` arrived with the scenarios (2026-10-09, above).

| Needed for | Rule type (built-in examples) | Comes with |
|---|---|---|
| `pb-malware-hash` (N8N-4.3), `syscheck.*` | FIM / syscheck (e.g. 550, 553, 554) | Wazuh M5 |
| `malware-detection` template | rootcheck (e.g. 510), VirusTotal (87105), YARA / ClamAV | Wazuh M5 |
| `pb-ids-alert` (N8N-4.4), `data.alert.*`, `data.src_ip`, `data.dest_ip`, `data.dest_port` | Suricata (86601) | Wazuh M3 (2026-11-03) |
| `network-scan` row, `data.dstip`, syslog device alerts | pfSense / router (103xxx, 102xxx) | Wazuh M4 (2026-11-10) |
| `ioc-match` row | MISP IOC matches (108xxx, C14) | Wazuh M6 |
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
| `synthetic/100100-misp-hit.json` | `data.srcip = "203.0.113.66"` (the MISP seed IOC, a documentation address) | enrichment (N8N-2.4): `MISP_2_1` hit; needs `full` (MISP) | `asox-test` alert; `203.0.113.66` (tags `src`, `range:documentation`) enriched by `MISP_2_1`: tags `asox:verdict=suspicious`, `analyzer:MISP_2_1`, `ioc` false, and since N8N-2.11 also `warninglist`, `warninglist:List of RFC 5735 CIDR blocks` (X-36, below); agent IP and hostname skipped; all in the writeback |
| `synthetic/100100-warninglist-demo.json` | `data.srcip = "8.8.8.8"`, `data.dstip = "185.220.101.1"`, `data.hostname = "github.com"` (the Cortex + MISP owner's C10 demo) | warninglist check (C10, N8N-2.11; needs `full`) | `asox-test` alert; `8.8.8.8` (`src`) tagged `warninglist`, `warninglist:List of known IPv4 public DNS resolvers`, `warninglist:Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters`; `185.220.101.1` (`dst`) tagged `warninglist`, `warninglist:List of known Tor exit nodes` and the vpn-ipv4 list; `github.com` (`fqdn`) tagged `warninglist` plus the first 3 of its ~17 lists by name; all three still enriched by `MISP_2_1` (`info`), `ioc` false; `lab-agent` and the agent IP unchanged; writeback: `Warninglists (MISP, C10): 3 of 3 checked value(s) ...` and three `On warninglist:` lines. The list names depend on MISP's warninglist version |
| `synthetic/100100-user-account.json` | `data.srcuser = "asox-test-src"`, `data.dstuser = "asox-test-target"` | `user-account` observables (N8N-2.3; needs TheHive's `entities/` loaded, T1.3) | `asox-test` alert with `user-account` observables `asox-test-src` (tag `src`) and `asox-test-target` (tag `target`), besides the agent's `ip` and `hostname` |

**`203.0.113.66` is on a MISP warninglist (X-36):** since `misp-config.sh apply` runs at bootstrap (R-22), MISP's "List of RFC 5735 CIDR blocks" (`203.0.113.0/24`, a documentation range) is enabled and matches the address `synthetic/100100-misp-hit.json` uses (also the MISP seed IOC and `wazuh/5712-sshd-bruteforce-invalid-users.json`'s source). Since N8N-2.11 (2026-10-10) n8n tags it `warninglist` and `warninglist:List of RFC 5735 CIDR blocks`; `MISP_2_1` (a local analyzer) still runs and reports the hit, so the address is both "common" and `suspicious`. The fixture **may change** when the owners (Cortex + MISP, Wazuh, n8n) pick a new test IOC; it is left as it is until then.

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
