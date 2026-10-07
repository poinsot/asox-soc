# Integrator / n8n → Wazuh: R-06 on `main`, routing questions, open items (2026-10-06)

Received by the Wazuh owner on 2026-10-07. The original message is kept below as sent. Answers are in the **Reply** column of the tracker, with the details under "Answers". The delivering task is in [BACKLOG.md](../BACKLOG.md).

## Reply tracker

| # | Ask (short) | Due | Wazuh task | Status | Reply |
|---|---|---|---|---|---|
| 1 | R-06 on `main`: build W1.1 (compose + `30-syslog-allowed-ips.sh`) | 2026-10-09 | W1.1 | done | Done 2026-10-07 (`de05b5c`). Own subnets plus `WAZUH_SYSLOG_ALLOWED_IPS`; fails closed. Tested live: listed address accepted, neighbour and unknown network rejected (remoted 1213) |
| 2 | Set both request files to `Status: done` | — | — | done | Done 2026-10-07 |
| 3.1 | suspicious-login: rule ID, does 40112 fire, T1078? | 2026-10-20 | W1.3, W2.2 | answered | **Use 40112**; it fires live. **Row order bug:** today it routes to `ssh-bruteforce`. See A1 |
| 3.2 | privilege-escalation: sudo groups, rule IDs, T1548? | 2026-10-20 | W1.3, W2.2 | answered | 5404 has only `syslog,sudo`, so the group clause never matches; T1548.003 does. See A2 |
| 3.3 | account-change: `adduser` / `addgroup`? | 2026-10-20 | W1.3 | answered | `adduser` only (`addgroup` doesn't exist); 5901 has no MITRE. See A3 |
| 3.4 | ioc-match: group `misp` or `ioc`? | 2026-10-20 | W1.3, W6.4 | answered | Group **`misp_ioc`**, range **108xxx** (not 103xxx). See A4 |
| 3.5 | network-scan: group `pfsense`, rule IDs, T1046? | 2026-10-20 | W1.3, W4.3 | answered | Groups `asox,pfsense,recon` + T1046 on scan rules, range **103xxx** (not 104xxx); IDs land with M4 (11-10). See A5 |
| 3.6 | Confirm sshd groups and T1110 | 2026-10-20 | W1.3 | answered | Confirmed from live alerts. See A6 |
| 4.4, 4.7 | `trigger.sh --scenario`; `ioc-ip` uses `203.0.113.66` | 2026-10-09 | W1.5 | done | Done 2026-10-05; `ioc-ip` already uses `203.0.113.66` (rule 5712, `data.srcip`). Reaches `main` with this checkpoint PR |
| 4.5 | Attack-start marker + low-noise rule | 2026-10-20 | W1.6 | answered | Rule 100101, level 3 (proposed), fields `data.scenario` / `data.run_id`; level to confirm with Jesus ([request-grafana-attack-start-marker.md](request-grafana-attack-start-marker.md)) |
| 4.1–3 | Field list, `<mitre>` blocks, standard field names | 2026-10-20 | W2.5, W2.3 | open | Checkpoint 1 |
| 4.6 | Should SCA reach n8n? | 2026-10-20 | W2.7 | open | Checkpoint 1 |
| 4.9 | C14 design with Diego | 2026-10-16 | W6.1 | open | |
| 5.1 | C9: acknowledge `n8n-response` (D44), fix README C9 row | 2026-10-16 | W1.7 | answered | **Acknowledged.** README row fixed 2026-10-07. See A7 |
| 5.2 | C11, C13: acknowledge the indexer parts | 2026-10-16 | W1.7 | answered | **Acknowledged**, with one retention proposal (C11) and the field-map check (C13). See A7 |

Status values: `open`, `answered`, `done`, `declined` (with the reason in Reply).

## Answers

Checked against live alerts in the indexer (lab scenarios of 2026-10-05, `trigger.sh --scenario`, Wazuh 4.14.8) and n8n's `lib-config` on branch `n8n` (`routing.rows`).

| Rule | Level | `rule.groups` | `rule.mitre.id` | Reaches n8n (≥ 7) |
|---|---|---|---|---|
| 5710 sshd invalid user | 5 | `syslog,sshd,authentication_failed,invalid_login` | `T1110.001,T1021.004` | no |
| 5760 sshd failed password | 5 | `syslog,sshd,authentication_failed` | `T1110.001,T1021.004` | no |
| 5712 brute force (invalid users) | 10 | `syslog,sshd,authentication_failures` | `T1110` | yes |
| 5763 brute force | 10 | `syslog,sshd,authentication_failures` | `T1110` | yes |
| 5715 sshd login | 3 | `syslog,sshd,authentication_success` | `T1078,T1021` | no |
| **40112** failures then success | **12** | **`syslog,attacks`** (no `sshd`) | `T1078,T1110` | yes |
| 5404 sudo, 3 wrong passwords | 10 | `syslog,sudo` | `T1548.003` | yes |
| 5901 new group | 8 | `syslog,adduser` | — | yes |
| 5902 new user | 8 | `syslog,adduser` | `T1136` | yes |

**A1. suspicious-login.**
- **The rule:** use **40112** (built-in, level 12). It fires live in `ssh-success-after-fail` (8 failures, then a login from the same address within 240 s). No W2.2 custom rule is needed for this case, and none is planned. If one is added later, it will be in 1002xx with `T1078`.
- **Bug: the row order.** "The first active match wins." 40112 carries `T1110`, so the active `ssh-bruteforce` row (`mitre_prefix: ['T1110']`) takes it first, and `suspicious-login` can never match it, even once it's active. **Please move `suspicious-login` above `ssh-bruteforce`.**
- **Drop the `T1078` clause, match `rule_ids: ['40112']` only.** 5715, every single successful SSH login, also carries `T1078`. It's level 3 today, so it never reaches n8n. But if `WAZUH_ALERT_MIN_LEVEL` is ever lowered, or a custom rule raises a login, every normal login would open a suspicious-login case.

**A2. privilege-escalation.**
- **The groups clause doesn't work:** sudo failures (5404) carry only `syslog,sudo`, with no `authentication_failed` or `authentication_failures`, so it never matches.
- **The MITRE clause does:** 5404 carries `T1548.003`, and `mitre_prefix: ['T1548']` matches it. Keep the MITRE clause; the groups clause can go, or become `groups_all: ['sudo']` with `rule_ids: ['5404']` if you want an explicit rule list.
- **Rule IDs:** 5404 (level 10). Sudo to root (5403, level 4) stays below the threshold on purpose. No custom sudo rule is planned before checkpoint 1.

**A3. account-change.**
- **The group is `adduser` only.** `addgroup` doesn't exist in the Wazuh ruleset: Wazuh files both new users (5902) and new groups (5901) under `adduser`, and the same group covers 5903 (user or group deleted, level 3) and 5904 (user information changed, level 8).
- **Keep `groups_any: ['adduser']`.** 5901 has no MITRE ID, so the `T1136` clause alone would miss new groups.

**A4. ioc-match.** The group is **`misp_ioc`**, the one new group name in the W1.3 plan (README, "Rules: ID plan, files and groups"). The range is **108000–108999** in `1080-misp-ioc.xml`, not 103xxx: those rules must load after every source's rules, because they match IOCs across all of them. Each also keeps `asox` and the matched source's standard groups (e.g. `sshd`). **Please match `groups_any: ['misp_ioc']`**, and put the row **above** `ssh-bruteforce` and `ids-network-alert`, so an IOC match wins over the generic type.

**A5. network-scan.**
- **pfSense is range 103000–103999** (`1030-pfsense.xml`; routers are 102xxx), not 104xxx.
- **Scan and repeated-block rules** will carry `asox,pfsense,recon` and `<mitre><id>T1046</id></mitre>`. So `groups_all: ['pfsense'], mitre_prefix: ['T1046']` works as written.
- **Rule IDs** come with W4.3 (M4, 2026-11-10); I'll send them then.

**A6. ssh-bruteforce (active row):** confirmed from the live alerts above.
- The single-failure rules carry `authentication_failed`, plus `invalid_login` for unknown users. The brute-force rules (5712, 5763) carry `authentication_failures`. All carry `sshd`.
- Their MITRE IDs are `T1110` or `T1110.001`, so `mitre_prefix: ['T1110']` matches both.
- Only 5712 and 5763 reach n8n (level 10).

**A7. Contracts (W1.7).**
- **C9 (D44): acknowledged.** A separate Wazuh user and role `n8n-response`, with `n8n-api` staying read-only, so C2's "active response is refused" check keeps its meaning. My W7.1 already says so, and the README's C9 row is fixed.
- **C11 (D46): acknowledged.**
  - `asox-metrics` can live in my indexer, with `grafana-ro` reading it and `n8n-indexer` writing it.
  - **Proposal:** one primary shard, zero replicas (single node), and no deletion policy until after the 2026-12-01 delivery. At one small document per alert at level ≥ 7 (tens per day in the lab), that's well under 1 MB a month, and one more shard is negligible for the indexer on `low` (heap 512 MB, limit 1.15 GB).
  - Retention goes in the index template (R-16), revisited in Phase 2.
- **C12 (D47):** noted as rejected; nothing to build.
- **C13 (D48): acknowledged.** Field map checked against live alerts:
  - Confirmed: `data.srcip` (sshd), `data.srcuser` and `data.dstuser` (sshd, sudo, useradd), `agent.name`, `agent.ip` (`172.18.0.4`).
  - Not seen yet: `data.dstip`, `data.hostname`, Suricata's `data.src_ip` / `data.dest_ip` (M3, 11-03) and `syscheck.*_after` (no FIM alert in 30 days; M5). They're confirmed as those milestones produce them (W2.5).

---

## Original message

**To:** Daniel (@dmelgar1110), Wazuh owner
**From:** Inigo (@poinsot), integrator and n8n owner
**Refs:** R-06, W1.1, W1.3, W1.5, W1.6, W1.9, W2.5, X-01, X-04, X-05, X-32, C9, C11, C13, C14, D44
**Files:** `docs/decisions.md` (A81–A83), `docs/integration-backlog.md`, `CONTRIBUTING.md` (Troubleshooting); n8n's routing table in `nodes/core/n8n/workflows/lib-config.json` (branch `n8n`)

Hi Daniel,

Thanks for the R-06 spec and the source-IP test. They made this straightforward. Below: R-06 is done, your two core-only findings are fixed, and I have routing questions for your rule plan.

### 1. R-06 is on `main`: your W1.1 can start

Built exactly as your spec (A81):

- **Per machine:** optional `SYSLOG_ALLOWED_IPS` in `topology.env` (commented out in `topology.env.example`).
- **Rendered:** to `WAZUH_SYSLOG_ALLOWED_IPS` in `nodes/core/.env`. **Empty by default**, meaning "only the manager's own Docker networks". No `172.16.0.0/12`, no other default.
- **Format:** comma-separated IPv4 addresses or CIDRs, no spaces, e.g. `192.168.1.1,10.0.5.0/24`.
- **Validation:** `render-env.sh` refuses the value **before writing any file**, with an ERROR line, when it has: a space; an empty entry (`a,,b`, trailing comma); an entry that isn't `a.b.c.d` or `a.b.c.d/n` (including IPv6); an octet above 255 or a prefix above /32; an octet with leading zeros (`010`; a plain `0` is fine); any `/0`; a prefix below /8 (`10.0.0.0/8` is still accepted); any `0.x.x.x` entry, at any prefix.

  Your entrypoint can count on these rules for anything rendered through `render-env.sh`, but should still fail closed on its own, as you planned.

**Your next step (W1.1):** pass `WAZUH_SYSLOG_ALLOWED_IPS` to the manager in `nodes/core/wazuh/compose.yml` and add `30-syslog-allowed-ips.sh` as you described (own subnets always; fail closed on an invalid value). The distributed-mode question (do LAN senders keep their real source IP?) stays open for your W4.5, as you proposed.

### 2. Your two core-only findings: done

- **Grafana login in `healthcheck.sh` (A82):** the first try now uses `--max-time 20`; if it fails, it waits 5 s and retries once. A slow first request on `low` no longer reads as a failure.
- **Stale `THEHIVE_N8N_API_KEY` (A83):** `render-env.sh` now prints an INFO line when it renders `THEHIVE_ENABLED=true`. In single-host mode, clearing the key only in `nodes/core/.env` doesn't work, because the next render copies it back from `nodes/cases/.env`. To go core-only: empty `THEHIVE_N8N_API_KEY` in **both** `nodes/core/.env` and `nodes/cases/.env`, run `scripts/render-env.sh`, then `scripts/bootstrap.sh core`. It's in CONTRIBUTING.md, "Troubleshooting".

You can set both request files (`request-integrator-r06-...` and `request-integrator-core-only-findings.md`) to `Status: done`.

### 3. Routing: questions for your rule plan (W1.3, X-04, due 2026-10-20)

n8n's Router de Playbooks is built (branch `n8n`, merging at checkpoint 1). It picks the TheHive case template using Park's table (ALERT-FORMAT §3). Four rows are active. Five rows are *proposed* and wait on your rule IDs: until you confirm them, a match is only recorded and the alert goes to `wazuh-generic`.

1. **suspicious-login:** what is the rule ID of your W2.2 rule (login success after failures)? Does built-in 40112 fire in our setup? Will your rules carry `T1078` in `rule.mitre.id`?
2. **privilege-escalation:** do sudo failures arrive with the group `sudo` plus `authentication_failed` or `authentication_failures`? Which rule IDs? Do they carry `T1548`?
3. **account-change:** are the groups `adduser` / `addgroup` (e.g. rule 5902)? Any other rules or groups to add?
4. **ioc-match:** will your W6.4 / C14 rules (103xxx) use the group `misp` or `ioc`?
5. **network-scan:** do pfSense alerts carry the group `pfsense`? Which W4.3 rule IDs (104xxx) mean port scan or repeated blocks, and do they carry `T1046`?
6. **Active ssh row:** please confirm the sshd groups (`authentication_failed`, `authentication_failures`, `invalid_login`) and `T1110` in `rule.mitre.id`.

### 4. Still open from my 2026-09-30 memo (`n8n-requests-2026-09-30.md`)

| # | What | Due |
|---|---|---|
| 4, 7 | `trigger.sh --scenario` (W1.5). Please make `ioc-ip` use **`203.0.113.66`**: n8n's enrichment now finds it in MISP, so that scenario will exercise the whole chain | **2026-10-09** |
| 5 | Attack-start marker + its low-noise rule (X-32, W1.6). Without it C11 has no MTTD | before 2026-10-20 |
| 1–3 | Field list agreement (`WAZUH-FIELDS.md`, W2.5), `<mitre>` blocks in custom rules, standard field names | 2026-10-20 |
| 6 | Should SCA reach n8n? (n8n still skips the `sca` group) | 2026-10-20 |
| 9 | C14 design with Diego | **2026-10-16** |

### 5. Contracts waiting on you

- **C9** (Phase 2): please acknowledge the separate `n8n-response` user (D44), and update W7.1 and your README's C9 row. The row still says it "extends `n8n-api`'s role".
- **C11** and **C13:** acknowledgement of the indexer parts (PROJECT.md 5).
- **C12** was rejected (D47): nothing for you to build.

Thanks!
Inigo
