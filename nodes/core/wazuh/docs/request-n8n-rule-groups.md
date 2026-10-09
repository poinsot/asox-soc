# Request: agree the rule groups and rule IDs n8n and TheHive route on

**To:** Inigo (@poinsot), n8n owner; Park (@Jinhyuk-P), TheHive owner
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-05
**Refs:** W1.3, X-04, D-N2 (n8n routing key), N8N-1.3 (router), ALERT-FORMAT.md §3 and T2.6 (case templates), ALERT-TO-THEHIVE.md §3
**Status:** sent (2026-10-07, with the checkpoint PR)

## What I need

Read the proposal in the Wazuh README, section **"Rules: ID plan, files and groups"** ([README.md](../README.md#rules-id-plan-files-and-groups-w13)), and confirm it or say what to change. In short:

1. **Groups:** every custom rule carries `asox`, one source group (`test`, `linux`, `windows`, `suricata`, `router`, `pfsense`, `misp_ioc`), and **Wazuh's own standard group names** for what it detects (`sshd`, `authentication_failures`, `authentication_success`, `sudo`, `adduser`, `syscheck`, `rootcheck`, `malware`, `ids`…).
   - So your current matches keep working unchanged: n8n's `pb-*` routing, and Park's AF §3 (`ssh-bruteforce` on `sshd` + `authentication_*`, `malware-detection` on `rootcheck`/`malware`/`virustotal`, `ids-network-alert` on `ids`/`suricata`).
   - There are only two new names: `attack_start` (lab marker) and `misp_ioc` (C14).
2. **Rule IDs:** one range per source. Most relevant to you:

   | Range | Source |
   |---|---|
   | 1001xx | tests and markers |
   | 1002xx | Linux auth |
   | 101xxx | Suricata |
   | 103xxx | pfSense |
   | 108xxx | MISP IOC matches |
   | 109xxx | tuning |

   Built-in rules (e.g. 5763, 86601) keep their IDs. All IDs stay numeric, so Park's integer `wazuh-rule-id` keeps working.
3. **Stability:** once on `main`, an ID, a group or a file name is never renamed or reused.

## Questions

- **Inigo:** for D-N2, is "groups first, then a short rule-ID map" what the router expects? Do you want a group for the playbook itself (e.g. `pb_ssh_bruteforce`)? I'd rather not: routing stays in n8n's data, not in my rules.
- **Park:** in AF §3, should `firewall_drop` / `recon` (pfSense scans, M4) get their own template, or stay on `wazuh-generic`?

## Update 2026-10-07: answers to Inigo's routing questions

Inigo's questions of 2026-10-06 (routing rows) are answered in [integrator-requests-2026-10-06.md](integrator-requests-2026-10-06.md), "Answers" A1–A6, from live alerts. **Park:** ALERT-FORMAT.md §3 needs the same fixes as n8n's table:

1. **Order:** "first match wins", and 40112 (failures then success, level 12) carries `T1110` as well as `T1078`, so the `ssh-bruteforce` row takes it. Move **`suspicious-login` above `ssh-bruteforce`**, and match it on rule 40112, not on `T1078` alone: every normal SSH login (5715) also carries `T1078`.
2. **privilege-escalation:** sudo failures (5404) carry only `syslog,sudo`, with no `authentication_*` group. The `T1548` clause matches them (T1548.003).
3. **account-change:** the group is `adduser` only. `addgroup` doesn't exist in Wazuh: new groups (5901) are `adduser` too, and 5901 has no MITRE ID.
4. **ioc-match:** group **`misp_ioc`**, range **108xxx**. Put it above `ssh-bruteforce` and `ids-network-alert`, so an IOC match wins.
5. **network-scan:** pfSense is range **103xxx** (routers 102xxx). Scan rules carry `pfsense`, `recon` and T1046.

## Update 2026-10-08: first custom detection rules (W2.2)

Now in `rules/1002-linux-auth.xml` (catalog: README "Detection catalog"):

| Rule | Level | Groups | MITRE | Route it to |
|---|---|---|---|---|
| 100200 SSH login as root | 10 | `asox,linux,sshd,authentication_success` | T1078.003 | **`suspicious-login`**: please add it to that row's `rule_ids` with 40112 (`T1078.003` would also match a `T1078` prefix, so if you keep the prefix clause this already works) |
| 100211 usermod: user added to a privileged group | 10 | `asox,linux,adduser,account_changed` | T1098 | `account-change` (group `adduser` already matches) |
| 100212 gpasswd: user added to a privileged group | 10 | same | T1098 | `account-change` |

`new-user` now ends with 100211 (the new account goes into `sudo`), and there's a new scenario, `root-login` (100200), for fixtures. Privileged groups: sudo, wheel, admin, root, docker, lxd.

## Why

n8n's router (N8N-1.3) and TheHive's template choice (T2.6) both key on `rule.groups`. If I invented my own group names, both would miss my alerts silently: `pb-generic` and `wazuh-generic` would take everything.

## By

Checkpoint 1, **2026-10-20** (X-04). No contract change: C1's payload is unchanged; this documents the values inside it.
