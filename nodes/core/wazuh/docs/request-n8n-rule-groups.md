# Request: agree the rule groups and rule IDs n8n and TheHive route on

**To:** Inigo (@poinsot), n8n owner; Park (@Jinhyuk-P), TheHive owner
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-05
**Refs:** W1.3, X-04, D-N2 (n8n routing key), N8N-1.3 (router), ALERT-FORMAT.md §3 and T2.6 (case templates), ALERT-TO-THEHIVE.md §3
**Status:** draft

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

## Why

n8n's router (N8N-1.3) and TheHive's template choice (T2.6) both key on `rule.groups`. If I invented my own group names, both would miss my alerts silently: `pb-generic` and `wazuh-generic` would take everything.

## By

Checkpoint 1, **2026-10-20** (X-04). No contract change: C1's payload is unchanged; this documents the values inside it.
