# Live lab on Monday 2026-10-26: the SOC machine must accept the lab devices

**To:** Inigo (@poinsot), integrator (he sets up the SOC machine)
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-21
**Refs:** W4.1, W4.4, W4.5, W7.3, D16 (single binds 127.0.0.1), PROJECT.md 7 (A71, WSL firewall), `nodes/core/wazuh/ENROLLMENT.md`
**Status:** sent (2026-10-21)

## Why

For the FASE 2 presentation the physical lab runs live: a Cisco 2900 router, a Catalyst 2960 switch (SPAN), and five computers. They are the SOC (your machine, `full`), the OPNsense firewall, the Suricata sensor, the victim and the Kali attacker. Real attacks must reach Wazuh from real devices:

| Sender | To the SOC machine | What |
|---|---|---|
| OPNsense (`192.168.1.1` in the lab) | **514/udp** | syslog (tested with OPNsense 26.7 on 2026-10-21: decodes, scan → 103000) |
| Cisco router and switch | **514/udp** | syslog (`rules/1020-router.xml`, new) |
| Suricata sensor VM (`sensor-suricata`, group `network-sensors`) | **1515/tcp** once, **1514/tcp** | Wazuh agent 4.14.8 |
| Victim (Ubuntu Server, group `linux-servers`) | **1515/tcp** once, **1514/tcp** | Wazuh agent 4.14.8 |

In `single` mode these ports listen on `127.0.0.1` only (D16), so none of the lab devices can reach Wazuh.

## What I need on the SOC machine

1. **Distributed mode on your machine, all hosts on its LAN IP.** Wazuh needs 514/udp, 1514/tcp and 1515/tcp on the LAN address, and `BIND_ADDR` is `0.0.0.0` only with `DEPLOY_MODE=distributed`. A single machine with every `*_HOST` on its own LAN IP is the step 1.8 setup (2026-09-26: C1–C8 passed through published ports only), so it needs nothing new:

   ```env
   DEPLOY_MODE=distributed
   CORE_HOST=<SOC machine LAN IP>
   CASES_HOST=<same IP>
   INTEL_HOST=<same IP>
   SYSLOG_ALLOWED_IPS=192.168.1.0/24   # the lab LAN, or its real subnet
   ```

   Then `render-env.sh`, the MISP certificate and the node restarts as in step 1.8.
2. **`SYSLOG_ALLOWED_IPS`** = the whole lab LAN (above). Without it the manager drops the OPNsense, router and switch syslog (W1.1).
3. **WSL:** `networkingMode=mirrored`, the lab network marked *Private* in Windows (the rules use the `Domain,Private` profiles), and `windows/firewall-rules.ps1` with all nodes (A71). From another lab machine, `nc -vz <SOC IP> 1515` and `nc -vzu <SOC IP> 514` should connect.
4. **The enrollment password** (`WAZUH_ENROLLMENT_PASSWORD` in `nodes/core/.env`) for me on the day, to enroll the sensor and the victim. Don't put it in chat; I'll read it on the machine.
5. **Time together before Monday** (about 1 hour, e.g. Saturday or Sunday), with the machine in the lab: I enroll the two agents, point the three devices at it, and run the attacks once.

## One open point to check together (W4.5)

Whether a LAN sender keeps its real address through Docker's published 514/udp in this setup. If Docker rewrites it to the gateway, syslog is still accepted (the gateway is in the manager's own networks), but `location` shows the gateway instead of the device. For the demo that's cosmetic. I'll look at it on the machine.

## Open on purpose, hardened later

For Monday the setup stays as open as possible, so a failure is never a filter: every published port on the lab LAN and syslog from the whole LAN. This is fine only on the closed lab network. After the demo, back to `single` and `firewall-rules.ps1 -Remove` when the machine leaves the lab. Filters to add one at a time, testing each, once the chain works:

- `firewall-rules.ps1 -Nodes core`: TheHive, Cortex and MISP closed to the LAN; the nodes still talk inside the machine.
- `SYSLOG_ALLOWED_IPS` narrowed to the OPNsense, router and switch addresses.
- 3000, 5678 and 55000 reachable only from the lab subnet or an admin address (needs a remote-address option in `firewall-rules.ps1`, your file).
- 1515 closed once the agents are enrolled.
- Production design for the FASE 2 document: a SOC VLAN with inter-VLAN ACLs (collection ports from monitored VLANs, consoles from the analyst VLAN only).

## What is ready on my side (branch `wazuh`, to merge before Monday)

- OPNsense: real 26.7 captures pinned as tests (`tests/cases/1030-opnsense.cases`).
- Cisco IOS: user and source decoded on logins, brute force 102000, device login block 102001, port security 102010, failed login 4724 lowered to 5; `trigger.sh --scenario router-bruteforce`.
- Victim web server: the `linux-servers` group now reads `/var/log/nginx/access.log` and `/var/log/apache2/access.log`, so a SQL injection from Kali gives 31103 / 31152.
- Rule tests 84/84; demo script `tests/demo.sh` and `DEMO.md` as the fallback if a device fails on the day.
