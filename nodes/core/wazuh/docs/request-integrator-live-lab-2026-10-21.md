# Live lab on Monday 2026-10-26: the SOC machine must accept the lab devices

**To:** Inigo (@poinsot), integrator (he sets up the SOC machine)
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-21
**Refs:** W4.1, W4.4, W4.5, W7.3, D16 (single binds 127.0.0.1), PROJECT.md 7 (A71, WSL firewall), `nodes/core/wazuh/ENROLLMENT.md`
**Status:** draft

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

1. **The manager's ports on the LAN address:** 514/udp, 1514/tcp, 1515/tcp. As far as I can see in `render-env.sh`, `BIND_ADDR` is `0.0.0.0` only with `DEPLOY_MODE=distributed`. Is `distributed` with `CORE_HOST`, `CASES_HOST` and `INTEL_HOST` all set to the SOC machine's LAN IP supported on one machine, or do you prefer another way? Your call; Wazuh only needs those three ports.
2. **`SYSLOG_ALLOWED_IPS`** = the OPNsense, router and switch addresses (or the lab LAN, e.g. `192.168.1.0/24`). Without it the manager drops their syslog (W1.1).
3. **WSL:** `networkingMode=mirrored` and `windows/firewall-rules.ps1` (A71). From another lab machine, `nc -vz <SOC IP> 1515` and `nc -vzu <SOC IP> 514` should connect.
4. **The enrollment password** (`WAZUH_ENROLLMENT_PASSWORD` in `nodes/core/.env`) for me on the day, to enroll the sensor and the victim. Don't put it in chat; I'll read it on the machine.
5. **Time together before Monday** (about 1 hour, e.g. Saturday or Sunday), with the machine in the lab: I enroll the two agents, point the three devices at it, and run the attacks once.

## One open point to check together (W4.5)

Whether a LAN sender keeps its real address through Docker's published 514/udp in this setup. If Docker rewrites it to the gateway, syslog is still accepted (the gateway is in the manager's own networks), but `location` shows the gateway instead of the device. For the demo that's cosmetic. I'll look at it on the machine.

## What is ready on my side (branch `wazuh`, to merge before Monday)

- OPNsense: real 26.7 captures pinned as tests (`tests/cases/1030-opnsense.cases`).
- Cisco IOS: user and source decoded on logins, brute force 102000, device login block 102001, port security 102010, failed login 4724 lowered to 5; `trigger.sh --scenario router-bruteforce`.
- Victim web server: the `linux-servers` group now reads `/var/log/nginx/access.log` and `/var/log/apache2/access.log`, so a SQL injection from Kali gives 31103 / 31152.
- Rule tests 84/84; demo script `tests/demo.sh` and `DEMO.md` as the fallback if a device fails on the day.
