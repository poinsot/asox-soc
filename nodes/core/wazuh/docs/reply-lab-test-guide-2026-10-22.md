# Review of "ASOX SOC: lab test guide for the n8n playbooks" (main `da333f2`)

**To:** Inigo (@poinsot), n8n owner and integrator
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-22
**Refs:** C9 v0 (D44, A105), W7.1, W7.2, W3.7, X-23; Wazuh commits `3f7b170`, `bea67f1` and this PR
**Status:** draft

The guide matches the Wazuh side. Below, the points it marks **(unconfirmed)** that I tested on 2026-10-22, plus three changes on my side that alter it. I tested on an Ubuntu 24.04 agent with systemd and rsyslog (a stand-in for the victim, agent 4.14.8 in `linux-servers,asox-response`), the lab agent, and `wazuh-logtest`.

## Changes on the Wazuh side that alter the guide

1. **§1.2, §1.6, §3.12 "two identical alerts": confirmed, then fixed.** On Ubuntu 24.04 the agent's installer adds a `journald` source by itself, and `linux-servers` added `/var/log/auth.log`. One failed SSH password gave **two 5760** (`location` `/var/log/auth.log` and `journald`). **`linux-servers` now reads the journal only** (`bea67f1`), and one failed password gives one alert. In §1.2 the group's logs are: journald, `/var/log/nginx/access.log`, `/var/log/apache2/access.log`. §1.6's count check should now always give one.
2. **§3.1 extra PAM alerts: confirmed, then silenced for sshd.** A real wrong SSH password logs sshd's `Failed password` (5760) **and** PAM's `pam_unix(sshd:auth): authentication failure` (5503). Ten of each gave 5763 **and 5551** (level 10, T1110, route `login-bruteforce`, uncorrelated). New tuning rule **109020** (level 0) silences 5551 when the line is `(sshd:auth)`. One SSH brute force now gives one brute-force alert, the 5763. PAM brute force on other services (`su`) still gives 5551. 40111 did not fire in that stream. Pinned in `tests/cases/builtin-linux.cases`.
3. **§3.3, §4: `<white_list>` does not apply to API commands. Tested.** `firewall-drop60` for `192.168.1.1` (in the manager's `<white_list>`) through the API as `n8n-response` was **applied** on the lab agent, and reverted after 60 s. **`protected_cidrs` is the only guard**, so the demo-day lib-config edit is mandatory, not optional. README C9 row and `ossec.conf` comment updated.

## Points marked (unconfirmed), now checked

| § | Point | Result |
|---|---|---|
| 3.4 | Root login after failures from the same source: 100200 or 40112? | **40112** (level 12). Logtest: 8 failures for root, then `Accepted password for root` → 5763, then 40112. The guide's advice (root login from a clean source) is right |
| 3.6 | How many 550 after `useradd -m` + `usermod -aG sudo` | **Three**: `/etc/passwd`, `/etc/shadow`, `/etc/group` (Ubuntu 24.04 agent), plus 5901, 5902, 100211 |
| 3.9 | Does a `logger` line decode on newer Ubuntu (ISO timestamps in `auth.log`)? | No longer relevant: the agent reads the journal, not `auth.log`. A `logger -p auth.info -t "sshd[…]" "Failed password …"` line came through the journal as decoder `sshd`, 5760 |
| 1.6 | Duplicates journald + auth.log | Confirmed, fixed (above) |
| 3.1 | PAM lines → 5503 / 5551 | Confirmed, 5551 silenced for sshd (above) |

## Other corrections

- **§4, Suricata on real networks: `HOME_NET` is the victim only**, e.g. `"[<VICTIM>]"`, not the lab LAN. ET SCAN rules fire only from `EXTERNAL_NET` into `HOME_NET`; with Kali inside a `/24` `HOME_NET` the scan gives no 101010 (ENROLLMENT.md and the Kali playbook updated, `3f7b170`).
- **§2 row 10, `network-scan` (103000) from the lab LAN:** OPNsense's "Default allow LAN" lets every packet to the firewall through, so a scan from Kali leaves no `block` lines. The demo needs a logged block rule (LAN net → This Firewall, TCP 1024–65535, Log) above it, and `nmap -p 1024-1100 192.168.1.1`.
- **§3.3, seeing the block:** besides `iptables -S`, the victim's agent logs built-in **651** "Host Blocked by firewall-drop Active Response" and **652** "Host Unblocked" (level 3, indexed, not forwarded), tested on the Ubuntu agent. Grafana's Recent alerts, `rule.id: 651 OR 652`, shows the block and its automatic removal. Pinned as tests.

Nothing else in the guide needs changing from the Wazuh side.
