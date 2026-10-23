# Lab day checklist: connect each machine, check it reaches Wazuh

**Owner:** Daniel (@dmelgar1110). **For:** the physical-lab demo (2026-10-23, then the FASE 2 presentation on 2026-10-26).
**Setup:** a Catalyst 2960 switch and four computers: SOC, victim, Kali, and one PC running two VirtualBox VMs (OPNsense and the Suricata sensor). Optional: the Cisco 2900 router.
**Attacks:** `docs/attack-playbook-2026-10-26.md`. This file is only about getting each machine connected and proving its events arrive.

Run every `wazuh-query.sh` and `docker exec` below **on the SOC machine**, from the repo root. `<mgr>` is `asox-core-wazuh-manager-1`.

## 0. Addresses (fill in first)

| Machine | Address | Switch port | Notes |
|---|---|---|---|
| SOC (Inigo's machine) | `<SOC_IP>` | | `CORE_HOST`, all `*_HOST` |
| Victim (Ubuntu Server) | `<VICTIM_IP>` | `Gi0/<V>` | the SPAN source |
| Kali | `<KALI_IP>` | | **no Wazuh agent** (n8n never blocks an agent's address) |
| VM PC, NIC 1 (built-in) | | | OPNsense and Suricata adapter 1, bridged |
| VM PC, NIC 2 (USB) | no IP | `Gi0/<S>` | SPAN destination, Suricata adapter 2 only |
| OPNsense VM | `192.168.1.1` | (via NIC 1) | |
| Suricata VM, adapter 1 | `<SENSOR_IP>` | (via NIC 1) | agent `sensor-suricata` |
| Catalyst 2960 | `<SWITCH_IP>` (VLAN 1) | | syslog to the SOC |

All on one subnet, e.g. `192.168.1.0/24`. Static addresses are fine.

## 1. Order

Do the steps in this order. Each one ends with a check; don't go on until it passes.

| # | Machine | Time |
|---|---|---|
| 1 | Switch (addresses, SPAN, logging) | 10 min |
| 2 | SOC (Inigo): distributed mode, ports, n8n C9 settings | 20 min |
| 3 | Victim | 20 min |
| 4 | VM PC: OPNsense | 10 min |
| 5 | VM PC: Suricata sensor | 20 min |
| 6 | Kali | 5 min |
| 7 | Final check, 15 min before the demo | 10 min |

## 2. Switch (Catalyst 2960)

```
configure terminal
interface vlan 1
 ip address <SWITCH_IP> 255.255.255.0
 no shutdown
monitor session 1 source interface Gi0/<V> both
monitor session 1 destination interface Gi0/<S>
service timestamps log datetime msec
logging host <SOC_IP>
logging trap informational
login block-for 60 attempts 5 within 30
login on-failure log
login on-success log
end
```

SSH or telnet to the switch must be enabled for the login logs (`line vty 0 4`, `login local`, a local user).

**Check:**
- `show monitor session 1`: source `Gi0/<V>` (Both), destination `Gi0/<S>`.
- `show logging | include Logging to`: `<SOC_IP>`.
- Once the SOC is up (step 2), log in to the switch with a wrong password from Kali: `scripts/wazuh-query.sh -s 5m -r 4724` shows it (level 5).

## 3. SOC (Inigo)

His part: `request-integrator-live-lab-2026-10-21.md` and the n8n README "Response actions (C9 v0)".
- `DEPLOY_MODE=distributed`, every `*_HOST=<SOC_IP>`, `SYSLOG_ALLOWED_IPS=192.168.1.0/24`, `render-env.sh`, `soc.sh up`, `windows/firewall-rules.ps1` as Administrator, the lab network marked *Private*.
- n8n lib-config: `mode: 'live'`, `protected_cidrs` with `<SOC_IP>/32`, `192.168.1.1/32`, `<SWITCH_IP>/32`, `<SENSOR_IP>/32` (**never** the whole subnet: Kali would be protected too). Then `scripts/n8n-import.sh nodes/core/n8n/workflows/lib-config.json`. **This is the only guard for C9**: Wazuh's `<white_list>` doesn't apply to API commands.

**Check, from Kali:**
- `nc -vz <SOC_IP> 1515` and `nc -vz <SOC_IP> 1514` connect.
- `nc -vzu <SOC_IP> 514` reports nothing refused.
- On the SOC: `scripts/healthcheck.sh` all PASS.

## 4. Victim (Ubuntu Server)

```bash
sudo apt install -y openssh-server nginx iptables
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
# Real-time FIM watches only folders that exist when the agent starts.
sudo mkdir -p /root/.ssh /etc/sudoers.d /etc/cron.d && sudo chmod 700 /root/.ssh
```

Wazuh agent: ENROLLMENT.md "Linux server", with:
- `WAZUH_MANAGER='<SOC_IP>'`;
- `WAZUH_AGENT_GROUP='linux-servers,asox-response'`;
- `WAZUH_AGENT_NAME='srv-victim'` (`srv-`: an alert if it stops reporting);
- **`wazuh-agent=4.14.8-1`**.

Do it **early**: a later group change reloads the agent, and a C9 command sent meanwhile is lost.

**Check:**
- `docker exec <mgr> /var/ossec/bin/agent_control -l`: `srv-victim` is `Active`.
- `docker exec <mgr> /var/ossec/bin/agent_groups -s -i <id>`: `linux-servers`, `asox-response`.
- On the victim, `logger -p auth.notice "asox-test: ASOX_TEST_EVENT id=lab-$(date +%s)"`. Then `scripts/wazuh-query.sh -s 5m -r 100100` shows **one** alert (two would mean a duplicated log source, see Troubleshooting).
- On the victim, `echo test | sudo tee /etc/cron.d/asox-check && sudo rm /etc/cron.d/asox-check`. Then `scripts/wazuh-query.sh -s 5m -a srv-victim` shows 100302 and 553.

## 5. VM PC: OPNsense

VirtualBox: one adapter, **Bridged** to NIC 1. LAN `192.168.1.1/24`.
- System › Settings › Logging › Remote: UDP(4), host `<SOC_IP>`, port 514, levels info…emergency, **rfc5424 unticked**.
- Firewall › Rules › LAN, **above** "Default allow LAN": Block, TCP, source LAN net, destination This Firewall, ports 1024–65535, **Log**, description "ASOX prueba escaneo". Apply. (Without it, a scan from the LAN leaves no block lines.)

**Check:**
- From Kali, `nmap -sS -p 1024-1100 192.168.1.1`: Firewall › Log Files › Live View shows red blocks, and `scripts/wazuh-query.sh -s 5m -r 103000` shows the scan (from `<KALI_IP>`).
- If nothing arrives: Wazuh drops syslog from addresses outside `SYSLOG_ALLOWED_IPS`, and Windows on the SOC may block 514/udp (step 3).

## 6. VM PC: Suricata sensor

VirtualBox, VM powered off, Settings › Network:
- **Adapter 1: Bridged to NIC 1** (built-in). Gets `<SENSOR_IP>`, for apt and the Wazuh agent.
- **Adapter 2: Bridged to NIC 2 (the USB adapter on the SPAN port)**, Advanced › **Promiscuous Mode: Allow All**, Cable Connected.
- On Windows, NIC 2 needs no IP (it only carries the mirror).

In the VM:
- Adapter 2 without an IP and in promiscuous mode (`asox-sniff.service`, made earlier).
- Suricata as in ENROLLMENT.md "Suricata sensor VM": `HOME_NET: "[<VICTIM_IP>]"` (**the victim only**), `af-packet` on adapter 2, `eve-log` types `- alert` only, `2009582` in `/etc/suricata/enable.conf` then `suricata-update`.
- Agent: `WAZUH_AGENT_GROUP='network-sensors'`, `WAZUH_AGENT_NAME='sensor-suricata'`, `wazuh-agent=4.14.8-1`.

**Check:**
- In the VM, `sudo tcpdump -ni <adapter 2> host <VICTIM_IP>` shows traffic when Kali pings the victim (the SPAN works).
- From Kali, `sudo nmap -sS -p 1-1024 <VICTIM_IP>`: `sudo tail -f /var/log/suricata/eve.json` shows alerts, and `scripts/wazuh-query.sh -s 5m -r 101010` shows them.
- `agent_control -l`: `sensor-suricata` is `Active`.

## 7. Kali

`sudo apt install -y sshpass nmap sqlmap curl` (most come with Kali). **No Wazuh agent.** Check: `ping <VICTIM_IP>`, `curl -s http://<VICTIM_IP> | head -3` (nginx page).

## 8. Optional: Cisco 2900 router

The same `logging host`, `login on-failure log`, `login block-for` lines as the switch. A wrong password to it gives 4724; five from one address give 102000.

## 9. Fifteen minutes before the demo

- All agents `Active`: `agent_control -l` (`srv-victim`, `sensor-suricata`).
- **No attacks in the last 5 minutes**: 5763, 5712 and 31152 stay quiet for 60–120 s after firing.
- `scripts/contracts-check.sh --only C9` PASS (it blocks 192.0.2.1 for 60 s on an `asox-response` agent).
- Browser tabs: Grafana SOC Status (last 15 min, refresh 10 s) and Attack Scenarios; n8n `recv-wazuh-alert` executions; TheHive Alerts.
- **C9 last** in the demo: the block cuts Kali off the victim for 300 s.
- Fallback if a machine fails: `nodes/core/wazuh/tests/demo.sh --from <step>` on the SOC (the lab container's version of each attack).

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Agent never `Active` | ports 1514/1515 blocked, wrong manager address or password, agent newer than 4.14.8 | `nc -vz <SOC_IP> 1515` from the machine; `/var/ossec/logs/ossec.log` on it |
| One event, two alerts on the victim | an old `linux-servers` (with `auth.log`) on the manager | the SOC needs Wazuh's PR with "journal only" merged, then `soc.sh up` |
| FIM shows nothing for `/root/.ssh` | the folder didn't exist when the agent started | create it, `sudo systemctl restart wazuh-agent` |
| No 101010 | `HOME_NET` is the whole LAN; SPAN not on the victim's port; adapter 2 not "Allow All" | step 6 checks, in order |
| No 103000 | block rule missing, below "allow", or Log unticked; OPNsense IP not allowed | step 5 |
| No 4724 from the switch | `login on-failure log` missing; syslog source not allowed | step 2 |
| C9 `(live): sent` but no block | agent group changed just before; `iptables` missing | `sudo tail /var/ossec/logs/active-responses.log` on the victim |
| C9 refused `protected` | Kali's address inside `protected_cidrs` | use `/32` entries only (step 3) |
