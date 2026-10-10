# Enrolling endpoints and sensors

Owner: Daniel (@dmelgar1110), Wazuh. How to connect real machines to the ASOX Wazuh manager: Linux servers, Windows desktops, the Suricata sensor VM, and the OPNsense firewall. The lab agent (`nodes/lab/`) is the reference: it enrolls exactly this way.

## What every agent needs

| Value | Where to get it |
|---|---|
| **Manager address** | `single` mode: `127.0.0.1`, only from the same PC (Windows reaches WSL's ports through mirrored networking). `distributed` mode: the core machine's LAN IP (`CORE_HOST` in `topology.env`) |
| **Enrollment password** | `WAZUH_ENROLLMENT_PASSWORD` in `nodes/core/.env` on the core machine (D33). Without it, enrollment is refused |
| **Group** | `linux-servers`, `windows-desktops` or `network-sensors` (`groups/`). The manager pushes that group's `agent.conf`, so the agent needs no extra configuration |
| **Agent version** | **4.14.8**, the manager's version. An agent newer than the manager is refused; older ones work but miss features |
| **Ports** | 1515/tcp (enrollment, once) and 1514/tcp (events), from the agent to the manager |

**Other machines can only connect in `distributed` mode.** In `single` mode the ports listen on `127.0.0.1` (D16). For a VM on another computer, the core machine first needs:
1. `DEPLOY_MODE=distributed` and the `*_HOST` values in `topology.env`, then `./scripts/render-env.sh` and `./scripts/soc.sh up core`.
2. `windows/firewall-rules.ps1` run once as Administrator. WSL's Hyper-V firewall blocks inbound traffic by default (PROJECT.md 7, A71).

Check from the other machine: `nc -vz <core IP> 1515` and `nc -vz <core IP> 1514` both connect.

Every agent appears in `docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/agent_control -l` as `Active` once connected.

## Linux server (Ubuntu or Debian)

As root:

```bash
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER='<manager address>' \
WAZUH_REGISTRATION_PASSWORD='<enrollment password>' \
WAZUH_AGENT_GROUP='linux-servers' \
WAZUH_AGENT_NAME="$(hostname)" \
  apt-get install -y wazuh-agent=4.14.8-1
apt-mark hold wazuh-agent              # stays at the manager's version
systemctl daemon-reload && systemctl enable --now wazuh-agent
```

- **What the group adds:** `auth.log` and journald, plus real-time integrity checks on `/etc/passwd`, `/etc/shadow`, `/etc/group`, sudoers, SSH keys, cron and systemd units (`groups/linux-servers/agent.conf`).
- **How to check it:**
  1. `id=$(nodes/lab/trigger.sh --scenario persistence)` shows what the alerts look like on the lab agent.
  2. On the new server, `sudo touch /etc/sudoers.d/zz-test` gives rule 100300 within seconds.
  3. Delete the file afterwards.

## Windows desktop

In PowerShell **as Administrator**:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q `
  WAZUH_MANAGER='<manager address>' `
  WAZUH_REGISTRATION_PASSWORD='<enrollment password>' `
  WAZUH_AGENT_GROUP='windows-desktops' `
  WAZUH_AGENT_NAME=$env:COMPUTERNAME
NET START WazuhSvc
```

- **What the group adds:** the PowerShell, Sysmon (if installed) and Defender channels, real-time integrity checks on the all-users Startup folder, and the `Run` / `RunOnce` registry keys. The agent's own configuration already reads the Security, System and Application channels.
- **How to check it:** run `runas /user:asox-nobody cmd` and type a wrong password, which gives a failed logon (Windows event 4625, built-in rule 60122, level 5). Several in a row give 60204 (level 10), which reaches n8n.
- **Your own Windows PC with the stack in `single` mode:** use `WAZUH_MANAGER='127.0.0.1'`. Mirrored networking forwards it to WSL. Tested 2026-10-10 (W5.5): agent `YOGA` (Windows 11 Home) in `windows-desktops`. Its first SCA scan came in at level 5, and 10 `runas` failures gave 60122 × 10 and **60204** (level 10, sent to n8n).

## Suricata sensor VM (VirtualBox)

The Phase 2 sensor: Suricata on its own Ubuntu VM, with a Wazuh agent in group `network-sensors` (D49, W7.3). The lab's Suricata container is the test version of the same thing.

**1. Network (VirtualBox, VM powered off), Settings → Network:**
- **Adapter 1:** NAT or Bridged, for management, updates and the connection to the Wazuh manager.
- **Adapter 2:** attached to the network to watch: the **Internal Network** the lab machines and OPNsense's LAN side share (e.g. `asox-lab`), or a Bridged adapter. Advanced → **Promiscuous Mode: Allow All**, and **Cable Connected**. Without "Allow All", the VM sees only its own traffic.
- In the VM, give adapter 2 no IP (it only listens): `ip link set <ifname> up promisc on`, made permanent in netplan with `dhcp4: false`.

**2. Suricata:**

```bash
add-apt-repository -y ppa:oisf/suricata-stable && apt-get update && apt-get install -y suricata
suricata-update                                    # ET Open rules
```

In `/etc/suricata/suricata.yaml`:

| Setting | Value |
|---|---|
| `vars.address-groups.HOME_NET` | the protected lab network, e.g. `"[192.168.10.0/24]"` (the LAN behind OPNsense). Not every private range: ET SCAN rules only fire for traffic from `EXTERNAL_NET` into `HOME_NET` |
| `af-packet` | `interface: <adapter 2 name>` |
| `outputs` → `eve-log` → `types` | keep only `- alert` (as in `nodes/lab/suricata/asox.yaml`) |

Then `systemctl enable --now suricata`. Refresh the rules daily: `suricata-update && systemctl reload suricata`, from cron.

**3. Wazuh agent:** the Linux steps above with **`WAZUH_AGENT_GROUP='network-sensors'`**. The group tells the agent to read `/var/log/suricata/eve.json` (`groups/network-sensors/agent.conf`); nothing else to configure.

**4. Check:** from a machine on the watched network, `curl "http://example.com/?q=uid=0(root)"` gives Suricata 2100498, which becomes ASOX rule 101001 (level 10). An `nmap -sS` of a host in `HOME_NET` gives 101010 (T1046, once SID 2009582 is enabled as in `nodes/lab/suricata/enable.conf`).

## OPNsense firewall

OPNsense sends syslog; it needs no agent. Steps in the README, "OPNsense firewall":
- remote logging over UDP to the core machine's port 514, BSD format (**not** RFC 5424);
- "Log packets matched from the default block rules";
- the firewall's IP in `SYSLOG_ALLOWED_IPS` on the core machine.

OPNsense also has a Wazuh agent plugin (`os-wazuh-agent`). It isn't needed here: syslog covers the firewall, and the sensor VM covers Suricata.

## Troubleshooting

- **The manager log shows `Invalid password provided by …`.** The agent's password file doesn't match `WAZUH_ENROLLMENT_PASSWORD`, often because a placeholder or a partial value was pasted. On 2026-10-10 the Windows agent's file held the 14 bytes of the text `<contraseña>`. Rewrite the file and restart the agent; no reinstall is needed. On Windows (PowerShell as Administrator, on the PC that runs WSL):
  ```powershell
  $p = (wsl -e sh -c "sed -n 's/^WAZUH_ENROLLMENT_PASSWORD=//p' ~/asox-soc/nodes/core/.env").Trim()
  Set-Content -Path 'C:\Program Files (x86)\ossec-agent\authd.pass' -Value $p -NoNewline -Encoding ascii
  Restart-Service WazuhSvc
  ```
  On Linux, the file is `/var/ossec/etc/authd.pass`; then `systemctl restart wazuh-agent`.
- **The agent stays `Pending` for a minute after enrolling:** it is receiving its group's configuration, then it restarts and shows `Active`.
- **The first minutes bring many SCA alerts (19007).** That's the first CIS scan, at level 5 since W2.7, so nothing reaches n8n.

## Removing or re-enrolling an agent

A reinstalled machine with the same name is refused while the manager still has the old registration. Remove the old one first:

```bash
docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/agent_control -l                 # find its ID
docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/manage_agents -r <agent-id>
```

To move an agent to another group: `docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/agent_groups -a -i <agent-id> -g <group> -q`.
