#!/usr/bin/env bash
# Produce test alerts (owner: Wazuh) by writing lines to the lab agent's
# monitored test log.
#
# Without --scenario: one line with the marker ASOX_TEST_EVENT. The manager's
# test rule 100100 (level 10) turns it into an alert, which is indexed and,
# above WAZUH_ALERT_MIN_LEVEL, forwarded to n8n (C1).
#
# With --scenario: the attack-start marker (rule 100101, level 3:
# "ASOX_ATTACK_START scenario=<name> id=<run id>"), then, a second later,
# realistic log lines of that attack, each ending in "asox_run=<run id>".
# Attacker addresses are documentation ranges; ioc-ip uses the MISP seed IOC.
#
#   scenario                expected alerts (built-in rules, Wazuh 4.14.8)
#   ssh-bruteforce          5763 level 10: 8 failed SSH passwords for root from 198.51.100.23
#   ssh-success-after-fail  5763 level 10, then 40112 level 12: the same, then a login from 198.51.100.24
#   sudo-fail               5404 level 10: 3 wrong sudo passwords by labuser
#   new-user                5901, 5902 level 8, then 100211 level 10: a new group and user
#                           "svc-backup", then added to group sudo (usermod)
#   root-login              100200 level 10: an SSH login as root from 198.51.100.25
#   ids-test                101001 level 10 (Suricata 2100498): an HTTP request carrying
#                           "uid=0(root)" from the lab agent to example.com (needs internet)
#   ids-scan                101010 level 10, T1046 (ET SCAN): an nmap SYN scan of the lab
#                           agent from a throwaway container on the lab network
#   persistence             100300, 100301, 100302 level 10: real file changes in the lab
#                           agent (sudoers.d, root's authorized_keys, cron.d), seen by
#                           real-time FIM (group linux-servers); each run adds new files
#   opnsense-scan           103000 level 10, T1046: OPNsense filterlog blocks of 10 ports
#                           from 203.0.113.77, sent as syslog to the manager's 514/udp
#   opnsense-gui-bruteforce 103011 level 10, T1110: 5 failed OPNsense web GUI logins from
#                           203.0.113.51, sent as syslog
# ids-test and ids-scan make real traffic that the Suricata sensor sees (W3.4);
# their alerts come from Suricata, so --print only shows the marker.
# The opnsense-* lines travel as real syslog from the lab container to
# WAZUH_MANAGER_ADDR:514 (W4.5), so they also test the allowed sources (W1.1).
#   ioc-ip                  5712 level 10: 8 failed SSH logins for invalid users from 203.0.113.66
# The brute-force rules (5763, 5712) stay quiet for 60 s after they fire, for
# every source address. So wait a minute before repeating a scenario, and
# between ssh-bruteforce and ssh-success-after-fail (both use 5763).
#
# Usage: nodes/lab/trigger.sh [--id ID] [--scenario NAME [--print]] [--list]
#   --id ID          event or run ID to embed (default: a new unique one)
#   --scenario NAME  write the attack scenario NAME (see above)
#   --print          with --scenario: print the lines instead of sending them
#   --list           list the scenario names
# Prints the ID on stdout, so scripts can capture it, e.g.
#   id=$(nodes/lab/trigger.sh) && scripts/wazuh-query.sh --rule 100100 --match "$id"
#   id=$(nodes/lab/trigger.sh --scenario ssh-bruteforce) && scripts/wazuh-query.sh --match "$id"
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_LOG=/var/log/asox-lab/test.log
SCENARIOS="ssh-bruteforce ssh-success-after-fail sudo-fail new-user ioc-ip root-login ids-test ids-scan opnsense-scan opnsense-gui-bruteforce persistence"
NMAP_IMAGE=${NMAP_IMAGE:-instrumentisto/nmap:7.98-r2}

# The comment block at the top of this file.
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

id="" scenario="" print=0
while (( $# > 0 )); do
  case $1 in
    --id) id=${2:?--id needs a value}; shift ;;
    --scenario) scenario=${2:?--scenario needs a name (--list shows them)}; shift ;;
    --print) print=1 ;;
    --list) tr ' ' '\n' <<<"$SCENARIOS"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
if [[ -n $scenario && " $SCENARIOS " != *" $scenario "* ]]; then
  echo "ERROR unknown scenario '$scenario'; one of: $SCENARIOS" >&2; exit 2
fi
(( print == 0 )) || [[ -n $scenario ]] || { echo "ERROR --print needs --scenario" >&2; exit 2; }
if [[ -z $id ]]; then
  if [[ -n $scenario ]]; then id=$(cat /proc/sys/kernel/random/uuid); else id="trig-$(date +%s)-$RANDOM"; fi
fi
[[ $id =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "ERROR --id may only contain letters, digits and . _ : -" >&2; exit 2; }

[[ -f $DIR/.env ]] || { echo "ERROR nodes/lab/.env not found; run scripts/soc.sh init core" >&2; exit 1; }
host=$(sed -n 's/^LAB_AGENT_NAME=//p' "$DIR/.env")

send() {  # appends stdin to the test log in the lab agent
  if (( print )); then cat; return; fi
  if ! docker compose --project-directory "$DIR" --env-file "$DIR/.env" \
      -f "$DIR/docker-compose.yml" exec -T lab-agent sh -c "cat >> $TEST_LOG"; then
    echo "ERROR could not write to the lab agent (is the lab node running? scripts/soc.sh up core)" >&2
    exit 1
  fi
}

ts() { date '+%b %e %H:%M:%S'; }

# The scenario's events, one per line. $1 = scenario, $2 = run ID.
events() {
  local t run=" asox_run=$2" pid=$(( 2000 + RANDOM % 30000 )) i
  t=$(ts)
  case $1 in
    ssh-bruteforce)
      for i in {1..8}; do echo "$t $host sshd[$pid]: Failed password for root from 198.51.100.23 port $(( 40000 + i )) ssh2$run"; done ;;
    ssh-success-after-fail)
      for i in {1..8}; do echo "$t $host sshd[$pid]: Failed password for labuser from 198.51.100.24 port $(( 41000 + i )) ssh2$run"; done
      echo "$t $host sshd[$pid]: Accepted password for labuser from 198.51.100.24 port 41009 ssh2$run" ;;
    sudo-fail)
      echo "$t $host sudo: labuser : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/bin/bash$run" ;;
    new-user)
      echo "$t $host groupadd[$pid]: new group: name=svc-backup, GID=1001$run"
      echo "$t $host useradd[$(( pid + 1 ))]: new user: name=svc-backup, UID=1001, GID=1001, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/0$run"
      echo "$t $host usermod[$(( pid + 2 ))]: add 'svc-backup' to group 'sudo'$run"
      echo "$t $host usermod[$(( pid + 2 ))]: add 'svc-backup' to shadow group 'sudo'$run" ;;
    ioc-ip)
      for i in {1..8}; do echo "$t $host sshd[$pid]: Failed password for invalid user admin from 203.0.113.66 port $(( 42000 + i )) ssh2$run"; done ;;
    root-login)
      echo "$t $host sshd[$pid]: Accepted password for root from 198.51.100.25 port 43001 ssh2$run" ;;
    opnsense-scan)
      for p in 21 22 23 25 80 110 139 443 445 3389; do
        echo "$t opnsense filterlog[$pid]: 84,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,block,in,4,0x0,,64,13567,0,DF,6,tcp,60,203.0.113.77,192.168.1.1,44322,$p,0,S,1406233372,,64240,,mss$run"
      done ;;
    opnsense-gui-bruteforce)
      for i in {1..5}; do echo "$t opnsense audit[$pid]: /index.php: Web GUI authentication error for 'root' from 203.0.113.51$run"; done ;;
  esac
}

compose() { docker compose --project-directory "$DIR" --env-file "$DIR/.env" -f "$DIR/docker-compose.yml" "$@"; }

# Sends stdin as syslog over UDP from the lab container to the manager's
# 514/udp, one datagram per line (facility local0, notice: <134>), the way a
# firewall sends its logs. The manager sees the lab agent's address, which
# is in the allowed sources (W1.1) in single-host mode.
syslog() {
  local mgr
  mgr=$(sed -n 's/^WAZUH_MANAGER_ADDR=//p' "$DIR/.env")
  compose exec -T lab-agent bash -c "while IFS= read -r l; do printf '<134>%s' \"\$l\" > /dev/udp/$mgr/514; done" \
    || { echo "ERROR could not send syslog to $mgr:514 from the lab agent" >&2; exit 1; }
}

# Network traffic for the IDS scenarios (seen by the suricata service).
# $1 = scenario, $2 = run ID (sent in the HTTP request, so the eve.json
# record can be tied to the run through its payload when needed).
traffic() {
  case $1 in
    ids-test)
      compose exec -T lab-agent curl -s -m 15 -o /dev/null \
        -A "asox-lab ids-test asox_run=$2" "http://example.com/?q=uid=0(root)" \
        || { echo "ERROR ids-test needs internet access from the lab agent (example.com)" >&2; exit 1; } ;;
    ids-scan)
      # The lab node's own network exists in both deployment modes.
      docker run --rm --network "$(sed -n 's/^SOC_INSTANCE=//p' "$DIR/.env")-lab_default" "$NMAP_IMAGE" \
        -sS -Pn -n -T4 -p 1-1024,1433,1521,3306 --max-retries 0 lab-agent >/dev/null \
        || { echo "ERROR ids-scan: could not run $NMAP_IMAGE on the lab network" >&2; exit 1; } ;;
    persistence)
      # What an attacker leaves behind. Real writes, so FIM sees them; names
      # carry the run ID, so every run adds new files (FIM rule 554).
      local r=${2:0:8}
      compose exec -T lab-agent sh -c "
        mkdir -p /root/.ssh && chmod 700 /root/.ssh
        echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASOXlabTESTkeyNOTreal attacker@asox-lab asox_run=$2' >> /root/.ssh/authorized_keys
        echo 'svc-backup ALL=(ALL) NOPASSWD:ALL # asox_run=$2' > /etc/sudoers.d/90-svc-backup-$r
        chmod 440 /etc/sudoers.d/90-svc-backup-$r
        echo '*/5 * * * * root /tmp/.update-$r # asox_run=$2' > /etc/cron.d/asox-update-$r
      " || { echo "ERROR persistence: could not write in the lab agent" >&2; exit 1; } ;;
  esac
}

if [[ -z $scenario ]]; then
  printf '%s\n' "$(ts) $host asox-test: ASOX_TEST_EVENT id=$id" | send
  echo "Test event sent: ASOX_TEST_EVENT id=$id" >&2
else
  # The marker goes first and a second ahead, so its time is the attack's start
  # (C11's t_attack_start) and every event of the run comes after it.
  printf '%s\n' "$(ts) $host asox-lab: ASOX_ATTACK_START scenario=$scenario id=$id" | send
  (( print )) || sleep 1
  case $scenario in
    ids-test|ids-scan|persistence) (( print )) || traffic "$scenario" "$id" ;;
    opnsense-*) if (( print )); then events "$scenario" "$id"; else events "$scenario" "$id" | syslog; fi ;;
    ssh-success-after-fail)
      # The login comes 2 s after the failures. Sent in the same burst, the
      # manager's parallel analysis can evaluate the login before it has
      # counted the 8th failure (5763), and 40112 then misses it (seen on a
      # fresh instance, 2026-10-11). A real attacker isn't that fast either.
      if (( print )); then events "$scenario" "$id"; else
        lines=$(events "$scenario" "$id")
        head -n -1 <<<"$lines" | send
        sleep 2
        tail -n 1 <<<"$lines" | send
      fi ;;
    *) events "$scenario" "$id" | send ;;
  esac
  (( print )) || echo "Scenario $scenario sent: run id=$id" >&2
fi
(( print )) || printf '%s\n' "$id"
