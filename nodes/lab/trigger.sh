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
#   new-user                5901, 5902 level 8: a new group and user "svc-backup"
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
SCENARIOS="ssh-bruteforce ssh-success-after-fail sudo-fail new-user ioc-ip"

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; }

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
      echo "$t $host useradd[$(( pid + 1 ))]: new user: name=svc-backup, UID=1001, GID=1001, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/0$run" ;;
    ioc-ip)
      for i in {1..8}; do echo "$t $host sshd[$pid]: Failed password for invalid user admin from 203.0.113.66 port $(( 42000 + i )) ssh2$run"; done ;;
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
  events "$scenario" "$id" | send
  (( print )) || echo "Scenario $scenario sent: run id=$id" >&2
fi
(( print )) || printf '%s\n' "$id"
