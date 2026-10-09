#!/bin/bash
# Run by the wazuh-manager image at every start, before Wazuh starts
# (/entrypoint-scripts/*.sh), after the config copy (05-restart-fixes.sh).
# Restricts the syslog listener (514/udp) to known senders (W1.1, R-06, A81):
#   1. always the subnets of the networks this container is attached to
#      (soc-net: the lab agent and Suricata; core's own network: senders
#      through the published port, which reach the manager from its gateway);
#   2. plus each entry of WAZUH_SYSLOG_ALLOWED_IPS (comma-separated IPv4
#      addresses or CIDRs, e.g. pfSense), from the optional SYSLOG_ALLOWED_IPS
#      in topology.env, validated by render-env.sh.
# Never writes 0.0.0.0/0. If the variable is invalid, only step 1 is applied
# (fails closed). Writes one <allowed-ips> per entry after the marker comment
# in the syslog <remote> block of ossec.conf.
set -euo pipefail
CONF=/var/ossec/etc/ossec.conf
MARK='ASOX-SYSLOG-ALLOWED-IPS'

# a.b.c.d or a.b.c.d/n, octets 0-255 without leading zeros, prefix 8-32,
# first octet not 0: the rules render-env.sh enforces (A81), checked again here.
valid() {
  local re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$' o
  [[ $1 =~ $re ]] || return 1
  for o in 1 2 3 4; do
    [[ ${BASH_REMATCH[o]} == 0 || ${BASH_REMATCH[o]} != 0* ]] || return 1
    (( 10#${BASH_REMATCH[o]} <= 255 )) || return 1
  done
  [[ ${BASH_REMATCH[1]} != 0 ]] || return 1
  [[ -z ${BASH_REMATCH[6]} ]] || (( 10#${BASH_REMATCH[6]} >= 8 && 10#${BASH_REMATCH[6]} <= 32 ))
}

# Hex fields of /proc/net/route are little-endian: 000012AC is 172.18.0.0.
hex_ip() { printf '%d.%d.%d.%d' "0x${1:6:2}" "0x${1:4:2}" "0x${1:2:2}" "0x${1:0:2}"; }
prefix() { local m=$(( 0x$1 )) n=0; while (( m )); do n=$(( n + (m & 1) )); m=$(( m >> 1 )); done; echo "$n"; }

allowed=()
while read -r iface dest _ _ _ _ _ mask _; do
  [[ $iface != Iface && $iface != lo && $dest != 00000000 && $mask != 00000000 ]] || continue
  allowed+=("$(hex_ip "$dest")/$(prefix "$mask")")
done < /proc/net/route

extra=${WAZUH_SYSLOG_ALLOWED_IPS:-}
if [[ -n $extra ]]; then
  IFS=, read -ra entries <<< "$extra"
  ok=1
  for e in "${entries[@]}"; do valid "$e" || ok=0; done
  if (( ok )) && [[ $extra != *[[:space:]]* && $extra != ,* && $extra != *, && $extra != *,,* ]]; then
    allowed+=("${entries[@]}")
  else
    echo "ERROR: WAZUH_SYSLOG_ALLOWED_IPS is invalid ('$extra'); syslog accepts only the manager's own networks (run scripts/render-env.sh)" >&2
  fi
fi

if (( ${#allowed[@]} == 0 )); then
  # No route found: accept nothing from outside rather than everything.
  echo "ERROR: no network found in /proc/net/route; syslog accepts only 127.0.0.1" >&2
  allowed=(127.0.0.1)
fi

if ! grep -q "$MARK" "$CONF"; then
  echo "ERROR: marker $MARK not found in $CONF; syslog sources left as in the file" >&2
  exit 0
fi

# Replace every <allowed-ips> between the marker and the end of its <remote>.
block=""
for a in "${allowed[@]}"; do block+="    <allowed-ips>$a</allowed-ips>"$'\n'; done
BLOCK=$block awk -v mark="$MARK" '
  index($0, mark)                { print; printf "%s", ENVIRON["BLOCK"]; skip = 1; next }
  skip && /<allowed-ips>/        { next }
  skip && /<\/remote>/           { skip = 0 }
                                 { print }
' "$CONF" > "$CONF.tmp"
cat "$CONF.tmp" > "$CONF"
rm -f "$CONF.tmp"
echo "syslog 514/udp allowed sources: ${allowed[*]}"
