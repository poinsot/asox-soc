#!/bin/bash
# Run by the wazuh-manager image at every start, before Wazuh starts
# (/entrypoint-scripts/*.sh), after the config copy (05-restart-fixes.sh).
# MISP IOCs as CDB lists (C14, W6.2-W6.5), with lists/misp-sync.py:
#   1. the three lists declared in ossec.conf (etc/lists/misp/misp-ip,
#      misp-domain, misp-hash) always exist, empty if never synced, so the
#      analysis engine starts with or without MISP;
#   2. one sync now (--no-reload: Wazuh loads the lists when it starts);
#   3. an s6 service (like the image's filebeat and ossec-logs services) that
#      syncs every WAZUH_MISP_SYNC_INTERVAL seconds and hot-reloads the
#      ruleset when a list changed. s6 restarts it if it dies. After a failed
#      sync (and from the start if the first one failed) it retries every
#      60 s, up to 10 times, before the next interval (R-34).
# Without WAZUH_MISP_URL / WAZUH_MISP_API_KEY (R-08) C14 is off: empty lists.
set -euo pipefail
LISTS=/var/ossec/etc/lists/misp
SYNC=/asox/lists/misp-sync.py
PY=/var/ossec/framework/python/bin/python3

mkdir -p "$LISTS"
for l in misp-ip misp-domain misp-hash; do
  [[ -e $LISTS/$l ]] || : > "$LISTS/$l"
done
chown -R wazuh:wazuh "$LISTS"
chmod 770 "$LISTS"
chmod 660 "$LISTS"/misp-*

if [[ -z ${WAZUH_MISP_URL:-} || -z ${WAZUH_MISP_API_KEY:-} ]]; then
  echo "misp-sync: C14 off (WAZUH_MISP_URL or WAZUH_MISP_API_KEY empty); lists stay as they are"
  exit 0
fi

# A slow or absent MISP must not hold up the manager's start.
loop_args=(--loop)
if ! timeout 90 "$PY" "$SYNC" --once --no-reload; then
  # R-34: e.g. intel not up yet (soc.sh up full starts core first). The
  # service then retries every minute for 10 minutes before the interval.
  echo "misp-sync: first sync failed; the service retries every 60 s for 10 min"
  loop_args+=(--after-failure)
fi

mkdir -p /etc/services.d/misp-sync
cat > /etc/services.d/misp-sync/run <<RUN
#!/usr/bin/with-contenv sh
exec $PY $SYNC ${loop_args[*]}
RUN
chmod 755 /etc/services.d/misp-sync/run
