#!/bin/bash
# Run by the wazuh-manager image at every start, before Wazuh starts
# (/entrypoint-scripts/*.sh). Works around two wazuh-docker 4.14 issues that
# appear when the SAME container is restarted (docker restart, Docker/WSL
# reboot) instead of recreated (soc.sh down/up):
#  1. The image's init (cont-init.d/0-wazuh-init) deletes its data template
#     after the first start. On a restart it finds the multigroups volume
#     empty (no agent groups), fails to copy the missing template, logs
#     "0-wazuh-init: exited 1" and skips the rest of its steps, including
#     copying /wazuh-config-mount (ossec.conf, rules, decoders) into
#     /var/ossec. Those skipped steps are repeated here; they are idempotent.
#  2. A manager stopped while starting leaves start-script-lock behind, and
#     the next start refuses to run. Nothing Wazuh is running yet when this
#     script runs, so the lock is always stale here.
set -euo pipefail

# 1. Same commands as mount_files and configure_permissions in 0-wazuh-init.
if [[ -d /wazuh-config-mount ]]; then
  cp -r /wazuh-config-mount/* /var/ossec
fi
chown -R wazuh:wazuh /var/ossec/queue/rids /var/ossec/etc/lists

# 2. The lock is a directory (mkdir-based).
rm -rf /var/ossec/var/start-script-lock
