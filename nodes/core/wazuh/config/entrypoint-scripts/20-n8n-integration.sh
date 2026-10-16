#!/bin/bash
# Run by the wazuh-manager image at every start, before Wazuh starts
# (/entrypoint-scripts/*.sh), after the config copy (05-restart-fixes.sh).
# Configures the custom-n8n integration (contract C1) from the environment,
# since the URL, token and level differ per machine:
#   N8N_WEBHOOK_URL, N8N_WEBHOOK_TOKEN, WAZUH_ALERT_MIN_LEVEL
set -euo pipefail
CONF=/var/ossec/etc/ossec.conf
BEGIN='<!-- ASOX-N8N-INTEGRATION-BEGIN -->'
END='<!-- ASOX-N8N-INTEGRATION-END -->'

# The scripts are copied from /wazuh-config-mount as root:root 644.
for f in /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py; do
  chown root:wazuh "$f"
  chmod 750 "$f"
done

# Drop a block left by a previous start, then add the current one.
sed -i "\|$BEGIN|,\|$END|d" "$CONF"
if [[ -z ${N8N_WEBHOOK_URL:-} || -z ${N8N_WEBHOOK_TOKEN:-} ]]; then
  echo "WARNING: N8N_WEBHOOK_URL or N8N_WEBHOOK_TOKEN is empty; alerts are not forwarded to n8n" >&2
  exit 0
fi
cat >> "$CONF" <<CONF
$BEGIN
<ossec_config>
  <integration>
    <name>custom-n8n</name>
    <hook_url>${N8N_WEBHOOK_URL}/webhook/wazuh-alert</hook_url>
    <api_key>${N8N_WEBHOOK_TOKEN}</api_key>
    <level>${WAZUH_ALERT_MIN_LEVEL:-7}</level>
    <alert_format>json</alert_format>
    <!-- X-10: passed to custom-n8n.py, which does the retries itself
         (integratord doesn't enforce the timeout). Per try: 10 s. -->
    <timeout>10</timeout>
    <retries>4</retries>
  </integration>
</ossec_config>
$END
CONF
echo "custom-n8n integration: level >= ${WAZUH_ALERT_MIN_LEVEL:-7} -> ${N8N_WEBHOOK_URL}/webhook/wazuh-alert"
