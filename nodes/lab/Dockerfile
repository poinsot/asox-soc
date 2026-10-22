# Lab test agent (owner: Wazuh): a Wazuh agent in a container, enrolled like
# a real endpoint. Versions come from nodes/lab/.env (docs/decisions.md).
ARG LAB_BASE_IMAGE
FROM ${LAB_BASE_IMAGE}

ARG WAZUH_AGENT_VERSION
# procps: wazuh-control needs ps. iptables: active response firewall-drop
# (C9, W7.2), with NET_ADMIN in docker-compose.yml.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg procps iptables \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
 && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      "wazuh-agent=${WAZUH_AGENT_VERSION}-1" \
 && rm -f /etc/apt/sources.list.d/wazuh.list \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 # Keep the package's default configuration: entrypoint.sh renders
 # ossec.conf from it at every start.
 && mkdir -p /opt/asox && cp /var/ossec/etc/ossec.conf /opt/asox/ossec.conf.dist

COPY entrypoint.sh healthcheck.sh /opt/asox/
ENTRYPOINT ["/opt/asox/entrypoint.sh"]
