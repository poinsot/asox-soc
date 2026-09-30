# Grafana — "Dashboard analitico"

Owner: Jesus (@JC-535). Branch: `grafana`. Node: `core`. Run mode: `core`.

Analytic dashboards and SOC metrics; the replacement for the Wazuh dashboard.

**Start here:** [CONTRIBUTING.md](../../../CONTRIBUTING.md) (light rules, exporting changes, onboarding), then this file. First time: `./scripts/soc.sh init core`; then `soc.sh up core` / `soc.sh down`. Test loop: edit a dashboard in the UI → `nodes/lab/trigger.sh` if you need more data → `scripts/grafana-export.sh`. Details: [PROJECT.md](../../../PROJECT.md) 6.3.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `grafana` |
| `provisioning/datasources/wazuh-indexer.yml` | The Wazuh indexer datasource (contract C8), read-only user `grafana-ro` |
| `provisioning/dashboards/asox.yml` | Loads every `*.json` in that folder into the "ASOX" folder |
| `provisioning/dashboards/*.json` | Dashboards (starter: `soc-overview.json`, "SOC Overview") |
| `provisioning/alerting/`, `provisioning/plugins/` | Empty; for alerting rules and app plugin settings later |

## Editing dashboards

Dashboards are provisioned with `allowUiUpdates: true`: edit them in the UI (`http://localhost:3000`, login from `scripts/soc.sh info`), then save them to the repo and review:

```bash
scripts/grafana-export.sh            # all dashboards, or: scripts/grafana-export.sh <uid>
git diff nodes/core/grafana/
```

A dashboard keeps its file (matched by `uid`); a new one becomes `provisioning/dashboards/<title>.json`. Keep `uid`s stable, and reference the datasource by its uid `wazuh-indexer`. If a file changes on disk (e.g. after `git pull`), Grafana applies it within 30 seconds and overwrites unsaved UI edits of that dashboard, so export first.

## Datasource notes

- The URL must be `${WAZUH_INDEXER_URL}` (`https://wazuh.indexer:9200`), the name in the indexer's certificate.
- The index pattern is daily, `[wazuh-alerts-4.x-]YYYY.MM.DD`, not `wazuh-alerts-*`: the OpenSearch plugin's health check fails with a wildcard pattern (PROJECT.md D35).
- `grafana-ro` can only read `wazuh-alerts-*`. Reading another index (e.g. TheHive data later) needs a role change in `scripts/bootstrap.sh` (ask the integrator).

## Contracts and exporting changes

| Contract | Role | Status at `v1.0-baseline` |
|---|---|---|
| C8 Grafana → Wazuh indexer | OpenSearch datasource `wazuh-indexer` as `grafana-ro` | Passes |

Check: `scripts/contracts-check.sh --only C8`. Exporting changes: `scripts/grafana-export.sh` (section "Editing dashboards"). Reading other data (e.g. TheHive metrics) is a contract change agreed with that owner (PROJECT.md 5).

## Local patches and deprecations (re-check on upgrade)

Pinned: `grafana/grafana` 12.4.11 and `grafana-opensearch-datasource` 2.34.4. On every version bump, re-check each item below and update this list.

- **Grafana is pinned to 12.4.x on purpose** (PROJECT.md D34): 13.2.2 leaked about 100 MiB of memory per browser session and restarted at its limit. **Re-test before moving to 13.x**: open the dashboard in a browser several times and watch `go_gc_heap_live_bytes` at `/metrics` (or `docker stats`); it must level off, not keep growing.
- **Plugin installation uses `GF_INSTALL_PLUGINS`, which is deprecated upstream** (and in Grafana 13 only runs with `GF_INSTALL_PLUGINS_FORCE=true`). Its replacement is `GF_PLUGINS_PREINSTALL_SYNC=<plugin-id>@<version>` (installed before the server starts). When upgrading, switch to it, but note what it does today (docs/decisions.md A35): it also downloads Grafana's default app plugins at unpinned versions and updates bundled plugins at every start (turn that off with `GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false`), and `GF_PLUGINS_PREINSTALL_DISABLED=true` disables the `_SYNC` install too. Check which plugins end up in `/var/lib/grafana/plugins` after the change.
- The plugin version is `GRAFANA_OPENSEARCH_PLUGIN_VERSION` in `nodes/core/.env.example` (integrator-owned; ask for a change).
- The admin login is set on Grafana's first start only; to change it later: `docker exec -it <instance>-core-grafana-1 grafana cli admin reset-admin-password '<new>'` and update `nodes/core/.env`.
- **Datasource `flavor: opensearch`, `version: 2.19.6`** (`provisioning/datasources/wazuh-indexer.yml`, A36): the OpenSearch version inside the Wazuh indexer (its `/` reports 7.10.2 for compatibility). Update it when the Wazuh indexer is upgraded (Wazuh owner).
- **Index pattern `[wazuh-alerts-4.x-]YYYY.MM.DD`** (D35) follows Wazuh 4.x index names; Wazuh 5 renames them (coordinate with the Wazuh owner).
- **Memory:** limit `GRAFANA_MEM` 256m / 250m, with swap capped at the limit (D40). Re-measure after an upgrade: anonymous memory peak from the container's `memory.stat`, not `docker stats` (which includes page cache).

## Backlog (PROJECT.md 11.3)

KPI plan for dashboards across 3 levels based on currently available data.

### "SOC Status" Dashboard — ready to build with `wazuh-alerts-*`
- 24h alerts, critical/high alerts, active endpoints (15 min)
- Alerts per hour, by severity, by rule, by endpoint
- Top source IPs, failed authentications, file changes (FIM)
- Alerts by MITRE tactic and HIPAA control

### "Attack Scenarios" Dashboard — requires additional rules and Snort/pfSense
- AD brute force and phishing/ransomware: achievable with current agents
- Network scanning and DDoS: require Snort or OPNsense forwarding logs to Wazuh

### "Performance and Compliance" Dashboard — requires data from n8n + TheHive
- MTTD/MTTA/MTTR, open/closed cases, executed playbooks, false positives
- Requires a new contract: n8n writing to its own index (`asox-metrics`) and a role modification for `grafana-ro` to read it (coordinate with the n8n owner)

### AI Layer — Phase 2+
- Anomalous alerts, prioritized queue, precision/recall of the phishing classifier