# Grafana — "Dashboard analitico"

Owner: Grafana owner. Node: `core`. Run mode: `core`.

Analytic dashboards and SOC metrics; the replacement for the Wazuh dashboard. The full component README (contracts, backlog) is completed at the end of Phase 1; this file already covers the operations below.

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

## Versions and upgrading

- **Grafana is pinned to 12.4.x on purpose** (PROJECT.md D34): 13.2.2 leaked about 100 MiB of memory per browser session and restarted at its limit. **Re-test before moving to 13.x**: open the dashboard in a browser several times and watch `go_gc_heap_live_bytes` at `/metrics` (or `docker stats`); it must level off, not keep growing.
- **Plugin installation uses `GF_INSTALL_PLUGINS`, which is deprecated upstream** (and in Grafana 13 only runs with `GF_INSTALL_PLUGINS_FORCE=true`). Its replacement is `GF_PLUGINS_PREINSTALL_SYNC=<plugin-id>@<version>` (installed before the server starts). When upgrading, switch to it, but note what it does today (docs/decisions.md A35): it also downloads Grafana's default app plugins at unpinned versions and updates bundled plugins at every start (turn that off with `GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false`), and `GF_PLUGINS_PREINSTALL_DISABLED=true` disables the `_SYNC` install too. Check which plugins end up in `/var/lib/grafana/plugins` after the change.
- The plugin version is `GRAFANA_OPENSEARCH_PLUGIN_VERSION` in `nodes/core/.env.example` (integrator-owned; ask for a change).
- The admin login is set on Grafana's first start only; to change it later: `docker exec -it <instance>-core-grafana-1 grafana cli admin reset-admin-password '<new>'` and update `nodes/core/.env`.
