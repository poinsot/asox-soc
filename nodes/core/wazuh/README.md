# Wazuh — "Recolector y Clasificador"

Owner: Wazuh owner. Node: `core` (plus the `lab` test agent). Run mode: `core`.

Collects events from agents and syslog, decodes them, classifies them with rules, stores alerts in the Wazuh indexer and forwards relevant alerts to n8n. The full component README (contracts, export rules, backlog) is completed at the end of Phase 1; this file already covers the operations below.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `wazuh-manager`, `wazuh-indexer` |
| `config/ossec.conf` | Manager configuration |
| `config/wazuh-indexer.yml` | Indexer (OpenSearch) configuration |
| `config/certs.yml` | Nodes for the certificate generator (`scripts/gen-certs.sh`) |
| `config/entrypoint-scripts/` | Scripts the manager image runs before Wazuh starts (writes the agent enrollment password) |
| `rules/`, `decoders/` | Custom rules and decoders (`local_rules.xml` holds the Phase 1 test rule `100100`) |

In the commands below, `<instance>` is `SOC_INSTANCE` from `topology.env` (default `asox`), so the manager container is `<instance>-core-wazuh-manager-1`.

## How configuration reaches the manager

`config/ossec.conf`, `rules/` and `decoders/` are mounted under `/wazuh-config-mount`, and they are **copied** into `/var/ossec/etc/` (the `wazuh_etc` data volume) at every start: by the image's init on a fresh container, and by `config/entrypoint-scripts/05-restart-fixes.sh` on a restart of the same container, where the image's init stops early (the log line `0-wazuh-init: exited 1` is expected then; see `docs/decisions.md` A26). So:

- **Adding or editing** a rule or decoder file: edit it, then restart the manager and check the result:
  ```bash
  docker restart <instance>-core-wazuh-manager-1
  nodes/lab/trigger.sh    # (step 1.2) or send a test event, then:
  scripts/wazuh-query.sh --rule <id>
  ```
  Editing or deleting individual `<rule>`/`<decoder>` entries inside a file works the same way, since the whole file is copied over.

- **Removing or renaming a file** needs one extra step, because the copy already in the data volume is **not** deleted:
  1. Make sure no remaining rule depends on it (`if_sid`, `if_group`, `decoded_as` or `<parent>` pointing at IDs or names in that file). Otherwise the manager's analysis engine refuses to start.
  2. Delete (or rename) the file in the repo.
  3. Delete the old copy from the volume, then test the configuration and restart:
     ```bash
     docker exec <instance>-core-wazuh-manager-1 rm /var/ossec/etc/rules/<file>.xml        # or etc/decoders/<file>.xml
     docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/wazuh-analysisd -t         # must print no errors
     docker restart <instance>-core-wazuh-manager-1
     ```
  4. Every teammate who pulls the change runs the same `rm` on their machine (mention it in the checkpoint pull request). A `soc.sh reset core` also clears it, but deletes all core data.

## Indexer admin password

`INDEXER_ADMIN_PASSWORD` (in `nodes/core/.env`, generated per machine) is written into the indexer's security index **only on the indexer's first start** (from `nodes/core/certs/internal_users.yml`, created by `gen-certs.sh`). Changing the value in `.env` afterwards does nothing by itself, and the manager's Filebeat would then fail to log in.

To change it:

- **If the core data can be thrown away:** `scripts/soc.sh reset core`, then `scripts/soc.sh init core`. Everything, including the password, is regenerated.
- **Keeping the data** (tested procedure, run from the repo root with core running):
  ```bash
  # 1. Put the new password in nodes/core/.env (render-env.sh keeps it from now on).
  #    At least 8 characters with upper and lower case letters and digits; avoid quotes, $ and spaces.
  NEW='<new-password>'
  sed -i "s|^INDEXER_ADMIN_PASSWORD=.*|INDEXER_ADMIN_PASSWORD=$NEW|" nodes/core/.env

  # 2. Apply it to the running indexer, authenticating with the admin client certificate.
  jq -nc --arg p "$NEW" '{password: $p, backend_roles: ["admin"], description: "Indexer admin"}' \
    | docker exec -i <instance>-core-wazuh-indexer-1 curl -s \
        --cacert config/certs/root-ca.pem --cert config/certs/admin.pem --key config/certs/admin-key.pem \
        -X PUT https://wazuh.indexer:9200/_plugins/_security/api/internalusers/admin \
        -H 'Content-Type: application/json' --data-binary @-
  # expect: {"status":"OK","message":"'admin' updated."}

  # 3. Regenerate internal_users.yml so a future first start uses the same password.
  rm nodes/core/certs/internal_users.yml && scripts/gen-certs.sh

  # 4. Recreate the manager with the new password (Filebeat, vulnerability detection), then verify.
  scripts/soc.sh up core
  scripts/bootstrap.sh core
  ```
  Only the `admin` user changes; `grafana-ro` and its role are untouched. Don't use the indexer's `securityadmin.sh` with the whole `opensearch-security/` folder for this: it would overwrite the users and roles created by `bootstrap.sh` (rerun `bootstrap.sh core` if that happens).

## Agent enrollment password

Agents must present `WAZUH_ENROLLMENT_PASSWORD` (in `nodes/core/.env`, generated per machine) to enroll on port 1515. `config/entrypoint-scripts/10-enrollment-password.sh` writes it to `/var/ossec/etc/authd.pass` at every manager start. To rotate it, change it in `nodes/core/.env` and in every agent, then run `scripts/soc.sh up core`. Already enrolled agents keep working: the password is only checked at enrollment.

## Backlog notes

- Restrict syslog sources (`<allowed-ips>` of the 514/udp listener in `config/ossec.conf`, currently any source) to the real devices before `core` is exposed on a LAN (PROJECT.md 11.3).
