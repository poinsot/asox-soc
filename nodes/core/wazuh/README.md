# Wazuh — "Recolector y Clasificador"

Owner: Daniel (@dmelgar1110). Branch: `wazuh`. Node: `core` (plus the `lab` test agent). Run mode: `core`.

Collects events from agents and syslog, decodes them, classifies them with rules, stores alerts in the Wazuh indexer and forwards relevant alerts to n8n.

**Start here:** [CONTRIBUTING.md](../../../CONTRIBUTING.md) (light rules, exporting changes, onboarding), then this file. First time: `./scripts/soc.sh init core`; then `soc.sh up core` / `soc.sh down`. Test loop: edit a rule → `docker restart <instance>-core-wazuh-manager-1` → `nodes/lab/trigger.sh` → `scripts/wazuh-query.sh` or Grafana. Details: [PROJECT.md](../../../PROJECT.md) 6.1.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `wazuh-manager`, `wazuh-indexer` |
| `config/ossec.conf` | Manager configuration |
| `config/wazuh-indexer.yml` | Indexer (OpenSearch) configuration |
| `config/certs.yml` | Nodes for the certificate generator (`scripts/gen-certs.sh`) |
| `config/entrypoint-scripts/` | Scripts the manager image runs before Wazuh starts (writes the agent enrollment password) |
| `rules/`, `decoders/` | Custom rules and decoders (`local_rules.xml` holds the Phase 1 test rule `100100`) |

No Wazuh web UI (the Wazuh dashboard isn't deployed): alerts are in Grafana (`http://localhost:3000`) and `scripts/wazuh-query.sh`; the Wazuh API is `https://localhost:55000` (self-signed certificate), login from `scripts/soc.sh info`. Agents connect on 1514/tcp and enroll on 1515/tcp; syslog on 514/udp.

In the commands below, `<instance>` is `SOC_INSTANCE` from `topology.env` (default `asox`), so the manager container is `<instance>-core-wazuh-manager-1`.

## How configuration reaches the manager

`config/ossec.conf`, `rules/` and `decoders/` are mounted under `/wazuh-config-mount`, and they are **copied** into `/var/ossec/etc/` (the `wazuh_etc` data volume) at every start: by the image's init on a fresh container, and by `config/entrypoint-scripts/05-restart-fixes.sh` on a restart of the same container, where the image's init stops early (the log line `0-wazuh-init: exited 1` is expected then; see `docs/decisions.md` A26). So:

- **Adding or editing** a rule or decoder file: edit it, then restart the manager and check the result:
  ```bash
  docker restart <instance>-core-wazuh-manager-1
  nodes/lab/trigger.sh    # prints the test event ID; then:
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

## Lab agent (`nodes/lab/`)

A containerized Wazuh agent (`lab-agent`), enrolled exactly like a real endpoint: the package's default configuration plus the manager address and the enrollment password (see `nodes/lab/entrypoint.sh`). It also produces realistic alerts (SCA, rootcheck, FIM) for Grafana.

- **Test alert:** `id=$(nodes/lab/trigger.sh) && scripts/wazuh-query.sh --rule 100100 --match "$id"` (the alert takes a few seconds to be indexed).
- **Enrollment** happens once; the agent's keys are kept in a volume. A fresh agent with the same name is refused while the manager still knows the old one, so `scripts/soc.sh reset lab` first removes that registration (when core runs on the same machine). For a real endpoint that is reinstalled, remove its old registration the same way: `docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/manage_agents -r <agent-id>`.
- **Healthy** means connected *and* ready to collect: right after enrolling, the agent reloads once when it receives the manager's shared configuration, and events written before that are lost.

## Contracts and exporting changes

| Contract | Role | Status at `v1.0-baseline` |
|---|---|---|
| C1 Wazuh → n8n | Sends alerts with level ≥ `WAZUH_ALERT_MIN_LEVEL` through `custom-n8n`, with the webhook token | Passes |
| C2 n8n → Wazuh API | Provides the read-only user `n8n-api` | Passes |
| C8 Grafana → Wazuh indexer | Provides the read-only user `grafana-ro` (`wazuh-alerts-*`) | Passes |
| C9 n8n → endpoints (Phase 2) | Active response through the API; extends `n8n-api`'s role (contract change) | Planned |

Check: `scripts/contracts-check.sh --only C1,C2,C8`. **Exporting changes:** Wazuh is configured by files (`config/`, `rules/`, `decoders/`, `integrations/`): edit, restart the manager, commit (section "How configuration reaches the manager"). Changing a contract needs the other owner's agreement first (PROJECT.md 5).

## Local patches and deprecations (re-check on upgrade)

Everything here works around upstream behaviour or depends on details of the pinned versions (`wazuh/wazuh-manager` / `wazuh/wazuh-indexer` 4.14.8, `wazuh/wazuh-certs-generator` 0.0.4, agent package 4.14.8). On every version bump, re-check each item and update this list. Wazuh 5.0 (beta when pinned) changes enough that every item needs checking.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| `config/entrypoint-scripts/05-restart-fixes.sh` | Upstream `wazuh-docker` 4.14 bugs: on `docker restart` the image's init exits early (`0-wazuh-init: exited 1`) and skips the config copy; a stale `start-script-lock` blocks the next start (docs/decisions.md A26) | `docker restart` the manager: if the init no longer exits 1 and edited rules apply without the script, delete it |
| `config/entrypoint-scripts/10-enrollment-password.sh` | Writes `authd.pass` from `WAZUH_ENROLLMENT_PASSWORD` at every start (D33, A25) | Enrollment without / with a wrong / with the right password (only the last works) |
| `config/entrypoint-scripts/20-n8n-integration.sh` | Writes the `custom-n8n` `<integration>` block (URL, token, level) into `ossec.conf` at every start (A41) | C1 passes (`scripts/contracts-check.sh --only C1`) |
| `integrations/custom-n8n` | Copy of the shell wrapper Wazuh ships for its integrations (A48) | Diff against the new image's wrappers in `/var/ossec/integrations/`; `custom-n8n.py` runs on Wazuh's bundled Python, so check it still imports `requests` |
| Manager healthcheck (`compose.yml`) | Names the daemons that must run (`wazuh-analysisd`, `-remoted`, `-authd`, `-db`, `-modulesd`, `-apid`; A27) | Daemon names still exist (`/var/ossec/bin/wazuh-control status`) |
| Indexer addressed as `wazuh.indexer` | The certificate tool only accepts dotted DNS names (D32, A15) | Tool version in `config/certs.yml` / `WAZUH_CERTS_GENERATOR_IMAGE`; `gen-certs.sh` on a clean `nodes/core/certs/` |
| `internal_users.yml` generated by `gen-certs.sh` with only `admin` | Drops the upstream demo users; hashed with the indexer image's tool (A16) | Hash tool path in the new indexer image; fresh `soc.sh init core` |
| Index names `wazuh-alerts-4.x-*` | Used by `grafana-ro`'s role (A19), `wazuh-query.sh` and the Grafana datasource pattern (D35) | Wazuh 5 renames the alert indices: update all three with the Grafana owner |
| Lab agent image (`nodes/lab/Dockerfile`) | `wazuh-agent=<version>-1` from the Wazuh apt repository on a dated Ubuntu tag (A28) | Must match the manager version; rebuild with `soc.sh init core` |

## Backlog (PROJECT.md 11.3)

Pick from this list; Phase 1 only built the baseline. The owner's plan, split into milestones with a "done when" check per task, is in [BACKLOG.md](BACKLOG.md).

- **Restrict syslog sources** (`<allowed-ips>` of the 514/udp listener in `config/ossec.conf`, currently any source) to the real devices before `core` is exposed on a LAN.
- Detection rules and decoders for the environment; false-positive tuning; the alert level threshold (`WAZUH_ALERT_MIN_LEVEL`, default 7).
- Agent groups and policies; an enrollment guide for real endpoints (the lab agent is the reference).
- Decoders for pfSense and router logs; MITRE ATT&CK mapping.
- CDB lists fed from MISP IOCs (with the Cortex + MISP owner).
- Later: response actions through C9 (Phase 2, with the n8n owner).
