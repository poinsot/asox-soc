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

## Rules: ID plan, files and groups (W1.3)

Status: **proposal**, to be agreed with the n8n owner (router, D-N2) and the TheHive owner (case templates, ALERT-FORMAT.md §3) by checkpoint 1 (2026-10-20); see [docs/request-n8n-rule-groups.md](docs/request-n8n-rule-groups.md). Once a rule ID, file name or group ships on `main`, it is **never renamed or reused**. Other owners route on them, and removing a file needs the manual `rm` above.

**Prefer built-in rules.** Wazuh's ruleset already covers sshd brute force (5763), sudo, new users, FIM, rootcheck and Suricata (86601). A custom rule is written only to fill a gap, to correlate, or to retune. Built-ins are retuned in the tuning file with `overwrite="yes"`, keeping their original ID.

### ID ranges and files

Custom IDs live in 100000–120999 (Wazuh reserves everything below 100000). Each source has its own range and its own file, and the file name starts with the range's first four digits:

| Range | File (`rules/`) | Source | Milestone |
|---|---|---|---|
| 100100–100199 | `local_rules.xml` | Tests and lab markers: 100100 test rule (C1, C8), 100101 attack-start marker (W1.6) | M0, M1 |
| 100200–100299 | `1002-linux-auth.xml` | Linux authentication: SSH, sudo, accounts | M2 |
| 100300–100499 | `1003-linux-system.xml` | Linux system: FIM, rootcheck, malware | M2, M5 |
| 100500–100999 | `1005-windows.xml` | Windows endpoints | M5 |
| 101000–101999 | `1010-suricata.xml` | Suricata IDS (on top of built-in 86601) | M3 |
| 102000–102999 | `1020-router.xml` | Router syslog | M4 |
| 103000–103999 | `1030-pfsense.xml` | pfSense syslog | M4 |
| 108000–108999 | `1080-misp-ioc.xml` | MISP IOC matches from CDB lists (C14), across every source above | M6 |
| 109000–109999 | `1090-tuning.xml` | Tuning: `overwrite="yes"` of built-ins (original IDs) and level-0 children that silence noise (109xxx), one reason per rule | M2 on |
| 110000–120999 | — | Reserved | — |

Custom decoders follow the same names in `decoders/` (e.g. `1030-pfsense.xml`).

**Why the number prefix:** the manager loads `etc/rules/` in **alphabetical order**, after the built-in ruleset. A child rule (`if_sid`) whose parent sits in a file loaded *later* is **dropped with only a warning** (`7617 Signature ID ... was not found`, `7619 Empty 'if_sid' value`), and the manager starts anyway (tested 2026-10-05). So a file may only depend on built-ins and on files that sort before it: that's why MISP IOC rules (1080) come after every source, and tuning (1090) comes last. `local_rules.xml` sorts after the digits, so nothing may depend on it. The rule test runner (W1.4) fails on these warnings.

### Rule groups (the routing key)

Every custom rule carries three kinds of groups:

1. **`asox`**: marks it as ours, so a Grafana panel or n8n can tell custom from built-in.
2. **One source group:** `test`, `linux`, `windows`, `suricata`, `router`, `pfsense` or `misp_ioc`.
3. **Wazuh's standard groups for what it detects**, spelled exactly as the built-in rules spell them. n8n's router and TheHive's templates already match on these:

| Detects | Standard groups | Case template (ALERT-FORMAT.md §3) |
|---|---|---|
| SSH failures, brute force | `sshd`, `authentication_failed` / `authentication_failures`, `invalid_login` | `ssh-bruteforce` |
| Successful login | `authentication_success` | `wazuh-generic` |
| sudo | `sudo` | `wazuh-generic` |
| New user or group | `adduser` (Wazuh uses it for both: 5901 new group, 5902 new user), `account_changed` | `wazuh-generic` |
| File integrity | `syscheck` | `wazuh-generic` |
| Malware, rootkits | `rootcheck`, `malware`, `virustotal` | `malware-detection` |
| Network IDS | `ids` (plus the source `suricata`) | `ids-network-alert` |
| Firewall blocks, scans | `firewall_drop`, `recon` | `wazuh-generic` (until a template exists) |

New group names are added only for things Wazuh has no name for: `attack_start` (the lab marker, W1.6) and `misp_ioc` (C14). Every custom rule also has a `<mitre>` block (W2.3), so the technique arrives as `rule.mitre.id`.

Example:

```xml
<group name="asox,linux,sshd,authentication_success,">
  <rule id="100210" level="12" frequency="..." timeframe="...">
    ...
    <mitre><id>T1110</id></mitre>
    <description>ASOX: successful SSH login after repeated failures from $(srcip)</description>
  </rule>
</group>
```

Routing (D-N2): n8n routes on these groups first, and on a short map of specific rule IDs where a group is too broad. The catalog of every custom rule (ID, groups, level, MITRE, lab scenario) is added here in W2.5.

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

Pick from this list; Phase 1 only built the baseline. The owner's plan, split into milestones with a "done when" check per task, is in [BACKLOG.md](BACKLOG.md). Requests from other owners and the replies are kept in [docs/](docs/).

- **Restrict syslog sources** (`<allowed-ips>` of the 514/udp listener in `config/ossec.conf`, currently any source) to the real devices before `core` is exposed on a LAN.
- Detection rules and decoders for the environment; false-positive tuning; the alert level threshold (`WAZUH_ALERT_MIN_LEVEL`, default 7).
- Agent groups and policies; an enrollment guide for real endpoints (the lab agent is the reference).
- Decoders for pfSense and router logs; MITRE ATT&CK mapping.
- CDB lists fed from MISP IOCs (with the Cortex + MISP owner).
- Later: response actions through C9 (Phase 2, with the n8n owner).
