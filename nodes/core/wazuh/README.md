# Wazuh — "Recolector y Clasificador"

Owner: Daniel (@dmelgar1110). Branch: `wazuh`. Node: `core` (plus the `lab` test agent). Run mode: `core`.

Collects events from agents and syslog, decodes them, classifies them with rules, stores alerts in the Wazuh indexer and forwards relevant alerts to n8n.

**Start here:** [CONTRIBUTING.md](../../../CONTRIBUTING.md) (light rules, exporting changes, onboarding), then this file. First time: `./scripts/soc.sh init core`; then `soc.sh up core` / `soc.sh down`. Test loop: edit a rule → `nodes/core/wazuh/tests/run.sh` (no restart needed) → `docker restart <instance>-core-wazuh-manager-1` → `nodes/lab/trigger.sh` → `scripts/wazuh-query.sh` or Grafana. Details: [PROJECT.md](../../../PROJECT.md) 6.1.

| Folder / file | What it is |
|---|---|
| `compose.yml` | `wazuh-manager`, `wazuh-indexer` |
| `config/ossec.conf` | Manager configuration |
| `config/wazuh-indexer.yml` | Indexer (OpenSearch) configuration |
| `config/certs.yml` | Nodes for the certificate generator (`scripts/gen-certs.sh`) |
| `config/entrypoint-scripts/` | Scripts the manager image runs before Wazuh starts: restart fixes, enrollment password, n8n integration (C1), syslog sources |
| `rules/`, `decoders/` | Custom rules and decoders (`local_rules.xml` holds the Phase 1 test rule `100100`) |
| `tests/` | Rule test runner: `tests/run.sh` checks the ruleset against sample log lines through `wazuh-logtest` ([tests/README.md](tests/README.md)) |

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
| Successful login | `authentication_success`; failures then success: built-in 40112 (`attacks`, T1078 + T1110, level 12) | `suspicious-login` (40112 only) |
| sudo | `sudo` (built-in 5404 has no `authentication_*` group; its MITRE is T1548.003) | `privilege-escalation` |
| New, deleted or changed user or group | `adduser` (Wazuh uses it for all of them: 5901 new group, 5902 new user, 5903, 5904) | `account-change` |
| File integrity | `syscheck` | `wazuh-generic` |
| Malware, rootkits | `rootcheck`, `malware`, `virustotal` | `malware-detection` |
| Network IDS | `ids` (plus the source `suricata`) | `ids-network-alert` |
| Firewall blocks, scans | `pfsense` or `router` source, plus `firewall_drop`, `recon` (scans carry T1046) | `network-scan` |

New group names are added only for things Wazuh has no name for: `attack_start` (the lab marker, W1.6) and `misp_ioc` (C14, template `ioc-match`). Every custom rule also has a `<mitre>` block (W2.3), so the technique arrives as `rule.mitre.id`.

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

Routing (D-N2): n8n routes on these groups first, and on a short map of specific rule IDs where a group is too broad.

### Detection catalog (W2.5)

Every custom rule, the alert it produces and how to fire it. Built-in rules the scenarios rely on are pinned in `tests/cases/builtin-linux.cases`; their levels are in "Alert levels".

| Rule | File | Level | Groups (besides `asox` + source) | MITRE | What it means | Lab scenario | Case template |
|---|---|---|---|---|---|---|---|
| 100100 | `local_rules.xml` | 10 | `test` | — | Synthetic test event (C1, C8) | `trigger.sh` (no option) | `wazuh-generic` |
| 100101 | `local_rules.xml` | 3 | `test`, `attack_start` | — | A lab scenario started (`data.scenario`, `data.run_id`; C11's `t_attack_start`) | every `--scenario` | — (not forwarded) |
| 100200 | `1002-linux-auth.xml` | 10 | `sshd`, `authentication_success` | T1078.003 | SSH login as root (built-in 5715 rates it 3) | `root-login` | `wazuh-generic` (proposed: `suspicious-login`) |
| 100210 | `1002-linux-auth.xml` | 3 | `adduser`, `account_changed` | T1098 | `usermod` added a user to a group (Wazuh doesn't decode usermod) | — | — (not forwarded) |
| 100211 | `1002-linux-auth.xml` | 10 | `adduser`, `account_changed` | T1098 | …to a privileged group: sudo, wheel, admin, root, docker, lxd | `new-user` | `account-change` |
| 100212 | `1002-linux-auth.xml` | 10 | `adduser`, `account_changed` | T1098 | `gpasswd` added a user to a privileged group (built-in 2960/2961 rate it 2/5) | — | `account-change` |
| 101000 | `1010-suricata.xml` | 12 | `suricata`, `ids` | — | Suricata alert of severity 1 (built-in 86601 rates every Suricata alert 3) | — | `ids-network-alert` |
| 101001 | `1010-suricata.xml` | 10 | `suricata`, `ids` | — | Suricata alert of severity 2 | `ids-test` | `ids-network-alert` |
| 101002 | `1010-suricata.xml` | 6 | `suricata`, `ids` | — | Suricata alert of severity 3 (context) | — | — (not forwarded) |
| 101010 | `1010-suricata.xml` | 10 | `suricata`, `ids`, `recon` | T1046 | `ET SCAN` signature (severity 1 or 2) | `ids-scan` | `ids-network-alert` (or `network-scan`) |
| 109010 | `1090-tuning.xml` | 0 | `suricata`, `ids`, `tuning` | — | Suricata engine events (`SURICATA STREAM`, invalid checksums) silenced | — | — |
| 19004, 19007 | `1090-tuning.xml` | 5 | `sca` | (SCA's own) | Built-in SCA, lowered (W2.7) | re-enrolling an agent | — (not forwarded) |

Decoder `asox-usermod` (`decoders/1002-linux-auth.xml`) gives `data.dstuser` (the account) and `data.group`, the same names as the built-in gpasswd decoder.

## Alert levels (W2.1)

What a Wazuh `rule.level` means in ASOX. Every component uses the same cut-offs: TheHive's severity (ALERT-FORMAT.md §2), Grafana's buckets (D-G4) and n8n's routing.

| Level | Meaning in ASOX | Sent to n8n (C1) | TheHive severity | Grafana bucket | Examples (verified on 4.14.8) |
|---|---|---|---|---|---|
| 0 | Silenced: a tuning child that drops noise (`1090-tuning.xml`) | no | — | — | — |
| 1–6 | Context: indexed for dashboards and investigation, never forwarded | no | (1 Low, manual only) | low | 100101 attack-start marker (3), 5715 SSH login (3), 5403 sudo to root (4), 5760 / 5710 single SSH failure (5) |
| 7–9 | **Medium:** worth an analyst's look | yes | 2 Medium | medium | 5901 new group, 5902 new user (8) |
| 10–11 | **High:** a likely attack or a policy break | yes | 3 High | high | 5763 / 5712 SSH brute force, 5404 three wrong sudo passwords, 100100 test rule (10) |
| 12–15 | **Critical:** an attack that deserves a case without waiting for triage | yes | 4 Critical | critical | 40112 login after brute force (12); planned: MISP IOC match (1080xx, 12), Suricata severity 1 (101xxx, 12) |

**Forwarding threshold:** `WAZUH_ALERT_MIN_LEVEL=7` (`nodes/core/.env`). `custom-n8n` sends alerts at this level or above, and n8n filters on the same value as a second guard. Changing it changes C1's volume, so it needs the n8n owner's agreement first.

**Rules for custom rules:**
- **Pick the level by what the analyst should do,** not by how bad the event type sounds. If nobody should look at it, it goes below 7. If someone should, it goes 7 or above.
- **12 or above only for precise detections.** n8n may promote Critical alerts of named playbooks straight to TheHive cases (D-N4), so a false positive at 12+ costs an analyst a case. A custom rule at 12+ gives its reason in the catalog (W2.5): correlation, an IOC match, or an IDS signature of severity 1.
- **Retuning a built-in:** an `overwrite="yes"` copy in `1090-tuning.xml` with the reason.
- **SCA (W2.7, X-09):** an agent's first scan reports every failed CIS check (about 85–130 alerts). 19007 (check failed) and 19004 (score < 50%) are lowered to 5 in `1090-tuning.xml`: indexed for compliance panels, not sent to n8n. Only a check that gets worse (19011, 19014, level 9) or a score below 30% (19005, level 9) reaches n8n. `wazuh-logtest` can't decode SCA events, so this is checked live: `soc.sh reset lab --yes && soc.sh init lab`, then count `rule.groups: sca` by level.

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

## Syslog sources (514/udp)

Devices that can't run an agent (pfSense, routers) send syslog to the manager on 514/udp. The manager only accepts it from a list of sources, which `config/entrypoint-scripts/30-syslog-allowed-ips.sh` writes into `ossec.conf` at every start (W1.1, R-06, docs/decisions.md A81):

1. **Always:** the subnets of the Docker networks the manager is attached to, read from `/proc/net/route` inside the container. That covers the lab agent and Suricata over `soc-net`, and anything sent to the published port from this machine: Docker's proxy delivers it from core's network gateway (W1.9 test, `docs/n8n-requests-2026-09-30.md`).
2. **Plus** each entry of `SYSLOG_ALLOWED_IPS` in `topology.env` (comma-separated IPv4 addresses or CIDRs, no spaces). `render-env.sh` validates it and renders it into core's `WAZUH_SYSLOG_ALLOWED_IPS`.

The list is never `0.0.0.0/0`. If the variable is invalid, the script logs an `ERROR` and keeps only step 1 (fails closed). The manager log shows the result: `docker logs <instance>-core-wazuh-manager-1 | grep "syslog 514"`.

**Adding a device** (e.g. pfSense at `192.168.1.1`) on the machine that receives its logs:

```bash
echo 'SYSLOG_ALLOWED_IPS=192.168.1.1' >> topology.env     # or edit the existing line; several: a,b
./scripts/render-env.sh
./scripts/soc.sh up core                                    # recreates the manager with the new list
```

Wazuh agents don't need this: they enroll with the password and send over 1514 with their own key. In `distributed` mode, whether LAN senders keep their real address through the published port is still to be confirmed (W4.5).

## Network IDS: Suricata (M3, D49)

A Suricata sensor runs in the lab node as service `suricata` (`nodes/lab/docker-compose.yml`, image `jasonish/suricata:8.0.7`). It shares the lab agent's network namespace (`network_mode: service:lab-agent`), so it sees that container's traffic on `eth0` (its own network, with the internet route) and `eth1` (`soc-net`, single-host mode). In Phase 2 it moves to its own machine with an agent in group `network-sensors` (PROJECT.md 13).

```
traffic to/from lab-agent --> suricata (ET Open rules) --> eve.json (alerts only)
   --> lab agent (localfile, log_format json) --> manager: built-in 86601 (level 3)
   --> 1010-suricata.xml sets the level from Suricata's severity --> C1 to n8n at 7+
```

- **Rules:** ET Open through `suricata-update` (no account), kept in volume `suricata-lib` and refreshed at most once a day by `nodes/lab/suricata/start.sh`; the first start needs the internet. `nodes/lab/suricata/enable.conf` turns on extra SIDs (2009582, nmap SYN scan); editing it forces a fresh update at the next start.
- **Config:** `nodes/lab/suricata/asox.yaml`, loaded with `--include`: EVE output is alerts only (no flow, DNS, TLS or stats records); one capture thread per interface and the `low` detection profile.
- **HOME_NET** is the lab agent's own addresses, set at start: ET rules alert on traffic from `$EXTERNAL_NET` into `$HOME_NET`, and with Docker's default (every private range) the other lab containers would count as home.
- **Levels** (W3.5, ALERT-FORMAT.md's mapping): severity 1 → 12, 2 → 10, 3 → 6; `ET SCAN` signatures add T1046 and group `recon`. Fields keep Suricata's names: `data.src_ip`, `data.dest_ip`, `data.dest_port` (a string), `data.proto`, `data.alert.signature`, `data.alert.signature_id`, `data.alert.severity` (a string), `data.alert.category`.
- **Try it:** `nodes/lab/trigger.sh --scenario ids-test` (needs internet from the lab agent) and `--scenario ids-scan` (nmap from a throwaway `instrumentisto/nmap:7.98-r2` container on the lab network). Measured 2026-10-08: 101001 and 4 × 101010 (nmap SYN scan, MSSQL, Oracle, MySQL probes), all received by n8n's `recv-wazuh-alert`.
- **Memory** (W3.6, D40): about 480–520 MiB at rest (anonymous, ~53,000 enabled signatures), 576 MiB peak while updating and loading rules, so the limit is `SURICATA_MEM` 750m (default in the compose file until R-07 puts it in `nodes/lab/.env.example`). `core` + lab + Suricata on `low` used about 3.8 GB of the WSL VM.
- `testmynids.org` (the usual test site) doesn't resolve on some networks, e.g. a university one; `ids-test` sends the same signature's content to `example.com` instead.

## Lab agent (`nodes/lab/`)

A containerized Wazuh agent (`lab-agent`), enrolled exactly like a real endpoint: the package's default configuration plus the manager address and the enrollment password (see `nodes/lab/entrypoint.sh`). It also produces realistic alerts (SCA, rootcheck, FIM) for Grafana.

- **Test alert:** `id=$(nodes/lab/trigger.sh) && scripts/wazuh-query.sh --rule 100100 --match "$id"` (the alert takes a few seconds to be indexed).
- **Attack scenarios** (W1.5): `id=$(nodes/lab/trigger.sh --scenario ssh-bruteforce) && scripts/wazuh-query.sh --match "$id"`. `--list` shows the scenarios (`ssh-bruteforce`, `ssh-success-after-fail`, `sudo-fail`, `new-user`, `ioc-ip`, `root-login`, and the IDS ones `ids-test`, `ids-scan`); `--help` shows the alerts each one produces; `--print` shows the lines without sending them. Each run starts with the attack-start marker (rule 100101, level 3, fields `data.scenario` and `data.run_id`; W1.6), and every event of the run ends with `asox_run=<run id>`. Wait a minute between SSH scenarios: the brute-force rules stay quiet for 60 s after firing.
- **Enrollment** happens once; the agent's keys are kept in a volume. A fresh agent with the same name is refused while the manager still knows the old one, so `scripts/soc.sh reset lab` first removes that registration (when core runs on the same machine). For a real endpoint that is reinstalled, remove its old registration the same way: `docker exec <instance>-core-wazuh-manager-1 /var/ossec/bin/manage_agents -r <agent-id>`.
- **Healthy** means connected *and* ready to collect: right after enrolling, the agent reloads once when it receives the manager's shared configuration, and events written before that are lost.

## Contracts and exporting changes

| Contract | Role | Status |
|---|---|---|
| C1 Wazuh → n8n | Sends alerts with level ≥ `WAZUH_ALERT_MIN_LEVEL` through `custom-n8n`, with the webhook token. Sends each alert once, with no retries (A48); n8n accepts this (X-10) | Passes |
| C2 n8n → Wazuh API | Provides the read-only user `n8n-api` | Passes |
| C8 Grafana → Wazuh indexer | Provides the read-only user `grafana-ro` (`wazuh-alerts-*`) | Passes |
| C9 n8n → endpoints (Phase 2, D44) | Active response through the API as a **separate** user and role `n8n-response` (`active-response:command` + `agent:read`, actionable agent groups only); `n8n-api` stays read-only, so C2 keeps passing. Built-in `firewall-drop`, `host-deny`, `disable-account` with timeouts; protected hosts in Wazuh's `<white_list>` (W7.1) | Planned; acknowledged 2026-10-07 |
| C11 n8n → indexer → Grafana (D46) | Hosts the `asox-metrics` index (one document per alert, written by `n8n-indexer`, read by `grafana-ro`). Proposed: 1 shard, 0 replicas, no deletion until after delivery. `t_attack_start` comes from the lab marker (rule 100101, W1.6) | Planned; acknowledged 2026-10-07 |
| C13 Cortex → n8n → indexer (D48) | Keeps the alert field names stable for the "seen before in Wazuh?" lookup: `data.srcip`/`dstip`, `data.src_ip`/`dest_ip` (Suricata), `agent.ip`, `agent.name`, `data.srcuser`/`dstuser`, `syscheck.*_after` (W2.5) | Planned; acknowledged 2026-10-07 (fields checked on live alerts, Suricata and FIM pending) |
| C14 MISP → Wazuh CDB lists | IOC lists in `lists/`, rules in `rules/1080-misp-ioc.xml` (group `misp_ioc`); who runs the sync is the design question (W6.1) | Proposed; design due 2026-10-16 |

**C1 sends once (X-10, A48, A78):** `custom-n8n.py` posts each alert once and never retries; n8n answers on receipt and accepts that a lost post is lost (the alert stays in the indexer). **Don't add retries without the n8n owner's agreement first:** TheHive's duplicate refusal isn't atomic, so overlapping copies of one alert create two TheHive alerts. `custom-n8n.py` must also keep sending valid JSON (`json.dumps` of the alert): n8n refuses anything else with HTTP 422 before a workflow runs, so only `/var/ossec/logs/integrations.log` would show it. That log only records failures; a "Read timed out" there can still mean n8n got the alert (seen 2026-10-05, `docs/n8n-requests-2026-09-30.md`).

Check: `scripts/contracts-check.sh --only C1,C2,C8`. **Exporting changes:** Wazuh is configured by files (`config/`, `rules/`, `decoders/`, `integrations/`): edit, restart the manager, commit (section "How configuration reaches the manager"). Changing a contract needs the other owner's agreement first (PROJECT.md 5).

## Local patches and deprecations (re-check on upgrade)

Everything here works around upstream behaviour or depends on details of the pinned versions (`wazuh/wazuh-manager` / `wazuh/wazuh-indexer` 4.14.8, `wazuh/wazuh-certs-generator` 0.0.4, agent package 4.14.8). On every version bump, re-check each item and update this list. Wazuh 5.0 (beta when pinned) changes enough that every item needs checking.

| What | Why it exists | How to re-check on upgrade |
|---|---|---|
| `config/entrypoint-scripts/05-restart-fixes.sh` | Upstream `wazuh-docker` 4.14 bugs: on `docker restart` the image's init exits early (`0-wazuh-init: exited 1`) and skips the config copy; a stale `start-script-lock` blocks the next start (docs/decisions.md A26) | `docker restart` the manager: if the init no longer exits 1 and edited rules apply without the script, delete it |
| `config/entrypoint-scripts/10-enrollment-password.sh` | Writes `authd.pass` from `WAZUH_ENROLLMENT_PASSWORD` at every start (D33, A25) | Enrollment without / with a wrong / with the right password (only the last works) |
| `config/entrypoint-scripts/20-n8n-integration.sh` | Writes the `custom-n8n` `<integration>` block (URL, token, level) into `ossec.conf` at every start (A41) | C1 passes (`scripts/contracts-check.sh --only C1`) |
| `config/entrypoint-scripts/30-syslog-allowed-ips.sh` | Writes the syslog `<allowed-ips>` from the container's own subnets plus `WAZUH_SYSLOG_ALLOWED_IPS` at every start (W1.1, A81); needs the marker comment `ASOX-SYSLOG-ALLOWED-IPS` in `ossec.conf` | `docker logs` shows `syslog 514/udp allowed sources: ...`, and `ossec.log` shows `Remote syslog allowed from` for each entry |
| `integrations/custom-n8n` | Copy of the shell wrapper Wazuh ships for its integrations (A48) | Diff against the new image's wrappers in `/var/ossec/integrations/`; `custom-n8n.py` runs on Wazuh's bundled Python, so check it still imports `requests` |
| Manager healthcheck (`compose.yml`) | Names the daemons that must run (`wazuh-analysisd`, `-remoted`, `-authd`, `-db`, `-modulesd`, `-apid`; A27) | Daemon names still exist (`/var/ossec/bin/wazuh-control status`) |
| Indexer addressed as `wazuh.indexer` | The certificate tool only accepts dotted DNS names (D32, A15) | Tool version in `config/certs.yml` / `WAZUH_CERTS_GENERATOR_IMAGE`; `gen-certs.sh` on a clean `nodes/core/certs/` |
| `internal_users.yml` generated by `gen-certs.sh` with only `admin` | Drops the upstream demo users; hashed with the indexer image's tool (A16) | Hash tool path in the new indexer image; fresh `soc.sh init core` |
| Index names `wazuh-alerts-4.x-*` | Used by `grafana-ro`'s role (A19), `wazuh-query.sh` and the Grafana datasource pattern (D35) | Wazuh 5 renames the alert indices: update all three with the Grafana owner |
| Lab agent image (`nodes/lab/Dockerfile`) | `wazuh-agent=<version>-1` from the Wazuh apt repository on a dated Ubuntu tag (A28) | Must match the manager version; rebuild with `soc.sh init core` |

## Backlog (PROJECT.md 11.3)

Pick from this list; Phase 1 only built the baseline. The owner's plan, split into milestones with a "done when" check per task, is in [BACKLOG.md](BACKLOG.md). Requests from other owners and the replies are kept in [docs/](docs/).

- ~~Restrict syslog sources~~ Done (W1.1): see "Syslog sources (514/udp)".
- Detection rules and decoders for the environment; false-positive tuning; the alert level threshold (`WAZUH_ALERT_MIN_LEVEL`, default 7).
- Agent groups and policies; an enrollment guide for real endpoints (the lab agent is the reference).
- Decoders for pfSense and router logs; MITRE ATT&CK mapping.
- CDB lists fed from MISP IOCs (with the Cortex + MISP owner).
- Later: response actions through C9 (Phase 2, with the n8n owner).
