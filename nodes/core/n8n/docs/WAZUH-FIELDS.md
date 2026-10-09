# Wazuh alert fields n8n relies on (N8N-0.3)

Owner: n8n (Inigo). **Status: reviewed by the Wazuh owner (Daniel) on 2026-10-07 against real alerts** (`nodes/core/wazuh/docs/request-n8n-wazuh-fields-review.md`, W2.5, X-01), and his corrections applied here on 2026-10-09. The five points of "To agree with the Wazuh owner" are **agreed** (section at the end). **Not yet "agreed" as a whole:** the fields no lab alert produces yet stay to confirm when their sources land (FIM M5, Suricata M3, firewall decoders M4; "Still open" at the end). C1's payload shape doesn't change (PROJECT.md 5); this file only turns the fields n8n reads into a documented promise, so a rule or decoder change on the Wazuh side that drops or retypes one of them is agreed first.

**Verified against the fixtures, not from memory** (`../fixtures/wazuh/`, Wazuh 4.14.8): the 2026-09-30 captures, and since 2026-10-09 the exact C1 bodies of the Wazuh owner's lab scenarios (`trigger.sh --scenario`). A field no fixture has says **not seen**.

Fixtures used (short names in the tables):

| Short | File | Rule | Level | Sent by C1 |
|---|---|---|---|---|
| **test** | `100100-asox-test-c1.json` (exact C1 body) | 100100 ASOX test rule, from a monitored log file | 10 | yes |
| **syslog** | `100100-asox-test-syslog-c1.json` | 100100, received over syslog (514/udp): no agent | 10 | yes |
| **sca-check** | `19007-sca-check-failed.json` | 19007 SCA check failed (level 7 before Wazuh's W2.7 tuning; now 5) | 7 | yes then, no longer |
| **sca-sum** | `19004-sca-summary.json` | 19004 SCA summary (same) | 7 | yes then, no longer |
| **agent** | `503-agent-started.json` | 503 agent started | 3 | no (below threshold); only as a sample |
| **sshd** | `5763-sshd-bruteforce.json`, `5712-sshd-bruteforce-invalid-users.json`, `100200-ssh-root-login.json`, `40112-login-after-bruteforce.json` | sshd brute force (existing / invalid users), root login, login after failures | 10, 10, 10, 12 | yes |
| **sudo** | `5404-sudo-three-failures.json` | 5404 three failed sudo attempts | 10 | yes |
| **accounts** | `5901-new-group.json`, `5902-new-user.json`, `100211-user-added-to-privileged-group.json` | groupadd, useradd, usermod (privileged group) | 8, 8, 10 | yes |

"Optional" means the normalizer (N8N-1.2) must accept the alert without the field; "required" means an alert without it is malformed and is parked (N8N-1.2), not dropped.

## Core fields (every alert)

| Field | Type (seen) | Carried by | Not carried by | Promise | Notes |
|---|---|---|---|---|---|
| `id` | string, `"<epoch>.<offset>"` (e.g. `"1790461241.14189"`) | all | — | **required** (agreed) | Dedup key everywhere: TheHive `sourceRef` (D-N1), C11 document ID. Keep it a string: it looks like a decimal number, and parsing it as one loses digits (`Number("1790378132.1860721")` is `1790378132.186072` in n8n's Node.js). |
| `timestamp` | string, `YYYY-MM-DDTHH:MM:SS.mmm+0000` | all | — | **required** (agreed) | The offset has **no colon** (`+0000`). Inside n8n both JavaScript `Date.parse` and Luxon `DateTime.fromISO` accept it (checked in the n8n 2.40.7 container), but stricter parsers don't (jq's `fromdateiso8601` rejects it): the normalizer emits a canonical ISO/epoch value so later steps and other tools don't depend on this format. Source of C11's `t_event` and TheHive `date`. |
| `@timestamp` | string, ISO with `Z` | indexer copies only | **C1 body** | never use | Added by the indexer pipeline, like `input.type`; not in the C1 POST. |
| `rule.id` | **string** (`"100100"`, `"5763"`, `"40112"`) | all | — | **required** (agreed) | A string in C1, while TheHive's custom field `wazuh-rule-id` is an **integer** (ALERT-FORMAT §4): n8n converts. Routing (D-N2) compares it as a string. |
| `rule.level` | number (12, 10, 8, 7, 3) | all | — | **required** (agreed) | Severity mapping (ALERT-FORMAT §2) and the C1 threshold. |
| `rule.description` | string | all | — | **required** (agreed) | TheHive title. |
| `rule.groups` | **array** of strings (`["asox","test"]`, `["syslog","sshd","authentication_failures"]`, `["syslog","attacks"]`) | all | — | **required** (agreed; may be a one-element array) | Routing key (D-N2) and TheHive tags; always an array, never a comma string. Group names: Wazuh's standard ones plus `asox`, a source group, `attack_start` and `misp_ioc` (Wazuh README, "Rule groups"). |
| `rule.firedtimes` | number | all | — | optional | Times the rule fired in this manager session; 130 on the SCA start-up burst. Useful for flood protection (N8N-1.4), not a count per source. |
| `agent.id` | string, zero-padded (`"001"`); **`"000"` on syslog alerts** | all | — | **required** (agreed) | `"000"` is the manager itself: every alert received over syslog (514/udp) has it. See "Alerts received over syslog". |
| `agent.name` | string | all | — | **required** (agreed) | TheHive title, tag `agent:<name>`, custom field `wazuh-agent-name`; C13 `hostname`. **On a syslog alert it is the manager (`wazuh-manager`), not the device** (below). |
| `agent.ip` | string (`172.18.0.7`, the lab container) | test, sshd, sudo, accounts, agent | **sca-check, sca-sum, syslog** | **optional** | Absent on SCA alerts (generated by the agent's SCA module, not from a log) and on syslog alerts. C13 `ip`. |
| `manager.name` | string | all | — | optional | Not used yet. |
| `full_log` | string | test, syslog, sshd, sudo, accounts, agent | **sca-check, sca-sum** | **optional** | Absent on SCA alerts; TheHive's description must cope without it (ALERT-FORMAT §1 puts it in a code block). **Lab scenario lines end with ` asox_run=<run id>`** (W1.6, ties an alert to its attack-start marker for C11): not part of the message, never parse it as such. Real logs never have it. |
| `location` | string: a log file (`/var/log/asox-lab/test.log`), a module (`sca`, `wazuh-agent`), or **the sender's IP on a syslog alert** (`172.19.0.1`, `10.99.0.50`) | all | — | optional | On a syslog alert, the device's address. |
| `decoder.name` | string (`sshd`, `sudo`, `groupadd`, `useradd`, `asox-usermod`, `sca`) | all but test and syslog | **test, syslog** (`decoder` is `{}`) | **optional** | The test rule matches without a decoder. `lib-extract-observables` reads it for the user-field quirks (below). |
| `predecoder.*` | object (`hostname`, `program_name`, `timestamp`) | test, syslog (RFC 3164), sshd, sudo, accounts | sca-check, sca-sum, agent; **a syslog line in RFC 5424 format** (no `predecoder` at all) | optional | Syslog-style lines only. On a syslog alert, `predecoder.hostname` is the device's own name. |
| `data` | object | sshd, sudo, accounts, sca-check, sca-sum, agent | **test, syslog** (no `data` at all) | **optional, and so is every `data.*` field** | The shape of `data` depends entirely on the decoder. **Every `data.*` value seen is a string**, numbers included (`srcport: "41008"`, `uid: "1001"`). |

## Alerts received over syslog (no agent)

Seen on `syslog` (2026-10-09) and confirmed by the Wazuh owner (review item 6). Matters for pfSense and routers (M4) and for anything sent to 514/udp.

| Field | Value on a syslog alert |
|---|---|
| `agent.id` | `"000"` |
| `agent.name` | `wazuh-manager` |
| `agent.ip` | absent |
| `location` | the sender's IP (through the published port in single mode: core's network gateway, `172.19.0.1`) |
| `predecoder.hostname` | the device's own name, on RFC 3164 lines only |

**Normalizer (2026-10-09):** `canonical.host` is the host the alert is about. When `agent.id` is `"000"` and `location` is an IP, it is the device: `ip` = `location`, `name` = `predecoder.hostname` (or none), `source: syslog`; otherwise it is the agent (`agent.name`, `agent.ip`, `source: agent`). `canonical.agent` keeps the alert's `agent.*` as received. `lib-extract-observables` builds the `agent`-tagged `ip` / `hostname` observables from `host`, so a pfSense alert no longer gets `wazuh-manager` as its host observable. The TheHive **title**, the `agent:` tag and the custom field `wazuh-agent-name` still use `agent.name` as ALERT-FORMAT §1/§4 say: question F to TheHive (ALERT-TO-THEHIVE §8), and C13's `hostname` → `agent.name` mapping has the same issue (Cortex + MISP).

## MITRE ATT&CK

| Field | Type (seen) | Carried by | Not carried by | Promise | Notes |
|---|---|---|---|---|---|
| `rule.mitre.id` (and `.tactic`, `.technique`) | **array** of technique IDs: `["T1110"]` (5712, 5763), `["T1078","T1110"]` (40112), `["T1078.003"]` (100200), `["T1548.003"]` (5404), `["T1136"]` (5902), `["T1098"]` (100211) | sshd, sudo, 5902, 100211 | test, syslog, **5901**, sca-check, sca-sum, agent | **optional** (agreed) | Every custom rule that maps to ATT&CK carries a `<mitre>` block (W2.3); 100100 and the marker 100101 have none, and built-in rules keep Wazuh's own mapping, so some have none (5901, new group). So routing can't rely on MITRE alone (e.g. `account-change` also matches the group `adduser`). |
| `rule.mitre_techniques` | array of strings (`["T1003","T1003.008","T1222","T1222.002"]`) | sca-check | others | optional | How **SCA** alerts carry MITRE: a different path from `rule.mitre.id`. Together with `rule.mitre_tactics` (`["TA0005"]`) and `rule.mitre_mitigations`. Since W2.7 only SCA regressions (19011, 19014) and a score below 30% (19005) still reach n8n. |
| `data.sca.check.compliance.mitre_techniques` | string, comma-separated (`"T1003,T1003.008,…"`) | sca-check | others | optional | Same list as a comma string; don't use it when `rule.mitre_techniques` is present. |

**Normalizer (implemented 2026-10-06, agreed in ALERT-FORMAT §3/§4):** MITRE techniques = `rule.mitre.id` if it has at least one technique, else `rule.mitre_techniques`, else none; one canonical list (`mitre_ids`, plus `mitre_source` naming the field it came from). A single string is accepted as a one-element list. Used for the `attack.*` tags, the `mitre-technique` custom field (first technique) and routing (prefix match, `T1110` matches `T1110.001`).

## Network and user fields (observables, C13 field map)

All **optional**. Decoder field names are agreed (custom decoders use `srcip`, `dstip`, `srcuser`, `dstuser`, `hostname`, `url`; any other name is announced first, C13).

| Field | Seen in | Type | Used for |
|---|---|---|---|
| `data.srcip` | sshd (5712, 5763, 100200, 40112) | string | observable `ip` tag `src`; C13 `ip`; aggregation key for `pb-ssh-bruteforce` |
| `data.srcport` | sshd (5763, 100200, 40112) | **string** (`"43001"`) | not read by n8n |
| `data.dstip` | **not seen** (firewall decoders, M4) | — | observable `ip` tag `dst`; C13 `ip` |
| `data.srcuser` | sshd 5712 (invalid user: the **attempted** name), sudo 5404 (who ran sudo) | string | observable `user-account`: tag `src`, except on sshd (`target`, below); C13 `user-account` |
| `data.dstuser` | sshd 5763, 100200, 40112 (the targeted existing account), sudo 5404 (the target, `root`), useradd 5902, usermod 100211 (the account), **groupadd 5901 (a group name)** | string | observable `user-account` tag `target`, except groupadd (skipped, below); C13 `user-account` |
| `data.hostname` | **not seen** (M4) | — | observable `domain`/`fqdn`; C13 `hostname` |
| `data.url` | **not seen** (web decoders, M4) | — | observable `url` |

**User fields don't always mean source and target** (Wazuh review item 3, Wazuh's built-in decoders, which the Wazuh owner won't override). `lib-config` `observable_user_fields` lists the decoders, matched on `decoder.name`; `lib-extract-observables` applies them (2026-10-09):

- **sshd** (`target_only_decoders`): the targeted account is in `data.dstuser` for an existing user (5760, 5763, 5715, 40112, 100200) and in `data.srcuser` for an invalid one (5710, 5712). Both are tagged **`target`** on sshd alerts.
- **groupadd** (`group_name_decoders`): 5901 puts the new **group** in `data.dstuser` (plus `data.gid`). No `user-account` observable is made from it; it is listed in `skipped` (`a group name, not an account`).
- **sudo** is consistent: `srcuser` is who ran sudo (`src`), `dstuser` the target (`target`). **useradd** (5902) and **usermod** (`asox-usermod`, 100211) put the account in `dstuser` (`target`).

## sudo and account fields (not observables)

| Field | Seen in | Type | Notes |
|---|---|---|---|
| `data.command`, `data.pwd`, `data.tty` | sudo 5404 | string | Useful in TheHive's description for `privilege-escalation` (Wazuh review item 5): not used yet, a candidate for that playbook (N8N-4.5). In the lab, `data.command` **also ends with ` asox_run=<run id>`** (the decoder takes the rest of the line). |
| `data.uid`, `data.gid`, `data.home`, `data.shell` | useradd 5902 (`gid` also groupadd 5901) | string | Not used. |
| `data.group` | usermod 100211 (decoder `asox-usermod`; same name as Wazuh's gpasswd decoder, 100212) | string | The privileged group (sudo, wheel, admin, root, docker, lxd). Not used yet. |

## FIM (syscheck)

**Not seen**: no FIM alert on the lab in 30 days; comes with Wazuh M5. All **optional**, to confirm then.

| Field | Seen in | Used for |
|---|---|---|
| `syscheck.path` | not seen | observable `filename` |
| `syscheck.md5_after`, `syscheck.sha1_after`, `syscheck.sha256_after` | not seen | observable `hash` (sha256 preferred); C13 `hash`; `pb-malware-hash` |
| `syscheck.event` | not seen | added / modified / deleted (a deleted file has no `*_after` hashes: to confirm) |

## Suricata (D49, PROJECT.md 5, ALERT-FORMAT §3)

**Not seen**: Suricata arrives with Wazuh's M3 (2026-11-03). All **optional**. Suricata keeps its own names (agreed): `data.src_ip`, `data.dest_ip`, `data.dest_port`; `data.alert.signature` and `data.alert.severity` are named in PROJECT.md 5; the others are the usual EVE JSON names, listed as candidates. All to confirm on real alerts.

| Field | Seen in | Used for |
|---|---|---|
| `rule.id` `86601`, `rule.groups` ∋ `suricata` / `ids` | not seen | routing to `pb-ids-alert`, template `ids-network-alert` |
| `data.alert.signature`, `data.alert.signature_id`, `data.alert.severity`, `data.alert.category` | not seen | TheHive title/description, severity input |
| `data.src_ip`, `data.dest_ip` | not seen | observables `ip` (`src` / `dst`); C13 `ip`. **Different names from `data.srcip` / `data.dstip`**: the normalizer maps both |
| `data.dest_port`, `data.src_port`, `data.proto` | not seen | description; probably strings, like every `data.*` seen so far (to confirm) |

## Other fields seen (not relied on)

- SCA (`data.sca.*`): every value is a **string**, numbers included (`score: "46"`, `passed: "73"`, `check.id: "35770"`). Useful for a later SCA playbook.
- `data.extra_data` (rule 503): agent name and group, e.g. `"lab-agent->any"`.
- Compliance arrays on the rule (`rule.pci_dss`, `rule.gdpr`, `rule.hipaa`, `rule.nist_800_53`, `rule.tsc`, `rule.cis`, …) on SCA and on the built-in sshd, sudo and account rules.

## To agree with the Wazuh owner (X-01, W2.5): answered 2026-10-07

| # | n8n asked | Wazuh's answer | Status |
|---|---|---|---|
| 1 | The **required** set stays present and keeps its type at level ≥ `WAZUH_ALERT_MIN_LEVEL`: `id` (string), `timestamp` (`+0000`), `rule.id` (string), `rule.level` (number), `rule.description`, `rule.groups` (array), `agent.id`, `agent.name` | Agreed. A Wazuh upgrade that changes any of them is announced first (Wazuh README "Local patches", WO.5). On syslog alerts `agent.*` is the manager | **agreed** |
| 2 | Custom rules mapped to ATT&CK use a `<mitre>` block (`rule.mitre.id`, array) | Agreed (W2.3). Exceptions: 100100 and 100101 have no technique; built-ins keep Wazuh's mapping (5901 has none); SCA has only `rule.mitre_techniques` | **agreed** |
| 3 | Standard decoder field names; Suricata keeps `data.src_ip` / `data.dest_ip` / `data.dest_port`; other names announced first (C13) | Agreed. The sshd user-field quirk is Wazuh's built-in decoder and stays (n8n handles it, above) | **agreed** |
| 4 | One captured alert per scenario in n8n's fixtures | Scenarios done (W1.5); n8n captured them 2026-10-09. FIM and Suricata come with M5 and M3: the Wazuh owner says when each lands | **done** for today's scenarios |
| 5 | Should the SCA start-up burst reach n8n? (X-09) | No: 19007 and 19004 lowered to level 5 (W2.7); only regressions (19011, 19014) and a score below 30% (19005) still reach n8n. n8n drops its temporary `sca` exclusion (N8N-1.1) | **agreed** (X-09 closed on n8n's side) |

## Still open

| What | Comes with |
|---|---|
| `data.dstip`, `data.hostname`, `data.url`, syslog device alerts with real devices | firewall, router and web decoders, Wazuh M4 (2026-11-10) |
| `syscheck.*` | FIM, Wazuh M5 |
| Suricata fields (`data.alert.*`, `data.src_ip`, `data.dest_ip`, `data.dest_port`, types) | Wazuh M3 (2026-11-03) |
| TheHive title / `agent:` tag / `wazuh-agent-name` on syslog alerts (`agent.name` is the manager) | ALERT-TO-THEHIVE §8 question F (TheHive); C13 `hostname` mapping (Cortex + MISP) |

Each row moves to "seen" when a real alert of it exists, and the file is then marked agreed as a whole.
