# Review: `WAZUH-FIELDS.md` checked against real alerts (W2.5, X-01)

**To:** Inigo (@poinsot), n8n owner; cc Park (@Jinhyuk-P) for ALERT-FORMAT §1 and §5, Diego (@DiegoGuerraA00835430) for C13's field map
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-07
**Refs:** W2.5, X-01, X-26 (C13), N8N-0.3, N8N-1.2 (normalizer); `nodes/core/n8n/docs/WAZUH-FIELDS.md` (branch `n8n`, read 2026-10-07)
**Status:** draft

Your draft was written before any sshd, sudo or account alert existed. The lab scenarios (`trigger.sh --scenario`, 2026-10-05) and the W1.1 syslog tests (2026-10-07) now give real ones. I checked every field in the indexer (Wazuh 4.14.8): rules 5712, 5763, 40112, 5404, 5901, 5902, the marker 100101, and a 100100 test alert received over syslog. **Your file is yours, so I haven't edited it**; here is what to change, and my answers to its section "To agree with the Wazuh owner".

## Confirmed as you wrote them

| Field | Type on every alert checked |
|---|---|
| `id` | string |
| `timestamp` | `YYYY-MM-DDTHH:MM:SS.mmm+0000` (no colon) |
| `rule.id` | string |
| `rule.level` | number |
| `rule.groups` | array |
| `rule.description` | present |
| `agent.id`, `agent.name` | present, zero-padded string id |
| `full_log` | string on every log-based alert |
| `rule.mitre.id` | **array** of technique IDs: `["T1110"]` on 5712 and 5763; `["T1078","T1110"]` on 40112; `["T1548.003"]` on 5404; `["T1136"]` on 5902 |
| `data.srcip` | string (sshd) |
| `agent.ip` | string (`172.18.0.4`) on alerts from the lab agent |

## To correct or add

1. **`rule.mitre.id` exists, and some rules have none.** Mark it "seen". 5901 (new group) and the marker 100101 have no `rule.mitre`. So "optional" stays right, and routing can't rely on MITRE alone for account changes (my routing answer A3).
2. **`data.srcport` is a string** (`"41008"`), not a number. Keep it as a string, or convert in the normalizer.
3. **sshd's user fields don't mean "source" and "target" consistently.** That's Wazuh's built-in decoder, not something I can rename safely:
   - failed password for an **existing** user (5760, 5763) and a login (5715, 40112): the account is in **`data.dstuser`** (`root`, `labuser`);
   - failed login for an **invalid** user (5710, 5712): the attempted name is in **`data.srcuser`** (`admin`).

   So `srcuser` → tag `src`, `dstuser` → tag `target` mislabels sshd. Suggestion: on sshd alerts treat whichever is present as the **targeted account**. For sudo (5404) the meaning is consistent: `srcuser` is who ran sudo (`labuser`), `dstuser` is the target (`root`).
4. **`groupadd` (5901) puts the group name in `data.dstuser`** (`svc-backup`, plus `data.gid`). A `user-account` observable made from it would be a group. `useradd` (5902) puts the new user there, with `uid`, `gid`, `home` and `shell`.
5. **sudo carries `data.command`, `data.pwd` and `data.tty`.** Useful in TheHive's description for privilege-escalation.
6. **Alerts received over syslog have no agent.** This matters for pfSense and routers (M4) and for anything sent to 514/udp:

   | Field | Value on a syslog alert |
   |---|---|
   | `agent.id` | `"000"` |
   | `agent.name` | `wazuh-manager` |
   | `agent.ip` | absent |
   | `location` | the sender's IP (e.g. `10.99.0.50`) |
   | `predecoder.hostname` | the device's own name (e.g. `pfsense`) |

   So for `agent.id == "000"`, use `predecoder.hostname` as the host and `location` as its address. Otherwise the TheHive title, the `agent:` tag and C13's `hostname` would all say `wazuh-manager`. **Diego (C13):** the same applies to the `hostname` → `agent.name` mapping. **Park:** ALERT-FORMAT §1 builds the title from `agent.name`.
7. **Lab scenario lines end with ` asox_run=<run id>`** in `full_log` (W1.6). It ties an alert to its attack-start marker for C11. Real logs never have it, so don't parse it as part of the message.
8. **Fixtures:** every scenario now produces real alerts. To capture exact C1 bodies, run a scenario and take the body from the `recv-wazuh-alert` execution, or from the indexer minus `@timestamp`.

   | Scenario | Alerts it produces |
   |---|---|
   | `ssh-bruteforce` | 5763 |
   | `ssh-success-after-fail` | 5763, 40112 (wait 60 s after `ssh-bruteforce`) |
   | `sudo-fail` | 5404 |
   | `new-user` | 5901, 5902 |
   | `ioc-ip` | 5712, from 203.0.113.66 |

## Answers to "To agree with the Wazuh owner"

1. **Required set and types: agreed.** Every alert at level ≥ `WAZUH_ALERT_MIN_LEVEL` keeps `id` (string), `timestamp` (`+0000`), `rule.id` (string), `rule.level` (number), `rule.description`, `rule.groups` (array), `agent.id` and `agent.name`. Note item 6: on syslog alerts `agent.*` is the manager, not the device. A Wazuh upgrade that changes any of them is announced first (README "Local patches", WO.5).
2. **`<mitre>` blocks: agreed.** Every custom rule that maps to ATT&CK carries `<mitre><id>…</id></mitre>`, so it arrives as `rule.mitre.id` (array) (W2.3). Exceptions:
   - the test rule 100100 and the marker 100101 have no technique;
   - built-in rules keep Wazuh's own mapping, so some have `rule.mitre.id` and some (5901) have none;
   - SCA has only `rule.mitre_techniques`, and is now mostly below the threshold (W2.7).
3. **Field names: agreed.** Custom decoders use `srcip`, `dstip`, `srcuser`, `dstuser`, `hostname`, `url`. Suricata keeps `data.src_ip`, `data.dest_ip`, `data.dest_port`. Any other name is announced first (C13). The sshd user-field quirk (item 3) is Wazuh's built-in decoder: I won't override it, because that would diverge from upstream on every upgrade.
4. **Fixtures:** done on my side (scenarios, item 8). FIM and Suricata alerts come with M5 and M3. I'll tell you when each lands, so you can move its rows from "not seen" to "seen".
5. **SCA:** answered in `n8n-requests-2026-09-30.md` item 6 (W2.7). Only regressions (19011, 19014) and a score below 30% (19005) still reach n8n.

## Still not seen (confirm later)

| Fields | Comes with |
|---|---|
| `data.dstip`, `data.hostname`, `data.url` | firewall and web decoders, M4 |
| `syscheck.*` | FIM, M5: no FIM alert in 30 days on the lab |
| Suricata fields | M3, 2026-11-03 |

## By

Checkpoint 1, **2026-10-20** (X-01). This documents fields; C1's payload is unchanged.
