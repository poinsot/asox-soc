# n8n → Wazuh: field list and fixtures (2026-09-30)

Received by the Wazuh owner on 2026-10-01. The original message is kept below as sent. Answers go in the **Reply** column of the tracker, and the delivering task is in [BACKLOG.md](../BACKLOG.md).

## Reply tracker

| # | Ask (short) | Due | Wazuh task | Status | Reply |
|---|---|---|---|---|---|
| 1 | Agree the field list; keep types stable (`id`, `rule.id` strings; `rule.level` number; `rule.groups` array; same `timestamp`) | 2026-10-20 | W2.5 | open | |
| 2 | Custom ATT&CK rules use `<mitre>` (`rule.mitre.id`) | 2026-10-20 | W2.3 | open | |
| 3 | Standard field names: `srcip`, `dstip`, `srcuser`, `dstuser`; Suricata `data.src_ip`, `data.dest_ip`, `data.dest_port` | 2026-10-20 | W2.2, W3.3, W4.2 | open | |
| 4 | `trigger.sh --scenario` for fixtures | 2026-10-09 | W1.5 | open | |
| 5 | Attack-start marker and its low-noise rule | before 2026-10-20 | W1.6 | open | |
| 6 | Should SCA alerts reach n8n? | 2026-10-20 | W2.7 | open | |
| 7 | `ioc-ip` and the other scenarios use documentation-range attacker IPs (`203.0.113.66` for `ioc-ip`) | 2026-10-09 | W1.5 | open | |
| 8 | C1 retries: n8n accepts send-once; tell n8n before adding any | before any change | W1.8 | open | |
| 9 | C14: n8n prefers a Wazuh-side sync script with its own MISP key (R-08) | 2026-10-16 | W6.1 | open | |
| 10 | R-06: format, default, and a test of which source IP the manager sees through the published UDP port | **2026-10-07** | W1.9 | open | |

Status values: `open`, `answered`, `done`, `declined` (with the reason in Reply).

### Syslog source-IP test (item 10c)

Fill in from W1.9.

| Sender | Sent to | Source IP the manager saw |
|---|---|---|
| WSL host | `127.0.0.1:514/udp` | |
| lab container | `wazuh-manager:514/udp` over `soc-net` | |
| another machine (optional) | host LAN IP `:514/udp` (distributed mode) | |

---

## Original message

**To:** Daniel (@dmelgar1110), Wazuh owner
**From:** Inigo (@poinsot), n8n owner
**Date:** 2026-09-30
**Refs:** X-01 / W2.5 (field list), X-05 / W1.5 (fixtures), X-09 / W2.1 (threshold), X-32 (attack-start marker), X-10 (C1 retries), X-24 / C14 (MISP → CDB lists), R-06
**Files:** `nodes/core/n8n/docs/WAZUH-FIELDS.md` (draft, on branch `n8n`), `nodes/core/n8n/fixtures/README.md`

### Context

n8n's draft list of the Wazuh alert fields it relies on is written and checked against real alerts from the indexer. It becomes a documented promise once you agree it. No contract changes (C1's payload stays as it is).

### What I need from you

| # | Ask | Ref | By |
|---|---|---|---|
| 1 | Agree the field list and keep the types stable: `id` and `rule.id` as **strings**, `rule.level` as a **number**, `rule.groups` as an **array**, same `timestamp` format | X-01, W2.5 | 2026-10-20 |
| 2 | Custom rules mapped to ATT&CK should use a `<mitre>` block, so the technique arrives as `rule.mitre.id`. No current alert has it; SCA alerts only carry `rule.mitre_techniques` | X-01 | 2026-10-20 |
| 3 | Use the standard decoder field names: `srcip`, `dstip`, `srcuser`, `dstuser`. For Suricata: `data.src_ip`, `data.dest_ip`, `data.dest_port` | X-01, X-34 | 2026-10-20 |
| 4 | Ship `trigger.sh --scenario` so I can capture real fixtures for the types listed below | X-05, W1.5 | 2026-10-09 |
| 5 | Add the attack-start marker `ASOX_ATTACK_START scenario=<x> id=<uuid>` to the lab trigger, with a dedicated low-noise rule. Without it C11 has no MTTD | X-32 | before 2026-10-20 |
| 6 | **Should SCA alerts reach n8n at all?** An agent start runs an SCA scan that sends a burst of level-7 alerts to n8n (rule 19007: 130 alerts from one scan on 2026-09-25). That is the flood risk behind X-09. Options: raise their level threshold, exclude the `sca` group from `custom-n8n`, or let n8n aggregate them (N8N-1.4) | X-09, W2.1 | 2026-10-20 |
| 7 | In the `ioc-ip` scenario, use an attacker IP from a **documentation range**, ideally the MISP seed IOC `203.0.113.66`. Today every IP the lab produces is internal (`172.18.x.x`), so n8n's enrichment would never send anything to Cortex/MISP and never find a match | X-05, W1.5 | 2026-10-09 |
| 8 | **C1 retries (X-10):** n8n accepts C1's "send once, no retries" (it answers 200 on receipt now). If you ever add retries to `custom-n8n`, **tell me first**: TheHive's duplicate refusal isn't atomic, so overlapping copies of one alert create two TheHive alerts | X-10 | before any change |
| 9 | **C14 (with Diego, due 2026-10-16):** my preference is a **Wazuh-side sync script** with its own read-only MISP key (R-08). If n8n ran it, n8n would need write access to Wazuh's CDB lists: a new Wazuh permission and a contract change, like C9. I'm not against it, but it costs more | X-24, C14 | 2026-10-16 |
| 10 | **R-06 (`WAZUH_SYSLOG_ALLOWED_IPS`), for your W1.1:** (a) the **format** your entrypoint parses (my proposal: comma-separated IPv4 addresses/CIDRs, one `<allowed-ips>` per entry); (b) the **default** (my proposal: `172.16.0.0/12`, Docker networks only, so the lab agent and W4.5 work; a machine with pfSense adds its LAN). Each machine can override it with a new optional `SYSLOG_ALLOWED_IPS` in `topology.env`, which `render-env.sh` validates. (c) please **test which source IP the manager actually sees** for UDP syslog arriving through the published port (`${BIND_ADDR}:514:514/udp`): if Docker's NAT or userland proxy shows every sender as a `172.x` gateway address, a `172.16.0.0/12` default lets every source through and W1.1's "a message from another source produces no alert" check fails. Your entrypoint script (`30-syslog-allowed-ips.sh`) isn't on any branch yet, so the format is your call. Reply and I'll put it on `main` the same day | R-06, W1.1 | **2026-10-07**, so it's on `main` by 2026-10-09 |

### What exists today

Only three rules reach level 7 or above in the indexer (last 30 days, 526 alerts):

| Rule | Level | Description | Count |
|---|---|---|---|
| 100100 | 10 | ASOX test rule | 17 |
| 19007 | 7 | SCA check failed | 130 |
| 19004 | 7 | SCA summary | 1 |

Saved as fixtures: one alert of each rule, the exact C1 body of a 100100 alert, and one real level-3 alert (rule 503) labelled "below threshold, not sent by C1". Nothing was generated or invented.

### Fixtures missing (to come from Wazuh)

- sshd authentication failures and brute force
- sudo
- FIM / syscheck
- rootcheck and VirusTotal / malware
- Suricata (rule 86601, from M3 on 2026-11-03)
- the attack-start marker
- any rule that carries `rule.mitre.id`

### Fields never seen in a real alert yet

`data.srcip`, `data.dstip`, `data.srcuser`, `data.dstuser`, `data.hostname`, `data.url`, all `syscheck.*`, all Suricata fields. Until scenarios exist, the normalizer treats them as optional.

### For information: n8n's intake since 2026-09-30

- n8n now filters on the same `WAZUH_ALERT_MIN_LEVEL` as `custom-n8n` (a second guard, same value from `nodes/core/.env`).
- n8n **temporarily skips the `sca` rule group** until item 6 (X-09) is decided; skipped alerts are recorded in n8n, never sent to TheHive.
- **Once n8n's checkpoint is merged** and you run only `core`, your n8n will record Wazuh alerts as "skipped: TheHive not configured" (flag `THEHIVE_ENABLED`, derived by `render-env.sh` from whether core has a TheHive key). Existing instances keep the old stub until `scripts/n8n-import.sh`.
- **R-06** (`WAZUH_SYSLOG_ALLOWED_IPS`) is waiting on your answer to item 10.
- A C1 body that isn't valid JSON gets HTTP 422 from n8n before any workflow runs, so it can't be parked; only `integrations.log` would show it. `custom-n8n.py` sends `json.dumps` of the alert, so this shouldn't happen, but keep it in mind if the integration script changes.
