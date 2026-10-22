# W3.7: the IDS (Suricata) alerts, for `pb-ids-alert`, the `ids-network-alert` template and GRAF-2.3

**To:** Inigo (@poinsot, n8n: N8N-4.4 `pb-ids-alert`), Park (TheHive: `ids-network-alert`, T3.6), Jesus (Grafana: GRAF-2.3)
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-22
**Refs:** W3.3–W3.7, X-23, X-34, D49; `nodes/core/n8n/docs/WAZUH-FIELDS.md` "Suricata"; `rules/1010-suricata.xml`, `rules/1080-misp-ioc.xml`
**Status:** draft

The fields in n8n's `WAZUH-FIELDS.md` ("Suricata", seen 2026-10-15) are **confirmed unchanged** on new alerts from `ids-test` and `ids-scan` (2026-10-22). This note adds what only the Wazuh side knows: which rules fire, what reaches n8n, and what changes with the physical sensor on Monday.

## Rules (all `asox`, `suricata`, `ids`)

| Rule | Level | When | To n8n | MITRE | Extra group |
|---|---|---|---|---|---|
| 86601 (built-in) | 3 | every Suricata alert | no | — | — |
| **101000** | 12 | `data.alert.severity` 1 | yes | — | — |
| **101001** | 10 | severity 2 | yes | — | — |
| **101002** | 6 | severity 3 or 4 | no | — | — |
| **101010** | 10 | signature starts with `ET SCAN ` | yes | T1046 | `recon` |
| **108010 / 108011** | 12 | `data.src_ip` / `data.dest_ip` is a MISP IOC (C14) | yes | — | `misp_ioc` (routes to `ioc-match` first) |
| 109010 | 0 | Suricata engine events (`SURICATA STREAM …`), silenced | no | — | — |

Only 101010 carries MITRE: Suricata's categories ("Potentially Bad Traffic", "Attempted Information Leak") don't map to one technique. Use `data.alert.category` and `data.alert.signature` in the title.

## Fields: what to rely on

- **All values are strings**, including `data.alert.severity` (`"2"`), `data.alert.signature_id` (`"2010935"`), the ports, and the `data.flow.*` counters. Never use `data.flow_id` as an identifier: it is float-formatted (`"889294418694949.000000"`).
- **Identity:** `data.alert.signature`, `data.alert.signature_id`, `data.alert.category`, `data.alert.severity`, `data.alert.metadata.signature_severity` (a list, e.g. `["Informational"]`).
- **Addresses:** `data.src_ip`, `data.src_port`, `data.dest_ip`, `data.dest_port`, `data.proto`, `data.direction` (`to_server`), plus the same in `data.flow.*`.
- **No application-layer fields:** no `data.http.*`, `data.dns.*` or `data.tls.*`, so no host name or URL on an IDS alert. Both sensors log `alert` events only (`nodes/lab/suricata/asox.yaml`, ENROLLMENT.md step 2), to keep `eve.json` small. If `pb-ids-alert` needs the HTTP host or URL, tell me and I'll weigh turning on Suricata's alert metadata.

## Who is the attacker

`data.src_ip` / `data.dest_ip` follow the **flow** (the client is the source), not the attack:
- `ET SCAN …` (101010): `src_ip` is the scanner. Use it.
- `GPL ATTACK_RESPONSE id check returned root` (101001 from `ids-test`): the signature matches the server's *answer*. `src_ip` is the lab host that made the request (the possibly compromised one) and `dest_ip` is the remote server.

So don't call `src_ip` "the attacker" in the template text. "Source" and "destination" are always correct.

## Volume: group per source

One scan gives **several** 101010 within seconds, one per matched signature (4 on 2026-10-22: `NMAP -sS window 1024`, inbound to MSSQL 1433, mySQL 3306, Oracle 1521), all from the same `data.src_ip`. As `pb-ssh-bruteforce` does by source IP, `pb-ids-alert` should group them per `data.src_ip` (e.g. ±10 min) so a scan is one TheHive alert with its signatures listed, not four.

## Lab sensor and physical sensor (Monday)

| | Lab (`ids-test`, `ids-scan`) | Physical lab, Monday 2026-10-26 |
|---|---|---|
| Agent | `lab-agent` (group `linux-servers`) | **`sensor-suricata`** (group `network-sensors`) |
| `location` | `/var/log/suricata/eve.json` | the same |
| Traffic | the lab containers (`172.20.0.0/16`) | the switch's SPAN port: real attacker and victim addresses (`192.168.1.0/24` or the lab's subnet) |
| If it goes quiet | — | rule 100400, level 10 ("sensor-*" disconnected), to n8n |

The rules and fields are the same; match on `rule.groups`, never on `agent.name`.

## For each of you

- **Inigo (N8N-4.4):** route `suricata` + `ids` (already `ids-network-alert`, ahead of `network-scan`). Group per `data.src_ip`; observables `ip` for `data.src_ip` and `data.dest_ip` (already in the extractor); title from `data.alert.signature`. 101010 also has `recon` and T1046.
- **Park (`ids-network-alert`):** the "who is the attacker" note above for the task text; `data.alert.category` and `data.alert.signature_id` are useful custom fields.
- **Jesus (GRAF-2.3):** panels on `rule.groups: ids` by `data.alert.signature` (top), `data.src_ip` (top sources), and `rule.id: 101010` over time (scans). The lab dashboard can filter `agent.name: sensor-suricata` for the physical sensor.
