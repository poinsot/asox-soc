# TheHive → n8n, Wazuh: X-44 (web and FIM alerts), web template

**To:** Inigo (@poinsot), n8n owner; Daniel (@dmelgar1110), Wazuh owner
**From:** Park (@Jinhyuk-P), TheHive owner
**Date:** 2026-10-20
**Refs:** X-44, X-04; Daniel's `nodes/core/wazuh/docs/request-n8n-2026-10-19.md` (scenarios `fim-tamper`, `web-attack`); Inigo's fixtures of 2026-10-20
**Files (branch `thehive`):** `docs/ALERT-FORMAT.md` (§1, §3, §5, §7), `docs/TRIAGE.md`, `entities/case-templates.json`, `scripts/thehive-test-alert.sh`

Thanks for the fixtures and the scenarios. My decisions below are in ALERT-FORMAT.

## 1. `data.url` is path-only → `uri_path` observable

- **Path-only values** (`/products.php?id=1' OR 1=1--`, what access logs give) → TheHive's built-in **`uri_path`** type, tagged `request`. It is a real TheHive type, so no new entity is needed.
- **Full URLs** (`scheme://host/...`) stay `url`, as today.
- **Inigo:** please send path-only values as `uri_path` instead of skipping them. Capping long attacker-written values is fine with me; please cap them in the observable too, not only in the writeback.

## 2. FIM alerts (553 and the others)

- **Title:** for group `syscheck`, the title adds `syscheck.path` after the description, so 553 becomes `File deleted. /etc/cron.d/backup (lab-agent)`. Same cap as above.
- **Tags:** the hash and `filename` observables get `fim:modified`, `fim:added` or `fim:deleted`. Take it from `syscheck.event`, or from the groups `syscheck_entry_*`.
- **Deleted file:** the hash observable's description says "Last known hash of a deleted file". So nobody looks for the file on disk, and the hash still goes to the analyzers.

## 3. Two new templates: `web-attack` and `file-integrity` (Daniel's question)

Yes, I want a web template, and FIM gets one too. Both are in `entities/` now (12 templates). They're **proposed** in §3 until Inigo checks them against the fixtures:

| Row | Match | Rules | Position |
|---|---|---|---|
| `web-attack` | `rule.groups` has `web` **and** `attack` | 31103, 31152 | after `network-scan` |
| `file-integrity` | `rule.groups` has `syscheck` | 550, 553, 554, 100302 | after `web-attack`, before `wazuh-generic` |

`ioc-match` stays first, so a web attack from a known IOC still goes there.

- **Daniel:** please confirm the groups from your live alerts: do 31103 / 31152 carry `web` + `attack`, and does 100302 carry `syscheck`?
- **Inigo:** once the fixtures match, the two rows can go active in `lib-config`. Tell me and I'll switch §3 to active.

## 4. Test alerts

`thehive-test-alert.sh` has two new scenarios, `web` and `fim`, so the new templates can be tested in `cases` mode.
