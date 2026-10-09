# Request: confirm the attack-start marker for Grafana's annotation

**To:** Jesus (@JC-535), Grafana owner; cc Inigo (@poinsot), n8n owner (C11 writer)
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-05
**Refs:** W1.5, W1.6, X-32, GRAF-2.2, D-G3, C11 (`t_attack_start`)
**Status:** sent (2026-10-07, with the checkpoint PR)

## What exists now (branch `wazuh`, tested on the live lab)

`nodes/lab/trigger.sh --scenario <name>` writes the marker first, then the attack's events a second later. The scenarios are `ssh-bruteforce`, `ssh-success-after-fail`, `sudo-fail`, `new-user` and `ioc-ip`; `--list` and `--help` show them. The marker line is:

```
<date> lab-agent asox-lab: ASOX_ATTACK_START scenario=<name> id=<uuid>
```

In the indexer (`wazuh-alerts-*`) it's an alert with:

| Field | Value |
|---|---|
| `rule.id` | `100101` |
| `rule.level` | `3` |
| `rule.groups` | `asox`, `test`, `attack_start` |
| `data.scenario` | e.g. `ssh-bruteforce` |
| `data.run_id` | the uuid |
| `timestamp` | the attack's start, `t_attack_start` |
| `rule.description` | `ASOX lab: attack scenario <name> started (run <uuid>)` |

Every event of the run ends with ` asox_run=<uuid>`, so its alerts can be tied to the marker through `full_log`. The SSH, sudo and user-creation decoders still extract their fields normally.

## What I need

1. **Jesus:** confirm the annotation query works for you: `rule.id:100101`, or `rule.groups:attack_start`, with `data.scenario` as the annotation text. Confirm too that level 3 is fine. The marker is indexed (`log_alert_level` is 3), but never sent to n8n or TheHive (C1 starts at 7).
2. **Inigo:** for C11, is linking an alert to its run by `asox_run=<uuid>` in `full_log` enough? The other option is the nearest earlier marker on the same agent. Or do you need something else?

## Example to try

```bash
id=$(nodes/lab/trigger.sh --scenario ssh-bruteforce)
scripts/wazuh-query.sh --match "$id"     # the marker (100101) and the run's alerts
```

## By

Before checkpoint 1, **2026-10-20** (X-32). It isn't a contract change: these are fields inside C8's existing index.
