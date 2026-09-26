# Memory report

> Best-effort mode (D39). Run in an earlier session (2026-09-26), before the
> `low` limits of grafana (200m -> 250m, from this report) and wazuh-indexer
> (1100m -> 1150m) were raised, and before the report showed VM peaks and the
> processes outside containers. `soc.sh init core-cases` passed, and so did
> C1-C6 and C8 and `healthcheck.sh --cross-node` (C7 skipped: intel not
> running). The VM was near its limit: ~0.2-0.35 GB available, ~0.35 GB
> swapped. The `full` run that followed stalled the VM (docs/decisions.md A70).

- Date: 2026-09-26 20:48 UTC
- Profile: `low`, deploy mode `single`, nodes: core cases lab
- Anon peak: highest value sampled every 2s over 1200s
- MiB. anon = anonymous memory (what limits are sized from); file = page cache (reclaimable); peak = cgroup memory.peak since the container started (includes cache)

| Node | Container | Limit | Anon | Anon peak | File | Peak | Swap | OOM kills | D40 limit |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| core | grafana | 200 | 98 | 121 | 23 | 200 | 0 | 0 | 250 ! |
| core | n8n | 650 | 314 | 444 | 16 | 650 | 0 | 0 | 600 |
| core | wazuh-indexer | 1100 | 880 | 883 | 20 | 1041 | 0 | 0 | 1100 |
| core | wazuh-manager | 700 | 306 | 306 | 16 | 700 | 0 | 0 | 450 |
| cases | cassandra | 1000 | 755 | 802 | 26 | 848 | 0 | 0 | 1000 |
| cases | cortex | 550 | 419 | 420 | 14 | 452 | 0 | 0 | 550 |
| cases | elasticsearch | 1450 | 1075 | 1075 | 21 | 1162 | 0 | 0 | 1300 |
| cases | thehive | 1300 | 911 | 923 | 18 | 949 | 0 | 0 | 1150 |
| lab | lab-agent | 100 | 18 | 18 | 6 | 90 | 0 | 0 | 100 |

| Node | Sum of limits | Anon | Sum of anon peaks |
|---|--:|--:|--:|
| core | 2650 | 1598 | 1754 |
| cases | 4300 | 3159 | 3220 |
| lab | 100 | 18 | 18 |
| **all** | **7050** | **4776** | **4992** |

OOM kills: 0. Container swap: 0 MiB.

WSL VM (`free -m`, includes WSL, Docker and everything else running):

```
               total        used        free      shared  buff/cache   available
Mem:            5927        5698          65           0         504         228
Swap:           8192         355        7836
```
