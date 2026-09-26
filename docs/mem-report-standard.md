# Memory report

- Date: 2026-09-26 19:15 UTC
- Profile: `standard`, deploy mode `single`, nodes: core cases intel lab
- Anon peak: highest value sampled every 2s over 1500s
- MiB. anon = anonymous memory (what limits are sized from); file = page cache (reclaimable); peak = cgroup memory.peak since the container started (includes cache)

| Node | Container | Limit | Anon | Anon peak | File | Peak | Swap | OOM kills | D40 limit |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| core | grafana | 256 | 96 | 113 | 2 | 123 | 0 | 0 | 200 |
| core | n8n | 750 | 317 | 487 | 47 | 614 | 0 | 0 | 650 |
| core | wazuh-indexer | 2048 | 1438 | 1439 | 2 | 1453 | 0 | 0 | 1750 |
| core | wazuh-manager | 700 | 308 | 309 | 212 | 619 | 0 | 0 | 450 |
| cases | cassandra | 1600 | 1302 | 1331 | 45 | 1388 | 0 | 0 | 1600 |
| cases | cortex | 600 | 479 | 486 | 37 | 531 | 0 | 0 | 650 ! |
| cases | elasticsearch | 2400 | 1655 | 1658 | 1 | 1670 | 0 | 0 | 2000 |
| cases | thehive | 1900 | 1456 | 1457 | 12 | 1483 | 0 | 0 | 1750 |
| intel | mariadb | 550 | 148 | 151 | 0 | 155 | 0 | 0 | 250 |
| intel | misp-core | 900 | 386 | 393 | 177 | 900 | 0 | 0 | 550 |
| intel | misp-modules | 400 | 266 | 266 | 83 | 365 | 0 | 0 | 400 |
| intel | misp-nginx | 100 | 5 | 9 | 0 | 12 | 0 | 0 | 100 |
| intel | redis | 100 | 3 | 7 | 0 | 9 | 0 | 0 | 100 |
| lab | lab-agent | 100 | 18 | 19 | 1 | 41 | 0 | 0 | 100 |

| Node | Sum of limits | Anon | Sum of anon peaks |
|---|--:|--:|--:|
| core | 3754 | 2159 | 2348 |
| cases | 6500 | 4892 | 4931 |
| intel | 2050 | 808 | 826 |
| lab | 100 | 18 | 19 |
| **all** | **12404** | **7877** | **8125** |

OOM kills: 0. Container swap: 0 MiB.

WSL VM (`free -m`, includes WSL, Docker and everything else running):

```
               total        used        free      shared  buff/cache   available
Mem:           15995        9333        2369          30        4796        6661
Swap:           4096           0        4096
```

Follow-up: cortex was the only container below its D40 limit (`!`), so `CORTEX_MEM` (standard) was raised from 600m to 650m after this report (docs/decisions.md A69).
