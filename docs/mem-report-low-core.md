# Memory report

- Date: 2026-09-26 21:38 UTC
- Profile: `low`, deploy mode `single`, nodes: core lab
- Anon peak: highest value sampled every 2s over 1200s
- MiB. anon = anonymous memory (what limits are sized from); file = page cache (reclaimable); peak = cgroup memory.peak since the container started (includes cache)

| Node | Container | Limit | Anon | Anon peak | File | Peak | Swap | OOM kills | D40 limit |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| core | grafana | 250 | 95 | 122 | 98 | 236 | 0 | 0 | 250 |
| core | n8n | 650 | 307 | 447 | 109 | 607 | 0 | 0 | 600 |
| core | wazuh-indexer | 1100 | 902 | 902 | 6 | 920 | 0 | 0 | 1150 ! |
| core | wazuh-manager | 700 | 307 | 310 | 164 | 637 | 0 | 0 | 450 |
| lab | lab-agent | 100 | 18 | 18 | 57 | 97 | 0 | 0 | 100 |

| Node | Sum of limits | Anon | Sum of anon peaks |
|---|--:|--:|--:|
| core | 2700 | 1611 | 1781 |
| lab | 100 | 18 | 18 |
| **all** | **2800** | **1629** | **1799** |

OOM kills: 0. Container swap: 0 MiB.

WSL VM (`free -m`, includes WSL, Docker and everything else running):

```
               total        used        free      shared  buff/cache   available
Mem:            5927        3074          85           3        2953        2853
Swap:           8192           0        8191
```

WSL VM used (total - available): now 3074 MiB, peak 3081 MiB. Swap used: now 1 MiB, peak 1 MiB.

Outside containers: not shown for this run. The first version of this table
counted container processes too (`ps` truncated the cgroup column); fixed
before the `cases` run. Measured in the later runs: Claude Code ~0.3-0.4 GB,
VS Code server ~0.6 GB, dockerd + containerd ~0.2 GB.
