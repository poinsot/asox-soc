# Memory report

- Date: 2026-09-26 21:49 UTC
- Profile: `low`, deploy mode `single`, nodes: cases
- Anon peak: highest value sampled every 2s over 600s
- MiB. anon = anonymous memory (what limits are sized from); file = page cache (reclaimable); peak = cgroup memory.peak since the container started (includes cache)

| Node | Container | Limit | Anon | Anon peak | File | Peak | Swap | OOM kills | D40 limit |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| cases | cassandra | 1000 | 781 | 806 | 27 | 864 | 0 | 0 | 1000 |
| cases | cortex | 550 | 400 | 400 | 62 | 477 | 0 | 0 | 550 |
| cases | elasticsearch | 1450 | 1074 | 1074 | 58 | 1145 | 0 | 0 | 1300 |
| cases | thehive | 1300 | 877 | 891 | 92 | 993 | 0 | 0 | 1100 |

| Node | Sum of limits | Anon | Sum of anon peaks |
|---|--:|--:|--:|
| cases | 4300 | 3133 | 3172 |
| **all** | **4300** | **3133** | **3172** |

OOM kills: 0. Container swap: 0 MiB.

WSL VM (`free -m`, includes WSL, Docker and everything else running):

```
               total        used        free      shared  buff/cache   available
Mem:            5927        4569         106           3        1607        1357
Swap:           8192          11        8180
```

WSL VM used (total - available): now 4570 MiB, peak 4602 MiB. Swap used: now 12 MiB, peak 12 MiB.

Outside containers (RSS, now 1372 MiB in total), largest by peak:

| Process | RSS now | RSS peak |
|---|--:|--:|
| MainThread | 627 | 628 |
| claude | 341 | 392 |
| dockerd | 93 | 113 |
| containerd | 56 | 65 |
| containerd-shim | 47 | 48 |
| bash | 26 | 39 |
