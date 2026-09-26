# Memory report

- Date: 2026-09-26 22:02 UTC
- Profile: `low`, deploy mode `single`, nodes: cases intel
- Anon peak: highest value sampled every 2s over 720s
- MiB. anon = anonymous memory (what limits are sized from); file = page cache (reclaimable); peak = cgroup memory.peak since the container started (includes cache)

| Node | Container | Limit | Anon | Anon peak | File | Peak | Swap | OOM kills | D40 limit |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| cases | cassandra | 1000 | 749 | 774 | 37 | 860 | 0 | 0 | 1000 |
| cases | cortex | 550 | 382 | 385 | 48 | 439 | 0 | 0 | 550 |
| cases | elasticsearch | 1450 | 1071 | 1071 | 16 | 1131 | 0 | 0 | 1300 |
| cases | thehive | 1300 | 895 | 895 | 35 | 944 | 0 | 0 | 1100 |
| intel | mariadb | 400 | 133 | 133 | 18 | 161 | 0 | 0 | 250 |
| intel | misp-core | 900 | 386 | 456 | 161 | 900 | 0 | 0 | 600 |
| intel | misp-modules | 400 | 266 | 266 | 22 | 400 | 0 | 0 | 400 |
| intel | misp-nginx | 100 | 5 | 7 | 13 | 25 | 0 | 0 | 100 |
| intel | redis | 100 | 3 | 3 | 10 | 20 | 0 | 0 | 100 |

| Node | Sum of limits | Anon | Sum of anon peaks |
|---|--:|--:|--:|
| cases | 4300 | 3097 | 3125 |
| intel | 1900 | 794 | 866 |
| **all** | **6200** | **3891** | **3990** |

OOM kills: 0. Container swap: 0 MiB.

WSL VM (`free -m`, includes WSL, Docker and everything else running):

```
               total        used        free      shared  buff/cache   available
Mem:            5927        5271         100          29         930         655
Swap:           8192         141        8050
```

WSL VM used (total - available): now 5272 MiB, peak 5312 MiB. Swap used: now 141 MiB, peak 143 MiB.

Outside containers (RSS, now 993 MiB in total), largest by peak:

| Process | RSS now | RSS peak |
|---|--:|--:|
| MainThread | 310 | 628 |
| claude | 308 | 389 |
| containerd-shim | 100 | 108 |
| dockerd | 68 | 94 |
| containerd | 42 | 58 |
| bash | 26 | 37 |
