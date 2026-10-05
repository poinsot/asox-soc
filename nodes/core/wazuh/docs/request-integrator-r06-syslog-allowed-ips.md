# Request: R-06 `WAZUH_SYSLOG_ALLOWED_IPS` (answer to memo item 10)

**To:** Inigo (@poinsot), integrator
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-01
**Refs:** R-06, W1.9 (test), W1.1 (entrypoint), memo item 10 in [n8n-requests-2026-09-30.md](n8n-requests-2026-09-30.md)
**Status:** draft

## The test (10c)

Full table in [n8n-requests-2026-09-30.md](n8n-requests-2026-09-30.md#syslog-source-ip-test-item-10c). In short, on my machine (`single`, Docker 29.8.1, userland proxy on by default):

- The WSL host and Windows both sent to `127.0.0.1:514`. The manager saw **`172.19.0.1`**, the gateway of `asox-core_default`, which is where `docker-proxy` sends from.
- The lab container and a throwaway container both sent over `soc-net`. The manager saw their **real** addresses (`172.18.0.4`, `172.18.0.5`).
- A sender on another machine wasn't tested (no second computer).

So your concern was right: anything coming through the published port looks like the core network's gateway. Docker picks that subnet per machine (here 172.19/16, with `soc-net` on 172.18/16), so a fixed narrow default wouldn't be portable.

## What I need from you

| Item | Proposal |
|---|---|
| **Variable** | `WAZUH_SYSLOG_ALLOWED_IPS` in `nodes/core/.env.example`. `render-env.sh` takes it from a new optional `SYSLOG_ALLOWED_IPS` in `topology.env` (and `topology.env.example`, commented out). |
| **Default** | **Empty.** It means "only the manager's own Docker networks" (see below). **Not `172.16.0.0/12`.** |
| **Format (10a)** | A comma-separated list of IPv4 addresses or CIDRs with no spaces, e.g. `192.168.1.1,10.0.5.0/24`. `render-env.sh` validates it: each entry is `a.b.c.d` or `a.b.c.d/n` with octets 0–255 and `n` 0–32; empty entries and spaces are refused; and `0.0.0.0/0` is refused with a message saying it disables the restriction. |
| **Container** | Nothing from you: I pass the variable to the manager in `nodes/core/wazuh/compose.yml` (my file). |

## What my side does (W1.1, after yours is on `main`)

`config/entrypoint-scripts/30-syslog-allowed-ips.sh` rewrites the `<allowed-ips>` of the syslog `<remote>` block at every start:

1. It always allows the subnets of the networks the manager is attached to. It reads them from `/proc/net/route` inside the container, so whatever Docker picked on that machine is used. This covers the lab agent and Suricata over `soc-net`, and local senders through the published port, which appear as the core network's gateway.
2. It adds one `<allowed-ips>` per entry of `WAZUH_SYSLOG_ALLOWED_IPS`. That's where a machine that receives pfSense or router syslog lists those devices.
3. It never writes `0.0.0.0/0`. If the variable is invalid, it logs an error and keeps only step 1, so the restriction fails closed.

## Why not `172.16.0.0/12`

- It doesn't add anything for local senders. Through the published port they all appear as one gateway address anyway. In `single` mode the real protection is `BIND_ADDR=127.0.0.1` (D16).
- It's also a private **LAN** range. On a network that uses 172.16–172.31 (common in schools and companies), it would accept every device on the LAN.
- The manager's own subnets are exact on every machine, and much smaller.

## Open point: distributed mode (no action from you now)

Normally only loopback traffic goes through `docker-proxy`. Traffic arriving on a LAN interface is redirected by Docker's iptables rules, which keep the real source address. If that holds under WSL's mirrored networking, a pfSense box listed in `WAZUH_SYSLOG_ALLOWED_IPS` is matched by its own IP and everything else on the LAN is refused.

I can't test it on one machine, so I'll confirm it in W4.5 or on the first real multi-host run. If LAN senders also show up as the gateway, source filtering can't work through the published port. The fix would then be on your side: `"userland-proxy": false` in `daemon.json` (CHECKLIST.md 4), or another way to publish 514/udp. I'll raise it then with numbers.

## By

**2026-10-07** for your answer, so R-06 is on `main` by 2026-10-09 and W1.1 can follow. No contract changes.
