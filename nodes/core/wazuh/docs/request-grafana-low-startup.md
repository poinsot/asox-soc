# Finding: Grafana is slow to start on `low` after the checkpoint-1 dashboards

**To:** Jesus (@JC-535), Grafana owner; cc Inigo (@poinsot), integrator (`healthcheck.sh`, `GRAFANA_MEM`)
**From:** Daniel (@dmelgar1110), Wazuh owner
**Date:** 2026-10-14
**Refs:** A82 (healthcheck Grafana retry), D40 (memory limits), Grafana `provisioning/dashboards/` (SOC Status, Attack Scenarios)
**Status:** draft

## What I saw

On `main` at `16455b7` (after PRs #17–#20), on my `low` machine (WSL 8 GB), I followed CONTRIBUTING's "After a checkpoint merge": `render-env.sh`, then `soc.sh up core`, then `n8n-import.sh`. Then:

- **`healthcheck.sh`:** `FAIL core: Grafana login as admin failed on http://127.0.0.1:3000 (2 tries)`. A82's retry wasn't enough. A second run a few minutes later passed.
- **Grafana's log at that moment:** `dashboard-service` "Failed to cleanup k8s dashboard resources … context deadline exceeded", and `grafana-apiserver` "Handler timeout" on `GET /apis/dashboard.grafana.app/v0alpha1/namespaces/default/dashboards` (15.8 s).
- **Memory:** `asox-core-grafana-1` at **215 MiB of its 250 MiB** limit, with no OOM kill and no restart. That's above the ~175 MiB measured for 12.4.11 in D34.
- C8 passed, and so does everything on the Wazuh side. Nothing broken, just a slow start.

## Possibly useful

- Is the new dashboard provisioning, or the k8s-style dashboard API cleanup, the slow part on start? If so, a provisioning or feature setting might avoid it on `low`.
- With 215 of 250 MiB in use, a re-measure under D40 may show `GRAFANA_MEM` needs a bump on `low` (Inigo's file).
- `healthcheck.sh` could allow Grafana more time right after `up` (Inigo's file).

## By

No deadline; for checkpoint 1 if it affects others. I can re-run anything on my `low` machine.
