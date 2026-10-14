# Wazuh docs: requests and replies

Owner: Daniel (@dmelgar1110). This folder holds everything the Wazuh component exchanges with other owners.

## Working rule

Wazuh work changes only Wazuh's folders: `nodes/core/wazuh/` and `nodes/lab/` (PROJECT.md 11.1, light rule 3). Any other folder or shared file is never edited from the `wazuh` branch, even for a small fix. That includes other components' folders, `scripts/`, `docs/`, the `.env.example` files, `PROJECT.md` and the node root compose files.

When Wazuh needs something from someone else, write a request file here and send it to that owner. They make the change on their own branch, or the integrator makes it on `main`.

## Files

| File | What it is |
|---|---|
| `request-<owner>-<topic>.md` | A request **from** Wazuh to another owner (e.g. `request-integrator-r06-syslog-allowed-ips.md`) |
| `<owner>-requests-<date>.md` | Requests **to** Wazuh from another owner, kept as received, with a reply tracker (e.g. `n8n-requests-2026-09-30.md`) |

`<owner>` is one of `integrator`, `n8n`, `thehive`, `grafana`, `cortex-misp`.

## What a request file contains

- **To / From / Date**, and the related IDs (`W` task, `X-`/`R-` row in `docs/integration-backlog.md`, contract `C`).
- **What is needed:** the exact change, the file it touches and, where possible, the proposed text or value.
- **Why:** the Wazuh task it unblocks.
- **By:** the date it's needed, and what slips if it's late.
- **Status:** `draft`, `sent`, `done` or `declined`, updated when the answer arrives.
