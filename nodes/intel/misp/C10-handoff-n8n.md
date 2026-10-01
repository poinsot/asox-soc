# C10 handoff: what n8n and the integrator still need to do

**For:** Inigo (@poinsot), as n8n owner and as integrator. **From:** Diego (Cortex + MISP). **Date:** 2026-10-01.

Contract C10 (PROJECT.md 5, D45): before enrichment, n8n checks an alert's observables against MISP's warninglists in one call and tags the ones that match.

## Where it stands

Tested on my machine in `full` / `single` / `standard`, branch `cortex-misp` with `main` (6da861b) merged in.

| Piece | State |
|---|---|
| Wazuh → n8n → TheHive (C1, C3, C4) | Works. `nodes/lab/trigger.sh` produces an `asox-test` alert in TheHive, created by `n8n@asox.local`, with observables and the writeback comment. C1–C8 all pass. |
| MISP warninglists | Done. 215 of 225 lists enabled (every list with at most 100,000 entries; R-14's size cap). |
| MISP user for n8n | Done. `n8n@asox.local`, role Read Only, own API key in `nodes/intel/.env` as `MISP_N8N_API_KEY`. Created by `nodes/intel/misp/misp-config.sh apply`. |
| n8n reaches MISP | Works. From inside the n8n container, `POST https://misp-nginx:8443/warninglists/checkValue` with that key answers HTTP 200 in about 0.3 s. |
| Warninglist tag on the observable in TheHive | **Missing.** Nothing in n8n calls MISP yet: `pb-generic`'s enrichment step is a no-op. |

What the test showed: an alert replayed with `data.srcip=8.8.8.8`, `data.dstip=185.220.101.1`, `data.hostname=github.com` arrives in TheHive with those three observables, tagged only `src`, `dst` and nothing. MISP, asked directly, puts all three on warninglists (public DNS resolvers; Tor exit nodes; top-site lists). The link between the two is the only gap.

There is **no fallback through Cortex**: the catalog's MISPWarningLists analyzer doesn't query our MISP and fails with "wrong configuration settings", so it stays disabled.

## The API n8n calls

```
POST ${MISP_URL}/warninglists/checkValue
Authorization: <MISP_N8N_API_KEY>          (the bare key, no "Bearer")
Accept: application/json
Content-Type: application/json

["8.8.8.8", "185.220.101.1", "github.com", "zz-unknown.invalid"]
```

Answer, HTTP 200. Only values that match appear as keys:

```json
{
  "8.8.8.8":       [{"id": "162", "name": "List of known IPv4 public DNS resolvers", "matched": "8.8.8.8/32"}],
  "185.220.101.1": [{"id": "…",   "name": "List of known Tor exit nodes", "matched": "…"}],
  "github.com":    [{"id": "…",   "name": "Top 1000 website from Alexa", "matched": "…"}]
}
```

Two things to handle:

- **No value matches → the body is an empty array `[]`, not `{}`.** Treat any non-object answer as "no matches".
- The certificate is self-signed (PROJECT.md 4.1): certificate check off in the credential.

Works for `ip`, `fqdn`, `domain`, `url` and `hash` observables. `hostname` values such as `lab-agent` simply never match.

## Steps for the integrator (R-13)

1. `nodes/core/.env.example`: add `MISP_URL` (derived, like in `nodes/cases/.env.example`) and `MISP_N8N_API_KEY=__from:intel__`.
2. `nodes/intel/.env.example`: add `MISP_N8N_API_KEY=__bootstrap__`. Until then `render-env.sh` keeps my key but warns that it isn't in `.env.example`.
3. `scripts/render-env.sh`: derive `MISP_URL` for `core` (`https://misp-nginx:8443` in single-host mode, `https://<INTEL_HOST>:9443` distributed).
4. `nodes/core/n8n/compose.yml`: pass `MISP_URL` into n8n's environment. The key must not go there (D37).
5. `scripts/bootstrap.sh core`: create the n8n credential "MISP API (n8n)" with a fixed ID. Header Auth, name `Authorization`, value the key; certificate check off on the HTTP node.
6. `scripts/bootstrap.sh intel`: either call `misp-config.sh apply`, or move the user creation there. Today a fresh `soc.sh init` doesn't create the user or cap the lists until someone runs `misp-config.sh apply` by hand.
7. `scripts/contracts-check.sh`: C10 with `chk-misp-api`. `8.8.8.8` is on a public-DNS list; `POST /events/add` gets 403. `misp-config.sh apply` already runs both checks with the n8n key.

## Steps for n8n (N8N-2.11)

1. New workflow `lib-misp-warninglist`:
   - Input: the `observables` array from `lib-extract-observables`.
   - One HTTP Request to the call above, with every observable's `data`. Timeout a few seconds; no retry loop.
   - Output: the same observables, each match with extra tags.
   - MISP unreachable, timeout, or not HTTP 200: return the observables unchanged and record it. Never park the alert because of this (C10: "MISP unreachable = continue").
2. Call it in `pb-generic` **between** `Extract observables` and `Upsert input`. The tags then travel in the alert-creation body that `lib-thehive-upsert-alert` already sends, so no extra TheHive call is needed.
3. Suggested tags per matching observable: `warninglist` once, plus `warninglist:<list name>` for each list (cap at 3; `github.com` matches 17). Naming to confirm with Park (TheHive, ALERT-FORMAT).
4. Keep `ioc: false` and change nothing else. A match means *common*, never *safe*: don't lower severity, close or suppress (D12). Later `lib-enrich-observable` may skip quota-limited analyzers for observables carrying the `warninglist` tag.
5. Optional: list the matches in the writeback comment.

## How to check it works

```bash
./nodes/intel/misp/misp-config.sh apply      # 215 lists, n8n user and key
jq '.data = ((.data // {}) + {srcip: "8.8.8.8", dstip: "185.220.101.1", hostname: "github.com"})' \
  nodes/core/n8n/fixtures/wazuh/100100-asox-test-c1.json > /tmp/warninglist-demo.json
./nodes/core/n8n/fixtures/replay.sh --fresh-id --file /tmp/warninglist-demo.json
```

Expected in TheHive (http://localhost:9000, `analyst@asox.local`), on the new `asox-test` alert: observable `8.8.8.8` tagged `warninglist:List of known IPv4 public DNS resolvers`, `185.220.101.1` tagged with the Tor exit node list, `github.com` with top-site lists; `lab-agent` and the agent's internal IP unchanged. Today the first three carry no warninglist tag.

## TheHive (Park)

Nothing has to change for the tags to show: observable tags are free text and `n8n@asox.local` may already set them. Only the tag names in step 3 need agreeing.

## Also seen during the test

Cortex sat at 628 of 650 MiB (97% of `CORTEX_MEM`, `standard`) after the contract checks, and was OOM-killed once earlier today. A measurement for raising the limit follows separately (Cortex backlog).
