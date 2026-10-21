# Integrator / n8n → Cortex + MISP: your MISP settings in bootstrap, C10 live, test IOC, C14 (2026-10-10)

**To:** Diego (@DiegoGuerraA00835430), Cortex + MISP owner
**From:** Inigo (@poinsot), integrator and n8n owner
**Refs:** C7, C10 (D45), C14, R-13, R-14, R-21, R-22, R-23, X-07, X-31, X-36; follows `diego-enrichment-questions.md` (2026-10-06)
**Files:** `scripts/bootstrap.sh` (intel), `docs/decisions.md` (A92),
`docs/integration-backlog.md` (R-13, R-22, X-31, X-36); n8n's `README.md`
("Warninglist check") and `lib-config` `misp_warninglist` (branch `n8n`, merging at
checkpoint 1)

Hi Diego,

Your C10 handoff is fully done, on both sides. Thanks: it was precise enough to
build straight from.

## 1. `misp-config.sh apply` now runs from `bootstrap.sh intel` (R-22)

Your settings no longer depend on someone remembering to run the script. On the
build instance:

| | Before | After |
|---|---|---|
| Warninglists enabled | 0 of 225 | 215 of 225 (your 100,000-entry cap) |
| Events | 1 (seed) | 436 (435 from Botvrij, 28,915 attributes) |
| Users | admin, cortex | + `n8n@asox.local` (Read Only), key in `nodes/intel/.env` |

- **Memory** during apply and the ~3-minute Botvrij fetch: misp-core 488 of 900 MiB,
  MariaDB 341 of 550, misp-modules 266 of 400, Redis 24 of 100. No OOM kills; C7
  passes.
- **Other machines** get this state only after pulling `main` and running
  `bootstrap.sh intel` once. That also starts the Botvrij fetch.

## 2. C10 is live

- **Integrator side (on `main`, R-13):** steps 1, 2, 3, 5, 6 and 7 of your handoff.
  `MISP_URL` and `MISP_N8N_API_KEY` reach core, the credential "MISP API (n8n)" is
  created, and `contracts-check.sh` has a C10 check.
- **n8n side (branch `n8n`, N8N-2.11):** step 4 and every n8n step, including the
  optional writeback line.
  - Before creating the TheHive alert, n8n sends all eligible values in **one**
    `checkValue` call. It sends ip, fqdn, domain, url and hash, but not the agent's
    own observables or internal IPs.
  - Matches get `warninglist` + `warninglist:<list>` tags (max 3).
  - **MISP unreachable = no tags, alert unaffected, never parked.**
- **Your demo works:** `8.8.8.8`, `185.220.101.1` and `github.com` get their tags;
  `lab-agent` and the agent's IP stay unchanged.
- **The C10 check passes** on the build instance: 8.8.8.8 matches the public DNS
  list, and a write with the n8n key gets 403.

**Memory under batch `checkValue`** (your open point from the handoff):

| Test | misp-core anon | Limit |
|---|---|---|
| 20 direct `checkValue` calls at once, 10 values each | 388 → 553 MiB | 900m |
| 20 real alerts at once through n8n | 386 → 453 MiB | 900m |

No OOM kill; MariaDB stayed flat at 345 MiB.

## 3. Three C10 settings for you to confirm (your policy, X-07)

1. **`skip_online_analyzers: true`.** A warninglisted value goes to local analyzers
   only (MISP_2_1 still runs), so online quotas aren't spent on common values. It
   has no visible effect yet, because the online analyzers are still disabled.
2. **`prefer: ['public DNS', 'Tor exit']`.** When a value matches more than 3 lists,
   these come first, then the rest by name. `github.com` matches 17 lists; it
   currently gets the first 3 by name, not the top-site lists. Add substrings (e.g.
   `Top 1000`) if you want those preferred.
3. **8.8.8.8 now matches 2 lists:** public DNS resolvers and the vpn-ipv4 list.
   `185.220.101.1` is also on the vpn-ipv4 list. Is that expected after your list
   refresh?

## 4. X-36: the seed IOC is warninglisted (your decision)

**`203.0.113.66` matches "List of RFC 5735 CIDR blocks"**, because documentation
ranges are on a warninglist. With C10 live, that observable is now tagged as
*common* **and** still reported suspicious by MISP_2_1. It works, but it's confusing
in a demo. Your seed event, Daniel's `ioc-ip` scenario and n8n's `100100-misp-hit`
fixture all use this address.

**Options:**
- (a) Re-seed with an IP outside the reserved ranges. For example, one from the
  Botvrij data, kept in the seed event so it doesn't depend on the feed's content.
  This is my preference.
- (b) Keep it and accept the mixed result in demos.
- (c) Disable the RFC 5735 list. Not recommended: it's a useful list.

Please decide with Daniel as part of C14. Then n8n and Daniel will update the fixture
and the scenario.

## 5. Still open

- **C14:** please answer Daniel's proposal
  (`nodes/core/wazuh/docs/request-cortex-misp-c14-design.md`, option a) by
  **2026-10-16**. R-08 (the variables Wazuh needs) waits on your answer.
- **Enrichment questions 1–6** (`diego-enrichment-questions.md`): the analyzer list,
  verdict rules, quotas, TLP, `filename`, and when a MISP hit is an IOC.
- **Your 10-01 Cortex memory measurement (R-21):** please send it.
- **In your folder:** the `misp-config.sh` header and the MISP BACKLOG still say
  "run by hand"; in `C10-handoff-n8n.md`, every step is now done.

Thanks!
Inigo
