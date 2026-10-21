# n8n → Cortex + MISP: enrichment is built, questions for `n8n-enrichment.md` (2026-10-06)

**To:** Diego (@DiegoGuerraA00835430), Cortex + MISP owner
**From:** Inigo (@poinsot), n8n owner
**Refs:** X-06, X-07, X-08, X-17 (D-N3), X-18, X-31 (C10), N8N-2.4, N8N-2.11, R-13, R-14
**Files (branch `n8n`):** `nodes/core/n8n/README.md` ("Enrichment policy"),
`nodes/core/n8n/workflows/lib-config.json` (`enrichment`, `cortex_http`),
`nodes/core/n8n/docs/ALERT-TO-THEHIVE.md` §8

Hi Diego,

n8n's enrichment at intake (D-N3) works now with the MISP analyzer. I built it so
your `n8n-enrichment.md` only has to fill a table: no workflow changes on my side.
Below is what it does today and what I need from your doc.

## What n8n does today

- **When:** only for a **newly created** TheHive alert. A repeated Wazuh alert is
  not enriched again.
- **Which observables:** `ip`, `domain`, `fqdn`, `url`, `hash`, `filename` (the
  types `MISP_2_1` accepts that n8n produces), at most **10 per alert**.
  - **Never sent:** the agent's own IP and hostname (tag `agent`), and internal IPs
    (tag `range:internal`: RFC 1918, loopback, link-local).
  - **Documentation-range IPs** (`range:documentation`, e.g. 203.0.113.0/24) go to
    local analyzers only, never online.
  - The alert's TLP/PAP must be ≤ the analyzer's `max_tlp`/`max_pap` (2/2 assumed).
- **How:** C6 with the existing `n8n` user (no contract change):
  - `POST /api/analyzer/<id>/run` with `force: false`, so your 10-min job cache
    is used;
  - `GET /api/job/<id>/waitreport?atMost=<timeout>`.
  - **Jobs run one at a time**, because of the 650m Cortex OOM you saw on 10-01.
- **Retries:** 10 s HTTP timeout; connection errors, timeouts and 5xx are retried
  after 2 s and 5 s, never 4xx. If Cortex is down, the alert is still created and
  commented, and enrichment is reported as failed after ~9 s. Enrichment never
  blocks or parks an alert.
- **Verdict:** the worst taxonomy level across the analyzers that ran
  (info < safe < suspicious < malicious); no taxonomy counts as info. Per-analyzer
  overrides are supported but empty today.
- **Result in TheHive:** tags `asox:verdict=<verdict>` and `analyzer:<name>` on
  the observable, plus a summary in n8n's writeback comment. `ioc: true` only for
  malicious; n8n never lowers severity, closes or suppresses anything (D12).
- **Analyzers in n8n's table:**
  - `MISP_2_1`: enabled.
  - `AbuseIPDB_2_0`, `OTXQuery_2_0`, `URLhaus_2_0`, `MalwareBazaar_1_0`,
    `VirusTotal_GetReport_3_1`: present but **disabled** until your keys and doc
    are in; their data types are my guesses, marked "to confirm".
- **C10 hook:** a labelled empty step before the analyzers run, where the
  warninglist check (`checkValue`, N8N-2.11) goes once R-13 is done.

**Tested on the build instance (`full`):**
- Synthetic alert with `data.srcip = 203.0.113.66` (your seed IOC): `MISP_2_1`
  finds "ASOX seed event" (~11 s), verdict suspicious.
- Agent IP and hostname: skipped.
- The same alert again: no new job.
- Cortex stopped: alert created, enrichment failed cleanly, nothing parked.
- Cortex memory peak during the tests: 491 MiB of 650, no OOM. The load was
  light: one new job, then cached ones.
- C6 and C7 pass.

## Questions for `n8n-enrichment.md`

1. **Analyzers per observable type:** for `ip`, `domain`, `fqdn`, `url`, `hash`,
   `filename`, which analyzers should n8n run (local or online), and what run time
   should I expect for each (it sets each analyzer's wait timeout)?
2. **Verdict rules:** does any analyzer need a rule other than its own taxonomy
   level? For example, AbuseIPDB confidence ≥ X = malicious, or VirusTotal ≥ N
   engines. These go in n8n's `verdict.overrides`.
3. **Quotas:** AbuseIPDB 1000/day and VirusTotal 500/day + 4/min are noted. What
   are the limits for OTX and abuse.ch (URLhaus, MalwareBazaar)? Should n8n keep
   VirusTotal for Critical alerts only ("severe path")?
4. **TLP/PAP:** is `max_tlp` / `max_pap` = 2 on every analyzer the policy n8n
   should enforce, until your written policy (X-08, 2026-11-10)? I couldn't
   verify `MISP_2_1`'s values on the build instance, because its config holds the
   key.
5. **`filename`:** is it worth sending `syscheck.path` values to MISP? They are
   noisy (full paths). I can drop `filename` from enrichment if not.
6. **When is a MISP hit an IOC? (also asked of Park).** `MISP_2_1` reports a hit
   as **suspicious** (`MISP:Search="1 event(s)"`), never malicious. TheHive's
   ALERT-FORMAT §5 says "an IP found in MISP" should be marked `ioc: true`. Our
   MISP pulls Botvrij, so a hit may only mean "listed in a feed". Until you and
   Park agree, n8n uses **suspicious, `ioc: false`**. Options: (a) malicious for
   any MISP hit; (b) only for our own events, not feeds; (c) keep suspicious.

## Two things I noticed

- **Warninglists differ between our instances:** 0 of 225 are enabled on the
  build instance, while your C10 handoff says 215 on your machine. So
  `misp-config.sh apply` hasn't run here, and a fresh `init` doesn't run it either
  (it isn't in `bootstrap.sh`). I'll handle the bootstrap side as integrator;
  just so you know the two instances behave differently until then.
- **Cortex memory:** when your online analyzers are enabled, I'll re-measure
  Cortex with several jobs in a row. If you have your parallel-run measurement
  from 10-01, please send it; it decides whether we raise `CORTEX_MEM`.

## Small edits in your folder (when convenient)

From the 2026-10-06 status audit and today's integrator session (register section G):

- MISP README: the file table doesn't list `misp-config.sh`, and the README and
  backlog still mention Snort (D49: Suricata).
- Cortex README: still calls the export scripts the "first task"; `analyzers.sh`
  exists.
- The register now tracks your items as **R-21** (`CORTEX_MEM`: your 10-01 OOM
  measurement decides it), **R-22** (`misp-config.sh` in `bootstrap.sh intel`,
  mine) and **R-23** (warninglist state per instance).

## Timing

Your doc is due **2026-10-20**, the same day as checkpoint 1. Anything earlier,
even a partial answer to 1 and 6, lets me enable the online analyzers and test
them before the checkpoint. A reply in this file, in an issue or by message is
fine.

Thanks!
Inigo
