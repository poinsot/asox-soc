# n8n enrichment guide: analyzers, verdicts, quotas, TLP (X-06, X-07)

**To:** Inigo (@poinsot), n8n owner and integrator
**From:** Diego (@DiegoGuerraA00835430), Cortex + MISP owner
**Date:** 2026-10-21 (was due 2026-10-20, checkpoint 1)
**Answers:** `diego-enrichment-questions.md` (2026-10-06), questions 1–6
**Refs:** X-06, X-07, X-08, X-18, X-36, X-44, N8N-2.4, R-09, R-21, R-22
**Applies to:** n8n's `lib-config` → `enrichment` (no workflow change needed)

Hi Inigo,

Sorry this is a day late. Below are the answers, written so they map straight onto
your `enrichment.analyzers` table. A summary of the edits is at the end.

**What was verified:** everything below was checked on 2026-10-21. The data types
come from Cortex's own catalog (`GET /api/analyzerdefinition`). The keys are in on
my instance: `analyzers.sh apply` enabled all five online analyzers, and
`analyzers.sh test` passes for all five as the `n8n` user (C6). The run times and
levels below were measured from those jobs.

## 1. Analyzers per observable type

Data types each analyzer accepts, according to the Cortex catalog, limited to the
types n8n produces:

| Analyzer | Kind | Catalog data types (n8n's types only) | Change from your table |
|---|---|---|---|
| `MISP_2_1` | local | ip, domain, fqdn, url, hash, filename | drop `filename` (question 5) |
| `AbuseIPDB_2_0` | online | ip | none |
| `OTXQuery_2_0` | online | ip, domain, url, hash | **remove `fqdn`** (not in the catalog) |
| `URLhaus_2_0` | online | ip, domain, fqdn, url, hash | **add `ip`** |
| `MalwareBazaar_1_0` | online | hash | none |
| `VirusTotal_GetReport_3_1` | online | ip, domain, fqdn, url, hash | none; severe path only (question 3) |

The same table by observable type, which is what n8n runs:

| Observable | Local | Online (every alert) | Online (severe path only) |
|---|---|---|---|
| `ip` | MISP | AbuseIPDB, OTX, URLhaus | VirusTotal |
| `domain` | MISP | OTX, URLhaus | VirusTotal |
| `fqdn` | MISP | URLhaus | VirusTotal |
| `url` | MISP | OTX, URLhaus | VirusTotal |
| `hash` | MISP | OTX, URLhaus, MalwareBazaar | VirusTotal |
| `filename` | none | none | none |

**URLs (X-44):** web access log URLs are path-only (`/wp-login.php`). Please send
a `url` to the online analyzers **only when it is absolute** (`http://` or
`https://` plus a host). Path-only values can still go to MISP.

**Run times and `timeout_s`:**

| Analyzer | Measured (Cortex job run time) | `timeout_s` |
|---|---|---|
| `MISP_2_1` | 21–34 s today (your ~11 s on the build instance) | 60, unchanged |
| `AbuseIPDB_2_0` | 8 s | 60 |
| `OTXQuery_2_0` | 11–45 s (3 runs: 24, 11, 45 s) | **90** |
| `URLhaus_2_0` | 7 s | 60 |
| `MalwareBazaar_1_0` | 4 s | 60 |
| `VirusTotal_GetReport_3_1` | 10 s (known hash) | 120 |

**Per observable:** with concurrency 1, an IP takes about 60 s through MISP,
AbuseIPDB, OTX and URLhaus, or about 70 s with VirusTotal. OTX varies the most,
which is why it gets 90 s. Cached jobs (10 min) are much faster.

VirusTotal used to rescan hashes whose report was older than 30 days
(`rescan_hash_older_than_days: 30`). I removed that setting from `analyzers.json`:
a rescan spends extra quota and can overrun 120 s. GetReport now only reads
existing reports.

On a timeout, please keep today's behaviour: enrichment is reported as failed for
that analyzer, and the alert is unaffected. Cortex keeps the job, so the next
identical observable within 10 minutes gets the cached report.

## 2. Verdict rules

**Use each analyzer's own levels, with one override:**

```js
overrides: { 'AbuseIPDB_2_0': { safe: 'info' } }
```

**Why no threshold rules:** the thresholds you mention (AbuseIPDB confidence ≥ X,
VirusTotal ≥ N engines) can't be expressed in `overrides`. It maps one level to
another per analyzer, while those rules need the full report. Each analyzer already
applies its own threshold when it picks a level.

**What the analyzers reported (2026-10-21):**

| Analyzer | Value | Taxonomies (level) |
|---|---|---|
| AbuseIPDB | 8.8.8.8 | Whitelisted=True, Usage=CDN, Reports=62 (info); **Score=0 (safe)** |
| AbuseIPDB | 101.99.75.184 (seed IOC) | Usage=Data Center (info); **Score=0, Reports=0 (safe)** |
| OTX | 8.8.8.8 | 0 pulses (info) |
| OTX | 101.99.75.184 | 2 pulses, 0 with a malicious tag (info) |
| URLhaus | example.com | no taxonomies |
| URLhaus | 101.99.75.184 | No results (info) |
| MalwareBazaar | test hash | No results (info) |
| VirusTotal | test hash (known malware) | 66/75 engines, 30 contacted domains (malicious) |

**Why the AbuseIPDB override:** AbuseIPDB reports `safe` whenever an IP has a
score of 0, which only means "nobody reported it". With `rank` ordered info < safe,
that `safe` would outrank every other analyzer's `info` and tag the observable
`asox:verdict=safe`, which reads as a clearance. Example: the seed IOC with MISP
skipped. That goes against D12, where common doesn't mean safe and n8n never
clears anything. Mapping AbuseIPDB's `safe` to `info` keeps the positive levels
(suspicious, malicious) as they are.

**Still to check:** a value with a nonzero AbuseIPDB score, to see where it moves
from suspicious to malicious. None of today's test values had one. If it turns out
too loud, I'll send another remap in the same format.

## 3. Quotas

| Service | Limit (free key) | Policy for n8n |
|---|---|---|
| AbuseIPDB | 1000 checks/day | every alert. Cortex also enforces `rate: 1000/Day` |
| VirusTotal | 4/min, 500/day (shared by everything using the same key) | **severe path only**, as your table already says. Cortex enforces `rate: 500/Day` |
| OTX | no fixed daily quota published; fair use | every alert |
| abuse.ch (URLhaus, MalwareBazaar) | Auth-Key required; no fixed daily quota published; fair use | every alert |

These help keep us under the limits:

- Cortex's 10-minute job cache (`force: false`);
- your `concurrency: 1`;
- 10 observables per alert at most;
- `skip_online_analyzers` for warninglisted values (confirmed below).

**VirusTotal per minute:** Cortex's `rate` is per day, not per minute. With
concurrency 1 and only severe alerts, 4/min should hold. A 429 from VirusTotal
shows up as a failed job, not an HTTP 4xx from Cortex. Like any failed analyzer it
must not park the alert, which is today's behaviour.

## 4. TLP/PAP

**Yes:** `max_tlp: 2`, `max_pap: 2` (AMBER) on every analyzer, local and online,
until the written policy (X-08, 2026-11-10). TLP:RED never leaves the lab.

**`MISP_2_1` has the same values.** `scripts/bootstrap.sh cases`
(`bootstrap_misp_analyzer`) configures it with `check_tlp: true, max_tlp: 2,
check_pap: true, max_pap: 2`. The online analyzers get the same values from
`analyzers.json` → `defaults`. Cortex checks again on its side, so n8n's check and
Cortex's agree.

## 5. `filename`

**Drop it from enrichment.** `syscheck.path` values are full local paths
(`/etc/passwd`, `C:\Windows\...`): they say what changed on the agent, not what is
known outside. MISP `filename` attributes almost never match a full path, and
sending local paths to MISP adds load for no hit. Keep the `filename` observable in
TheHive for the analyst; just leave it out of `data_types` for `MISP_2_1`. The
file's **hash** is what gets enriched.

## 6. When is a MISP hit an IOC?

**(c): suspicious, `ioc: false`**, as n8n does today. Park agreed (TheHive question
E).

- **Why:** our MISP pulls Botvrij (435 events), so a hit often only means "listed
  in a feed". `ioc: true` stays for `malicious`, which today means an online
  analyzer said so.
- **Our own events:** an analyst who wants an own-event hit treated as an IOC marks
  it in TheHive. This is no longer needed for C14: Wazuh's CDB lists raise the
  alert with the `ioc-match` template, so the IOC path doesn't depend on
  enrichment.
- **Revisit with X-08**, if we start publishing our own events with a threat level
  that should map to `malicious`.

## Also answered: your 2026-10-10 note, section 3

1. **`skip_online_analyzers`: please set it to `false`.** This changes what I
   said in the C10 handoff. Checked on 2026-10-21 with `checkValue`: every cloud
   address I tried is on a warninglist.

   | Value | Lists matched |
   |---|---|
   | 159.89.10.10, 104.248.1.1 | DigitalOcean, vpn-ipv4 |
   | 3.120.0.10 | Amazon AWS, vpn-ipv4 |
   | 45.33.32.156 | Linode, vpn-ipv4 |
   | 20.50.2.1 | Azure, GitHub, vpn-ipv4 |
   | 89.248.165.10 | "Recyber IP ranges used for scanning" |

   - **Why `false`:** with `true`, an SSH brute force from a VPS, which is most of
     them, would never reach AbuseIPDB or OTX: the very values that need them. A
     scanner listed *because* it scans would be skipped too.
   - **Quota cost:** small. AbuseIPDB's 1000/day and the 10-minute job cache are
     plenty for the lab, and VirusTotal stays on the severe path only.
   - **Later, if quota becomes a problem:** a per-list switch, where online
     analyzers are skipped only when every matching list is on an allowlist
     (public DNS, top sites), never for cloud, VPN, Tor or scanner lists. Today the
     setting is a single boolean, so this would be a new n8n feature; not needed
     now.
2. **`prefer`:** keep `['public DNS', 'Tor exit']` (now applied to the description
   order, answer G).
3. **8.8.8.8 and 185.220.101.1 on the vpn-ipv4 list: expected.** The list's full
   name is "Specialized list of vpn-ipv4 addresses belonging to common VPN
   providers **and datacenters**". It's a broad list of 42,965 CIDR ranges.
   8.8.8.8 is in Google's datacenter space, and 185.220.101.0/24 is a hosting range
   used for Tor exits. Each also matches its specific list (public DNS, Tor exit
   nodes), and `prefer` puts those first.

**Cortex memory (R-21):** I don't have the 10-01 parallel-run figures anymore, so
I measured again on 2026-10-21 (`standard`: `CORTEX_HEAP=512m`, `CORTEX_MEM=650m`).
Memory was read from Cortex's cgroup every second while 9 jobs ran one after
another, covering all five online analyzers.

| | anon (heap + JVM) | Including file cache | Limit hits | OOM kills |
|---|---|---|---|---|
| At rest (after ~2 h up) | 515 MiB | 648 MiB | 570 since start | 0 |
| During 9 sequential jobs | 515 → 526 MiB | peak 648 MiB | 0 | 0 |

- **Jobs barely matter:** analyzers run in their own containers, outside Cortex's
  limit. Cortex itself only grew 11 MiB under sequential load, so concurrency 1
  holds with the online analyzers enabled.
- **The margin is thin anyway.** The heap is fixed at 512 MiB (`-Xms` = `-Xmx`), so
  Cortex's own use can only grow by its JVM overhead. With 650m, that leaves about
  120 MiB for metaspace, threads and the file cache, and the cgroup already runs at
  its limit (570 reclaims). The 10-01 OOM was this ceiling.
- **Recommendation (yours: `render-env.sh`):** `standard`: `CORTEX_MEM=768m` with
  the heap unchanged at 512m, which gives the JVM about 250 MiB above the heap.
  `light` (256m in 550m) already has room.

## Summary: edits to `lib-config` → `enrichment`

```js
{ name: 'MISP_2_1', ..., data_types: ['ip', 'domain', 'fqdn', 'url', 'hash'] },          // - filename
{ name: 'AbuseIPDB_2_0', ..., timeout_s: 60, data_types: ['ip'] },
{ name: 'OTXQuery_2_0', ..., timeout_s: 90, data_types: ['ip', 'domain', 'url', 'hash'] }, // - fqdn
{ name: 'URLhaus_2_0', ..., timeout_s: 60, data_types: ['ip', 'domain', 'fqdn', 'url', 'hash'] }, // + ip
{ name: 'MalwareBazaar_1_0', ..., timeout_s: 60, data_types: ['hash'] },
{ name: 'VirusTotal_GetReport_3_1', ..., timeout_s: 120, data_types: ['ip', 'domain', 'fqdn', 'url', 'hash'] }, // severe path only
// verdict.overrides: { 'AbuseIPDB_2_0': { safe: 'info' } }; ioc_verdicts: ['malicious'] (unchanged)
// url: online analyzers only for absolute http(s) URLs (X-44)
```

**Enable each online analyzer** (`enabled: true`) once it shows up in
`GET /api/analyzer` for the `n8n` user, which happens after the keys are in and
`analyzers.sh apply` has run. An analyzer that isn't enabled in Cortex should
simply be skipped by n8n.

## On my side

- ✅ The four API keys are in (my instance); `analyzers.sh apply` and
  `analyzers.sh test` pass for all five online analyzers (2026-10-21). They're
  enabled in Cortex, so you can enable them in `lib-config` and test on your side.
  Your build instance needs your own keys in its `analyzer-keys.env`.
- ✅ Measured Cortex memory with the online analyzers running one after another
  (R-21, above).
- ✅ Removed `rescan_hash_older_than_days` from VirusTotal in `analyzers.json`.

## Recommendation for you as integrator: analyzers at bootstrap

**Today** the online analyzers are only enabled when someone runs
`nodes/cases/cortex/analyzers/analyzers.sh apply` by hand, after `soc.sh init`. A
fresh instance has `MISP_2_1` and nothing else. This is the same gap
`misp-config.sh` had before R-22.

**Proposal:** call it from `bootstrap.sh cases`, following the pattern of
`bootstrap_misp_config`:

```bash
CORTEX_ANALYZERS_SCRIPT="$REPO_ROOT/nodes/cases/cortex/analyzers/analyzers.sh"
bootstrap_cortex_analyzers() {
  if bash "$CORTEX_ANALYZERS_SCRIPT" apply 2>&1 \
       | sed -e '/^$/d' -e '/^All checks passed\.$/d' -e '/^[0-9]* check(s) failed\.$/d'; then
    pass "Cortex: analyzers.sh apply (online analyzers from analyzers.json)"
  else
    fail "Cortex: analyzers.sh apply failed (its FAIL lines are above)"
  fi                     # no return 1: TheHive's bootstrap still runs
}

bootstrap_cases() {
  echo "== bootstrap cases"
  bootstrap_cortex                # creates the org admin analyzers.sh logs in as
  bootstrap_misp_analyzer         # MISP_2_1 stays here: its key comes from intel
  bootstrap_cortex_analyzers
  bootstrap_thehive
}
```

**Why it's safe in every case:**

- **Idempotent:** an analyzer is created if missing and updated if present.
  `MISP_2_1` is reserved for `bootstrap_misp_analyzer`, so the two never touch the
  same analyzer.
- **No keys = no failure:** keys come from the git-ignored
  `analyzer-keys.env` on the cases machine (R-09). If the file is missing, the
  script warns. If a key is blank, that analyzer is a SKIP and **its existing
  configuration in Cortex is left as it is**. So a teammate bootstrapping without
  the file neither fails nor erases keys applied earlier.
- **Keys persist:** once applied, they live in Cortex's Elasticsearch and survive
  `soc.sh down`/`up`. Only a fresh cases volume needs the file again.
- **What can still fail:** an empty Cortex catalog (no internet to
  `catalogs.download.strangebee.com`) and an image pull failing. Both are real
  problems on a machine that should run online analyzers.

**Not in bootstrap:** `analyzers.sh test`, because it forces new jobs and spends
API quota. If you want it covered, it could be an opt-in check in
`contracts-check.sh`, like `C1-RETRY`.

**Same gap in TheHive (Park's entities):** nothing calls
`nodes/cases/thehive/scripts/thehive-import.sh`. A fresh TheHive therefore lacks the
`user-account` observable type, the 9 `wazuh-*` custom fields and the 10 case
templates. On 2026-10-21 that made `POST /api/v1/alert` return 404 ("Data type not
found: user-account"), parked every E2E alert in lib-error (`thehive_4xx`) and
failed the E2E check, until I ran the import by hand. That script is idempotent and
never deletes, so it could run at the end of `bootstrap_thehive` the same way.

Thanks!
Diego
