# Wazuh alert → TheHive: format, mapping and alert-to-case rules

Owner: TheHive (Park). **Status: agreed with the n8n owner (2026-10-14, PR #19 and n8n's PR #23; X-02, X-04) and matching n8n's `lib-config` routing row for row; §3 rules confirmed with the Wazuh owner (W1.3). §6 R2 (D-N4) to confirm by 2026-11-03.** Dedup by `sourceRef` (§1) is D-N1 (`docs/decisions.md`). It builds on contract C3 (n8n → TheHive, Service account `n8n@asox.local`) without changing it: C3 fixes *how* n8n authenticates; this document fixes *what* it sends.

Reference implementation: `scripts/thehive-test-alert.sh` sends alerts in exactly this format, and `scripts/lib.sh` (`th_severity`) holds the severity table.

## 1. Alert fields

One TheHive alert per Wazuh alert forwarded by C1 (`rule.level >= WAZUH_ALERT_MIN_LEVEL`, default 7).

| TheHive field | Value | From the Wazuh alert |
|---|---|---|
| `type` | `wazuh` | — |
| `source` | `wazuh` (test alerts: `asox-test`) | — |
| `sourceRef` | the Wazuh alert ID | `id` |
| `title` | `<rule description> (<host>)`; for FIM alerts (group `syscheck`) `<rule description> <syscheck.path> (<host>)` | `rule.description`, `syscheck.path`, host (below) |
| `description` | Markdown table: rule, level, host, MITRE, **time**, alert ID; then `full_log` in a code block **when the alert has one** (SCA alerts don't); for sudo (5404) also `data.command`, `data.pwd`, `data.tty` | several |
| `severity` | table in section 2 | `rule.level` |
| `tlp` / `pap` | `2` / `2` (AMBER), section 2 | — |
| `date` | alert time, epoch milliseconds | `timestamp` |
| `tags` | `wazuh`, `rule:<id>`, `agent:<host>`, `attack.<technique, lowercase>`, plus `rule.groups` | `rule.id`, `agent.name`, `rule.mitre.id` (see §3 for the fallback), `rule.groups` |
| `caseTemplate` | template name from section 3 | `rule.groups`, `rule.id` |
| `customFields` | section 4 | several |
| `observables` | section 5 | several |

**FIM titles (X-44, 2026-10-20).** Wazuh's FIM descriptions don't name the file (553 is just "File deleted."), so for alerts in group `syscheck` the title adds `syscheck.path` after the description, e.g. `File deleted. /etc/cron.d/backup (lab-agent)`. The path can be attacker-chosen: n8n caps its length like any attacker-written value.

**Host of the alert.** Normally `agent.name`. Alerts received over **syslog** (pfSense, routers, anything sent to 514/udp) have `agent.id` = `"000"` and `agent.name` = `wazuh-manager`; for those the host is **`predecoder.hostname`** (the device's own name, e.g. `pfsense`), **else `location`** when the line has no hostname, and its address is **`location`** (the sender's IP). This applies to the title, the `agent:` tag, `wazuh-agent-name` (§4) and the host observables (§5) (Daniel's fields review, item 6).

**Deduplication for free:** TheHive refuses a second alert with the same `type` + `source` + `sourceRef`. Using the Wazuh alert ID as `sourceRef` makes a re-run of the same alert harmless (the n8n "idempotent and safe to re-run" convention, PROJECT.md 6.2); the playbook should treat that refusal (HTTP 400 `CreateError`, "already exists") as "already done", not as an error.

**Limit (measured by n8n on 5.7.6, 2026-09-30):** the refusal is not atomic. Two *simultaneous* `POST /api/v1/alert` with the same `type` + `source` + `sourceRef` both return 201 and create two alerts; only copies sent one after another are refused, and TheHive has no setting to enforce it. C1 can't cause this (Wazuh sends each alert once, no retries, X-10); anything that re-sends alerts (tests, n8n's replay N8N-6.3) must send them one at a time and look the `sourceRef` up first.

## 2. Severity, TLP and PAP

**Severity** (TheHive 1 Low, 2 Medium, 3 High, 4 Critical) from the Wazuh rule level:

| Wazuh `rule.level` | Meaning in Wazuh | TheHive severity |
|---|---|---|
| 12–15 | High importance event … severe attack | **4 Critical** |
| 10–11 | Repeated errors, integrity warning | **3 High** |
| 7–9 | Bad word matching, first-time events | **2 Medium** |
| 0–6 | Below the forwarding threshold (not sent by C1) | 1 Low (manual / test alerts only) |

Then **+1 (max 4) when `asset-criticality` is `high` or `critical`**. Until an asset inventory exists, n8n sends `medium`; the analyst can change it on the case.

**TLP / PAP: AMBER (2) by default.** Reason: Cortex's MISP analyzer is configured with `max_tlp: 2` and `max_pap: 2` (`scripts/bootstrap.sh`), so anything marked above AMBER can't be analyzed. Raise TLP to RED (4) only by hand, for cases whose data must not leave the SOC, knowing that analyzers will then refuse them.

## 3. Choosing the case template

Checked against live alerts (Wazuh 4.14.8, lab scenarios) and Daniel's rule-ID plan (Wazuh README, "Rules: ID plan, files and groups"). Every custom rule carries `asox`, a source group and Wazuh's standard group names. Ranges: 1001xx tests and markers, 1002xx Linux auth, 101xxx Suricata, 102xxx routers, **103xxx pfSense**, **108xxx MISP IOC matches**, 109xxx tuning; built-in rules keep their IDs.

| Template (`entities/case-templates.json`) | When (first match wins) | Rules today |
|---|---|---|
| `ioc-match` | `rule.groups` has `misp_ioc` | 108000 / 108001 (C14, W6.4, live since 2026-10-15; test IOC `101.99.75.184`, X-36; the alert carries only the groups `asox`, `misp_ioc`); above every other row, so an IOC match wins |
| `suspicious-login` | `rule.id` is `40112` or `100200` (rule IDs only: every normal SSH login, 5715, also carries `T1078`) | 40112 failures then success (level 12), 100200 SSH login as root (level 10) |
| `ssh-bruteforce` | `rule.groups` has `sshd` and either one of `authentication_failures`, `authentication_failed`, `invalid_login`, or `rule.mitre.id` `T1110` (`sshd` required in both clauses, 2026-10-14) | 5712, 5763 (level 10) |
| `login-bruteforce` | `rule.mitre.id` has `T1110` (any other service: firewall / router admin GUI, web app, VPN) | 103011 OPNsense / pfSense GUI login brute force; built-in 40111, 2502 |
| `malware-detection` | `rule.groups` has one of `virustotal`, `rootcheck`, `yara`, `clamd`, `malware` | |
| `ids-network-alert` | `rule.groups` has `suricata` or `ids` (Suricata network IDS, D49; built-in rule 86601 "Suricata: Alert - …", fields `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port`) | 86601, 101xxx (M3) |
| `privilege-escalation` | `rule.id` is `5404`, or `rule.mitre.id` has `T1548` (sudo failures carry only `syslog,sudo`, no `authentication_*` group) | 5404, three wrong sudo passwords (T1548.003, level 10) |
| `account-change` | `rule.groups` has `adduser`, or `rule.mitre.id` has `T1136` (Wazuh files new users **and** new groups under `adduser`; `addgroup` doesn't exist, and 5901 has no MITRE ID, so the group is the main clause) | 5901 new group, 5902 new user (level 8), 5904, 100211 usermod / 100212 gpasswd: user added to a privileged group (level 10, T1098) |
| `network-scan` | `rule.groups` has `pfsense` and either `recon` or `rule.mitre.id` `T1046` (the `pfsense` group stands for "the firewall", answer D) | 103000 (scan / repeated blocks, groups `pfsense,recon`, seen from `opnsense`) and further 103xxx (W4.3) |
| `web-attack` *(proposed 2026-10-20)* | `rule.groups` has `web` and `attack` (web access-log attack rules) | 31103 SQL injection attempt, 31152 repeated SQL injection from one source (`web-attack` scenario) |
| `file-integrity` *(proposed 2026-10-20)* | `rule.groups` has `syscheck` | 550 / 554 modified / added, 553 deleted, 100302 (`fim-tamper` scenario) |
| `wazuh-generic` | everything else, including single pfSense blocks (`firewall_drop` without `recon`) | |

**MITRE technique:** read `rule.mitre.id` (an array); when it is absent, fall back to `rule.mitre_techniques` (what SCA alerts carry). "Has `T1110`" is a prefix match: it also matches sub-techniques such as `T1110.001`. Some rules have no technique (5901, the test rule 100100, the marker 100101), so no row relies on MITRE alone where that would miss them.

**Why `login-bruteforce` (agreed 2026-10-14 with n8n and Wazuh):** rule 103011 (OPNsense login brute force) carries `T1110` but isn't SSH; with the old `ssh-bruteforce` row it got SSH-specific tasks (rule 5715, `sshd` settings). Requiring `sshd` in `ssh-bruteforce` and adding a generic row right after it keeps every SSH alert where it was (all sshd rules carry `sshd`) and gives other brute force a fitting template.

**Active rows (answer B).** Every row is active in n8n (`lib-config` routing version 2026-10-15); `ioc-match` went active when C14 went live. `web-attack` and `file-integrity` (2026-10-20) are *proposed* until n8n checks them against Daniel's `web-attack` and `fim-tamper` fixtures; until then those alerts go to `wazuh-generic`. The route n8n wanted is recorded even while only `pb-generic` runs (answer C: the `playbook` field says the playbook that actually ran).

The alert only *names* the template; TheHive applies its tasks and custom fields when the alert is promoted to a case.

## 4. Custom fields filled by n8n

| Field | Value |
|---|---|
| `wazuh-alert-id` | `id` |
| `wazuh-rule-id` | `rule.id`, cast to integer (it arrives as a string in C1) |
| `wazuh-rule-level` | `rule.level` (integer) |
| `wazuh-agent-name` | the host (§1: `agent.name`, or `predecoder.hostname` on syslog alerts) |
| `mitre-technique` | first of `rule.mitre.id` (else `rule.mitre_techniques`), if any |
| `asset-criticality` | `medium` until an asset inventory exists |
| `playbook` | the playbook that actually ran (`pb-generic` while it is the only one; answer C) |
| `n8n-execution-id` | `$execution.id` |

Send `customFields` as an **array** of `{name, value}` objects, as `thehive-test-alert.sh` does. A field TheHive doesn't know is dropped silently (HTTP 201), so the fields exist only once `entities/` is loaded (`thehive-import.sh`, T1.3).

`containment-action` is set later, by the playbook that performs the action (default `none`). Option lists are enforced by TheHive: `asset-criticality` ∈ low / medium / high / critical; `containment-action` ∈ none / ip-blocked / host-isolated / user-disabled / file-removed.

**Which `containment-action` values a playbook can set (C9, D44, X-21).** C9's action catalog v1 is Wazuh's built-in active-response commands only, in Phase 2: `firewall-drop` or `host-deny` → `ip-blocked`, `disable-account` → `user-disabled`. `host-isolated` and `file-removed` have no active-response command yet (they need custom scripts from the Wazuh owner), so they are **manual-only**: set by the analyst for an action done outside the SOC's automation and described in a case comment.

## 5. Observables

| Wazuh field | TheHive `dataType` | Tags |
|---|---|---|
| `data.srcip` | `ip` | `src` |
| `data.dstip` | `ip` | `dst` |
| `data.src_ip`, `data.dest_ip` (Suricata) | `ip` | `src` / `dst` |
| `agent.ip` (syslog alerts: `location`) | `ip` | `agent` |
| `agent.name` (syslog alerts: `predecoder.hostname`) | `hostname` | `agent` |
| sshd alerts: `data.dstuser` and `data.srcuser` | `user-account` | both `target` (the attacked account: Wazuh's sshd decoder puts an existing user in `dstuser`, an invalid one in `srcuser`; answer F) |
| sudo (5404): `data.srcuser` / `data.dstuser` | `user-account` | `src` (who ran sudo) / `target` (usually `root`) |
| `useradd` (5902): `data.dstuser` | `user-account` | `new` |
| other rules: `data.srcuser`, `data.dstuser` | `user-account` | `src` / `target` |
| `syscheck.sha256_after` (or `data.virustotal.source.sha256`) | `hash` | `sha256`, plus on FIM alerts `fim:modified`, `fim:added` or `fim:deleted` (from `syscheck.event`, or the groups `syscheck_entry_modified` / `_added` / `_deleted`) |
| `syscheck.path` | `filename` | `path`, plus the same `fim:` tag |
| `data.url` when it is a full URL (`scheme://host/...`) | `url` | — |
| `data.url` when it is **path-only** (`/login.php?id=1'--`, what web access logs give) | `uri_path` (TheHive built-in type) | `request` |
| `data.hostname` | `fqdn` if it contains a dot, `ip` if it is an IP, otherwise `hostname` | — |

n8n also tags each IP observable with its range, `range:internal` (RFC 1918, loopback, link-local) or `range:documentation` (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); nothing is dropped because of its range. `user-account` exists only once `entities/` is loaded: before that, TheHive refuses the **whole alert** (HTTP 404 "Data type not found").

**Warninglists (C10, answer G, revised 2026-10-14 with Diego's proposal).** Before creating the alert, n8n checks the observables against MISP's warninglists. A match adds **one tag, `warninglist`**, and writes **every matching list's full name in the observable's description** (`message`):

```
On MISP warninglists (common, not safe):
- List of known IPv4 public DNS resolvers
- Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters
```

No `warninglist:<list name>` tags: TheHive cuts long tags at ~25 characters and pushes `src` / `dst` / `asox:verdict=` behind "Show more", and a value like `github.com` is on ~17 lists. The writeback comment also names the lists. A warninglist match means the value is **common** (public DNS, Tor exit, a well-known site), **not safe**: n8n never changes severity, status or `ioc` because of it.

**Deleted files (X-44).** On 553 the hash is the file's **last known** content (Wazuh still sends `*_after`). The `fim:deleted` tag says so, and the observable's description reads "Last known hash of a deleted file", so nobody looks for the file on disk.

`groupadd` (5901) puts a **group** name in `data.dstuser`: n8n doesn't make a `user-account` observable from it (it stays in the description).

**IOC flag (answer E).** n8n sets `ioc: true` only for a **malicious** verdict (e.g. a hash flagged by VirusTotal). A **MISP hit stays `suspicious` with `ioc: false`**: our MISP also holds public feeds (Botvrij), so a hit can mean "listed in a feed", not "confirmed bad". The analyst marks the observable as IOC after checking it (TRIAGE.md, "Working the case"). To revisit with Diego if MISP later separates the SOC's own confirmed events from feeds.

## 6. Alert-to-case rules

TheHive 5 has no automatic promotion rules of its own; these rules are applied by the analyst (docs/TRIAGE.md) and, where marked, may later be automated by n8n.

| # | Rule |
|---|---|
| R1 | Every forwarded Wazuh alert becomes a TheHive **alert** (status New), never directly a case. |
| R2 | **Critical** alerts are promoted to a case at once. n8n auto-promotes them (`POST /api/v1/alert/<id>/case`) **only for named playbooks**; otherwise the analyst does it first (D-N4, combining this rule with n8n's proposal). |
| R3 | **High** and **Medium** alerts are promoted when triage says true positive or "needs investigation". |
| R4 | **Merge instead of a new case** when an open case already exists for the same agent and the same template within 24 h (TheHive: alert → *Merge into case*). |
| R5 | False positives are closed as **Ignored** with the reason in a comment; the same rule ignored 3 times → tuning request to the Wazuh owner. |
| R6 | Test alerts (`source` = `asox-test` or `contract-check`) are never promoted; `thehive-test-alert.sh --cleanup` removes them. |

**Triage targets (lab SLAs):** Critical 15 min · High 1 h · Medium 4 h · Low next working day.

## 7. Agreed with the n8n owner

| Item | State (2026-10-14) |
|---|---|
| Fields and names, §1, §4, §5 (`source` = `wazuh`, `sourceRef` = Wazuh alert ID) | Reviewed by Inigo 2026-10-06; his questions A (Time row, optional `full_log`), C (`playbook`) answered here. F: syslog host rule (`predecoder.hostname`, else `location`) in §1 and sshd/groupadd user rules in §5, as n8n already does |
| Template routing, §3 (D-N2: n8n keeps it as data in `lib-config`) | Rows corrected with Daniel's live alerts (A1–A6) and his 2026-10-08 rules (100200, 100211, 100212); n8n's `lib-config` routing 2026-10-14 matches §3 row for row, incl. `login-bruteforce` (103011, 40111, 2502); `network-scan` active (103000); `ioc-match` active since 2026-10-15 (C14 live, routing version 2026-10-15) |
| IOC flag for MISP hits, §5 | Answer E: suspicious, `ioc: false`; Diego asked the same (his question 6) |
| SCA, Q4 | No compliance template: W2.7 leaves only SCA regressions at level ≥ 7, routed to `wazuh-generic`; n8n's `sca` exclusion dropped 2026-10-09 |
| Warninglists, §5 | Answer G revised 2026-10-14: only the `warninglist` tag; all list names in the observable's description, no cap (Diego's proposal, `nodes/intel/misp/request-n8n-warninglist-description.md`). Applied by n8n 2026-10-15; the description survives promotion to a case unchanged |
| Web and FIM alerts (X-44) | Proposed 2026-10-20: templates `web-attack` and `file-integrity`; path-only `data.url` → `uri_path`; FIM title adds `syscheck.path`; FIM observables tagged `fim:<change>` (`reply-n8n-wazuh-2026-10-20.md`) |
| `Ignored` = false positive (C11) | Confirmed 2026-10-14: an analyst ignores an alert only when it is a false positive (TRIAGE.md), so n8n's `resolution: Ignored` counts as a false positive in the FP rate |
| Timing | Alerts are queued in n8n and processed 2 at a time (A87): a few seconds when quiet, up to ~30 s at the end of a burst; format unchanged |
| R2 / D-N4 (auto-promotion of Critical alerts of named playbooks only) | To confirm by 2026-11-03 |
| How a playbook reports what it did | Writeback comment `[asox-n8n writeback] wazuh-alert-id=<id>`, plus `containment-action`, `playbook`, `n8n-execution-id` |
