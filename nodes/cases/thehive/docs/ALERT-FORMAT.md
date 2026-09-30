# Wazuh alert → TheHive: format, mapping and alert-to-case rules

Owner: TheHive (Park). **Status: proposal, to agree with the n8n owner (Inigo) by checkpoint 1 (2026-10-20)**; dedup by `sourceRef` (§1) is already agreed in principle (D-N1, `docs/decisions.md`) before n8n's playbooks implement it (CONTRIBUTING.md rule 5). It builds on contract C3 (n8n → TheHive, Service account `n8n@asox.local`) without changing it: C3 fixes *how* n8n authenticates; this document fixes *what* it sends.

Reference implementation: `scripts/thehive-test-alert.sh` sends alerts in exactly this format, and `scripts/lib.sh` (`th_severity`) holds the severity table.

## 1. Alert fields

One TheHive alert per Wazuh alert forwarded by C1 (`rule.level >= WAZUH_ALERT_MIN_LEVEL`, default 7).

| TheHive field | Value | From the Wazuh alert |
|---|---|---|
| `type` | `wazuh` | — |
| `source` | `wazuh` (test alerts: `asox-test`) | — |
| `sourceRef` | the Wazuh alert ID | `id` |
| `title` | `<rule description> (<agent>)` | `rule.description`, `agent.name` |
| `description` | Markdown table: rule, level, agent, MITRE, alert ID, then `full_log` in a code block | several |
| `severity` | table in section 2 | `rule.level` |
| `tlp` / `pap` | `2` / `2` (AMBER), section 2 | — |
| `date` | alert time, epoch milliseconds | `timestamp` |
| `tags` | `wazuh`, `rule:<id>`, `agent:<name>`, `attack.<technique, lowercase>`, plus `rule.groups` | `rule.id`, `agent.name`, `rule.mitre.id`, `rule.groups` |
| `caseTemplate` | template name from section 3 | `rule.groups`, `rule.id` |
| `customFields` | section 4 | several |
| `observables` | section 5 | several |

**Deduplication for free:** TheHive refuses a second alert with the same `type` + `source` + `sourceRef`. Using the Wazuh alert ID as `sourceRef` makes a re-run of the same alert harmless (the n8n "idempotent and safe to re-run" convention, PROJECT.md 6.2); the playbook should treat that refusal as "already done", not as an error.

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

| Template (`entities/case-templates.json`) | When (first match wins) |
|---|---|
| `ssh-bruteforce` | `rule.groups` has `sshd` and one of `authentication_failures`, `authentication_failed`, `invalid_login`; or `rule.mitre.id` has `T1110` |
| `malware-detection` | `rule.groups` has one of `virustotal`, `rootcheck`, `yara`, `clamd`, `malware` |
| `ids-network-alert` | `rule.groups` has `suricata` or `ids` (Suricata network IDS, D49; built-in rule 86601 "Suricata: Alert - …", fields `data.alert.signature`, `data.alert.severity`, `data.src_ip`, `data.dest_ip`, `data.dest_port`) |
| `wazuh-generic` | everything else |

The alert only *names* the template; TheHive applies its tasks and custom fields when the alert is promoted to a case.

## 4. Custom fields filled by n8n

| Field | Value |
|---|---|
| `wazuh-alert-id` | `id` |
| `wazuh-rule-id` | `rule.id` (integer) |
| `wazuh-rule-level` | `rule.level` (integer) |
| `wazuh-agent-name` | `agent.name` |
| `mitre-technique` | first of `rule.mitre.id`, if any |
| `asset-criticality` | `medium` until an asset inventory exists |
| `playbook` | the playbook that handled it, e.g. `pb-ssh-bruteforce` |
| `n8n-execution-id` | `$execution.id` |

`containment-action` is set later, by the playbook that performs the action (default `none`). Option lists are enforced by TheHive: `asset-criticality` ∈ low / medium / high / critical; `containment-action` ∈ none / ip-blocked / host-isolated / user-disabled / file-removed.

**Which `containment-action` values a playbook can set (C9, D44, X-21).** C9's action catalog v1 is Wazuh's built-in active-response commands only, in Phase 2: `firewall-drop` or `host-deny` → `ip-blocked`, `disable-account` → `user-disabled`. `host-isolated` and `file-removed` have no active-response command yet (they need custom scripts from the Wazuh owner), so they are **manual-only**: set by the analyst for an action done outside the SOC's automation and described in a case comment.

## 5. Observables

| Wazuh field | TheHive `dataType` | Tags |
|---|---|---|
| `data.srcip` | `ip` | `src` |
| `data.dstip` | `ip` | `dst` |
| `data.src_ip`, `data.dest_ip` (Suricata) | `ip` | `src` / `dst` |
| `agent.ip` | `ip` | `agent` |
| `agent.name` | `hostname` | `agent` |
| `data.srcuser`, `data.dstuser` | `user-account` (added by this component) | `src` / `target` |
| `syscheck.sha256_after` (or `data.virustotal.source.sha256`) | `hash` | `sha256` |
| `syscheck.path` | `filename` | `path` |
| `data.url` | `url` | — |
| `data.hostname` / domains | `domain` or `fqdn` | — |

Mark as IOC (`ioc: true`) only what is known bad (a hash flagged by VirusTotal, an IP found in MISP); the analyst decides the rest.

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

## 7. To agree with the n8n owner

1. Fields and names in sections 1, 4, 5 (especially `source` = `wazuh` and `sourceRef` = Wazuh alert ID).
2. The template routing in section 3: one input of n8n's routing map (D-N2, rule groups + rule-ID map kept as data in a `lib-` workflow), agreed together with the Wazuh owner's rule-ID plan (W1.3) by 2026-10-20.
3. R2: D-N4 (auto-promotion of Critical alerts of named playbooks only), to confirm by 2026-11-03.
4. How a playbook reports what it did: comment on the case, plus `containment-action`, `playbook`, `n8n-execution-id`.
