# Wazuh alert → TheHive: the n8n side (N8N-0.4)

Owner: n8n (Inigo). **Status (2026-10-14): n8n agrees with ALERT-FORMAT as merged on `main` (PR #19)**, after Park's answers A–G (§9): it can be marked agreed at checkpoint 1, 2026-10-20 (X-02, TheHive T2.4/T2.5). Still open: R2 / D-N4 (by 2026-11-03) and Diego's confirmation of E (X-07). Diego's warninglist proposal (answer G revised) was agreed by Park and applied 2026-10-15 (§9).

The format itself is Park's: [`nodes/cases/thehive/docs/ALERT-FORMAT.md`](../../../cases/thehive/docs/ALERT-FORMAT.md) (cited as **AF §n**). This file doesn't repeat it. It records what n8n reads to fill it: the exact Wazuh path for each AF field, checked against the fixtures (`../fixtures/`, field details in [`WAZUH-FIELDS.md`](WAZUH-FIELDS.md)), plus the gaps found, the duplicate handling, what the C4 events look like to n8n, and the answers and questions for AF §7.

Checked on 2026-09-30 on the build instance (TheHive 5.7.6, Community license) with short-lived `source: asox-test` alerts created with n8n's key (C3) and deleted afterwards.

## 1. AF §1: alert fields

| TheHive field | n8n reads | Fixture check | Notes |
|---|---|---|---|
| `type` | constant `wazuh` | — | |
| `source` | constant `wazuh` (`asox-test` only for test alerts) | — | Part of the dedup key, so a replayed fixture sent as `asox-test` never collides with the real alert. |
| `sourceRef` | `id` (string, as is) | all fixtures | Never convert it to a number: `1790378132.1860721` loses a digit (WAZUH-FIELDS.md). |
| `title` | `rule.description` + ` (` + `agent.name` + `)` | all fixtures | |
| `description` | `rule.id`, `rule.level`, `agent.name`, MITRE (§ below), `id`, then `full_log` in a code block | `full_log` **absent** on sca-check and sca-sum | Leave the code block out when there is no `full_log` (SCA alerts); for SCA, `data.sca.check.title` / `.result` / `.remediation` are the useful text instead. |
| `severity` | `rule.level` → AF §2 table | test 10 → 3, sca 7 → 2 | Then +1 for `asset-criticality` high/critical (n8n sends `medium` until an inventory exists, so no raise yet). |
| `tlp` / `pap` | constant `2` / `2` | — | |
| `date` | `timestamp` → epoch ms | all fixtures | Format `…+0000` (no colon); keep the milliseconds (`2026-09-26T22:20:41.052+0000` → `1790461241052`). TheHive then computes `timeToDetect` from it (seen in the alert-create event). |
| `tags` | `wazuh`, `rule:<rule.id>`, `agent:<agent.name>`, one `attack.<technique lowercase>` **per** technique, plus **each** element of `rule.groups` | groups: all; techniques: only sca-check | `rule.groups` is an array (e.g. `["asox","test"]` → two tags). Techniques: `rule.mitre.id` (not seen in any fixture) or, for SCA, `rule.mitre_techniques` (4 techniques on 19007 → 4 tags). TheHive returns tags sorted. |
| `caseTemplate` | AF §3 on `rule.groups` / `rule.mitre.id` | test, sca → `wazuh-generic` | See §3 below: silently dropped when the template doesn't exist. |
| `customFields` | AF §4 | | See §4 below: silently dropped when the field doesn't exist. |
| `observables` | AF §5 | | See §5 below: an unknown `dataType` makes TheHive refuse the whole alert. |

## 2. Duplicate `sourceRef`: "already done"

Verified by posting the same alert twice with n8n's key:

```
HTTP 400
{"type":"CreateError","message":"Alert wazuh:asox-test:1790461241.14189 already exists in organisation SOC"}
```

The key is `type:source:sourceRef` in the organisation. How `lib-thehive-upsert-alert` (N8N-2.1) handles it:

1. `POST /api/v1/alert`. HTTP 201 → created; carry on with its `_id`.
2. HTTP 400 with `type` = `CreateError` **and** a message ending in `already exists in organisation <org>` → don't fail, and don't rely on the message text alone: look the alert up (`POST /api/v1/query`, `listAlert` filtered on `type`, `source`, `sourceRef`) and carry on with the existing `_id` as **"already done"**. The execution records `outcome: duplicate` (not an error) and does not repeat actions already recorded on the alert (writeback, enrichment); new information is merged instead (N8N-3.2).
   Implemented in `lib-thehive-upsert-alert` (2026-09-30). The lookup is `{"query": [{"_name": "listAlert"}, {"_name": "filter", "_and": [{"_field": "type", "_value": …}, {"_field": "source", "_value": …}, {"_field": "sourceRef", "_value": …}]}, {"_name": "page", "from": 0, "to": 2}]}` and must return exactly one alert, otherwise the workflow fails and `recv-n8n-error` parks it.
3. Any other 400, a 404 or a 5xx → the error path (N8N-2.5, retry or park).
4. **Race: not covered. TheHive doesn't enforce the uniqueness under concurrent creates** (measured 2026-09-30, TheHive 5.7.6). Two simultaneous `POST /api/v1/alert` with the same `type`+`source`+`sourceRef`, sent straight to TheHive's API with n8n's key, both got **HTTP 201**: two alerts, same `_createdAt` to the millisecond. A third POST a moment later got the usual 400. Through n8n, `replay.sh --fresh-id --times 2` (two POSTs back to back) gave two `pb-generic` runs reporting `created`, two alerts and one writeback on each. The same with `--delay 5` gave one alert, one writeback, and `duplicate` / `already written` on the second run.
   - **C1 can't produce concurrent copies:** `custom-n8n` sends each alert once and never retries (A48), and every Wazuh alert has its own `id`. Only tests and replays (`replay.sh`, a double-post, N8N-6.3's replay) can.
   - **Decision (n8n owner, 2026-09-30): accepted, not fixed.** Sequential duplicates (a later replay or retry) are handled as above; the replay workflow (N8N-6.3) processes items one at a time and checks by `sourceRef` before creating; a scheduled duplicate report lists alerts sharing `type`+`source`+`sourceRef` and comments on them, never deleting (N8N-3.5). Asked of TheHive: can it enforce the uniqueness itself (question 9 below)?

## 3. AF §3: case template

| Template | Condition, as n8n reads it | Fixtures that would match |
|---|---|---|
| `ssh-bruteforce` | `rule.groups` ∋ `sshd` and ∩ {`authentication_failures`, `authentication_failed`, `invalid_login`} ≠ ∅; or any technique starts with `T1110` | none (no sshd alert yet, X-05) |
| `malware-detection` | `rule.groups` ∩ {`virustotal`, `rootcheck`, `yara`, `clamd`, `malware`} ≠ ∅ | none |
| `ids-network-alert` | `rule.groups` ∋ `suricata` or `ids` | none (Suricata from M3) |
| `wazuh-generic` | everything else | test (100100), sca-check (19007), sca-sum (19004) |

Gaps:
- **`rule.mitre.id` exists in no fixture**, so the T1110 branch is untested; the group names are also unverified until real sshd/rootcheck alerts exist (X-05).
- "Starts with T1110" (so `T1110.001` counts) is n8n's reading of "has `T1110`"; confirm.
- **An unknown `caseTemplate` is silently dropped:** an alert created with `caseTemplate: "wazuh-generic"` on the build instance (no templates loaded) got HTTP 201 with `caseTemplate: null`. The same applies to custom fields (§4). So a missing template won't fail the playbook, but the case would silently get no tasks. The playbook will check the returned `caseTemplate` and log a warning when it comes back null.
- The mapping (AF §3) is one input of n8n's routing table (D-N2, X-04), kept as data in a `lib-` workflow, not hardcoded in each playbook. **Done 2026-10-06:** all 9 AF §3 rows are in `lib-config` `routing` (README "Routing"); the table above shows only the 2026-09-30 state, see §8. **Since 2026-10-09** n8n's order and matches differ from AF §3 (Wazuh's answers A1–A6): §8, "Routing after the Wazuh owner's answers". **Since 2026-10-14 they are the same again** (AF §3 of PR #19, plus `login-bruteforce` and `network-scan` active): §9.

## 4. AF §4: custom fields

| Custom field (type in `entities/custom-fields.json`) | n8n reads | Mismatch / note |
|---|---|---|
| `wazuh-alert-id` (string) | `id` | OK (string both sides). |
| `wazuh-rule-id` (**integer**) | `rule.id` | **`rule.id` is a string in C1** (`"100100"`), the field is an integer: n8n converts with `parseInt`. Fine while Wazuh rule IDs stay numeric. |
| `wazuh-rule-level` (integer) | `rule.level` | OK (number in C1). |
| `wazuh-agent-name` (string) | `agent.name` | OK. |
| `mitre-technique` (string) | first of `rule.mitre.id`, else first of `rule.mitre_techniques` | AF §4 names only `rule.mitre.id`, which no fixture has; SCA uses `rule.mitre_techniques`. Only the first technique is kept; the rest are in tags. |
| `asset-criticality` (string, options) | constant `medium` | OK. |
| `playbook` (string) | the handling workflow's name (e.g. `pb-generic`) | OK. |
| `n8n-execution-id` (string) | `$execution.id` | OK (n8n execution IDs are numeric strings, e.g. `"136"`). |
| `containment-action` (string, options) | set by `pb-ssh-response` after a live `firewall-drop` Wazuh accepted: `ip-blocked` (C9 v0, 2026-10-22; §13) | Not set at creation. Written with the **object** form `customFields: {"containment-action": "ip-blocked"}` on `PATCH /api/v1/alert/<id>`, which keeps the alert's other fields; the array form `[{name, value}]` on a PATCH **replaces all of them** (TheHive 5.7.6, checked 2026-10-22). |

- **Unknown custom fields are silently dropped:** tested in both body forms (array `[{name, value}]` and object `{name: value}`): HTTP 201, `customFields: []`. On the build instance none of the 9 fields exists yet (Park's `entities/` aren't loaded, T1.3), so today every n8n alert would lose all custom fields without an error.
- Which body form does TheHive 5.7.6 expect when the fields do exist? Park's `thehive-test-alert.sh` uses the array form; to be confirmed on an instance with the fields loaded (T1.3). **Re-checked 2026-09-30:** the build instance still has no custom field (`listCustomField` → `[]`), so the question **can't be answered there**. `lib-thehive-upsert-alert` sends the array form `[{name, value}]` (HTTP 201, `customFields: []` returned) and records a warning when the alert comes back without them. Re-test when T1.3 is loaded. **Re-tested 2026-10-06** with T1.3 loaded: both forms are filled, n8n keeps the array (§8).

## 5. AF §5: observables

| AF row | n8n reads | Fixture check | Note |
|---|---|---|---|
| `ip` / `src` | `data.srcip` | not seen | |
| `ip` / `dst` | `data.dstip` | not seen | |
| `ip` / `src`, `dst` (Suricata) | `data.src_ip`, `data.dest_ip` | not seen | Different names from `srcip`/`dstip`: the normalizer maps both. |
| `ip` / `agent` | `agent.ip` | test, agent; **absent on SCA** | Optional. In the lab it is the container's private Docker IP (`172.18.0.7`): `lib-extract-observables` (N8N-2.3) keeps it, tagged `range:internal` and flagged for `lib-enrich-observable`, which decides what goes to online analyzers (N8N-2.4). |
| `hostname` / `agent` | `agent.name` | all | |
| `user-account` / `src`, `target` | `data.srcuser`, `data.dstuser` | not seen | **The type doesn't exist on the build instance** (see below). |
| `hash` / `sha256` | `syscheck.sha256_after`, else `data.virustotal.source.sha256` | not seen | |
| `filename` / `path` | `syscheck.path` | not seen | |
| `url` | `data.url` | not seen | |
| `domain` / `fqdn` | `data.hostname` | not seen | Which of the two? AF says "`domain` or `fqdn`"; n8n needs one rule (proposal: `fqdn` when it contains a dot, else skip). |

- **An unknown observable `dataType` refuses the whole alert:** Park's `thehive-test-alert.sh ssh` failed on the build instance with `HTTP 404 {"type":"NotFoundError","message":"Data type not found: user-account"}`, and no alert was created. Unlike templates and custom fields (dropped silently), this loses the alert. Until `user-account` is loaded everywhere (T2.3 is done in `entities/`, not loaded on the build instance, T1.3), `lib-thehive-upsert-alert` must either skip unknown types or retry without the failing observable. Otherwise one missing type loses every sshd alert.
- Duplicate observables in one alert (e.g. the same IP as `src` and `agent`) are merged by `lib-extract-observables` into one observable carrying both tags (N8N-2.3). Values are refanged and validated first; an invalid value is left out and listed in the playbook's writeback.
- `data.hostname` (n8n's rule until question 6 is answered): an IP → `ip`, a name with a dot → `fqdn`, else `hostname`.
- `ioc: true` only for known-bad values (AF §5), decided after enrichment, so observables are created with `ioc: false`.
- **Warninglists (C10, N8N-2.11; answer G as revised, agreed by Park 2026-10-14, applied 2026-10-15, §9):** an `ip`, `fqdn`, `domain`, `url` or `hash` observable whose value is on a MISP warninglist is created with the single tag `warninglist` and a `message` (TheHive's observable description) naming **every** matching list, no cap: `On MISP warninglists (common, not safe):` then one `- <list name>` line per list (public DNS and Tor exit lists first, then by name). No `warninglist:<list name>` tags any more. The agent's own observables and internal addresses are not checked. A match means "common value", never "safe": `ioc`, severity and status are not touched. Tag and message are set when the alert is created (nothing is written on a duplicate); when MISP can't be reached the observables simply have neither (the writeback says so). The `message` **survives promotion**: the case's observables carry the same text (checked 2026-10-15, §9).

## 6. C4 events as n8n sees them (input for N8N-1.5, 2.9, 5.3)

From the 20 event fixtures (`../fixtures/thehive/`, captured from `recv-thehive-event`):

- **Actor = top-level `_createdBy`** (the audit record's author) on every event, **deletes included**. `object._createdBy` / `_updatedBy` describe the object, not necessarily this event. Loop prevention (N8N-1.5, implemented in `recv-thehive-event`): events whose `_createdBy` is `n8n@asox.local` are recorded and end there (fixtures 01–03, and the C4 check's test alert). One event caused by n8n and one caused by the analyst on the same alert are both in the set (03 vs 04).
- **Deletes carry no `object`:** `19-case-delete` has `details: {number, title}`, `20-alert-delete` has `details: {}`; only `objectId`, `objectType` and `_createdBy` identify them. A deleted alert's `sourceRef` (the Wazuh alert ID, which keys C11's document) is therefore not in the payload. **Open design question for N8N-1.5, not decided:** ignore deletes, or correlate them by `objectId` (or `requestId`) with an ID n8n recorded earlier (e.g. `thehive_alert_id` in `asox-metrics`).
- **Deleting a case sends no event for its alert:** the alert went back from Imported to InProgress with `caseId: null`, silently. C11's `case_id` for that alert would go stale unless the case delete event is handled.
- **Promotion is 4+ events with one `requestId`:** case `update` (`share`), alert `update` (`caseId`, status Imported), one observable `create` per copied observable, then the case `create`, which arrived ~3 s after the others. So n8n must not assume the case `create` comes first. The case object has no `sourceRef`; the link to the Wazuh alert is the alert `update` with `details.caseId` (its `object.sourceRef`).
- **Status changes** are `update` events with `details.status` (and `details.stage`): alert New → InProgress (C11 `t_ack`), alert → Imported, case New → InProgress (**done by TheHive itself** when a task starts, fixture 13), case → `FalsePositive` with stage `Closed`, `endDate` and `summary` (C11 `t_closed` and `resolution`; N8N-5.3).
- Comments: `object.alert` (fixture 06) or `object.case` (fixture 16) is set, the other is null; the actor is `_createdBy`. Task logs: `object.task` is set and `object.case` is null, so the case is found through `rootId`.
- **Tag changes (captured 2026-10-22, C9 v0):** an alert `update` (`action: update`) whose `details.tags` is the full tag list after the change; when the tags were set as a list (`PATCH` with `tags`, as the UI does) `details` also has `tagChanges: [{operation: "added" | "removed", values: [...]}]`; an `addTags` call gives `details.tags` only. The actor is the top-level `_createdBy` as always; `object` is read when the notification is sent, so it can already show a later change (it is not a snapshot of this event).
- Headers: TheHive sends `Authorization: Bearer <token>` and n8n stores it in the execution, as with C1 (N8N-6.5).

## 7. For AF §7: answers and questions to send to Park

**Answers (n8n agrees):**
1. §1: `type: wazuh`, `source: wazuh` (`asox-test` for tests), `sourceRef` = Wazuh `id` as a string. n8n treats the duplicate refusal (HTTP 400 `CreateError … already exists …`) as "already done" (§2 above).
2. §2: severity table and TLP/PAP AMBER as written; n8n sends `asset-criticality: medium` until an inventory exists.
3. §4: the 9 fields and their types are fine; n8n converts `rule.id` (string in C1) to an integer for `wazuh-rule-id`.
4. AF §7 item 4 (reporting what a playbook did): a comment on the alert or case, plus `playbook`, `n8n-execution-id` and, from C9, `containment-action`. Implemented (`lib-thehive-writeback`, 2026-09-30) as a **comment on the alert**: TheHive 5.7.6 supports them (`POST /api/v1/alert/<id>/comment` `{message}` → 201; read back with the query `getAlert` + `comments`, author in `createdBy`). First line, fixed: `[asox-n8n writeback] wazuh-alert-id=<id>`, then the playbook, its n8n execution ID and the actions taken. A second run finds that line from `n8n@asox.local` and writes nothing. Since N8N-2.9 (2026-10-14) the actions end with `Systems changed: TheHive, and the Wazuh indexer (asox-metrics document, C11).` and one line on the alert's C11 metrics document: `metrics: ok`, `metrics: skipped (<why>)` or `metrics: failed (<class>)` (n8n README, "Metrics (C11)"); a metrics failure never stops the comment. Errors use a different first line, `[asox-n8n error] wazuh-alert-id=<id>` (`lib-error`).

**Questions:** (status 2026-10-06: Q1, Q2, Q3, Q5, Q6 and Q9 are **answered**, Q4 and Q8 still open, Q7 needs no answer; see §8)
1. **Load `entities/` on the build instance (T1.3) before checkpoint 1**: today the instance has no custom fields, no case templates and no `user-account` type. Templates and custom fields are then silently dropped, and `user-account` observables make TheHive refuse the whole alert (404). Can T1.3 happen on the build instance, or should n8n's playbook refuse to run without them?
2. **MITRE path:** AF §1/§3/§4 use `rule.mitre.id`. No current alert has it, and SCA alerts carry `rule.mitre_techniques`. OK to read `rule.mitre.id`, else `rule.mitre_techniques`?
3. §3: does "`rule.mitre.id` has `T1110`" include sub-techniques (`T1110.001`)? n8n reads it as "starts with `T1110`".
4. §3: SCA (group `sca`, 131 level-7 alerts per agent start) falls into `wazuh-generic`. Do you want a compliance template, or should SCA not become TheHive alerts at all (X-09 with Daniel)?
5. §4: which body form of `customFields` does TheHive 5.7.6 take for alerts, the array `[{name, value}]` your script uses or the object `{name: value}`? Both were accepted but dropped here, since the fields didn't exist.
6. §5: `data.hostname`: `domain` or `fqdn`? Should `agent.ip` be an observable when it is a private address?
7. Promotion (R2, D-N4): n8n's `analyst` profile **can** promote (`POST /api/v1/alert/<id>/case` → 201, checked 2026-09-30; part of X-15). Whether it can delete cases wasn't tested and isn't needed: n8n deletes nothing except its own test alerts.
8. Deleting a case silently reopens its alert (no alert event). Is that expected in TheHive 5.7.6, and does the triage procedure ever delete cases (C11 would keep a stale `case_id`)?
9. **Duplicate refusal isn't atomic** (§2 step 4 above): two concurrent creates with the same `type`+`source`+`sourceRef` both get 201. AF §1's "deduplication for free" holds only for requests that don't overlap. Can TheHive enforce this uniqueness itself (a setting, a unique index, a newer version), or should AF §1 say so? n8n's side: C1 can't produce concurrent copies; tests and replays can, and n8n serializes its own replays (N8N-6.3).

## 8. Review of ALERT-FORMAT §1–§5 (2026-10-06)

ALERT-FORMAT as merged on `main` (PR #14), compared line by line with what `lib-normalize-wazuh-alert`, `lib-extract-observables` and `lib-thehive-upsert-alert` sent on 2026-10-06, before the changes of that day. TheHive's `entities/` were loaded on the build instance the same day (`thehive-import.sh`: 9 custom fields, 9 case templates, `user-account`; backup `backups/cases-20261006-164943/` first), so templates, custom fields and `user-account` were checked on a real instance. Probe alerts (`source: asox-test`) were created with n8n's key and deleted.

Verdicts: **agree** = n8n already sends this; **n8n changes** = changed by n8n in this session (N8N-1.2, N8N-1.3); **question** = to Park, listed after the table.

| AF | Item | AF says | n8n sends | Verdict |
|---|---|---|---|---|
| §1 | `type` | `wazuh` | `wazuh` (`lib-config` `thehive_alert_type`) | agree |
| §1 | `source` | `wazuh`; test alerts `asox-test` | `wazuh`; `asox-test` for rule `100100` (`source_by_rule_id`) | agree |
| §1 | `sourceRef` | Wazuh alert `id` | `id`, kept a string | agree |
| §1 | `title` | `<rule.description> (<agent.name>)` | same | agree |
| §1 | `description` | Markdown table: rule, level, agent, MITRE, alert ID, then `full_log` in a code block | same rows **plus a `Time` row** (the Wazuh `timestamp`); the code block is left out when there is no `full_log` (SCA); the fence grows if the log contains backticks | differs slightly: question A |
| §1 | Dedup | 400 `CreateError` "already exists" = already done; not atomic under concurrent creates | same (§2 above); n8n's limit is now written in AF §1 | agree (§7 Q9 answered: no TheHive setting) |
| §2 | `severity` | 12–15 → 4, 10–11 → 3, 7–9 → 2, 0–6 → 1; +1 (max 4) for `asset-criticality` high/critical | same table (`severity_by_level`, default 1), +1 rule implemented; `medium` sent, so no raise | agree |
| §2 | `tlp` / `pap` | `2` / `2` | `2` / `2` | agree |
| §1 | `date` | alert time, epoch ms | `Date.parse(timestamp)`, milliseconds kept | agree |
| §1 | `tags` | `wazuh`, `rule:<id>`, `agent:<name>`, `attack.<technique lowercase>`, `rule.groups` | same, de-duplicated | agree |
| §1, §3 | Techniques for tags and §3 | `rule.mitre.id`, else `rule.mitre_techniques` | `rule.mitre.id` only | **n8n changes** (N8N-1.2): fallback added; §7 Q2 answered |
| §1, §3 | `caseTemplate` | 9 templates, first match wins, `wazuh-generic` last; *proposed* rows may go to `wazuh-generic` until W1.3 confirms them | 3 named templates + `wazuh-generic`, computed inside `lib-thehive-upsert-alert` | **n8n changes** (N8N-1.3): routing table in `lib-config` seeded from §3, chosen by `lib-route-alert`; questions B, D |
| §3 | Prefix match | "has `T1110`" also matches `T1110.001` | `startsWith` | agree (§7 Q3 answered) |
| §3 | Template kept by TheHive | — | sent; dropped while templates weren't loaded | **checked 2026-10-06**: `caseTemplate: "wazuh-generic"` kept on the returned alert |
| §4 | `customFields` form | array of `{name, value}` | array of `{name, value}` | agree; **both forms are filled on 5.7.6** with the fields loaded (array and object probes returned the same 4 fields with values): §7 Q5 answered, n8n keeps the array |
| §4 | `wazuh-alert-id`, `wazuh-rule-id` (integer), `wazuh-rule-level`, `wazuh-agent-name` | `id`, `rule.id` as integer, `rule.level`, `agent.name` | same (`rule.id` → `parseInt`) | agree; integer accepted (`100100` stored as a number) |
| §4 | `mitre-technique` | first of `rule.mitre.id`, else `rule.mitre_techniques` | first of `rule.mitre.id` only; left out when none | **n8n changes** with the fallback |
| §4 | `asset-criticality` | `medium` until an inventory exists | `medium` | agree |
| §4 | `playbook` | "the playbook that handled it" | `$workflow.name` of the running playbook (`pb-generic`) | agree; question C (route vs. playbook that ran) |
| §4 | `n8n-execution-id` | `$execution.id` | the playbook's execution ID (not `recv-wazuh-alert`'s) | agree; the recv execution ID goes in the writeback |
| §4 | `containment-action` | set later by the acting playbook | not sent | agree |
| §5 | `data.srcip` / `data.dstip`, Suricata `data.src_ip` / `data.dest_ip` | `ip`, tags `src` / `dst` | same | agree |
| §5 | `agent.ip` | `ip`, tag `agent` | same, plus `range:internal` in the lab | agree |
| §5 | `agent.name` | `hostname`, tag `agent` | same | agree |
| §5 | `data.srcuser` / `data.dstuser` | `user-account`, tags `src` / `target` | extracted, but the type is **disabled** in `lib-config` (`skipped`, listed in the writeback) | differs, temporary: unblocked by T1.3 on 2026-10-06 (`user-account` accepted by the probe); **re-enabled 2026-10-06** (N8N-2.3; `fixtures/synthetic/100100-user-account.json` → `user-account` observables tagged `src` / `target`). **2026-10-09, after the Wazuh field review:** on sshd alerts both fields are the targeted account (Wazuh's decoder puts an invalid user in `srcuser`), so both are tagged `target`; groupadd's `dstuser` is a group name and is skipped (`WAZUH-FIELDS.md`): question F |
| §5 | `syscheck.sha256_after` (else `data.virustotal.source.sha256`) | `hash`, tag `sha256` | same | agree |
| §5 | `syscheck.path` | `filename`, tag `path` | same | agree |
| §5 | `data.url` | `url`, no tag | same | agree |
| §5 | `data.hostname` | `fqdn` with a dot, `ip` if an IP, else `hostname` | same | agree (§7 Q6 answered) |
| §5 | Ranges | `range:internal` / `range:documentation` tags, nothing dropped | same | agree (§7 Q6 second part answered) |
| §5 | `ioc` | `true` only when known bad | always `false` at creation; since N8N-2.4 (2026-10-06) set to `true` by enrichment only for a `malicious` verdict | **conflict, open:** AF's example "an IP found in MISP" is an IOC, but `MISP_2_1` reports a hit as taxonomy level `suspicious`, so n8n leaves `ioc: false` on a MISP hit (`asox:verdict=suspicious`). Question E below |

### Questions for Park (from this review)

- **A. Description:** OK to keep the extra `Time` row, and no code block for alerts without `full_log` (SCA today)?
- **B. Proposed rows:** n8n evaluates them, and when one matches first it sends `wazuh-generic` and records the row that would have matched (`proposed_match`), until the row is confirmed with the Wazuh owner (W1.3) and switched to `active` in `lib-config`. Now that the templates are loaded on the build instance, do you prefer n8n to send the proposed templates right away? *(2026-10-09: three of the five rows are active now, after the Wazuh owner's confirmation; B applies only to `ioc-match` and `network-scan`, whose rules don't exist yet.)*
- **C. `playbook` field:** n8n fills it with the playbook that **ran**. While only `pb-generic` exists, a route that names a future playbook (e.g. `pb-ssh-bruteforce`) still runs `pb-generic`, so the field says `pb-generic` and the writeback says which playbook the route wanted. OK?
- **D. `network-scan`:** "`rule.mitre.id` has `T1046` and the agent is the firewall": n8n has no notion of "the firewall agent". Proposal: the rule group `pfsense` stands for it (pfSense logs arrive through syslog with that group, W4.x). OK, or which field identifies the firewall? *(2026-10-09: the Wazuh owner confirms it (A5): pfSense scan and repeated-block rules carry `asox,pfsense,recon` and T1046; n8n matches `pfsense` + `recon`, or `pfsense` + T1046. Please mirror it in AF §3.)*

- **E. MISP hit and `ioc` (also to Diego):** `MISP_2_1` reports a hit as taxonomy level `suspicious`. ALERT-FORMAT §5 says an IP found in MISP should be marked `ioc: true`. Should a MISP hit be malicious (`ioc: true`) for all MISP sources, only for our own events (not feeds like Botvrij), or stay suspicious? n8n uses suspicious / `ioc: false` until you agree; switching is a one-line override in `lib-config`.

- **F. Wazuh field review (2026-10-09; `WAZUH-FIELDS.md`), two points for AF §1/§5:**
  1. **Syslog alerts** (pfSense, routers from M4; anything on 514/udp) have no agent: `agent.id` is `000` and `agent.name` is `wazuh-manager`; the device is `predecoder.hostname` (when the line has one) at the address in `location`. n8n now builds the `agent`-tagged `ip` / `hostname` observables from the device. AF §1 builds the **title** (`<rule.description> (<agent.name>)`), the `agent:` tag and `wazuh-agent-name` from `agent.name`, which would all say `wazuh-manager`. Proposal: for `agent.id` `000`, use `predecoder.hostname`, else `location`, in all three. OK? n8n keeps AF §1 as written until you answer.
  2. **`user-account` tags:** AF §5 says `srcuser` → `src`, `dstuser` → `target`. On sshd alerts Wazuh's decoder puts the targeted account in either field, so n8n tags both `target` there; on groupadd (5901) `dstuser` is a group and n8n makes no `user-account` from it. OK to write this in AF §5?

- **G. Warninglist tags (C10, 2026-10-10):** n8n now tags observables that are on a MISP warninglist with `warninglist` and `warninglist:<list name>` (at most 3 lists per observable; the list names are MISP's, with spaces, e.g. `warninglist:List of known Tor exit nodes`). Are these names fine for the analysts' filters and dashboards, or do you want another form (e.g. `asox:warninglist`, `misp-warninglist=<name>`, the generic tag only)? Both names are settings (`lib-config` `misp_warninglist.tag` / `list_tag_prefix`), so a rename costs nothing; existing alerts keep the old tags. Should AF §5 list them?

### Routing after the Wazuh owner's answers (2026-10-09)

Daniel answered n8n's routing questions from live alerts (A1–A6 in `nodes/core/wazuh/docs/integrator-requests-2026-10-06.md`, update of 2026-10-08 in `request-n8n-rule-groups.md`), and asked Park for the same fixes in AF §3. n8n applied them in `lib-config` `routing` (version `2026-10-09`; table in the README, "Routing"). **Until Park updates AF §3, n8n's table differs from it in order and matches:**

| Row | AF §3 today | n8n since 2026-10-09 | Why (Wazuh) |
|---|---|---|---|
| order | `ssh-bruteforce`, `malware-detection`, `ids-network-alert`, then the proposed rows | `ioc-match` first, `suspicious-login` second, then `ssh-bruteforce` … | A1, A4: first match wins; 40112 carries T1110; IOC rules keep the source's groups |
| `ioc-match` | groups `misp` or `ioc`, range 103xxx | group `misp_ioc`, range 108xxx; still proposed | A4 |
| `suspicious-login` | T1078, or 40112 | rules 40112 and 100200 only; **active** | A1: 5715 (every login) carries T1078; 100200 is the root-login rule (W2.2) |
| `privilege-escalation` | `sudo` + `authentication_failed`/`_failures`, or T1548 | rule 5404, or T1548; **active** | A2: 5404 has only `syslog,sudo` |
| `account-change` | `adduser` or `addgroup`, or T1136 | `adduser`, or T1136; **active** | A3: `addgroup` doesn't exist; 5901 has no MITRE |
| `network-scan` | `pfsense` + scan rule (104xxx), or T1046 and "the agent is the firewall" | `pfsense` + `recon`, or `pfsense` + T1046; still proposed | A5: pfSense is 103xxx; answers question D |

Three rows went from proposed to **active** (`suspicious-login`, `privilege-escalation`, `account-change`), because Daniel confirmed their rules from live alerts and AF §3 says proposed rows wait only for that. Checked live on 2026-10-09 with his scenarios: each TheHive alert carried that row's `caseTemplate` (README "Routing"). `ioc-match` and `network-scan` stay proposed until their rules exist (M6, M4).

**D-N2 (Daniel's question):** yes, "groups first, then a short rule-ID map" is what the router does. n8n wants **no playbook group** in Wazuh rules (no `pb_ssh_bruteforce`): routing stays n8n data in `lib-config`.

### §7 questions now answered

| §7 | Answered by |
|---|---|
| Q1 (load `entities/`) | Done on the build instance 2026-10-06 (T1.3) |
| Q2 (MITRE path) | AF §3: `rule.mitre.id`, else `rule.mitre_techniques` |
| Q3 (sub-techniques) | AF §3: prefix match |
| Q5 (`customFields` form) | Probe 2026-10-06: both forms filled; n8n keeps the array (AF §4) |
| Q6 (`data.hostname`, private `agent.ip`) | AF §5 |
| Q9 (atomic duplicate refusal) | AF §1 "Limit": no TheHive setting; serialize re-sends |
| Q4 (SCA template or no SCA in TheHive) | Wazuh W2.7 (2026-10-07): 19007/19004 lowered to level 5, only SCA regressions (19011, 19014, 19005) reach n8n and go to `wazuh-generic`; the Wazuh owner sees no need for a compliance template. n8n dropped its `sca` exclusion (2026-10-09). Park to confirm |
| Still open | Q7 (informational, nothing to answer), ~~Q8 (case delete silently reopens its alert)~~ answered 2026-10-14 (§9); Q4 confirmed by Park the same day |

## 9. TheHive's answers A–G (2026-10-14) and what n8n changed

Park's answers are in [`reply-n8n-2026-10-14.md`](../../../cases/thehive/docs/reply-n8n-2026-10-14.md) and ALERT-FORMAT §1/§3/§4/§5/§7 (PR #19, merged 2026-10-14). Applied on branch `n8n` the same day:

| # | Answer | n8n change |
|---|---|---|
| A | Keep the Time row; no code block without `full_log`; for sudo add `data.command`, `data.pwd`, `data.tty` | **Changed:** the normalizer keeps `sudo: {command, pwd, tty}` on alerts of decoder `sudo` (5404), and `lib-thehive-upsert-alert` adds the rows `sudo command`, `sudo working directory`, `sudo TTY` (a missing one is left out). The Time row and the optional code block were already so. Checked with the 5404 fixture in an offline run of the workflow code, not replayed live |
| B | The confirmed rows active; `ioc-match` and `network-scan` proposed until their rules exist | Superseded by X-04 the same day: `network-scan` is **active** (rule 103000 exists and its scenario was captured), `ioc-match` stays proposed (C14 not live yet) |
| C | `playbook` = the playbook that ran | None: already so |
| D | `pfsense` stands for the firewall | None: the `network-scan` clauses already say so |
| E | A MISP hit stays `suspicious`, `ioc: false` | None: already so. Diego's confirmation is left (X-07, `n8n-enrichment.md`) |
| F1 | Syslog alerts: title, `agent:` tag and `wazuh-agent-name` use `predecoder.hostname`, else `location` | **Changed:** `lib-thehive-upsert-alert` uses the normalizer's host (the device on a syslog alert, else the agent) for all three; the description's `Agent` row becomes `Host` there (`<device> (syslog from <location>; agent wazuh-manager (000))`). Checked live on 103011 and 103000 from `opnsense` |
| F2 | sshd: both user fields tagged `target`; no `user-account` from groupadd | None: already so since 2026-10-09 |
| G | Tags `warninglist` + `warninglist:<list name>` OK. **Revised 2026-10-14** (`reply-n8n-misp-2026-10-14.md`): only `warninglist`, every list in the observable's `message`, no cap | **Changed 2026-10-15:** Diego's patch applied (below) |
| Q4 | No compliance template | None |
| Q8 | Analysts never delete real cases | n8n keeps ignoring delete events (N8N-1.5 decided) |

**Routing (X-04, AF §3):** `lib-config` `routing` version `2026-10-14` has AF §3's rows in AF §3's order and with its matches: `ssh-bruteforce` requires `sshd` in both clauses, `login-bruteforce` (T1110 on anything else) right after it, `network-scan` active. Table in the README, "Routing".

### Diego's warninglist proposal (`nodes/intel/misp/request-n8n-warninglist-description.md`)

**What it changes:** observables keep only the `warninglist` tag (no `warninglist:<list name>` tags), and every matching list's full name goes into the observable's description (`message`): "On MISP warninglists (common, not safe):" plus one line per list. Three code strings in `lib-config`, `lib-misp-warninglist` and `lib-thehive-upsert-alert`; the writeback is unchanged.

**Agreed by Park 2026-10-14** (`nodes/cases/thehive/docs/reply-n8n-misp-2026-10-14.md`: answer G revised, no cap, AF §5/§7 and TRIAGE.md updated on his side) **and applied 2026-10-15** on branch `n8n`, as Diego wrote it: `lib-config` `misp_warninglist` `max_list_tags: 0`, `lists_in_message: true` (`list_tag_prefix` and `prefer` kept; `prefer` now sorts the description); `applyMatches` in `lib-misp-warninglist` ("Result" and "Select values", identical); `lib-thehive-upsert-alert` "Build alert" passes `message`. Setting `lists_in_message: false` and `max_list_tags: 3` gives the old behaviour back.

**Tested 2026-10-15** (build instance, `full`, `standard`; `n8n-import.sh`, then `replay.sh --fresh-id --file synthetic/100100-warninglist-demo.json`, read back through TheHive's API as `analyst@asox.local`):
- **Alert:** `8.8.8.8` (`src`), `185.220.101.1` (`dst`) and `github.com` each have the tag `warninglist` and no `warninglist:<list>` tag (plus `asox:verdict=info`, `analyzer:MISP_2_1`: still enriched by the local MISP analyzer). Their `message`: `8.8.8.8` → "On MISP warninglists (common, not safe):" + "List of known IPv4 public DNS resolvers", "Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters"; `185.220.101.1` → "List of known Tor exit nodes" and the vpn-ipv4 list; `github.com` → all 17 lists (security vendor blogs, LOTS, DigitalSide, the Cloudflare Radar, Cisco Umbrella, Alexa, Majestic, Tranco and Moz top lists). `lab-agent` and `172.18.0.7` have no `message`. The writeback still names the lists per value (at most 10, then "+7 more" for `github.com`) and now ends each line with `tagged warninglist.`
- **Promotion** (`POST /api/v1/alert/<id>/case` as `analyst@asox.local`): the case's 5 observables kept the tags and **the `message` text unchanged, character for character**, on all three; the two agent observables still have none. TheHive copies the observable `message` into the case as is.
- **Duplicate:** the same alert id sent again was answered `duplicate` at intake (`recv-wazuh-alert`, N8N-1.9: the queue row was `done`), so no playbook ran; the alert's observables (ids, `_updatedAt`, tags, messages) and its single writeback were unchanged. The playbook-level duplicate path (TheHive "already exists") is untouched by the patch: the `message` travels only in the creation body, and a duplicate sends no observable.
- The case, the alert and their objects were deleted afterwards (test source `asox-test`, so no `asox-metrics` document).

## 10. SSH correlation (N8N-4.2, 2026-10-21): new tags, escalation comment, severity raise

**Acknowledged by TheHive 2026-10-22** (`nodes/cases/thehive/docs/reply-n8n-2026-10-22.md` §1, ALERT-FORMAT §7; case severity stays the analyst's). `pb-ssh-bruteforce` (rows `ssh-bruteforce` and `suspicious-login-40112`) writes these on TheHive alerts. Names and text are lib-config data (`ssh_correlation`), so a different name from Park is a data change, not a code change.

| What | On which alert | When | Value |
|---|---|---|---|
| Tag `ssh-campaign:<srcip>` | every alert the playbook creates (5712, 5763, 40112) | after the upsert, `PATCH /api/v1/alert/<id>` with `addTags` (added, never replacing) | e.g. `ssh-campaign:198.51.100.24`; not set when the correlation is skipped (no `data.srcip`, or the address is tagged `agent`; `range:internal` too until 2026-10-22, now LAN attackers correlate) |
| Tag `ssh:login-after-bruteforce` | each `ssh-bruteforce` alert from the same address within 1 h of a 40112 (either way), and a brute-force alert that finds such a 40112 itself | escalation | added once (`addTags`) |
| Severity raised to **4** | the same alerts | escalation | only if lower (`ssh_correlation.escalate_severity`); **never lowered** (D12); a 40112 is already 4 (level 12). Matches TRIAGE.md: "SSH brute force followed by a successful login → Critical" |
| Comment `[asox-n8n escalation] wazuh-alert-id=<40112 id>` | the same alerts | escalation | **first line fixed**, then the playbook and execution, the 40112 (Wazuh id, TheHive id, time), what was done (tag, severity old → new, the `asox-metrics` line) and `Recommended: block <srcip> (response actions, C9 v0: the SSH playbook proposes a firewall-drop in its writeback, which an analyst approves with the tag approve:firewall-drop); nothing was changed.` (until 2026-10-22: `… (response actions, C9, Phase 2) …`; text only, the marker line is unchanged) Written only if no comment by `n8n@asox.local` starts with that first line (one per alert and 40112, like the writeback) |
| Writeback section "Related (same source within 1 h)" | every alert of the playbook | its writeback | total, up to 10 related alerts (Wazuh id, rule, time, TheHive id, template, severity), the tag, the escalations with old → new severity, then the response proposal or the recommendation (§13) |
| `asox-metrics` `severity` | the escalated alerts | escalation | `lib-metrics-upsert` mode `update` (C11's existing writer; n8n's own TheHive writes are dropped by C4's loop prevention, so `recv-thehive-event` never sees this raise) |

- **Unchanged:** one TheHive alert per Wazuh alert (D-N1), nothing suppressed, closed, merged or lowered (D12; merging repeats is N8N-3.2), no case created (D-N4's auto-promotion is N8N-5.1), `caseTemplate` from AF §3 (40112 and 100200 keep `suspicious-login`: the routing row was split for the playbook, not the template), the custom field `playbook` says `pb-ssh-bruteforce` for 5712, 5763 and 40112.
- **The lookup** (one bounded read per alert): `POST /api/v1/query?name=ssh-correlate` with `listObservable` filtered on `dataType` `ip` and `data` = `data.srcip` → `alert` → filter `date` ≥ event time − 3600 s and ≤ event time + 3600 s, `tags` in (`sshd`, `rule:40112`, `rule:100200`), `_id` ≠ the alert itself → sort `date` → page 0–50. **TheHive 5.7.6 has no `caseTemplate` query attribute** (`error.unknown.attribute`, checked live 2026-10-21), so the templates (`ssh-bruteforce`, `suspicious-login`) are checked on the answer, and the tag pre-filter keeps the 50 for SSH alerts (every `ssh-bruteforce` alert carries the group tag `sshd`). Checked against the live instance before use.
- **Questions for Park:** (1) are `ssh-campaign:<ip>` and `ssh:login-after-bruteforce` acceptable names (the first is per address, so the alert list can filter on one source; with an IPv4 address it is 20–28 characters, so TheHive's ~25-character cut-off in the alert list can shorten it), or other names? (2) the escalation comment's marker and content; (3) raising an alert that is already part of a case (promoted or merged) is done the same way; should the case's severity follow, or stay the analyst's? Today only the alert is raised.

## 11. X-44 applied (2026-10-21): `uri_path`, FIM title, tags and description, two routing rows

Park's decisions of 2026-10-20 (`nodes/cases/thehive/docs/reply-n8n-wazuh-2026-10-20.md`; AF §1, §3, §5) are built in `lib-config`, `lib-extract-observables`, `lib-thehive-upsert-alert` and `lib-enrich-observable` (config `2026-10-21.3`, routing `2026-10-21.2`). No contract change: C3's endpoint, credential and body shape are the same; `uri_path` is TheHive's built-in type (listed by `listObservableType` on the build instance, so no `entities/` change).

| AF | What n8n sends now | Settings (`lib-config`) |
|---|---|---|
| §5 `data.url` | A scheme and a host (`<scheme>://<host>...`, scheme letters, digits, `+.-`; e.g. `https://`, `ftp://`, `ssh://user@host`): `url`, no tag, refanged (as before; non-http(s) schemes since the follow-up below). **Anything else non-empty:** `uri_path`, tag `request`, the value **as sent** (not decoded, not refanged); longer than 512 characters (code points): cut to 512, and the observable's `message` says `Truncated by n8n: original length N characters; the full value is in the Wazuh alert <id>` (combined with any other message after a blank line). Nothing goes to `skipped` any more for a path-only value, so the writeback no longer copies it in full. A value with a control character is still refused (`invalid: control characters`); an empty or blank `data.url` makes no observable | `observable_url` (`path_only_type`, `path_only_tag`), `observable_caps.uri_path_max_chars` 512, `observable_types.uri_path` |
| §1 title, FIM | rule group `syscheck` and a `syscheck.path`: `<rule.description> <syscheck.path> (<host>)`, the path cut to 200 characters with `…` as the 200th, control characters replaced by `?` (title only; the `filename` observable keeps the full path). 553 → `File deleted. /etc/cron.d/asox-tamper-2cb38505 (lab-agent)`. When the description, trimmed, already ends with the raw path (ASOX rules 100300–100302), the path isn't added: `<rule.description> (<host>)` (follow-up below). Other titles unchanged | `fim.group`, `title_caps.syscheck_path_max_chars` 200 |
| §5 FIM tags | on a `syscheck` alert, the `hash` and `filename` observables get `fim:added`, `fim:modified` or `fim:deleted`: from `syscheck.event` (case-insensitive), else from the groups `syscheck_entry_added` / `_modified` / `_deleted`; no tag when neither says | `fim.tag_prefix`, `fim.events`, `fim.event_groups` |
| §5 deleted file | event `deleted`: each hash's `message` is `Last known hash of a deleted file`, first; a warninglist note follows after a blank line. Still enriched | `fim.deleted_hash_message` |
| §3 rows | `web-attack` (`groups_all` `web`, `attack`) right after `network-scan`, `file-integrity` (`groups_any` `syscheck`) right before `wazuh-generic`, both **active**, playbook `pb-generic`, case template = the row id. Since routing `2026-10-21.3` (N8N-4.3) `file-integrity` runs `pb-malware-hash` (§12); `web-attack` stays `pb-generic` | `routing` version `2026-10-21.2` |

**Checked against the fixtures** (harness, replays with `--fresh-id`, live `web-attack` and `fim-tamper` on 2026-10-21): 31103 and 31152 → `web-attack`; 553, 100302 (`added` and `modified`) and 100301 → `file-integrity`; 100300 stays `privilege-escalation` (T1548, an earlier row); 108000 stays `ioc-match`. The two templates came back on the alerts (TheHive knows them). **So AF §3 can mark both rows active** (message to Park, below).

**`uri_path` is never enriched:** no analyzer lists it in its data types and the warninglist check doesn't send it (`misp_warninglist.data_types`); the writeback says `Not enriched: uri_path <value>: never enriched (uri_path: a request path, no analyzer takes it; X-44).` (`enrichment.skip.reason_by_type`).

**Found while checking (for Park; both points resolved by the follow-ups below):** the ASOX FIM rules 100300, 100301 and 100302 already end their `rule.description` with the path (`ASOX: system cron job added or changed: /etc/cron.d/asox-tamper-…`), so AF §1's rule gives the path twice: `ASOX: system cron job added or changed: /etc/cron.d/x /etc/cron.d/x (lab-agent)`. Built as AF §1 says; a one-line change in `lib-thehive-upsert-alert` would skip the path when the description already ends with it, if Park agrees. Also: AF §5 says "a full URL (`scheme://host/...`)" stays `url`, while n8n keeps only `http(s)://host` as `url` (so an `ftp://host/x` becomes `uri_path`); the web access-log decoder only produces paths, so this matters only for future sources.

**Follow-ups applied (2026-10-21, before the PR merges):**
- **FIM title:** when `rule.description`, trimmed, already ends with `syscheck.path` (compared with the raw path, not the 200-character cut), the path isn't added again: 100302 → `ASOX: system cron job added or changed: /etc/cron.d/asox-tamper-2cb38505 (lab-agent)`, same for 100300 and 100301; 553 is unchanged; a description ending with another path still gets the path. Same AF §1 intent, no format change.
- **`data.url` typing as AF §5 says:** any value with a scheme and a host (`<scheme>://<host>...`) is `url`, so `ftp://host/x` and `ssh://user@host` are `url` now; everything else non-empty is `uri_path` (tag `request`, 512 cap). The online analyzers still take only absolute http(s) URLs (`url_online_requires_absolute`, unchanged): an `ftp://` url gets `MISP_2_1` only, and each online analyzer says `skipped (url not http(s))` (the reason text was `url not absolute`, misleading for `ftp://`; changed in the `Plan`, `Job gate` and `Reduce` copies of the plan code).
- Checked by the harness (titles of 100300, 100301, 100302 `added` and `modified`, 553; a description ending with another path; a 250-character path; `ftp://`, `https://`, `ssh://user@host`, scheme-less `host/path`, a path-only value; the online gate for `ftp://`), `--fresh-id` replays of 100302 `modified` and 553 (one alert each, `file-integrity`, titles as above, one writeback), and `contracts-check.sh --only C1,C3,E2E`.

## 12. Malware hash (N8N-4.3, 2026-10-21): alert-level verdict tag, severity raise, "same hash" section

**Acknowledged by TheHive 2026-10-22** (`nodes/cases/thehive/docs/reply-n8n-2026-10-22.md` §6, ALERT-FORMAT §7; case severity stays the analyst's). `pb-malware-hash` (routes `file-integrity` and `malware-detection`, routing `2026-10-21.3`) writes these on the alert it creates. The values are lib-config data (`malware`), so a change from Park is a data change.

| What | On which alert | When | Value |
|---|---|---|---|
| Tag `asox:verdict=<worst>` **on the alert** | the alert itself, when the worst verdict over its `hash` observables is `suspicious` or `malicious` | after the enrichment, one `PATCH /api/v1/alert/<id>` (`addTags`, added, never replacing) | `asox:verdict=suspicious` / `asox:verdict=malicious`: the same name the observables already carry (AF §5), so the alert list can be filtered on it. `info` and no verdict add nothing. A deleted file's last known hash (`fim:deleted`) counts the same |
| Severity raised to **4** | the same alert, `malicious` only | the same `PATCH`, before the writeback | only if lower (`malware.escalate_severity`); **never lowered** (D12). Its `asox-metrics` document is created after it, with 4. Without analyzer keys only `MISP_2_1` runs, and a MISP hit is `suspicious` (answer E), so today no live alert reaches this |
| Writeback section "Same hash on other alerts (7 days)" | every alert of the playbook with a hash | its writeback | the total and up to 10 other alerts with the same hash value (TheHive id, Wazuh id, host from the `agent:` tag, rule from the `rule:` tag, time); nothing is written on those alerts |
| Writeback line `Recommended: isolate or clean <host> after review (response actions, C9, Phase 2); nothing was changed.` | the alert | `malicious` only | text only; no response action exists before C9 |

*Note (2026-10-22):* C9 v0 (2026-10-22, §13) covers `firewall-drop` for the SSH playbook only (`pb-ssh-bruteforce` → `pb-ssh-response`). Isolating or cleaning a host needs custom active-response scripts from the Wazuh owner (W7.4) and stays Phase 2, so this line is unchanged.

- **Unchanged:** one TheHive alert per Wazuh alert, `caseTemplate` from AF §3 (`file-integrity`, `malware-detection`), the observables and their tags (AF §5, X-44), the custom field `playbook` says `pb-malware-hash`, nothing suppressed, closed, merged or lowered, no case created. 100300 (sudoers) stays `privilege-escalation` on `pb-generic`.
- **The lookup** (one bounded read per alert): `POST /api/v1/query?name=malware-same-hash` with `listObservable` filtered on `dataType` `hash` and `data` `_in` the alert's hash values → `alert` → filter `date` ≥ event time − 604800 s and ≤ event time + 604800 s, `_id` ≠ the alert itself → sort `date` desc → page 0–50. Accepted by TheHive 5.7.6 and matched live on 2026-10-21 (test case c and the `fim-tamper` scenario).
- **Questions for Park:** (1) is `asox:verdict=<verdict>` acceptable as an **alert** tag (today it is an observable tag only), or another name? (2) the severity raise to Critical on a malicious hash (TRIAGE.md: is a known-malicious file on a host Critical?); (3) should a later `malicious` verdict on an alert already in a case change the case's severity (today only the alert)?

## 13. Response actions, C9 v0 (2026-10-22): proposal, approval tag, response comment, `containment-action`

**Agreed by TheHive 2026-10-22 as a demo-only interim** (`nodes/cases/thehive/docs/reply-n8n-2026-10-22-c9.md`, TRIAGE.md "Interim for the physical-lab demo", PR #44), replaced by E7's approval tasks. D-N5's approval task ("Approve: `<action>`", TRIAGE.md "Approving a response action") stays the target; until E7 builds it, an analyst approves with a tag (A105). The names and texts are lib-config data (`response`), so a different name from Park is a data change. Details: n8n README "Response actions (C9 v0)".

| What | On which alert | Written by | Value |
|---|---|---|---|
| Writeback line `Proposed: firewall-drop <srcip> on <agent> for 300 s (<mode>). Approve by adding the tag approve:firewall-drop to this alert within 1 h.` | alerts of `pb-ssh-bruteforce` (`ssh-bruteforce`, `suspicious-login-40112`) with a `data.srcip` that may be blocked | n8n, in its writeback (no extra comment) | `<mode>` is `dry_run` or `live`. Otherwise the line is `Recommended: block <srcip> (response actions, C9); nothing was changed (no proposal: <reason>).` |
| Writeback line `[asox-n8n response-proposal] <agent id> <srcip> firewall-drop 300` | the same alerts | n8n, right after the line above | machine-readable: what an approval executes; the writeback comment's time is the proposal's time |
| Tag `approve:firewall-drop` | an alert with a proposal | **the analyst** | the approval: within 1 h of the proposal, by a user other than `n8n@asox.local`; removing and adding it again is a new approval (allowed only while nothing was sent for that alert) |
| Comment `[asox-n8n response] firewall-drop <srcip> on <agent> (<mode>): sent \| not sent \| not sent (dry_run) \| unknown` | the approved alert | n8n (`pb-ssh-response`) | first line fixed; then who approved and when, the Wazuh request, Wazuh's answer (`sent to <agent> (Wazuh accepted, total_affected 1)`: sent to the agent, not proof of a block), the revert (`automatic after 300 s, at about <time>`, or `NO automatic revert: unblock by hand …`), the TheHive and asox-metrics updates. One per approval that ran |
| Comment `[asox-n8n response-refused] <code>` | an alert whose approval failed a check | n8n | why nothing ran (`disabled`, `no-proposal`, `already-executed`, `expired`, `protected`, `agent_not_in_group`, `agent_address`, `rate_cap`, …); once per code and alert |
| Tag `asox:response=firewall-drop` | the alert, after a live send Wazuh accepted | n8n | `addTags` (added, never replacing) |
| Custom field `containment-action` = `ip-blocked` | the same alert | n8n | AF §4's option list; object form, so the other custom fields stay (§4) |

- **Unchanged:** no case is created, nothing is closed, suppressed or lowered (D12); C3 and C4 keep their shapes (the tag arrives as an ordinary alert update; §6).
- **`containment-action` in v0 is set on the alert only** (`pb-ssh-response`), not on a case the alert was promoted into. ALERT-FORMAT §4 (line 105) and TheHive's answer (`nodes/cases/thehive/docs/reply-n8n-2026-10-22-c9.md` §2) say n8n sets it "on the alert it acted on, and on the alert's case when the alert is already in one". The case follows in **N8N-5.1** (case-creation policy): n8n then also sets `containment-action` on the alert's case when the alert is in one (BACKLOG temporary row); until then AF §4's case half isn't built. The dry run checks that a case created after the action keeps `ip-blocked`.
- **Questions for Park:** (1) is an approval **tag** acceptable for the demo (anyone in the SOC organisation can add it; the comment records who), and when can D-N5's task replace it (T4.3, X-16)? (2) the tag names `approve:firewall-drop` and `asox:response=firewall-drop`, and the two comment markers; (3) `containment-action` on the alert only: should it also be set on a case the alert was promoted into? (4) should TRIAGE.md's "Approving a response action" mention the interim tag for the demo?

## 14. IDS alerts (N8N-4.4, 2026-10-22): alert-level verdict tag, severity raise, writeback sections

**FYI to TheHive: same conventions as §12** (acknowledged on 2026-10-22 for `pb-malware-hash`), now also on IDS alerts. `pb-ids-alert` (route `ids-network-alert`, routing `2026-10-22`) writes these on the alert it creates; the values are lib-config data (`ids`). Fields and rules: the Wazuh owner's W3.7 (`nodes/core/wazuh/docs/handoff-ids-fields-w37-2026-10-22.md`).

| What | On which alert | When | Value |
|---|---|---|---|
| Tag `asox:verdict=<verdict>` **on the alert** | the alert itself, when its remote party's verdict is `suspicious` or `malicious` | after the enrichment, one `PATCH /api/v1/alert/<id>` (`addTags`, added, never replacing) | the name the `ip` observable already carries (AF §5). The remote party: of the `src` / `dst` addresses, the one outside the internal ranges (not tagged `range:internal` or `agent`); both internal (a LAN attack): the source, unless it is the agent's own address; documentation ranges count (lab) |
| Severity raised to **4** | the same alert, `malicious` only | the same `PATCH`, before the writeback | only if lower (`ids.escalate_severity`); **never lowered** (D12); its `asox-metrics` document is created with it. Without analyzer keys a remote address reaches `suspicious` at most (a MISP hit, answer E) |
| Writeback section `IDS alert (N8N-4.4): …` and `Remote party: …` | every alert of the playbook | its writeback | the signature, `signature_id`, category, Suricata severity, protocol, `src_ip:src_port → dest_ip:dest_port`, the sensor (`agent.name`); then the remote party, which side it is and why, and its verdict. Words used: "source" / "destination", never "attacker" (W3.7: the flow decides `src` / `dst`, not the attack) |
| Writeback section `Related IDS alerts (1 h)` | every alert with a remote party | its writeback | the total, how many share the remote address and how many the `signature_id`, and up to 10 other alerts (TheHive id, Wazuh id, signature, their remote party, host from the `agent:` tag, time); nothing is written on those alerts |
| Writeback line `Recommended: review the remote address; blocking needs response on the attacked host (C9 scope: SSH playbook only); nothing was changed.` | every alert with a remote party | its writeback | text only; `pb-ids-alert` proposes no response action |

- **Unchanged:** one TheHive alert per Wazuh alert (a scan's alerts are listed under each other, not merged: W3.7 asked for one alert per source, which is N8N-3.2's merging), `caseTemplate` `ids-network-alert` (AF §3; 101010 still before `network-scan`), the observables and their tags (AF §5), the custom field `playbook` says `pb-ids-alert`, nothing suppressed, closed, merged or lowered, no case created.
- **The lookup** (one bounded read per alert): `POST /api/v1/query?name=ids-related` with `listAlert` → filter tag `suricata` (`_in`), `date` ≥ event time − 3600 s and ≤ event time + 3600 s, `_id` ≠ the alert itself, `_or` of `_like` `*<remote address>*` and `*<signature_id>*` on `description` → sort `date` desc → page 0–50. TheHive 5.7.6 has no attribute for an alert's observables in a `listAlert` filter (`observables.data`: `error.unknown.attribute`, checked 2026-10-22) and `signature_id` is neither a tag nor a custom field, so the match uses the alert's Suricata EVE line (Wazuh's `full_log`, in the description's log block); `_like` matches tokens (checked: "Status changed to failed" matched "…from 'not applicable' to failed"), so n8n parses each answered alert's EVE line and keeps it only when `src_ip` / `dest_ip` equals the remote address or `alert.signature_id` equals this one's. If TheHive later adds `signature_id` as a custom field (W3.7 suggests it for the template), the lookup could filter on it directly.
- **No question for Park** beyond §12's (case severity on a later raise): the tag and the raise are §12's, the rest is writeback text.
