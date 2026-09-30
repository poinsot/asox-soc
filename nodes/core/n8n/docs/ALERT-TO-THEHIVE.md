# Wazuh alert → TheHive: the n8n side (N8N-0.4)

Owner: n8n (Inigo). **Status: draft, for agreeing the format with the TheHive owner (Park) by checkpoint 1, 2026-10-20** (X-02, TheHive T2.4/T2.5).

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
- The mapping (AF §3) is one input of n8n's routing table (D-N2, X-04), kept as data in a `lib-` workflow, not hardcoded in each playbook.

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
| `containment-action` (string, options) | set later by the acting playbook (C9, Phase 2) | Not set at creation. |

- **Unknown custom fields are silently dropped:** tested in both body forms (array `[{name, value}]` and object `{name: value}`): HTTP 201, `customFields: []`. On the build instance none of the 9 fields exists yet (Park's `entities/` aren't loaded, T1.3), so today every n8n alert would lose all custom fields without an error.
- Which body form does TheHive 5.7.6 expect when the fields do exist? Park's `thehive-test-alert.sh` uses the array form; to be confirmed on an instance with the fields loaded (T1.3). **Re-checked 2026-09-30:** the build instance still has no custom field (`listCustomField` → `[]`), so the question **can't be answered there**. `lib-thehive-upsert-alert` sends the array form `[{name, value}]` (HTTP 201, `customFields: []` returned) and records a warning when the alert comes back without them. Re-test when T1.3 is loaded.

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

## 6. C4 events as n8n sees them (input for N8N-1.5, 2.9, 5.3)

From the 20 event fixtures (`../fixtures/thehive/`, captured from `recv-thehive-event`):

- **Actor = top-level `_createdBy`** (the audit record's author) on every event, **deletes included**. `object._createdBy` / `_updatedBy` describe the object, not necessarily this event. Loop prevention (N8N-1.5, implemented in `recv-thehive-event`): events whose `_createdBy` is `n8n@asox.local` are recorded and end there (fixtures 01–03, and the C4 check's test alert). One event caused by n8n and one caused by the analyst on the same alert are both in the set (03 vs 04).
- **Deletes carry no `object`:** `19-case-delete` has `details: {number, title}`, `20-alert-delete` has `details: {}`; only `objectId`, `objectType` and `_createdBy` identify them. A deleted alert's `sourceRef` (the Wazuh alert ID, which keys C11's document) is therefore not in the payload. **Open design question for N8N-1.5, not decided:** ignore deletes, or correlate them by `objectId` (or `requestId`) with an ID n8n recorded earlier (e.g. `thehive_alert_id` in `asox-metrics`).
- **Deleting a case sends no event for its alert:** the alert went back from Imported to InProgress with `caseId: null`, silently. C11's `case_id` for that alert would go stale unless the case delete event is handled.
- **Promotion is 4+ events with one `requestId`:** case `update` (`share`), alert `update` (`caseId`, status Imported), one observable `create` per copied observable, then the case `create`, which arrived ~3 s after the others. So n8n must not assume the case `create` comes first. The case object has no `sourceRef`; the link to the Wazuh alert is the alert `update` with `details.caseId` (its `object.sourceRef`).
- **Status changes** are `update` events with `details.status` (and `details.stage`): alert New → InProgress (C11 `t_ack`), alert → Imported, case New → InProgress (**done by TheHive itself** when a task starts, fixture 13), case → `FalsePositive` with stage `Closed`, `endDate` and `summary` (C11 `t_closed` and `resolution`; N8N-5.3).
- Comments: `object.alert` (fixture 06) or `object.case` (fixture 16) is set, the other is null; the actor is `_createdBy`. Task logs: `object.task` is set and `object.case` is null, so the case is found through `rootId`.
- Headers: TheHive sends `Authorization: Bearer <token>` and n8n stores it in the execution, as with C1 (N8N-6.5).

## 7. For AF §7: answers and questions to send to Park

**Answers (n8n agrees):**
1. §1: `type: wazuh`, `source: wazuh` (`asox-test` for tests), `sourceRef` = Wazuh `id` as a string. n8n treats the duplicate refusal (HTTP 400 `CreateError … already exists …`) as "already done" (§2 above).
2. §2: severity table and TLP/PAP AMBER as written; n8n sends `asset-criticality: medium` until an inventory exists.
3. §4: the 9 fields and their types are fine; n8n converts `rule.id` (string in C1) to an integer for `wazuh-rule-id`.
4. AF §7 item 4 (reporting what a playbook did): a comment on the alert or case, plus `playbook`, `n8n-execution-id` and, from C9, `containment-action`. Implemented (`lib-thehive-writeback`, 2026-09-30) as a **comment on the alert**: TheHive 5.7.6 supports them (`POST /api/v1/alert/<id>/comment` `{message}` → 201; read back with the query `getAlert` + `comments`, author in `createdBy`). First line, fixed: `[asox-n8n writeback] wazuh-alert-id=<id>`, then the playbook, its n8n execution ID and the actions taken. A second run finds that line from `n8n@asox.local` and writes nothing. Errors use a different first line, `[asox-n8n error] wazuh-alert-id=<id>` (`lib-error`).

**Questions:**
1. **Load `entities/` on the build instance (T1.3) before checkpoint 1**: today the instance has no custom fields, no case templates and no `user-account` type. Templates and custom fields are then silently dropped, and `user-account` observables make TheHive refuse the whole alert (404). Can T1.3 happen on the build instance, or should n8n's playbook refuse to run without them?
2. **MITRE path:** AF §1/§3/§4 use `rule.mitre.id`. No current alert has it, and SCA alerts carry `rule.mitre_techniques`. OK to read `rule.mitre.id`, else `rule.mitre_techniques`?
3. §3: does "`rule.mitre.id` has `T1110`" include sub-techniques (`T1110.001`)? n8n reads it as "starts with `T1110`".
4. §3: SCA (group `sca`, 131 level-7 alerts per agent start) falls into `wazuh-generic`. Do you want a compliance template, or should SCA not become TheHive alerts at all (X-09 with Daniel)?
5. §4: which body form of `customFields` does TheHive 5.7.6 take for alerts, the array `[{name, value}]` your script uses or the object `{name: value}`? Both were accepted but dropped here, since the fields didn't exist.
6. §5: `data.hostname`: `domain` or `fqdn`? Should `agent.ip` be an observable when it is a private address?
7. Promotion (R2, D-N4): n8n's `analyst` profile **can** promote (`POST /api/v1/alert/<id>/case` → 201, checked 2026-09-30; part of X-15). Whether it can delete cases wasn't tested and isn't needed: n8n deletes nothing except its own test alerts.
8. Deleting a case silently reopens its alert (no alert event). Is that expected in TheHive 5.7.6, and does the triage procedure ever delete cases (C11 would keep a stale `case_id`)?
9. **Duplicate refusal isn't atomic** (§2 step 4 above): two concurrent creates with the same `type`+`source`+`sourceRef` both get 201. AF §1's "deduplication for free" holds only for requests that don't overlap. Can TheHive enforce this uniqueness itself (a setting, a unique index, a newer version), or should AF §1 say so? n8n's side: C1 can't produce concurrent copies; tests and replays can, and n8n serializes its own replays (N8N-6.3).
