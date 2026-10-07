# n8n payload fixtures (N8N-0.2)

Real payloads as n8n receives them, for building and testing the normalizer, the routers and the playbooks without waiting for live alerts. Nothing in `wazuh/` and `thehive/` is invented: every file there is a Wazuh alert from the lab's indexer or a TheHive webhook payload recorded by `recv-thehive-event`. `invalid/` and `synthetic/` hold the only constructed files, each derived from a real one and listed below. Captured on 2026-09-30 from the build instance (Wazuh 4.14.8, TheHive 5.7.6 with a Community license).

- **Wazuh files** (`wazuh/<rule-id>-<short-name>.json`) are the alert JSON, the same object `custom-n8n` POSTs to `/webhook/wazuh-alert` (C1). Files read from the indexer carry two extra fields the indexer adds (`@timestamp`, `input.type`); `100100-asox-test-c1.json` is the exact C1 body of the same alert, for comparison.
- **TheHive files** (`thehive/NN-<object>-<action>-<detail>.json`) are the request body TheHive POSTs to `/webhook/thehive-event` (C4, webhook version 1). They are numbered in the order they happened, as one flow on one alert and its case.
- **Headers are not kept.** In n8n, a webhook item is `{headers, params, query, body, webhookUrl, executionMode}` and the payload is under `.body`. The recorded headers included the webhook token (`x-asox-token` for C1, `authorization` for C4), so only the body is saved. The other headers TheHive sends: `accept`, `content-type`, `content-length`, `context-tags`, `host`, `user-agent`, `x-b3-traceid`, `x-b3-spanid`, `x-b3-parentspanid`.
- Payloads contain lab data only (agent `lab-agent`, its Docker IP, the lab accounts `n8n@asox.local` and `analyst@asox.local`), no credentials.

## Wazuh alerts

| File | Rule | Level | Groups | Sent by C1? | How obtained | Alert time (UTC) |
|---|---|---|---|---|---|---|
| `wazuh/100100-asox-test.json` | 100100 ASOX test rule (`nodes/lab/trigger.sh`) | 10 | `asox`, `test` | yes | `scripts/wazuh-query.sh -r 100100 -n 1 -s 30d -j` | 2026-09-26 22:20:41 |
| `wazuh/100100-asox-test-c1.json` | same alert, exact C1 body | 10 | `asox`, `test` | yes | `recv-wazuh-alert` execution 96 (API, `includeData=true`), `.body` only | 2026-09-26 22:20:41 |
| `wazuh/19007-sca-check-failed.json` | 19007 SCA check failed (CIS Ubuntu 24.04), agent start-up scan | 7 | `sca` | yes (none reached n8n: they fired before C1 existed) | `wazuh-query.sh -r 19007 -n 1 -s 30d -j` | 2026-09-25 23:15:32 |
| `wazuh/19004-sca-summary.json` | 19004 SCA summary: score < 50 % | 7 | `sca` | yes (same) | `wazuh-query.sh -r 19004 -n 1 -s 30d -j` | 2026-09-25 23:15:39 |
| `wazuh/503-agent-started.json` | 503 Wazuh agent started. **Below threshold, not sent by C1** (level 3 < `WAZUH_ALERT_MIN_LEVEL` 7); kept as a sample of the `ossec` group and of `data.extra_data` | 3 | `ossec` | **no** | `wazuh-query.sh -r 503 -n 1 -s 30d -j` | 2026-09-30 20:30:42 |

These are all the rule types at level 7 or above in the indexer on 2026-09-30 (last 30 days: 100100 ×17, 19007 ×130, 19004 ×1). The 130 SCA alerts of one agent start-up are a sample of the flood the router must absorb (N8N-1.4, X-09).

### Missing (to come from Wazuh, X-05 / W1.5 `trigger.sh --scenario`, due 2026-10-09)

Not produced by the lab today at any level, so not captured and **not invented**:

| Needed for | Rule type (built-in examples) |
|---|---|
| `pb-ssh-bruteforce` (N8N-4.2), observables `data.srcip`, `data.srcuser`/`dstuser` | sshd authentication failures and brute force (e.g. 5710, 5712, 5716, 5760) |
| privilege escalation, user observables | sudo (e.g. 5401–5403) |
| `pb-malware-hash` (N8N-4.3), `syscheck.*` | FIM / syscheck (e.g. 550, 553, 554) |
| `malware-detection` template | rootcheck (e.g. 510), VirusTotal (87105), YARA / ClamAV |
| `pb-ids-alert` (N8N-4.4), `data.alert.*`, `data.src_ip`, `data.dest_ip`, `data.dest_port` | Suricata (86601), from Wazuh M3 (2026-11-03) |
| C11 `t_attack_start` | the attack-start marker rule (X-32) |
| routing on MITRE (`rule.mitre.*`) | any rule with a `<mitre>` block: none of today's alerts has `rule.mitre` |

### Constructed invalid payloads (`invalid/`)

The only files here that are **not** real payloads: test inputs for the malformed-alert path (N8N-1.2, lib-error). `replay.sh --all` doesn't pick them up; replay them with `--file`.

| File | Built from | Defect | Expected |
|---|---|---|---|
| `invalid/100100-no-id.json` | `wazuh/100100-asox-test-c1.json` without `id` | required `id` missing | passes the level filter, `lib-normalize-wazuh-alert` hands it to `lib-error`, parked as `malformed_input`; nothing in TheHive |

### Synthetic payloads (`synthetic/`)

**Synthetic, not captured:** copies of `wazuh/100100-asox-test-c1.json` (the real C1 body) with only the `data` field added, to exercise observable paths the lab doesn't produce yet (X-05). Everything else, `id` included, is the real alert, so replay them with `--fresh-id`. `replay.sh --all` doesn't pick them up.

| File | Changed from `wazuh/100100-asox-test-c1.json` | Exercises | Expected |
|---|---|---|---|
| `synthetic/100100-user-account.json` | `data.srcuser = "asox-test-src"`, `data.dstuser = "asox-test-target"` | `user-account` observables (N8N-2.3; needs TheHive's `entities/` loaded, T1.3) | `asox-test` alert with `user-account` observables `asox-test-src` (tag `src`) and `asox-test-target` (tag `target`), besides the agent's `ip` and `hostname` |

## TheHive events

One flow, produced on 2026-09-30 between 20:50 and 20:53 UTC on the build instance, then deleted: n8n's key created the alert (`source: asox-test`, from the 100100 alert) and added a tag; `analyst@asox.local` did everything else through the API. The recorded bodies were read from the `recv-thehive-event` executions (IDs 114–135) through the API. Events of the same HTTP request share `requestId`.

| File | `action` / `objectType` | Actor (`_createdBy`) | What happened | `details` keys |
|---|---|---|---|---|
| `01-observable-create-on-alert-by-n8n.json` | create / Observable | n8n | observable created with the alert (one event per observable, before the alert's own event) | full observable |
| `02-alert-create-by-n8n.json` | create / Alert | n8n | alert created | full alert |
| `03-alert-update-tags-by-n8n.json` | update / Alert | **n8n** | n8n added a tag: **the event loop prevention must ignore** (N8N-1.5) | `tags` |
| `04-alert-update-assignee.json` | update / Alert | analyst | alert assigned | `assignee` |
| `05-alert-update-status-inprogress.json` | update / Alert | analyst | alert status New → InProgress (MTTA `t_ack`, C11) | `status`, `stage` |
| `06-comment-create-on-alert.json` | create / Comment | analyst | comment on the alert (`object.alert` set, `object.case` null) | `author` |
| `07-case-update-share-on-promote.json` | update / Case | analyst | promotion, part 1: case shared with the org | `share` |
| `08-alert-update-caseid-on-promote.json` | update / Alert | analyst | promotion, part 2: alert gets `caseId`, status Imported | `caseId` |
| `09-observable-create-on-case-from-alert.json` | create / Observable | analyst | promotion, part 3: alert observables copied to the case | full observable |
| `10-case-create-from-alert.json` | create / Case | analyst | promotion, part 4: the case (arrived ~3 s after parts 1–2) | full case |
| `11-task-create.json` | create / Task | analyst | task added to the case | full task |
| `12-task-update-inprogress.json` | update / Task | analyst | task started | `status`, `startDate` |
| `13-case-update-status-inprogress-auto.json` | update / Case | analyst | case New → InProgress, done by TheHive because a task started | `status`, `stage` |
| `14-log-create.json` | create / Log | analyst | task log | full log |
| `15-task-update-completed.json` | update / Task | analyst | task completed | `status`, `endDate`, `timeToHandle` |
| `16-comment-create-on-case.json` | create / Comment | analyst | comment on the case | `author` |
| `17-observable-create-on-case.json` | create / Observable | analyst | observable added to the case (`192.0.2.10`, documentation range) | full observable |
| `18-case-update-closed-falsepositive.json` | update / Case | analyst | case closed as FalsePositive (C11 `t_closed`, `resolution`; N8N-5.3) | `status`, `stage`, `endDate`, `summary` |
| `19-case-delete.json` | delete / Case | analyst | case deleted: **no `object`**, `details` has only `number`, `title` | `number`, `title` |
| `20-alert-delete.json` | delete / Alert | analyst | alert deleted: **no `object`, empty `details`** | none |

Observations (details in `../docs/ALERT-TO-THEHIVE.md`):
- The actor of every event, deletes included, is the top-level `_createdBy` (the audit record's author). `object._updatedBy` exists only when there is an `object`.
- Delete events have no `object`, so a deleted alert's `sourceRef` (the Wazuh alert ID) can't be read from the payload.
- Deleting the case put the alert back to InProgress with `caseId` null **without any event** for the alert.
- Not captured: `User` events (skipped on purpose; they carry `details.key: "<hidden>"` on key renewals, not the key), alert merge into a case, alert status Ignored/FalsePositive, case template applied (no templates are loaded on the build instance), approval tasks (N8N-7.x).

## Replaying (`replay.sh`, N8N-0.6)

```bash
nodes/core/n8n/fixtures/replay.sh --file nodes/core/n8n/fixtures/wazuh/100100-asox-test-c1.json
nodes/core/n8n/fixtures/replay.sh --all --only wazuh --times 2   # idempotency test (N8N-3.3)
nodes/core/n8n/fixtures/replay.sh --all --no-token               # every POST must get 403 (N8N-1.6)
nodes/core/n8n/fixtures/replay.sh --fresh-id --times 2 --delay 5 --file nodes/core/n8n/fixtures/wazuh/100100-asox-test-c1.json
                                  # new unique alert id, sent twice 5 s apart: one TheHive alert, one writeback,
                                  # second run = duplicate (N8N-3.3)
```

With playbooks attached, a replayed Wazuh fixture creates a real TheHive alert (source `asox-test` for rule 100100, `wazuh` otherwise), and TheHive refuses a second alert with the same `sourceRef`. Use `--fresh-id` to replay a fixture as a new alert; the id is replaced once per file and run, so `--times N` still tests deduplication. Give `--delay` so the first run finishes first: **without it, the copies reach TheHive concurrently and TheHive creates one alert per copy** (its duplicate refusal isn't atomic; `../docs/ALERT-TO-THEHIVE.md` §2). Delete the test alerts afterwards (source `asox-test`).

It picks the webhook and the auth header from the payload (Wazuh → `wazuh-alert` + `X-ASOX-Token`, TheHive → `thehive-event` + `Authorization: Bearer`), reads the token from `nodes/core/.env` without printing it, and reaches n8n on its published port (`N8N_URL`, default `http://127.0.0.1:5678`, as the other scripts). Once playbooks are attached, a replay runs them for real.

Verified 2026-09-30: `--all --no-token` → 25 × HTTP 403; `100100-asox-test-c1.json` → HTTP 200 and `recv-wazuh-alert` execution 136 recorded alert `1790461241.14189`; a TheHive fixture `--times 2` → 2 × HTTP 200.
