# Jev offline core (stage 0, draft)

Owner: n8n. Proposal: `docs/jev-implementation.md` (version 0.1, **status Draft**).

## Purpose

Jev is the proposed AI triage judge: a hosted model that answers typed questions about an alert, while code owns the facts and the policy. This folder holds the part of that design that needs nothing else to exist: the versioned configuration and the pure JavaScript logic that builds the state Jev is given, builds the request bodies, and turns Jev's answers into a decision.

## Status

- **Stage 0, offline.** Nothing here calls Jev, n8n, or any other service. There is no workflow, no HTTP call, no API key and no contract change.
- **Nothing in the proposal is accepted yet.** C15, C16, D50–D56 and every threshold are proposals. This code exists so the proposal can be reviewed against something that runs.
- **Automatic closure is off.** `policy.json` has `auto_close_rules: []`, and `decide` returns `auto_close_fp` only in mode `gated`, for a listed rule, with every gate passing and no trigger fired.
- Every JSON file has a `version` and a `status`; the two field lists are marked `draft: pending Wazuh owner` and `draft: pending Cortex + MISP owner`.

## Layout

| Path | What it is |
|---|---|
| `lib/state.js` | `buildState(alert, enrichment, config)` → state; `buildCodeCtx(alert, policy, extra)` → code-only values |
| `lib/request.js` | `resolveQuestionSet(file, playbooks)` → effective question set; `buildRequests(state, questionSet, { model })` → `{ full, ablated, orderCheck }` |
| `lib/decide.js` | `decide(runs, facts, policy, mode, codeCtx)` → decision, triggers, tags, gate trace |
| `questions/triage-v1.json` | The 9 questions of doc 7.1: literal instructions, criteria for every Choice option and Score level |
| `policy.json` | Thresholds of doc 8.3 and 8.4, decision priority, verdict classes, state-builder parameters (network ranges, bucket limits) |
| `playbooks.json` | Playbook catalog for the `playbook` question (`pb-generic` only) |
| `assets.json` | Asset roles and criticality (`lab-agent` only) |
| `benign-patterns.json` | Known benign patterns in plain language (one example entry) |
| `untrusted-fields.json` | Attacker-writable Wazuh fields and their caps (doc 6.5) |
| `intel-fields.json` | Per analyzer, the report fields kept next to the taxonomies (doc 6.3) |
| `path-classes.json`, `user-agent-classes.json` | Ordered class lists for the two facts derived from untrusted fields |
| `tests/` | `node:test` unit tests, fixtures, the adversarial set |
| `run-tests.sh` | Runs the tests in the pinned Node image |

The three lib files are plain JavaScript with no `require`, no clock, no randomness and no network code, so they can run unchanged in an n8n Code node. Each ends with a guarded `module.exports` for the tests.

## Running the tests

```bash
nodes/core/n8n/jev/run-tests.sh            # every tests/*.test.js
nodes/core/n8n/jev/run-tests.sh tests/decide.test.js
```

- Image: **`node:26.7.0-alpine`**. `n8nio/n8n:2.40.7` ships Node `v26.7.0` (checked with `docker run --rm --entrypoint node n8nio/n8n:2.40.7 --version`), so the tests run on the runtime the code is meant for. When `N8N_IMAGE` changes, check its Node version and update `NODE_IMAGE` in `run-tests.sh`.
- The folder is mounted read-only and the container has no network. Nothing is installed; the SOC stack does not need to run.
- 57 tests: config files, state builder, request builder, decision step, and the scenarios end to end with mocked answers.

## How the three steps fit

```
alert (C1) + enrichment ──► buildState ──► state { alert, facts, intel, context, untrusted }
                                             │
state + question set + model ──► buildRequests ──► full / ablated / orderCheck request bodies
                                             │            (sent by lib-jev-judge, not built yet)
answers + state.facts + policy + mode + codeCtx ──► decide ──► decision
```

### State (`lib/state.js`)

- **Input:** the raw Wazuh alert and an `enrichment` object whose parts are all optional. The shape `buildState` reads is a draft, written at the top of the file: `observable`, `seen_before` (C13), `misp` (C7), `warninglists` (C10), `cortex_reports` (C6). `config.now` supplies the time, so the function stays pure.
- **Unknown:** a fact whose input is missing is the string `unknown`. Nothing is guessed toward "old", "low" or "none": a MISP event without a date makes `newest_event_age` unknown, and `intel` is `unknown` when no reports were given but `[]` when analyzers ran and found nothing.
- **Buckets:** counts, dates and addresses become the categories of doc 6.2. CIDR matching is done in code for IPv4 and IPv6; an address is classified `soc_internal`, `documentation`, `private`, else `public`, in that order.
- **Untrusted fields:** only fields listed in `untrusted-fields.json` are copied, into `untrusted`, each cut to 500 characters and all of them to 2,000 in total, in the file's order. A field listed nowhere is not sent at all: `alert` carries a fixed set of rule and agent fields.
- **Refinement over the doc:** two safe facts are derived in code from untrusted fields: `request_path_class` and `user_agent_class`. Their values come from a closed list of class names, never from the input, so they stay in `facts` (and in the ablated run) while the raw values stay in `untrusted`. A value that carries prose is classified `embedded_text` before any ordinary class, and user-agent classes are named `claims_…` because a user agent is whatever the client chose to send.
- **Data minimization:** `alert`, `facts`, `intel` and `context` never hold the raw observable value (it can still appear inside an untrusted field such as `full_log`); `intel` holds taxonomies and the selected fields, never a full report.

### Requests (`lib/request.js`)

- `resolveQuestionSet` fills the `playbook` options from `playbooks.json`. The effective version is `triage-v1+pb.<12 hex>`, where the hex is the start of the SHA-256 of the catalog's ids and descriptions in order. Adding, removing, rewording or reordering a playbook changes it. SHA-256 is implemented in the file (Code nodes cannot load `node:crypto` by default) and tested against `node:crypto`.
- `buildRequests` needs `options.model` and throws without it; no model name is written in this folder.
- `full`: the whole state and all 9 questions. `ablated`: the state without `untrusted`, and without the questions marked `reads_untrusted` (`outcome`, `steering`). `orderCheck`: the `verdict` question only, options reversed.
- Only the five state sections are copied into a request, so code-only values cannot leak even if a caller attaches them to the state object.

### Decision (`lib/decide.js`)

| Mode | `decision` |
|---|---|
| `off`, or a mode that is not one of the four | `none`; nothing evaluated |
| `shadow` | always `none`, no tags; `shadowDecision` holds what `advisory` would have returned |
| `advisory` | `escalate`, `human_review` or `advisory` |
| `gated` | the same, or `auto_close_fp` when every gate passes and no trigger fired |

- **Triggers (doc 8.4)** decide between `escalate`, `human_review` and `advisory`. The result lists each one that fired in `triggers`, with a detail line.
- **Gates (doc 8.3)** only decide whether `auto_close_fp` is allowed. `gatesFailed` lists the failed ones and `gateDetails` says why.
- A gate that cannot be checked has failed: an `unknown` fact, a missing answer, a missing ablated or order-check run.
- A missing or malformed full run, or a policy that fails `policyProblems`, gives `none`: the alert continues as it would without Jev.
- `wouldAutoClose` and `closeGatesFailed` are for metrics (doc 12.2, "would-have-closed precision"): gates G2–G11 as if the mode were `gated`, with G2 keeping the level cap and `never_auto_rules` but ignoring the `auto_close_rules` membership. In `gated` mode they are the real result and the real gate trace.
- `tags` are the signal tags only: `jev:conflict`, `jev:possible-manipulation`, `jev:untrusted-dependent`. The `jev:<decision>` tag of C16 is left to the record step.

## Decisions on the doc's open points

Decided by the n8n owner on 2026-10-12 for this stage. They differ from, or add to, the proposal, and should go into its next version.

1. **Shadow mode.** `decision` is always `none` and no tags are returned, so a playbook that acts on `decision` cannot act by mistake. The metrics record stores `shadowDecision.decision` in `jev_decision` with `jev_mode: shadow`, so the dashboard compares like with like across stages.
2. **Several triggers at once.** The decision is the first entry of `policy.decision_priority` (`escalate` > `human_review` > `advisory` > `none`) among those the fired triggers ask for. Every trigger and tag is kept. This supersedes doc 9.2's "human_review whatever the verdict": suspected manipulation can never lower the outcome below `human_review`, but `escalate` still wins, so an attacker cannot suppress a severity raise by adding steering text.
3. **Any fired trigger blocks `auto_close_fp`**, whatever the gates say.
4. **Ablation (refines doc 9.2).** A verdict that changes, or a probability that moves by more than the tolerance, between the ablated and the full run fails G6 and adds `jev:untrusted-dependent`. It only blocks de-escalation. `jev:possible-manipulation` is added only when `steering` reaches `escalation.steering_min`, or when the verdict flips from the malicious class in the ablated run to a benign class in the full run.
5. **Severity trigger.** It fires when Jev's severity expected value ≥ `escalation.severity_ev_min` (2.5) and `codeCtx.thehive_severity` < `escalation.severity_thehive_below` (3). Scales: Jev 0 negligible, 1 low, 2 medium, 3 high; TheHive 1 low, 2 medium, 3 high, 4 critical. Without `thehive_severity` the rule does not fire and the result carries the note `severity-rule-skipped`.
6. **Code-only values** travel in `codeCtx`, a separate argument of `decide`, never in the state: `wazuh_rule_id`, `wazuh_rule_level`, `rule_eligible_for_auto`, `thehive_severity`, `response_action_proposed`. The rule id and level are also in `state.alert`, where doc 6.6 puts them for Jev; the `codeCtx` copies have their own names so a test can prove no `codeCtx` key appears in a request body.
7. **A failed gate alone gives `advisory`.** `human_review` comes only from triggers. In doc 8.5's example the decision is `human_review` because `intel_conflict` 0.62 fires the 8.4 trigger (≥ 0.50), not because G9 failed. The explanation block should name the trigger and list the failed gates separately.
8. **`veto_action` is never returned here.** It belongs to `guard-v1` (`lib-jev-guard`), a separate path.

## Open items

Not decided here. Each needs an answer before the stage it blocks.

1. **How the lib code gets into n8n Code nodes.** Two options: inline the file contents into the Code nodes when the workflows are exported, or mount this folder into the n8n container and load it at run time. Inlining keeps workflows self-contained but duplicates the code in every export; mounting keeps one copy but needs a compose change and a way for the Code node sandbox to read files. The same question applies to the JSON config. Not decided.
2. **A fully steered Jev with a listed rule.** The adversarial tests pass with `policy.json` as committed, where no rule is listed. With a rule listed in `auto_close_rules` and mode `gated`, mocked answers in which all three runs are steered to a confident `false_positive` and `steering` stays low reach `auto_close_fp` for all four adversarial fixtures: every gate reads Jev's answers or facts the injection does not touch. Before any rule is listed, a code-side gate is needed. A candidate: block closure when `request_path_class` or `user_agent_class` is `embedded_text` or `attack_pattern`, and add a class fact for the other untrusted fields (user names, commands), which have none today.
3. **Class facts are attacker-selectable.** An attacker can request `/healthz` with a monitoring user agent and get `health_check` and `claims_monitoring_tool`. They cannot inject text through them, but they can pick the class. Whether benign patterns may rely on these classes needs a rule.
4. **`rule_description` can interpolate decoded fields.** Wazuh rule descriptions may contain `$(srcuser)`-style substitutions, which would carry attacker text into the trusted `alert` section. It is cut to 200 characters; whether such rules exist in our ruleset is a question for the Wazuh owner.
5. **Enrichment input shape.** The `enrichment` object is this folder's draft. C13 is not built, and `lib-enrich-observable` returns its own shape; the mapping is part of building `lib-jev-state`.
6. **One observable per judgment.** The state describes one primary observable. An alert with several needs either a choice of primary or one judgment per observable.
7. **`related_high_alerts` and the alert itself.** The C13 lookup will probably count the current alert. For a rule of level ≥ 10 that makes the fact `some` every time; harmless today (such rules cannot be closed), but the window and self-exclusion need defining with C13.
8. **`untrusted-fields.json`** (Wazuh owner): the per-decoder lists, the 500-character field cap, and the key names. The `web-accesslog` entry is a placeholder.
9. **`intel-fields.json`** (Cortex + MISP owner): the report paths have not been checked against real analyzer reports.
10. **Severity threshold** `severity_thehive_below: 3` (TheHive owner; the severity mapping is on his backlog).
11. **True-positive trigger with an unknown rule level.** It fires (caution) and adds the note `rule-level-unknown`. A Wazuh alert always has a level, so this only matters for malformed input.
12. **SOC ranges.** `policy.state.networks.soc_internal` is empty, so SOC containers classify as `private`. See "Integrator changes needed".
13. **TLP/PAP filter and user-name roles** (doc 10.4, 11): not built. `buildState` does not check TLP and sends user names in `untrusted` as they are.
14. **Answer shape** (doc Q1): `decide` reads `{ choice, confidence, probabilities }`, `{ noul }` and Score `probabilities` by level, as in doc 7.3. Score answers are not shown in the doc; the shape is assumed.
15. **Thresholds with no source in the doc:** `misp_events_many_min: 6` (few / many), `max_warninglists: 10`, `max_benign_patterns: 20`, the 5-minute clock-skew allowance, and the bucket edges for days (1–7 days = 24 hours up to 8 days; 8–30 days = up to 31 days).
16. **The hash covers the playbook catalog only.** Rewording a question without renaming the set is not detected by the version; doc 7.4's rule (new wording = new version) is enforced by review.
17. **Not built:** `guard-v1`, `lib-jev-record`, the explanation block, the audit sampling of `audit_sample_rate`, the golden set and `jev-eval.sh`.

## Integrator changes needed

None was made; nothing outside this folder was touched. Listed for when the proposal moves forward (most are already in doc 10.2 and 18).

1. **`scripts/ci-checks.sh`:** run `nodes/core/n8n/jev/run-tests.sh` as a check (and in `.github/` CI), so the unit tests gate every commit. Today they run only by hand.
2. **`docs/decisions.md`:** record the image pin `node:26.7.0-alpine` (CLAUDE.md: image changes are recorded there).
3. **`docs/jev-implementation.md`:** fold in the eight decisions above, the two class facts, and open item 2.
4. **SOC ranges for `ip_scope`:** a variable for the SOC's own subnets (the Docker networks) that the playbook passes into `policy.state.networks.soc_internal` at run time, instead of an address in a committed file.
5. **When C15 is built** (not now): `TYPESAFE_API_URL`, `JEV_MODEL`, `JEV_MODE`, `JEV_TIMEOUT_MS` in `nodes/core/.env.example`; `TYPESAFE_API_KEY` with the `__external__` marker in `render-env.sh`; the credential in `bootstrap.sh core`; `chk-jev-api` in `contracts-check.sh`; `TYPESAFE_API_KEY` in the secret scan.
6. **Depending on open item 1:** if the folder is mounted, a read-only volume in n8n's compose file (owner file) and whatever `n8n-import.sh` / `n8n-export.sh` need; if inlined, a step in `n8n-export.sh`.
