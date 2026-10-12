# Jev offline core (stage 0, draft)

Owner: n8n. Proposal: `docs/jev-implementation.md` (version 0.1, **status Draft**).

## Purpose

Jev is the proposed AI triage judge: a hosted model that answers typed questions about an alert, while code owns the facts and the policy. This folder holds the part of that design that needs nothing else to exist: the versioned configuration and the pure JavaScript logic that builds the state Jev is given, builds the request bodies, and turns Jev's answers into a decision.

## Status

- **Stage 0, offline.** Nothing here calls Jev, n8n, or any other service. There is no workflow, no HTTP call, no API key and no contract change.
- **Nothing in the proposal is accepted yet.** C15, C16, D50–D56 and every threshold are proposals. This code exists so the proposal can be reviewed against something that runs.
- **Automatic closure is off.** `policy.json` has `auto_close_rules: []`, and `decide` returns `auto_close_fp` only in mode `gated`, for a listed rule, with every gate passing and no trigger fired.
- **Hard precondition for listing a rule.** No rule goes into `auto_close_rules` until all of these hold:
  1. the strict ablation exists end to end: `lib-jev-judge` sends the `strictAblated` request and passes its answers to `decide` (the request body and gate G6 are built here; the workflow is not);
  2. benign patterns are verified in code: every pattern a closure may rest on has a `verify` block, its CIDR list is reviewed, and the playbook passes `benign_pattern_verified` in `codeCtx` (the check and gate G4 are built here; the lists and the workflow are not);
  3. the adversarial set passes with the rule listed and mode `gated` (`tests/scenarios.test.js`, "fully steered, rule listed, mode gated" and the `/healthz` look-alike), and again against the real model in the golden-set run of doc 13.2, which does not exist yet.

  The mocked run of point 3 passes today. Points 1 and 2 are half built, and the real-model run is not possible before C15.
- Every JSON file has a `version` and a `status`; the two field lists are marked `draft: pending Wazuh owner` and `draft: pending Cortex + MISP owner`.

## Layout

| Path | What it is |
|---|---|
| `lib/state.js` | `buildState(alert, enrichment, config)` → state; `buildCodeCtx(alert, config, extra)` → code-only values |
| `lib/request.js` | `resolveQuestionSet(file, playbooks)` → effective question set; `buildRequests(state, questionSet, { model })` → `{ full, ablated, strictAblated, orderCheck }` |
| `lib/decide.js` | `decide(runs, facts, policy, mode, codeCtx)` → decision, triggers, tags, gate trace |
| `questions/triage-v1.json` | The 9 questions of doc 7.1: literal instructions, criteria for every Choice option and Score level |
| `policy.json` | Thresholds of doc 8.3 and 8.4, decision priority, verdict classes, state-builder parameters (network ranges, bucket limits) |
| `playbooks.json` | Playbook catalog for the `playbook` question (`pb-generic` only) |
| `assets.json` | Asset roles and criticality (`lab-agent` only) |
| `benign-patterns.json` | Known benign patterns in plain language, each with an optional `verify` block checked in code (one example entry) |
| `ip-lists/` | CIDR list files named by `verify` blocks of type `source_ip_in` (one example list) |
| `untrusted-fields.json` | Attacker-writable Wazuh fields and their caps (doc 6.5), and `static_description_rules` |
| `intel-fields.json` | Per analyzer, the report fields kept next to the taxonomies (doc 6.3) |
| `path-classes.json`, `user-agent-classes.json`, `text-classes.json` | Ordered class lists for the three facts derived from untrusted fields |
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
- 69 tests: config files, state builder, request builder, decision step, and the scenarios end to end with mocked answers.

## How the three steps fit

```
alert (C1) + enrichment ──► buildState ──► state { alert, facts, intel, context, untrusted }
                                             │
state + question set + model ──► buildRequests ──► full / ablated / strictAblated / orderCheck bodies
                                             │            (sent by lib-jev-judge, not built yet)
answers + state.facts + policy + mode + codeCtx ──► decide ──► decision
```

### State (`lib/state.js`)

- **Input:** the raw Wazuh alert and an `enrichment` object whose parts are all optional. The shape `buildState` reads is a draft, written at the top of the file: `observable`, `seen_before` (C13), `misp` (C7), `warninglists` (C10), `cortex_reports` (C6). `config.now` supplies the time, so the function stays pure.
- **Unknown:** a fact whose input is missing is the string `unknown`. Nothing is guessed toward "old", "low" or "none": a MISP event without a date makes `newest_event_age` unknown, and `intel` is `unknown` when no reports were given but `[]` when analyzers ran and found nothing.
- **Buckets:** counts, dates and addresses become the categories of doc 6.2. CIDR matching is done in code for IPv4 and IPv6; an address is classified `soc_internal`, `documentation`, `private`, else `public`, in that order.
- **Rule description:** a Wazuh rule can interpolate decoded fields into its description, so `rule.description` goes into `untrusted`, not `alert`. `alert` keeps `rule_id`, `rule_level`, `rule_groups`, `mitre_tactics`, `agent_name` and `decoder`. For a rule listed in `static_description_rules` (`untrusted-fields.json`, empty today) the description is sent in `alert` instead.
- **Untrusted fields:** only fields listed in `untrusted-fields.json` are copied, into `untrusted`, each cut to 500 characters and all of them to 2,000 in total, in the file's order. A field listed nowhere is not sent at all: `alert` carries a fixed set of rule and agent fields.
- **Refinement over the doc:** three safe facts are derived in code from untrusted fields: `request_path_class`, `user_agent_class`, and `untrusted_text_class` for the fields with no class of their own (user names, commands, file names, the log line, the rule description). Their values come from a closed list of class names, never from the input, so they stay in `facts` (and in the plain ablation) while the raw values stay in `untrusted`. A value that carries prose is classified `embedded_text` before any ordinary class, and user-agent classes are named `claims_…` because a user agent is whatever the client chose to send.
- **One list of derived facts:** `DERIVED_FACTS` in `state.js`. The state carries it as `derived_facts`; `buildRequests` removes those facts for the strict ablation and never sends the list. A new class fact is added to that list and nowhere else; a test fails if a `*_class` fact is missing from it.
- **Verified benign patterns:** a pattern may carry `verify: { "type": "source_ip_in", "field": "data.srcip", "list": "ip-lists/<file>.json" }`. `buildCodeCtx` checks the address in that alert field, and only that field, against that list and returns `benign_pattern_verified`: `yes` when the check of at least one applicable pattern holds, `no` when none does (a pattern without a `verify` block verifies nothing), `unknown` when a check could not be made (no field named, no address in it, list not loaded, unknown type). Jev sees the description only.
- **Data minimization:** `alert`, `facts`, `intel` and `context` never hold the raw observable value (it can still appear inside an untrusted field such as `full_log`); `intel` holds taxonomies and the selected fields, never a full report.

### Requests (`lib/request.js`)

- `resolveQuestionSet` fills the `playbook` options from `playbooks.json`. The effective version is `triage-v1+pb.<12 hex>`, where the hex is the start of the SHA-256 of the catalog's ids and descriptions in order. Adding, removing, rewording or reordering a playbook changes it. SHA-256 is implemented in the file (Code nodes cannot load `node:crypto` by default) and tested against `node:crypto`.
- `buildRequests` needs `options.model` and throws without it; no model name is written in this folder.
- `full`: the whole state and all 9 questions. `ablated`: the state without `untrusted`, and without the questions marked `reads_untrusted` (`outcome`, `steering`). `strictAblated`: the same, also without the derived facts, so it holds nothing an attacker wrote or chose. `orderCheck`: the `verdict` question only, options reversed.
- `buildRequests` refuses a state without `derived_facts`, rather than build a strict ablation that keeps those facts.
- Only the five state sections are copied into a request, so code-only values cannot leak even if a caller attaches them to the state object.

### Decision (`lib/decide.js`)

| Mode | `decision` |
|---|---|
| `off`, or a mode that is not one of the four | `none`; nothing evaluated |
| `shadow` | always `none`, no tags; `shadowDecision` holds what `advisory` would have returned |
| `advisory` | `escalate`, `human_review` or `advisory` |
| `gated` | the same, or `auto_close_fp` when every gate passes and no trigger fired |

- **Triggers (doc 8.4)** decide between `escalate`, `human_review` and `advisory`. The result lists each one that fired in `triggers`, with a detail line.
- **Gates (doc 8.3)** only decide whether `auto_close_fp` is allowed. `gatesFailed` lists the failed ones and `gateDetails` says why. Three differ from the doc:
  - **G4** also needs `codeCtx.benign_pattern_verified = yes`: no benign verdict (`false_positive` or `benign_true_positive`) closes unless code verified a known benign pattern for the alert, whatever Jev answers to `benign_pattern_match`.
  - **G6** compares the full run with the strict ablation: same verdict, probability within the tolerance. It also fails when the plain ablation disagrees or either run is missing.
  - **G12** (new) fails when any fact has a value in `gates.blocked_fact_classes` (`embedded_text`, `attack_pattern`).
- A gate that cannot be checked has failed: an `unknown` fact, a missing answer, a missing ablated or order-check run.
- A missing or malformed full run, or a policy that fails `policyProblems`, gives `none`: the alert continues as it would without Jev.
- `wouldAutoClose` and `closeGatesFailed` are for metrics (doc 12.2, "would-have-closed precision"): gates G2–G12 as if the mode were `gated`, with G2 keeping the level cap and `never_auto_rules` but ignoring the `auto_close_rules` membership. In `gated` mode they are the real result and the real gate trace.
- `tags` are the signal tags only: `jev:conflict`, `jev:possible-manipulation`, `jev:untrusted-dependent`. The `jev:<decision>` tag of C16 is left to the record step.

## Decisions on the doc's open points

Decided by the n8n owner on 2026-10-12 for this stage. They differ from, or add to, the proposal, and should go into its next version.

1. **Shadow mode.** `decision` is always `none` and no tags are returned, so a playbook that acts on `decision` cannot act by mistake. The metrics record stores `shadowDecision.decision` in `jev_decision` with `jev_mode: shadow`, so the dashboard compares like with like across stages.
2. **Several triggers at once.** The decision is the first entry of `policy.decision_priority` (`escalate` > `human_review` > `advisory` > `none`) among those the fired triggers ask for. Every trigger and tag is kept. This supersedes doc 9.2's "human_review whatever the verdict": suspected manipulation can never lower the outcome below `human_review`, but `escalate` still wins, so an attacker cannot suppress a severity raise by adding steering text.
3. **Any fired trigger blocks `auto_close_fp`**, whatever the gates say.
4. **Ablation (refines doc 9.2).** Two ablated runs with two jobs. The *strict* ablation (no `untrusted`, no derived facts) decides G6. The *plain* ablation (no `untrusted`) drives the tags: a verdict that changes, or a probability that moves by more than the tolerance, between it and the full run adds `jev:untrusted-dependent`; `jev:possible-manipulation` is added only when `steering` reaches `escalation.steering_min`, or when the verdict flips from the malicious class in the plain ablation to a benign class in the full run. A disagreement in the strict ablation alone adds no tag.
5. **Severity trigger.** It fires when Jev's severity expected value ≥ `escalation.severity_ev_min` (2.5) and `codeCtx.thehive_severity` < `escalation.severity_thehive_below` (3). Scales: Jev 0 negligible, 1 low, 2 medium, 3 high; TheHive 1 low, 2 medium, 3 high, 4 critical. Without `thehive_severity` the rule does not fire and the result carries the note `severity-rule-skipped`.
6. **Code-only values** travel in `codeCtx`, a separate argument of `decide`, never in the state: `wazuh_rule_id`, `wazuh_rule_level`, `rule_eligible_for_auto`, `benign_pattern_verified`, `thehive_severity`, `response_action_proposed`. The rule id and level are also in `state.alert`, where doc 6.6 puts them for Jev; the `codeCtx` copies have their own names so a test can prove no `codeCtx` key appears in a request body.
7. **A failed gate alone gives `advisory`.** `human_review` comes only from triggers. In doc 8.5's example the decision is `human_review` because `intel_conflict` 0.62 fires the 8.4 trigger (≥ 0.50), not because G9 failed. The explanation block should name the trigger and list the failed gates separately.
8. **`veto_action` is never returned here.** It belongs to `guard-v1` (`lib-jev-guard`), a separate path.
9. **Closure requires a verified pattern** (G4): Jev's verdict alone never closes an alert, with or without a claimed pattern match. **A class fact reporting prose or attack syntax blocks closure** (G12). Both are code-side checks that hold even when every answer from Jev is steered.
10. **The rule description is untrusted** until the Wazuh owner confirms the rule's description is static.
11. **G6 is strict on both ablations.** It fails on a disagreement in the strict ablation or in the plain one, so an alert tagged `jev:untrusted-dependent` is never closed.
12. **Question sets: draft, then frozen.** A question set is a draft until it is first used in shadow mode, and may be edited in place until then (`triage-v1` was, to drop the rule description from the `verdict` criteria). From its first shadow-mode use it is frozen: any change to an instruction or criterion needs a new version (`triage-v2`), because recorded judgments name the version they were asked with.

## Open items

Not decided here. Each needs an answer before the stage it blocks.

1. **How the lib code gets into n8n Code nodes.** Two options: inline the file contents into the Code nodes when the workflows are exported, or mount this folder into the n8n container and load it at run time. Inlining keeps workflows self-contained but duplicates the code in every export; mounting keeps one copy but needs a compose change and a way for the Code node sandbox to read files. The same question applies to the JSON config. Not decided.
2. **Precondition for listing a rule: see "Status".** With the rule listed, mode `gated` and all four runs steered to a confident `false_positive`, the four adversarial fixtures do not close (G4 and G12), and the `/healthz` look-alike does not close without a verified pattern, whether or not Jev claims one. What the mocked tests cannot show:
   - **Proxies.** `source_ip_in` reads only the alert field its `verify` block names. Behind a proxy or load balancer, that field must hold the connection's source address as the proxy saw it, never a forwarded header (`X-Forwarded-For` and the like), which the client writes. Which decoder field that is, per log source, is a question for the Wazuh owner before any real list is added; if only a forwarded header is available, the pattern cannot be verified.
   - The `text-classes.json` phrases are a first draft and will miss paraphrases; G12 is a second line behind the ablation, not a detector.
3. **Strict ablation and patterns about paths.** The strict ablation removes the class facts because an attacker can pick them (`/healthz` with a monitoring user agent gets `health_check` and `claims_monitoring_tool`). A pattern such as "uptime checks against /healthz" can then only be matched in the full and plain runs, so G6 will fail for it whenever Jev needs the path to be sure. Expect path-based patterns to stay advisory unless the rest of the evidence carries the verdict; measure this in shadow mode before changing the gate.
4. **Rule descriptions (question for the Wazuh owner).** Which rules, built-in and custom, interpolate decoded fields into their description (`$(srcuser)`-style substitutions)? Until answered, every description is sent in `untrusted`. Rules confirmed static are added to `static_description_rules` in `untrusted-fields.json`, which restores their description to `alert`. The `verdict` criteria no longer mention the rule description (they point at the rule's groups, MITRE tactics and level); if descriptions return to `alert` for many rules, that wording can be reconsidered in a later version.
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
16. **The hash covers the playbook catalog only.** Rewording a question without renaming the set is not detected by the version; the freeze rule above is enforced by review.
17. **`benign_pattern_verified` is per alert, not per pattern.** Jev does not say which pattern it matched, so `yes` means "code confirmed at least one applicable pattern", not "the one Jev had in mind". It also means a rule with no verifiable pattern can never be closed automatically: closure is only for alerts that match a pattern someone wrote, listed addresses for, and had reviewed.
18. **Not built:** `guard-v1`, `lib-jev-record`, the explanation block, the audit sampling of `audit_sample_rate`, the golden set and `jev-eval.sh`.

## Integrator changes needed

None was made; nothing outside this folder was touched. Listed for when the proposal moves forward (most are already in doc 10.2 and 18).

1. **`scripts/ci-checks.sh`:** run `nodes/core/n8n/jev/run-tests.sh` as a check (and in `.github/` CI), so the unit tests gate every commit. Today they run only by hand.
2. **`docs/decisions.md`:** record the image pin `node:26.7.0-alpine` (CLAUDE.md: image changes are recorded there).
3. **`docs/jev-implementation.md`:** fold in the twelve decisions above, the three class facts, the strict ablation (a fourth call per alert: section 14's cost estimate becomes 4 calls), gates G4/G6/G12, and the precondition for listing a rule.
4. **SOC ranges for `ip_scope`:** a variable for the SOC's own subnets (the Docker networks) that the playbook passes into `policy.state.networks.soc_internal` at run time, instead of an address in a committed file.
5. **When C15 is built** (not now): `TYPESAFE_API_URL`, `JEV_MODEL`, `JEV_MODE`, `JEV_TIMEOUT_MS` in `nodes/core/.env.example`; `TYPESAFE_API_KEY` with the `__external__` marker in `render-env.sh`; the credential in `bootstrap.sh core`; `chk-jev-api` in `contracts-check.sh`; `TYPESAFE_API_KEY` in the secret scan.
6. **Depending on open item 1:** if the folder is mounted, a read-only volume in n8n's compose file (owner file) and whatever `n8n-import.sh` / `n8n-export.sh` need; if inlined, a step in `n8n-export.sh`.
