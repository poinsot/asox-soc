# Project status audit (2026-10-06)

Read-only audit of `main` at `2b7dff9` ("Merge pull request #14 from poinsot/thehive", 2026-10-05 12:04 -0600), clean working tree, 84 commits since `v1.0-baseline`. `soc.sh status` showed every node down, so `healthcheck.sh` wasn't run, and `soc.sh info cases | grep -i licen` printed nothing (TheHive not running). **No contract or health result below is from this commit: all are last-known results from the docs.**

## Summary

Phase 1 is done, and its one open follow-up, the TheHive license, was closed on 2026-09-30 (per the docs; not confirmed live). Since then four owner pull requests have been merged (#11–#14). n8n has the first working path: Wazuh alert → deduplicated TheHive alert with writeback, but no router and no enrichment yet. TheHive and Cortex + MISP have their configuration-as-code tooling on `main`. Wazuh has merged a config cleanup and the R-06 spec, but no new detection content. Grafana has nothing beyond the baseline dashboard.

None of the planned contracts C9–C14 is built, and `contracts-check.sh` still covers only C1–C8. The integrator's shared docs haven't changed since 2026-09-30, so several register rows are stale. **R-06 must be on `main` by 2026-10-09, and Daniel's spec for it is already on `main`.** The biggest risks are a stalled Grafana component and the 2026-10-20 checkpoint, which depends on several items that haven't started.

## Overview

| Component | Owner | Done / in progress / open | Contracts | Status |
|---|---|---|---|---|
| Wazuh | Daniel | M0 done (W0.8 answered in a file); W1.2 and W1.9 done; W1.1, W1.3–W1.8 and all of M2–M6 open | C1/C2/C8 passed on his `low` core run (2026-10-01). C9, C11, C13 acknowledgements pending. C14 design due 10-16 | **Behind**: W1.5 is due 10-09 and not started |
| n8n | Inigo | 13 workflows on `main`. About 17 items done, 3 partial; router, enrichment, C10/C11/C13 libs, E5, E7, E8 open | C1/C3/C4 verified 2026-09-30; acknowledged C9, C10, C11, C13 | **On track**, but N8N-1.3 and N8N-2.4 are open for 10-20 |
| Grafana | Jesus | Baseline only: `soc-overview.json`. No GRAF item started | C8 at baseline. C11 acknowledgement pending. No dates | **Behind / at risk** |
| TheHive | Park | Scripts plus 9 templates, 9 fields and 17 observable types. M0, M1 and part of M2–M5 done; T1.3 and T2.4–T2.7 open | C3/C4/C5. C12 rejection absorbed (T5.1/T5.2 closed) | **On track**, waiting on the n8n owner to review the agreements |
| Cortex + MISP | Diego | `analyzers.sh/json` and `misp-config.sh/json` merged (R-14 cap, C10 user). `n8n-enrichment.md`, API keys and the C13 analyzer not done | C5/C6/C7. C1–C8 passed on his `full` run (2026-10-01). Acknowledged C10, C13 | **On track with risks**: Cortex out of memory, enrichment doc due 10-20 |

## Done

**Phase 1** (from the docs and the tag)
- Tag `v1.0-baseline` exists, and PROJECT.md §17 marks steps 1.0–1.9 done.
- **TheHive license:** Community license activated 2026-09-30, valid until 2027-09-28 (handoff, register X-19). The backup `backups/cases-20260930-133649/` is on disk. Not confirmed live.
- **C4 on a Community license:** answered (PROJECT.md §16 Q6); n8n captured 20 C4 events on 2026-09-30 (N8N-0.2). The 2026-10-11 trial deadline no longer applies.

**Since the baseline** (from `git diff --stat` of each merge commit)
- **n8n (PR #11, `6da861b`):**
  - Workflows: `recv-wazuh-alert`, `pb-generic`, `lib-config`, `lib-normalize-wazuh-alert`, `lib-extract-observables`, `lib-thehive-upsert-alert`, `lib-thehive-writeback`, `lib-error`, `recv-n8n-error`, `recv-thehive-event` (router with loop prevention), plus the three `chk-*` check workflows.
  - Fixtures, `replay.sh`, `WAZUH-FIELDS.md` and `ALERT-TO-THEHIVE.md`.
  - `nodes/core/n8n/compose.yml` lines 41 and 46 pass `WAZUH_ALERT_MIN_LEVEL` and `THEHIVE_ENABLED`.
- **Integrator:**
  - R-18 done (`scripts/render-env.sh:113`, A79).
  - R-02 partly done: C1 cleans up the TheHive alert that `pb-generic` creates (`aac771e`).
  - Decisions A76–A80 recorded.
- **Cortex + MISP (PR #12, `6a400e7`):**
  - `analyzers/analyzers.sh` and `analyzers.json`: 5 online analyzers, keys pending.
  - `misp-config.sh` and `misp-config.json`: warninglist cap (R-14), Botvrij feed, C10 user `n8n@asox.local`.
  - Read Only role verified for `checkValue` (MISP backlog).
  - `C10-handoff-n8n.md`.
- **Wazuh (PR #13, `e1793b6`):**
  - W1.2: upstream cluster block and example email settings removed from `ossec.conf`.
  - W1.9: syslog source-IP test, with the R-06 spec in `nodes/core/wazuh/docs/request-integrator-r06-syslog-allowed-ips.md`.
  - Answers to §16 Q1 and Q3 in `request-integrator-w08-machine-info.md`.
  - Two findings from a core-only machine in `request-integrator-core-only-findings.md`.
- **TheHive (PR #14, `2b7dff9`):**
  - 9 case templates (`jq length` on `case-templates.json`).
  - `thehive-fp-report.sh`, `thehive-test-alert.sh --promote`, ALERT-FORMAT/TRIAGE marked "proposed, to confirm with n8n".

## In progress

- **n8n:** N8N-0.6 test strategy (partial); N8N-2.6 `lib-config` (partial); N8N-6.2 retries (TheHive done, Cortex to do). Enrichment is still a no-op stub in `pb-generic`.
- **Cortex:** online analyzers defined, but no keys and `analyzers.sh test` not exercised. `n8n-enrichment.md` (X-06/X-07, due 10-20) **is not on `main`**.
- **MISP:** memory re-measure with warninglists and Botvrij on; CIRCL feed off.
- **TheHive:** T3.5, T3.6, T3.7 written, still to be imported on a real instance; T4.3 and T4.4 waiting on the n8n owner's review or a run.
- **Wazuh:** W1.10 memo: only item 10 answered (`n8n-requests-2026-09-30.md`).

## Missing (not started; absent from `main`)

- **Wazuh:**
  - `local_rules.xml` holds only rule `100100`; `decoders/` is empty.
  - No `tests/` folder, no `trigger.sh --scenario`, no `30-syslog-allowed-ips.sh`, no `groups/` or `ENROLLMENT.md`.
  - No attack-start marker (X-32, W1.6), so C11 has no MTTD.
- **n8n:** router N8N-1.3, flood control N8N-1.4, enrichment N8N-2.4; N8N-2.9 (C11), 2.10 (C13), 2.11 (C10); playbooks 4.2–4.4; E5, E7, E8.
- **Grafana:** every GRAF item; `provisioning/alerting/` holds only `.gitkeep`.
- **Cortex:** C13 analyzer (needs R-10), local analyzers, written TLP/PAP policy (X-08).
- **Integrator (shared files):**
  - Open requests: R-01, R-03, R-04, R-05, R-06, R-07, R-08, R-10, R-11, R-13, R-15, R-16, R-17.
  - `scripts/contracts-check.sh:29` reads `ALL_CONTRACTS=(C1 … C8)`.
  - No shared file mentions `MISP_N8N_API_KEY`, `n8n-indexer`, `N8N_LOOKUP_TOKEN` or `SYSLOG_ALLOWED_IPS`.
  - `bootstrap.sh` doesn't call `misp-config.sh`.

### Contracts

| # | Acknowledged | Built | Check exists | Prerequisites / last result |
|---|---|---|---|---|
| C1–C8 | — | yes | yes (`contracts-check.sh:29`) | **Not run on HEAD.** Last results: integrator `full` healthcheck green, C4 verified 2026-09-30 (handoff). Diego C1–C8 pass at `6da861b` + `cortex-misp`, 2026-10-01 (`C10-handoff-n8n.md`). Daniel C1/C2/C8 pass on `low` core. W1.2 changed `ossec.conf` after those runs, so C1 should be re-run |
| C9 | n8n ✅, Wazuh pending | no | no | R-17 and W7.1/W7.2; after 2026-12-01 (Phase 2) |
| C10 | n8n ✅, Diego ✅ | MISP side only (user, cap) | no | R-13 (7 steps in `C10-handoff-n8n.md`), N8N-2.11, `chk-misp-api`, misp-core re-measure. Target 11-10 |
| C11 | n8n ✅, Grafana pending, Wazuh pending | no | no | R-16, R-11, N8N-2.9, X-32/W1.6, C4 (met) |
| C13 | n8n ✅, Diego ✅, Wazuh pending | no | no | R-10, R-16, R-15, N8N-2.10. Analyzer target 11-17 |
| C14 | design owed by Daniel + Diego | no | no | **Due 2026-10-16.** No written design on `main`. R-08 depends on it |

### Integrator items

- **Requests to act on:**
  - **R-06** answered (spec file above): empty default, `0.0.0.0/0` refused, no `172.16.0.0/12`. The register still says "waiting on Daniel".
  - **R-09** effectively done: the `.gitignore` line arrived through Diego's branch in PR #12.
  - **R-14** merged but must be run by hand.
- **New, not in the register yet:**
  - A stale `THEHIVE_N8N_API_KEY` renders `THEHIVE_ENABLED=true` on machines that now run core only.
  - The `healthcheck.sh` Grafana login uses `--max-time 10`, which fails right after `up` on `low`.
  - **Cortex killed for running out of memory at 650m** (`standard`, 2026-10-01; Cortex backlog, C10 handoff).
  - `bootstrap.sh intel` should run `misp-config.sh apply` (C10 handoff, step 6).
  - CHECKLIST needs a 12 GB row.
- **PROJECT.md §16 open questions:**
  - Q1 and Q3 partly answered (Daniel: Windows 11 Home 25H2, 12 GB; Park: 64 GB, Windows 11) but not recorded.
  - Q2 (phase definitions), Q4 (shared instance), Q5 (license re-activation) still open.

## Blocked

- **W1.1** waits on R-06 (integrator).
- **C10** waits on R-13 (integrator) and the misp-core re-measure (Diego).
- **C13** waits on R-10, R-15 and R-16 (integrator).
- **C11** waits on R-16 and R-11 (integrator), X-32 (Daniel) and the Grafana acknowledgement.
- **N8N-2.4 enrichment** waits on `n8n-enrichment.md` and analyzer API keys (Diego).
- **n8n fixtures for sshd, sudo, FIM and MITRE** wait on W1.5 (Daniel, due 10-09).
- **X-03 and X-15** wait on T1.3: `thehive-import.sh` on the build instance.
- **Phase 2 (C9, Suricata, pfSense, real endpoints):**
  - Suricata needs R-07 and W3.x; pfSense needs W4.x; real endpoints need W5.x and C9 (R-17, W7.x, N8N-8.x).
  - A real multi-host deployment needs `windows/firewall-rules.ps1` (never run, A71) and a host for the shared instance (§16 Q4).
- **Phase 3 (ASOX `ai` node, Slack bot):** nothing exists. N8N-9.1/9.2, N8N-7.5, R-01 and X-29 unscheduled; §16 Q2 open.

## Risks (ranked)

1. **Grafana has stalled.** Only three backlog-doc commits since the baseline (`931b98b`, `d3cbf08`, `2dd4d14`), no dates, no C11 acknowledgement, and its backlog still treats the metrics index as unagreed (it is C11). "Desempeño y cumplimiento" and MTTD/MTTA/MTTR are at risk for 12-01.
2. **Checkpoint 1 (10-20) depends on unstarted work:** n8n's router (N8N-1.3) and enrichment (N8N-2.4); X-01, X-02, X-04 agreements; Daniel's W1.3 rule plan and W1.5 scenarios (due 10-09); Diego's enrichment doc.
3. **HEAD is unverified end to end.** Three PRs merged since the last recorded `full` run, one touching `ossec.conf`. *Inferred:* no record of a post-merge `contracts-check.sh` run for #12–#14.
4. **Cortex runs out of memory at 650m** under analyzer activity; online analyzers and C13 will make it worse.
5. **A fresh `intel` still ships the 1M-entry warninglist**: `misp-config.sh` is manual, so a new `init` hits the out-of-memory problem on warninglist checks until it is run.
6. **C14's design is due 10-16** and nothing is on `main`.
7. **`THEHIVE_ENABLED` is wrong on core-only machines** with a leftover key: alerts are parked instead of skipped.
8. **Owner branches are editing shared files** (`.gitignore` in PR #12): minor, but against light rule 3.

## Docs drift

- **PROJECT.md:**
  - §17 line 890 still says "activate the TheHive Community license (trial ends 2026-10-11)"; done 2026-09-30.
  - §17 doesn't mention PRs #11–#14.
  - §16 doesn't record the Q1/Q3 answers.
- **`docs/handoff.md`:**
  - "Current state" dated 2026-09-30.
  - Line 14 says the n8n PR is pending and warns that `main`'s compose lacks `THEHIVE_ENABLED`/`WAZUH_ALERT_MIN_LEVEL`; both are now on `main`.
  - Line 11 says R-06 is waiting on Daniel.
- **`docs/integration-backlog.md`:** R-06 "waiting on Daniel" (answered); R-09 "open" (done); R-14 "watch at checkpoint" (merged, not in bootstrap); X-06 "not merged" (merged); Daniel's two findings and the Cortex out-of-memory event missing.
- **`docs/decisions.md`:** no A-entry for the R-14 cap (`maxEntries` 100,000), which affects a shared memory budget.
- **n8n (`n8n` branch):** BACKLOG "Temporary items" row on `THEHIVE_ENABLED` still says "until R-18" (done); N8N-5.4 and the D-N3 row still say "Cortex + MISP pending" (decided).
- **Wazuh:** README C9 row says it "extends `n8n-api`'s role", contradicting D44 (pending W1.7); request files on `main` still marked `Status: draft`.
- **TheHive:** README says "4 case templates"; `entities/` has 9. T0.5 still lists "C4 on a Community license" as open (X-19 resolved).
- **Grafana:** README and BACKLOG still mention Snort, reference "PROJECT.md v2.1" and N8N-9.3, and say D-G1–D-G4 are "not yet recorded" (they're in `decisions.md`).
- **MISP and Cortex:** MISP README backlog still says Snort and its file table omits `misp-config.sh`; Cortex README still calls the export scripts the "first task" (`analyzers.sh` exists).
- **CLAUDE.md:** git-ignored (`.gitignore:35`, `270ab00`), as PROJECT.md §12 records; it lists itself among the files the integrator changes on `main`, but it isn't in the repo.

## Top 5 next actions for the integrator

1. **Put R-06 on `main` before 2026-10-09.** Daniel's spec is complete and on `main`; his W1.1 is blocked on it, and core shouldn't go on a LAN with syslog open (A20).
2. **Verify HEAD on the build machine:** `soc.sh up full`, `n8n-import.sh`, `healthcheck.sh`, `contracts-check.sh` (C1–C8, `full`) and the license line. While it's up, run `thehive-import.sh` (T1.3), which unblocks X-03, X-15 and n8n's temporary `user-account` exclusion.
3. **Chase the 10-16 deadlines:** C14 design (Daniel + Diego); C9, C11, C13 acknowledgements (Daniel, Jesus); tell Daniel about C12's rejection; **get Grafana dates from Jesus**, without which checkpoint 1 slips for everyone (register section F).
4. **Bring the register, handoff and §17 up to date**, adding rows for: the stale `THEHIVE_ENABLED` key; the `healthcheck` Grafana timeout; Cortex out of memory at 650m (ask Diego for the measurement, then raise `CORTEX_MEM`); `misp-config.sh` in `bootstrap.sh intel`; the 12 GB CHECKLIST row.
5. **Start R-16 (`n8n-indexer`, the `asox-metrics` template, the CA in n8n), then R-10.** R-16 is the shared first piece of C11 and C13; C13's analyzer (11-17) also needs R-10. Both gate work by three other owners.

**n8n owner (on the `n8n` branch):** review and confirm TheHive's ALERT-FORMAT §1–§5 (T2.4–T2.6, due 10-20); build N8N-1.3 (router) and N8N-2.4 (enrichment) for checkpoint 1.

## Update 2026-10-06 (after the audit)

Integrator session on `main`, the same day. The audit above is unchanged; this section lists what changed since.

- **HEAD verified on the build machine (audit action 2).** `full` in `single` / `standard`, with `main`'s 13 n8n workflows imported for the test (`main` at `6a7e5b8`; the commits after the audit change only `render-env.sh`, `healthcheck.sh`, env templates and docs): `healthcheck.sh` all green on core, cases, intel and lab; `contracts-check.sh` **C1–C8 all pass** (27 s); license line `Community Regular, valid until 2027-09-28`. The running n8n was checked first: its 17 workflows were identical to the `n8n` branch's files, so nothing was lost. Afterwards the `n8n` branch's workflows were imported again and C1 re-run (pass).
- **R-06 done** (A81): optional `SYSLOG_ALLOWED_IPS` in `topology.env` → core's `WAZUH_SYSLOG_ALLOWED_IPS`, empty by default, validated by `render-env.sh` before any file is written. Daniel's W1.1 is unblocked.
- **Daniel's core-only findings:** Grafana login in `healthcheck.sh` retries once (R-20, A82); `render-env.sh` prints an INFO line for `THEHIVE_ENABLED=true` and CONTRIBUTING.md has a Troubleshooting note (R-19, A83). Correction found while testing: a stale key must be emptied in both `nodes/core/.env` and `nodes/cases/.env`, not only in core.
- **Register, handoff, decisions, PROJECT.md 16/17 updated** (status date 2026-10-06): R-06, R-09, R-14 statuses fixed; new rows R-19–R-25; A84 (n8n router), A85 (n8n enrichment defaults), A86 (R-14 cap); §17 line about the TheHive trial corrected; Q1/Q3 partial answers recorded.
- **n8n (branch `n8n`, not merged into `main`):** router N8N-1.3 built, enrichment N8N-2.4 partial (`MISP_2_1` only), ALERT-FORMAT §1–§5 reviewed with questions A–E to TheHive, T1.3 loaded on the build instance (9 fields, 9 templates, `user-account`; verified live 2026-10-06). The audit's "router and enrichment open" is therefore true for `main` only.
- **Found today:** the build instance's MISP has **0 of 225** warninglists enabled (`misp-config.sh` never run here; Diego's: 215), R-22/R-23. `n8n-import.sh` can fail to activate a workflow whose sub-workflow comes later alphabetically when the sub-workflows were deactivated first (`lib-enrich-observable` → `lib-thehive-tag-observable`, then `pb-generic`); a plain retry activated both (R-25).
- **Still as in the audit:** Grafana stalled, C14 design due 10-16, C9–C14 not built, Cortex memory (R-21).
