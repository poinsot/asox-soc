# TheHive → n8n, Cortex + MISP: warninglist description, `Ignored` in C11, test IOC

**To:** Inigo (@poinsot), n8n owner; Diego (@DiegoGuerraA00835430), Cortex + MISP owner · cc Jesus (@JC-535) for C11
**From:** Park (@Jinhyuk-P), TheHive owner
**Date:** 2026-10-14
**Refs:** X-02, X-04, X-36, C10, C11; `nodes/intel/misp/request-n8n-warninglist-description.md`, `nodes/core/n8n/docs/reply-grafana-c11.md` point 3, `nodes/core/n8n/docs/ALERT-TO-THEHIVE.md` §9
**Files (branch `thehive`):** `docs/ALERT-FORMAT.md` (status, §3, §5, §7), `docs/TRIAGE.md`, `scripts/thehive-test-alert.sh`, `BACKLOG.md`

Thanks for applying A and F, and for merging the routing.

## 1. Diego's warninglist proposal: agreed (answer G revised)

- **Tags:** observables keep only the `warninglist` tag; the `warninglist:<list name>` tags go.
- **Description:** every matching list goes in the observable's description (`message`), under "On MISP warninglists (common, not safe):". **No cap needed**, as Inigo said.
- **Written in:** ALERT-FORMAT §5 and §7.
- **TRIAGE.md:** now says "open the observable to see which lists" (Diego's question 2).
- **Inigo, you can apply the patch.** Please check, as you planned, that the observable's `message` survives promotion to a case.

## 2. C11: an ignored alert always means false positive. Confirmed

- In our procedure, an analyst ignores an alert **only** when it is a false positive, including expected or authorized activity.
- Anything real or unclear is promoted or merged instead.
- TRIAGE.md now says so explicitly, with the reason (Grafana's FP rate counts every `Ignored`).
- So FP rate = (`FalsePositive` + `Ignored`) over documents with a `resolution`, as in `reply-grafana-c11.md`.
- I also agree with your proposal: no metrics document for test alerts.

## 3. ALERT-FORMAT is agreed

- **The status line now says agreed** (X-02, X-04).
- **§3 matches your routing 2026-10-14 row for row:**
  - `login-bruteforce` takes 103011, 40111 and 2502;
  - `network-scan` is active on 103000;
  - `ioc-match` stays proposed until C14 is live (rule 108000).
- §6 R2 (D-N4) still to confirm by 2026-11-03.

## 4. Test IOC (X-36): done on my side

`thehive-test-alert.sh` now uses `101.99.75.184` instead of `203.0.113.66` in its 3 scenarios. The `ioc` scenario uses rule 108000 and `portscan` uses 103000, Daniel's real IDs. TRIAGE.md's example changed too.
