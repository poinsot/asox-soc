# TheHive → Wazuh: rule groups, fields review item 6, pfSense template

**To:** Daniel (@dmelgar1110), Wazuh owner · cc Inigo (@poinsot)
**From:** Park (@Jinhyuk-P), TheHive owner
**Date:** 2026-10-08
**Refs:** W1.3, W2.5, W2.7, X-01, X-04, T2.6, T3.5; your `request-n8n-rule-groups.md` (updates 10-07, 10-08) and `request-n8n-wazuh-fields-review.md`
**Files (branch `thehive`):** `nodes/cases/thehive/docs/ALERT-FORMAT.md` §1, §3, §5; `entities/case-templates.json`

Thanks, the live alerts made this easy.

## Rule groups and IDs (W1.3): agreed

- **Your plan is agreed:** `asox` + a source group + Wazuh's standard group names, one ID range per source, and IDs that stay numeric and stable.
- **§3 is rewritten with your fixes A1–A5:**
  - `ioc-match` comes first (`misp_ioc`, 108xxx).
  - `suspicious-login` comes before `ssh-bruteforce` and matches rule IDs 40112 and 100200 only.
  - `privilege-escalation` matches `T1548`.
  - `account-change` matches `adduser` only, which covers 5901, 5902, 5904, 100211 and 100212.
  - `network-scan` matches `pfsense` + `T1046`, range 103xxx.
- **Your 10-08 rules are in:** 100200 goes to `suspicious-login`, and 100211 / 100212 go to `account-change`. The template descriptions now name them.

## Your question: pfSense `firewall_drop` / `recon`

- **`recon`** (scans and repeated blocks, with T1046) → the existing **`network-scan`** template.
- **A single `firewall_drop`** → **`wazuh-generic`**. One blocked packet isn't worth a case. If single drops reach level 7 often, please tune them below the threshold.

Please send the W4.3 rule IDs when they exist, so I can name them in the template.

## Fields review

- **Item 6:** done. When `agent.id` = `"000"`, the host in TheHive's title, `agent:` tag and `wazuh-agent-name` is `predecoder.hostname`, and its IP comes from `location` (§1, §4, §5).
- **Items 3–4:**
  - sshd: the account present → `target`.
  - sudo: `srcuser` → `src`, `dstuser` → `target`.
  - 5901: no `user-account`.
- **Item 5:** the sudo command, pwd and tty go in the description.
- **SCA:** with your W2.7 tuning, TheHive needs no compliance template. The few SCA regressions that still pass go to `wazuh-generic`.

## Next on my side

I'll use `trigger.sh --scenario` in `full` mode for TheHive's end-to-end test (T3.4): ssh-bruteforce first, then the others.
