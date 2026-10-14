# Request: warninglist names in the observable's description, not one tag per list (C10)

**To:** Inigo (@poinsot), n8n owner; cc Park, TheHive owner (question G)
**From:** Diego (@DiegoGuerraA00835430), Cortex + MISP owner
**Date:** 2026-10-14
**Refs:** C10, N8N-2.11, question G (`nodes/cases/thehive/docs/reply-n8n-2026-10-14.md`), ALERT-FORMAT §5
**Status:** proposal, tested on my `full` instance; nothing committed in your files

Hi Inigo,

C10 works well. Thanks! I ran it on a fresh `full` instance today: C1–C8 and C10 pass, and the demo alert gets its tags. One thing for the analyst, though: in TheHive's observable list, the `warninglist:<list name>` tags are cut off after ~25 characters ("warninglist:List of known IPv4 p…"). They push the useful tags (`asox:verdict=…`, `src`/`dst`) onto a second line behind "Show more", and only 3 of the lists are shown (`github.com` matches 17).

## Proposal

- **Tags:** keep only the single `warninglist` tag. It's still filterable, and `skip_online_analyzers` still works on it.
- **Description:** put **every** matching list's full name in the observable's description (TheHive's observable `message`). It shows when the analyst opens the observable, and it's searchable:

  ```
  On MISP warninglists (common, not safe):
  - List of known IPv4 public DNS resolvers
  - Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters
  ```

The meaning doesn't change: a match is still *common, not safe*. `ioc`, severity and status are untouched (D12), and on a duplicate alert nothing is written, as today.

## Tested (2026-10-14, `full`, standard profile, branch `cortex-misp` = `main` + my MISP changes)

I re-imported the patched workflows with `scripts/n8n-import.sh`, then ran `replay.sh --fresh-id --file synthetic/100100-warninglist-demo.json`, and read the result back from TheHive's API:

| Observable | Tags | Description |
|---|---|---|
| `8.8.8.8` | `src`, `warninglist` | public DNS resolvers; vpn-ipv4 datacenters |
| `185.220.101.1` | `dst`, `warninglist` | Tor exit nodes; vpn-ipv4 datacenters |
| `github.com` | `warninglist` | 17 lists (LOTS, security vendor blogs, DigitalSide, Cloudflare/Umbrella/Tranco/Majestic/Alexa/Moz top sites) |
| `lab-agent`, `172.18.0.7` | `agent` (+ `range:internal`) | none (skipped, as before) |

All 23 workflows imported and active. I didn't re-run C1–C10 after the patch.

## What to change (your files)

The whole patch is four code strings in three workflow files. Here is the readable version.

**1. `lib-config.json`, node "Config", `misp_warninglist`:**

```js
    list_tag_prefix: 'warninglist:',
    max_list_tags: 0,                 // was 3
    // Every matching list's full name goes in the observable's description
    // (message) instead of one tag per list.
    lists_in_message: true,
```

With `max_list_tags: 0` the `prefer` order no longer picks tags, but it still sorts the description (public DNS and Tor exit first). Setting `lists_in_message: false` and `max_list_tags: 3` gives today's behaviour back.

**2. `lib-misp-warninglist.json`, `applyMatches` in node "Result"** (and the same copy in "Select values", to keep the two identical):

```js
    const addTags = wanted.filter((t) => !o.tags.includes(t));
    matches.push({ dataType: o.dataType, data: o.data, lists, add_tags: wanted });
    // Every list's full name in the observable's description (TheHive shows it
    // when the observable is opened), so the tags can stay short.
    if (!w.lists_in_message) return { ...o, tags: [...o.tags, ...addTags] };
    const note = `On MISP warninglists (common, not safe):\n${lists.map((n) => `- ${n}`).join('\n')}`;
    return { ...o, tags: [...o.tags, ...addTags], message: o.message ? `${o.message}\n\n${note}` : note };
```

**3. `lib-thehive-upsert-alert.json`, node "Build alert":** pass `message` through. Today only `dataType, data, tags, ioc` reach TheHive's body:

```js
const observables = ex.observables.map(({ dataType, data, tags, ioc, message }) => (
  message ? { dataType, data, tags, ioc, message } : { dataType, data, tags, ioc }));
```

**4. Docs that describe the per-list tags:**
- **Yours:** `nodes/core/n8n/README.md` ("Warninglist check": Tags, Settings), `nodes/core/n8n/docs/ALERT-TO-THEHIVE.md` (lines 96 and 182, question G), `nodes/core/n8n/BACKLOG.md` (line 30, the tag-names row).
- **Park's:** `nodes/cases/thehive/docs/ALERT-FORMAT.md` (§5, line 111, and line 140).
- **Mine:** I'll update `nodes/intel/misp/C10-handoff-n8n.md` (suggested tags, expected result) once you agree.

The writeback comment doesn't need a change. It already names the lists per value (at most 10, then "+N more"), and its "tagged …" part will simply show `warninglist` alone.

## Questions

1. **For you:** OK to take this as is, or would you rather cap the description (e.g. the first 5 lists, then "+12 more" for `github.com`)? I'm fine either way.
2. **For Park:** this changes answer G. The `warninglist` tag stays; the `warninglist:<list name>` tags go. Does TRIAGE.md need a line saying "open the observable to see which lists"?

There's no deadline on this: it's a presentation change, not a contract change (C10's call and Read Only key are unchanged). Whenever it suits your next n8n PR.

Thanks!
Diego
