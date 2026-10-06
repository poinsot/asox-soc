# Rule tests

`run.sh` checks the Wazuh ruleset against sample log lines, using the running manager's `wazuh-logtest`. It needs `core` up (`scripts/soc.sh up core`), and doesn't need a manager restart.

```bash
nodes/core/wazuh/tests/run.sh             # copy rules/ and decoders/ into the manager, then test everything
nodes/core/wazuh/tests/run.sh sshd        # only cases whose file or name contains "sshd"
nodes/core/wazuh/tests/run.sh --no-sync   # test what the manager already has
```

It prints one `PASS`/`FAIL` line per check and exits 1 if any check fails. The checks are:

1. **The ruleset loads** (`wazuh-analysisd -t`) with no errors, and with no rule dropped because its `if_sid` parent wasn't found. That happens when a file depends on a file that sorts after it; see the README, "Rules: ID plan, files and groups".
2. **Each case** in `cases/*.cases` produces the rule it expects.

The copy into the manager has no effect until the next restart: `wazuh-logtest` reads the rule files for each session, but the running analysis engine doesn't. A `WARN` line means a file is in the manager but not in the repo, so it was removed or renamed without the manual `rm` (README, "Removing or renaming a file").

## Writing cases

One file per rule file, named after it: `cases/1002-linux-auth.cases` tests `rules/1002-linux-auth.xml`. `builtin-linux.cases` pins the built-in rules our scenarios and n8n rely on, so a Wazuh upgrade that changes them shows up here.

```text
# comment
case sshd brute force (8 failures)
expect rule=5763 level=10 groups=sshd,authentication_failures decoder=sshd
repeat 8 Oct  5 10:00:01 lab-agent sshd[1234]: Failed password for root from 203.0.113.10 port 4242 ssh2

case a line that must not alert
expect rule=none
log Oct  5 10:00:00 lab-agent asox-test: ASOX_TEST id=1
```

| Line | Meaning |
|---|---|
| `case <name>` | Starts a case. All its lines go through one logtest session, so frequency rules see the earlier lines. |
| `expect rule=<id> [level=<n>] [groups=<a,b>] [decoder=<name>]` | Some event of the session must match this rule. Its level and decoder must be equal, and it must carry every listed group (other groups are allowed). `rule=none` means no event may produce an alert. |
| `log <line>` | One log line, exactly as the agent or syslog would send it. |
| `repeat <n> <line>` | The same line `n` times. |

"Some event" rather than "the last event": a frequency rule fires on the event that reaches the count and is then quiet for its `ignore` time, so a later line shows the single-event rule again.

Use attacker addresses from documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`), like the lab scenarios (n8n memo item 7).
