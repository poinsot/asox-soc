#!/usr/bin/env bash
# Sample documents in asox-metrics (C11) for drafting the "Desempeño y
# cumplimiento" panels (GRAF-3.x) on an instance without TheHive, where n8n
# writes no documents. Written as n8n-indexer (the only C11 writer role),
# IDs grafana-sample-NN, so they never collide with real ones (Wazuh alert
# IDs). Remove them with `clean` before a demo or a contracts check review.
# Usage: nodes/core/grafana/tests/metrics-sample.sh load|clean|count
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TESTS_DIR/../../../.." && pwd)"
instance=$(sed -n 's/^SOC_INSTANCE=//p' "$REPO_DIR/topology.env" 2>/dev/null | tail -1)
INDEXER="${instance:-asox}-core-wazuh-indexer-1"
PREFIX=grafana-sample-

if [[ $(docker inspect -f '{{.State.Running}}' "$INDEXER" 2>/dev/null) != true ]]; then
  echo "ERROR indexer container $INDEXER is not running (scripts/soc.sh up core)" >&2
  exit 2
fi
user=$(sed -n 's/^N8N_INDEXER_USER=//p' "$REPO_DIR/nodes/core/.env" | tail -1)
pass=$(sed -n 's/^N8N_INDEXER_PASSWORD=//p' "$REPO_DIR/nodes/core/.env" | tail -1)
[[ -n $user && -n $pass ]] || { echo "ERROR N8N_INDEXER_USER/PASSWORD empty in nodes/core/.env (scripts/bootstrap.sh core)" >&2; exit 2; }

# curl inside the indexer container; credentials pass through the environment,
# never on a command line or in the output.
es() { docker exec -i -e U="$user" -e P="$pass" "$INDEXER" sh -c 'curl -sk -u "$U:$P" -H "Content-Type: application/x-ndjson" "$@"' sh "$@"; }

sample_ids() {
  es "https://localhost:9200/asox-metrics/_search?size=500&_source=false&q=alert_id:${PREFIX}*" |
    python3 -c 'import json,sys; [print(h["_id"]) for h in json.load(sys.stdin)["hits"]["hits"]]'
}

case "${1:-}" in
  load)
    # Times relative to now, spread over the last 6 days. Lab alerts carry
    # t_attack_start (MTTD); acknowledged and closed ones carry t_ack,
    # t_case, t_closed and resolution (MTTA, MTTR, FP rate). t_contained stays
    # empty until C9, as in n8n's writer.
    python3 - "$PREFIX" <<'EOF' | es -X POST "https://localhost:9200/_bulk?refresh=true" --data-binary @- |
import json, random, sys
from datetime import datetime, timedelta, timezone
prefix = sys.argv[1]
random.seed(11)
now = datetime.now(timezone.utc)
iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.000Z")
# rule, level, TheHive severity, playbook, lab scenario?
rules = [
    ("5763", 10, 3, "login-bruteforce", True), ("40112", 10, 3, "suspicious-login", True),
    ("5404", 10, 3, "privilege-escalation", True), ("100211", 10, 3, "account-change", True),
    ("40501", 15, 4, "account-change", True), ("100200", 12, 4, "suspicious-login", True),
    ("108000", 12, 4, "ioc-match", True), ("100302", 7, 2, "wazuh-generic", True),
    ("86601", 7, 2, "wazuh-generic", True), ("103011", 10, 3, "login-bruteforce", False),
    ("31152", 7, 2, "wazuh-generic", False), ("550", 7, 2, "wazuh-generic", False),
]
resolutions = ["TruePositive"] * 6 + ["FalsePositive"] * 3 + ["Duplicated", "Indeterminate"]
for n in range(1, 25):
    rule, level, sev, pb, lab = rules[(n - 1) % len(rules)]
    t_event = now - timedelta(days=random.uniform(0, 6))
    t_alert = t_event + timedelta(seconds=random.uniform(2, 20))
    doc = {"alert_id": f"{prefix}{n:02d}", "thehive_alert_id": f"~sample{n:02d}",
           "rule_id": rule, "rule_level": level, "severity": sev, "playbook": pb,
           "n8n_execution_id": f"sample-{n}", "outcome": "none", "auto_promoted": False,
           "t_event": iso(t_event), "t_alert": iso(t_alert)}
    if lab and n % 4 != 0:  # some lab alerts without a marker (MTTD null)
        doc["t_attack_start"] = iso(t_event - timedelta(seconds=random.uniform(3, 90)))
    if n % 5 != 0:  # every 5th alert still New
        t_ack = t_alert + timedelta(minutes=random.uniform(1, 45))
        doc["t_ack"] = iso(t_ack)
        if n % 3 != 0:  # some acknowledged alerts still open
            if sev >= 3:
                doc["case_id"] = f"~case{n:02d}"
                doc["t_case"] = iso(t_ack + timedelta(minutes=random.uniform(1, 10)))
                doc["auto_promoted"] = sev == 4 and n % 2 == 0
            doc["t_closed"] = iso(t_ack + timedelta(minutes=random.uniform(10, 240)))
            doc["resolution"] = random.choice(resolutions)
    print(json.dumps({"index": {"_index": "asox-metrics", "_id": doc["alert_id"]}}))
    print(json.dumps(doc))
EOF
      python3 -c 'import json,sys; r=json.load(sys.stdin); bad=[i for i in r["items"] if i["index"].get("error")]; print(("FAIL " + json.dumps(bad[0]["index"]["error"])) if bad else "PASS  %d sample documents in asox-metrics (%s*)" % (len(r["items"]), sys.argv[1])); sys.exit(1 if bad else 0)' "$PREFIX"
    ;;
  clean)
    mapfile -t ids < <(sample_ids)
    if (( ${#ids[@]} == 0 )); then echo "PASS  no sample documents in asox-metrics"; exit 0; fi
    printf '%s\n' "${ids[@]}" | python3 -c 'import json,sys; [print(json.dumps({"delete":{"_index":"asox-metrics","_id":l.strip()}})) for l in sys.stdin]' |
      es -X POST "https://localhost:9200/_bulk?refresh=true" --data-binary @- |
      python3 -c 'import json,sys; r=json.load(sys.stdin); print("FAIL" if r["errors"] else "PASS  deleted %d sample documents" % len(r["items"])); sys.exit(1 if r["errors"] else 0)'
    ;;
  count)
    echo "$(sample_ids | wc -l) sample documents in asox-metrics"
    ;;
  *) echo "Usage: $0 load|clean|count" >&2; exit 2 ;;
esac
