#!/usr/bin/env bash
# Lint the n8n workflow files against the conventions of
# nodes/core/n8n/README.md (owner: n8n, N8N-0.7). Static checks on the JSON
# only: no containers, no n8n, no secrets read (needs bash and python3, the
# standard library only).
#
# Usage: nodes/core/n8n/scripts/lint-workflows.sh [options]
#   -f, --file PATH   lint this workflow file (repeatable)
#   -d, --dir DIR     lint every *.json in DIR (default: nodes/core/n8n/workflows)
#   -h, --help        show this help
# Rules (README "Workflow lint"):
#   a  valid JSON, n8n export shape, name = file name, name prefix
#      (recv-, pb-, lib-, sched-, chk-), unique 16-character IDs (listed
#      exceptions: ID_LENGTH_EXCEPTIONS), sub-workflow
#      and error-workflow IDs that exist
#   b  header sticky note with Trigger, Inputs, Actions taken, Systems changed,
#      Approval and Owner
#   c  credentials by ID, only the IDs bootstrap creates (scripts/lib/n8n.sh),
#      matching type; webhooks behind a webhook-token credential; TLS setting
#      per credential (MISP ignores SSL issues, the indexer never does)
#   d  no hardcoded secrets (auth headers, Bearer/Basic values, JWTs, private
#      keys, secret $env names) in parameters, notes, pinData or staticData
#   e  no hardcoded hosts: URLs from the documented $env URL variables
#   f  no pinData
#   g  error workflow recv-n8n-error on recv-*/pb-*, never on lib-*; lib-*
#      save failed executions only, recv-*/pb-*/chk-* every execution;
#      lib-*/pb-* active
# Files given with --file are checked against the IDs of the workflow
# directory too (references, duplicate IDs), so a copy elsewhere can be linted.
# One line per finding (FAIL, or WARN for judgement calls), PASS per clean
# file, then a summary line. Exit code 1 on any FAIL, 2 on usage errors.
set -euo pipefail

LINT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$LINT_DIR/../../../../scripts/lib/common.sh"

WORKFLOW_DIR="$REPO_ROOT/nodes/core/n8n/workflows"
CREDENTIALS_FILE="$REPO_ROOT/scripts/lib/n8n.sh"

usage() { print_usage "$0"; }
usage_error() { printf 'ERROR %s\n' "$*" >&2; usage >&2; exit 2; }

files=() dirs=()
while (( $# > 0 )); do
  case $1 in
    -f|--file) (( $# >= 2 )) || usage_error "$1 needs a path"; files+=("$2"); shift 2 ;;
    -d|--dir) (( $# >= 2 )) || usage_error "$1 needs a directory"; dirs+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown option: $1" ;;
  esac
done
(( ${#files[@]} + ${#dirs[@]} > 0 )) || dirs=("$WORKFLOW_DIR")
for d in "${dirs[@]}"; do
  [[ -d $d ]] || usage_error "no such directory: $d"
  dir_files=("$d"/*.json)
  [[ -f ${dir_files[0]} ]] || usage_error "no *.json files in $d"
  files+=("${dir_files[@]}")
done
for f in "${files[@]}"; do [[ -f $f ]] || usage_error "no such file: $f"; done
command -v python3 >/dev/null || die "python3 not found"

out=$(python3 - "$REPO_ROOT" "$WORKFLOW_DIR" "$CREDENTIALS_FILE" "${files[@]}" <<'PY'
import json, os, re, sys

repo, wf_dir, cred_file, files = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]

PREFIXES = ("recv", "pb", "lib", "sched", "chk")
HEADER_FIELDS = ("Trigger", "Inputs", "Actions taken", "Systems changed", "Approval", "Owner")
STICKY = "n8n-nodes-base.stickyNote"
ERROR_WORKFLOW = "recv-n8n-error"
# Documented $env variables (README "Credentials, URLs and secrets").
URL_VARS = {"WAZUH_API_URL", "THEHIVE_URL", "CORTEX_URL", "MISP_URL", "WAZUH_INDEXER_URL", "N8N_WEBHOOK_URL"}
ENV_VARS = URL_VARS | {"WAZUH_ALERT_MIN_LEVEL", "THEHIVE_ENABLED"}
WEBHOOK_CREDS = {"asoxWebhookToken", "asoxWebhookBear1"}
BEARER_WEBHOOKS = {"recv-thehive-event"}  # TheHive can't send X-ASOX-Token (D43)
MISP_CRED, INDEXER_CRED = "asoxMispApi00001", "asoxIndexerN8n01"
# Execution saving (N8N-6.5, N8N-1.4): documented exceptions only.
SAVE_SUCCESS = {"lib-alert-queue-drain": "all", "sched-alert-queue": "none"}
# Entry points without the error workflow, kept as WARN until decided (none:
# recv-n8n-start got it on 2026-10-15).
NO_ERROR_WORKFLOW_WARN = {}
# Workflow IDs allowed to differ from n8n's 16 letters or digits (rule a).
# Renaming one changes every Execute Workflow reference to it and the workflow
# on each live instance, so known ones are accepted here, with the reason.
ID_LENGTH_EXCEPTIONS = {
    "asoxLibThTagObs": "lib-thehive-tag-observable, 15 characters; renaming it would change "
                       "its callers' references and the workflow on the live instances",
}
# IPv4 literals that are data, not hosts (rule e); anything else is a WARN.
IP_ALLOWED = {
    ("chk-misp-api", "8.8.8.8"): "C10 check value",
    ("lib-config", "101.99.75.184"): "MISP seed IOC (X-36)",
    ("lib-config", "203.0.113.66"): "former seed IOC, a comment",
}
HOST_PATTERNS = [
    re.compile(r"\b[a-z][a-z0-9+.-]*://[A-Za-z0-9\[][^\s/'\"`{}<>]*"),  # a literal URL
    re.compile(r"\b(?:localhost|host\.docker\.internal)\b"),
    re.compile(r"\bwazuh[.-](?:manager|indexer|dashboard)\b"),
    re.compile(r"\b(?:thehive|cortex|misp|n8n|grafana|elasticsearch|cassandra)(?:-[a-z0-9]+)*:\d{2,5}\b"),
]
IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\d.])")
ENV_REF = re.compile(r"(?:\$env\.|\$env\[\s*['\"]|process\.env\.)([A-Za-z_][A-Za-z0-9_]*)")
SECRET_NAME = re.compile(r"(?:_KEY|_PASSWORD|_TOKEN|_SECRET|_FILE)$|^(?:PASSWORD|TOKEN|SECRET)$")
AUTH_HEADER = re.compile(r"^(?:authorization|proxy-authorization|x-asox-token|x-api-key|api[-_]?key|apikey|token|password|cookie)$", re.I)
SECRET_PATTERNS = [
    (re.compile(r"\b(?:Bearer|Basic)\s+(?!\{\{)[A-Za-z0-9._~+/=-]{16,}"), "literal Bearer/Basic credential"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), "JSON Web Token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
]
SECRET_ASSIGN = re.compile(r"""\b(?:password|passwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token)\b['"]?\s*[:=]\s*['"]([^'"\s{}$`]{8,})['"]""", re.I)
LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9+/=_-])")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

results = []  # (level, file, rule, message)

def rel(p):
    a = os.path.abspath(p)
    return os.path.relpath(a, repo) if a.startswith(repo + os.sep) else p

def add(level, f, rule, msg):
    results.append((level, rel(f), rule, msg))

def strings(obj, path=""):
    """Yield (path, string) for every string in obj, keys excluded."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from strings(v, f"{path}[{i}]")

def dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from dicts(v)

def is_expression(v):
    return isinstance(v, str) and v.startswith("=") and "{{" in v

def load(f):
    try:
        with open(f, encoding="utf-8") as fh:
            return json.load(fh), None
    except Exception as e:  # noqa: BLE001 - any parse error is a finding
        return None, str(e)

# Credentials bootstrap creates: the source of truth for IDs, names and types.
creds = {}
try:
    with open(cred_file, encoding="utf-8") as fh:
        for m in re.finditer(r'\{id: "([^"]+)", name: "([^"]+)", type: "([^"]+)"', fh.read()):
            creds[m.group(1)] = (m.group(2), m.group(3))
except OSError:
    pass

# The workflow directory: context for references and duplicate IDs.
context = {}  # id -> (name, basename)
for name in sorted(os.listdir(wf_dir)) if os.path.isdir(wf_dir) else []:
    if name.endswith(".json"):
        data, _ = load(os.path.join(wf_dir, name))
        if isinstance(data, dict) and isinstance(data.get("id"), str):
            context[data["id"]] = (data.get("name"), name)

loaded = []
for f in files:
    data, err = load(f)
    if err is not None:
        add("FAIL", f, "a/json", f"not valid JSON: {err}")
        continue
    if not (isinstance(data, dict) and data.get("id") and data.get("name") and isinstance(data.get("nodes"), list)):
        add("FAIL", f, "a/shape", "not an n8n workflow export (needs id, name, nodes)")
        continue
    loaded.append((f, data))

known = {i: n for i, (n, _) in context.items()}
known.update({d["id"]: d["name"] for _, d in loaded})
error_wf_id = next((i for i, n in known.items() if n == ERROR_WORKFLOW), None)

if not creds:
    add("FAIL", cred_file, "c/credential", "no credential list found (expected {id: ..., name: ..., type: ...} entries)")

seen_ids = {}
for f, d in loaded:
    wid, wname, base = d["id"], d["name"], os.path.basename(f)
    seen_ids.setdefault(wid, []).append(f)
    prefix = wname.split("-", 1)[0]
    nodes = [n for n in d["nodes"] if isinstance(n, dict)]
    settings = d.get("settings") or {}

    # a: naming and IDs
    if base != wname + ".json":
        add("FAIL", f, "a/name", f'workflow name "{wname}" does not match the file name {base}')
    if not re.fullmatch(r"(?:%s)-[a-z0-9]+(?:-[a-z0-9]+)*" % "|".join(PREFIXES), wname):
        add("FAIL", f, "a/prefix", f'name "{wname}" must be <kind>-<lowercase-words>, kind one of {", ".join(p + "-" for p in PREFIXES)}')
    if not re.fullmatch(r"[A-Za-z0-9]{16}", str(wid)) and wid not in ID_LENGTH_EXCEPTIONS:
        add("WARN", f, "a/id", f'ID "{wid}" is not 16 letters or digits like n8n\'s own (README "Sub-workflows"); n8n accepts it')
    other = context.get(wid)
    if other and other[1] != base:
        add("FAIL", f, "a/id-unique", f'ID "{wid}" is also used by {other[1]} in the workflow directory')
    for n in nodes:
        if n.get("type") == "n8n-nodes-base.executeWorkflow":
            ref = (n.get("parameters") or {}).get("workflowId")
            val = ref.get("value") if isinstance(ref, dict) else ref
            if not isinstance(val, str) or not val:
                add("FAIL", f, "a/reference", f'node "{n.get("name")}": no workflow ID (reference sub-workflows by ID)')
            elif val.startswith("="):
                pass  # chosen at run time (README: lib-alert-queue-drain's Playbook (by route))
            elif val not in known:
                add("FAIL", f, "a/reference", f'node "{n.get("name")}": calls unknown workflow ID "{val}"')
            elif isinstance(ref, dict) and ref.get("cachedResultName") not in (None, known[val]):
                add("WARN", f, "a/reference", f'node "{n.get("name")}": cached name "{ref.get("cachedResultName")}" but ID "{val}" is {known[val]}')
    ew = settings.get("errorWorkflow")
    if ew and ew not in known:
        add("FAIL", f, "a/reference", f'error workflow ID "{ew}" is not a known workflow')

    # b: header note
    notes = [str((n.get("parameters") or {}).get("content", "")) for n in nodes if n.get("type") == STICKY]
    if not notes:
        add("FAIL", f, "b/header-note", "no sticky note (header note with " + ", ".join(HEADER_FIELDS) + ")")
    else:
        best, best_missing, empty = None, None, []
        for text in notes:
            missing = [h for h in HEADER_FIELDS if not re.search(r"\*\*%s\s*:?\s*\*\*\s*:?" % re.escape(h), text, re.I)]
            if best is None or len(missing) < len(best_missing):
                best, best_missing = text, missing
        if best_missing:
            add("FAIL", f, "b/header-note", "header note misses " + ", ".join(best_missing))
        else:
            for h in HEADER_FIELDS:
                m = re.search(r"\*\*%s\s*:?\s*\*\*\s*:?([^\n]*)" % re.escape(h), best, re.I)
                if m and not m.group(1).strip():
                    empty.append(h)
            if empty:
                add("WARN", f, "b/header-note", "header note field(s) with nothing on the same line: " + ", ".join(empty))

    # c: credentials, webhook auth, TLS per credential
    for n in nodes:
        nname, ntype = n.get("name"), n.get("type")
        cr = n.get("credentials") or {}
        ids = set()
        for ctype, ref in (cr.items() if isinstance(cr, dict) else []):
            cid = ref.get("id") if isinstance(ref, dict) else None
            if not cid:
                add("FAIL", f, "c/credential", f'node "{nname}": credential {ctype} has no id (reference credentials by ID)')
                continue
            ids.add(cid)
            if creds and cid not in creds:
                add("FAIL", f, "c/credential", f'node "{nname}": credential ID "{cid}" is not created by bootstrap (scripts/lib/n8n.sh)')
            elif cid in creds:
                cname, want = creds[cid]
                if ctype != want:
                    add("FAIL", f, "c/credential", f'node "{nname}": credential "{cid}" used as {ctype}, bootstrap creates it as {want}')
                if isinstance(ref, dict) and ref.get("name") != cname:
                    add("WARN", f, "c/credential", f'node "{nname}": credential "{cid}" named "{ref.get("name")}", bootstrap names it "{cname}" (n8n resolves the ID)')
        params = n.get("parameters") or {}
        if ntype == "n8n-nodes-base.webhook":
            if params.get("authentication") != "headerAuth" or not ids & WEBHOOK_CREDS:
                add("FAIL", f, "c/webhook-auth", f'webhook "{nname}": needs Header Auth with "ASOX webhook token" (D36)')
            elif "asoxWebhookBear1" in ids and wname not in BEARER_WEBHOOKS:
                add("WARN", f, "c/webhook-auth", f'webhook "{nname}": Bearer token credential, documented only for webhooks TheHive calls')
        insecure = bool((params.get("options") or {}).get("allowUnauthorizedCerts"))
        if INDEXER_CRED in ids and insecure:
            add("FAIL", f, "c/tls", f'node "{nname}": "Ignore SSL Issues" on the Wazuh indexer, whose certificate is verified')
        if MISP_CRED in ids and not insecure:
            add("FAIL", f, "c/tls", f'node "{nname}": MISP call without "Ignore SSL Issues" (self-signed certificate)')

    # d, e: secrets and hosts in parameters, notes, pinData, staticData
    scopes = []
    for n in nodes:
        sticky = n.get("type") == STICKY
        scopes.append((f'node "{n.get("name")}"', n.get("parameters") or {}, sticky))
        if n.get("notes"):
            scopes.append((f'node "{n.get("name")}" notes', n.get("notes"), True))
    scopes.append(("pinData", d.get("pinData") or {}, False))
    scopes.append(("staticData", d.get("staticData") or {}, False))
    for where, obj, is_doc in scopes:
        for dct in dicts(obj):
            hname, hval = dct.get("name"), dct.get("value")
            if isinstance(hname, str) and AUTH_HEADER.match(hname.strip()) and isinstance(hval, str) and hval.strip() and not is_expression(hval):
                add("FAIL", f, "d/secret", f'{where}: header/parameter "{hname}" has a literal value (use a credential)')
        for path, s in strings(obj):
            loc = f"{where} {path}".rstrip()
            for rx, what in SECRET_PATTERNS:
                if rx.search(s):
                    add("FAIL", f, "d/secret", f"{loc}: {what}")
            for m in SECRET_ASSIGN.finditer(s):
                add("WARN", f, "d/secret", f"{loc}: literal value assigned to a secret-like key (check it is not a secret)")
            for m in ENV_REF.finditer(s):
                var = m.group(1)
                if SECRET_NAME.search(var):
                    add("FAIL", f, "d/secret", f"{loc}: reads secret variable ${var} from the environment (D37: credentials only)")
                elif var not in ENV_VARS and not is_doc:
                    add("WARN", f, "e/host", f"{loc}: $env.{var} is not one of the documented variables")
            if not is_doc:
                for m in LONG_TOKEN.finditer(s):
                    t = m.group(0)
                    if not UUID.match(t) and re.search(r"[a-z]", t) and re.search(r"[A-Z]", t) and re.search(r"\d", t) and not re.search(r"[a-z]{6}", t):
                        add("WARN", f, "d/secret", f"{loc}: long random-looking string (check it is not a key)")
            if is_doc:
                continue
            for rx in HOST_PATTERNS:
                m = rx.search(s)
                if m:
                    add("FAIL", f, "e/host", f'{loc}: hardcoded host "{m.group(0)}" (use the $env URL variables)')
                    break
            for m in IPV4.finditer(s):
                ip, cidr = m.group(1), m.group(2)
                if cidr or (wname, ip) in IP_ALLOWED or not all(int(o) <= 255 for o in ip.split(".")):
                    continue
                add("WARN", f, "e/host", f"{loc}: IP literal {ip} (a host? use the $env URL variables; data values go in the allow list)")
    for n in nodes:
        url = (n.get("parameters") or {}).get("url") if n.get("type") == "n8n-nodes-base.httpRequest" else None
        if isinstance(url, str) and not re.match(r"=\{\{\s*\$env\.(%s)\s*\}\}" % "|".join(sorted(URL_VARS)), url):
            add("WARN", f, "e/host", f'node "{n.get("name")}": URL does not start with a documented $env URL variable')

    # f: no pinned data
    if d.get("pinData"):
        add("FAIL", f, "f/pindata", "pinData is not empty (pinned data can hold real alert bodies; unpin and export again)")

    # g: error workflow, execution saving, active
    if prefix in ("recv", "pb") and wname != ERROR_WORKFLOW:
        if not ew:
            if wname in NO_ERROR_WORKFLOW_WARN:
                add("WARN", f, "g/error-workflow", f"no error workflow: {NO_ERROR_WORKFLOW_WARN[wname]}")
            else:
                add("FAIL", f, "g/error-workflow", f"entry point without the error workflow {ERROR_WORKFLOW} (A77, N8N-6.1)")
        elif error_wf_id and ew != error_wf_id:
            add("FAIL", f, "g/error-workflow", f'error workflow "{ew}" is not {ERROR_WORKFLOW} ({error_wf_id})')
    if prefix == "lib" and ew:
        add("FAIL", f, "g/error-workflow", "lib-* must not set an error workflow (each error would be reported twice, N8N-6.1)")
    want_success = SAVE_SUCCESS.get(wname, {"lib": "none", "recv": "all", "pb": "all", "chk": "all"}.get(prefix))
    if want_success:
        got_s, got_e = settings.get("saveDataSuccessExecution"), settings.get("saveDataErrorExecution")
        if got_s != want_success or got_e != "all":
            add("FAIL", f, "g/saving", f'saveDataSuccessExecution "{got_s}", saveDataErrorExecution "{got_e}"; expected "{want_success}" and "all" (N8N-6.5)')
    if prefix in ("lib", "pb") and d.get("active") is not True:
        add("FAIL", f, "g/active", 'lib-*/pb-* must keep "active": true (n8n runs only published sub-workflows)')

for wid, fs in seen_ids.items():
    if len(fs) > 1:
        for f in fs:
            add("FAIL", f, "a/id-unique", f'ID "{wid}" is used by {len(fs)} files: ' + ", ".join(os.path.basename(x) for x in fs))

flagged = {r[1] for r in results}
for f in files:
    if rel(f) not in flagged:
        print("PASS  lint " + rel(f))
for level, f, rule, msg in results:
    print(f"{level}  lint {f} [{rule}]: {msg}")
nf = sum(1 for r in results if r[0] == "FAIL")
nw = sum(1 for r in results if r[0] == "WARN")
print(f"....  lint: {len(files)} file(s), {nf} FAIL, {nw} WARN")
PY
) || die "lint crashed"
printf '%s\n' "$out"
FAILURES=$(grep -c '^FAIL' <<<"$out" || true)
finish
