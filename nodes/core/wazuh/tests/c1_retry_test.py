"""C1 retry logic of integrations/custom-n8n.py (X-10), against a stub HTTP
server that answers a scripted list of status codes. Runs inside the manager
container with Wazuh's bundled Python; started by tests/c1-retry.sh.
One PASS/FAIL line per case; exit 1 if any fails."""
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

SCRIPT = sys.argv[1]
PY = sys.executable
work = tempfile.mkdtemp(prefix="c1-retry-")
MARK = os.path.join(work, "custom-n8n.down")
ALERT = os.path.join(work, "alert.json")
with open(ALERT, "w") as f:
    json.dump({"id": "c1-retry-test", "rule": {"id": "100100", "level": 10}}, f)

codes, hits = [], []


class Stub(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        hits.append(self.headers.get("X-ASOX-Token"))
        code = codes.pop(0) if codes else 200
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b'{"status":"queued"}' if code == 200 else b"{}")

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=server.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{server.server_address[1]}/webhook/wazuh-alert"
with socket.socket() as s:            # a port with nothing listening
    s.bind(("127.0.0.1", 0))
    DEAD = f"http://127.0.0.1:{s.getsockname()[1]}/webhook/wazuh-alert"

env = dict(os.environ, ASOX_C1_MARK=MARK, ASOX_C1_WAITS="0.1,0.1,0.1,0.1",
           ASOX_C1_LOG=os.path.join(work, "integrations.log"))
fails = 0


def run(url, retries=4, extra=None):
    # Exactly what integratord passes without debug (v4.14.8): alert, key, url,
    # "" (debug), "" (options), timeout, retries, and the literal redirection.
    args = ([PY, SCRIPT, ALERT, "token-test", url, "", "", "2", str(retries), "> /dev/null 2>&1"]
            if extra is None else [PY, SCRIPT, *extra])
    return subprocess.run(args, env=env).returncode


def case(name, script_codes, want_rc, want_hits, want_mark, url=None, pre_mark=False, **kw):
    global fails
    codes[:] = list(script_codes)
    hits.clear()
    if pre_mark:
        open(MARK, "w").close()
    elif os.path.exists(MARK):
        os.remove(MARK)
    rc = run(url or URL, **kw)
    got = (rc, len(hits), os.path.exists(MARK))
    want = (want_rc, want_hits, want_mark)
    ok = got == want if want_hits is not None else (rc, os.path.exists(MARK)) == (want_rc, want_mark)
    print(f"{'PASS' if ok else 'FAIL'}  {name} (exit {rc}, {len(hits)} request(s), mark {'set' if got[2] else 'clear'})")
    fails += not ok


case("200: delivered at once", [200], 0, 1, False)
case("404, 404, 200: retried until delivered", [404, 404, 200], 0, 3, False)
case("503 x5: chain exhausted, fast-fail mark set", [503] * 5, 1, 5, True)
case("mark set + 500: one try only", [500], 1, 1, True, pre_mark=True)
case("mark set + 200: delivered, mark cleared", [200], 0, 1, False, pre_mark=True)
case("403 (token): final, not retried", [403], 1, 1, False)
case("422 (bad JSON): final, not retried", [422], 1, 1, False)
case("connection refused, retries 1: two tries, mark set", [], 1, None, True, url=DEAD, retries=1)
case("no timeout/retries arguments: one try", [500, 200], 1, 1, False,
     extra=[ALERT, "token-test", URL])
case("debug mode (no redirection argument): retries still read", [500, 200], 0, 2, False,
     extra=[ALERT, "token-test", URL, "debug", "", "2", "4"])
old = time.time() - 400                # a mark older than FAST_FAIL_SECONDS
case_name = "stale mark (>300 s) + 500, 500, 200: full chain again"
codes[:] = [500, 500, 200]
hits.clear()
open(MARK, "w").close()
os.utime(MARK, (old, old))
rc = run(URL)
ok = rc == 0 and len(hits) == 3 and not os.path.exists(MARK)
print(f"{'PASS' if ok else 'FAIL'}  {case_name} (exit {rc}, {len(hits)} request(s))")
fails += not ok

server.shutdown()
subprocess.run(["rm", "-rf", work])
print(f"\n{11 - fails} passed, {fails} failed")
sys.exit(1 if fails else 0)
