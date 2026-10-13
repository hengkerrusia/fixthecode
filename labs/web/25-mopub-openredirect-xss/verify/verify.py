#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 25.

Rantai: MoPub login open redirect -> XSS via javascript: URI (H1 #683298).

  1. Open redirect: POST /login (kredensial valid) menerima parameter `next`
     tanpa validasi.
  2. Sink client-side: server membalas halaman dengan
     <script>window.location.href = "<next>";</script>.
  3. Skema javascript:: browser mengeksekusi URI javascript: yang di-assign
     ke window.location.href -> XSS di sesi korban.

Eksekusi JS dibuktikan dengan service `browser` (headless Chromium +
shim POST /render): exploit mem-post HTML halaman redirect ke shim dan
memeriksa marker di DOM hasil render. Tanpa WebSocket/CDP, tanpa
dependency di host.

Alur:
  FASE 1 (pristine): bangun lab, pastikan
      - GET / -> 200, GET /login -> 200 (form), GET /dashboard -> 200
      - POST /login kredensial salah -> 401
      - POST /login demo/demo123 next=/dashboard -> 200 + redirect JS
      - browser shim: POST /render -> 200 + dom
      - serangan referensi (health): solutions/exploit.py -> MARKER
      - exploit/exploit.py milik learner -> STATUS 200, NEXT javascript:,
        RENDERED true, MARKER == MOPUB-XSS-OK
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - POST /login next=javascript:... -> 400 (gerbang fix, fail-closed)
      - serangan referensi GAGAL: tidak ada MARKER
      - fungsi normal utuh: next=/dashboard redirect benar, 401 tetap,
        halaman lain 200

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/app/app.py identik byte-per-byte dengan app/app.py -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum diisi).
"""
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlencode, urlsplit

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = "127.0.0.1"
APP_PORT, BROWSER_PORT = 8080, 8081
MARKER = "MOPUB-XSS-OK"
JS_PAYLOAD = "javascript:document.title='%s'" % MARKER
PASS, FAIL = "LULUS", "GAGAL"
results = []


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    results.append((name, ok))
    log("  [%s] %s%s" % (PASS if ok else FAIL, name,
                         " -- " + detail if detail else ""))
    return ok


def run_compose(args):
    cmd = ["docker", "compose"] + args
    p = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True, text=True,
                       timeout=900)
    if p.returncode != 0:
        log("perintah gagal: %s\n%s" % (" ".join(cmd), p.stderr[-2000:]))
        sys.exit(1)
    return p


def req(port, method, path, body=None, ctype=None, timeout=15):
    c = HTTPConnection(HOST, port, timeout=timeout)
    try:
        headers = {}
        if body is not None:
            headers["Content-Type"] = ctype or "application/octet-stream"
            headers["Content-Length"] = str(len(body))
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        c.close()


def post_login(username, password, nxt):
    body = urlencode({"username": username, "password": password,
                      "next": nxt}).encode()
    return req(APP_PORT, "POST", "/login", body,
               "application/x-www-form-urlencoded")


def render(html):
    body = json.dumps({"html": html}).encode()
    return req(BROWSER_PORT, "POST", "/render", body, "application/json",
               timeout=120)


def run_exploit(path):
    p = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, timeout=180,
                       cwd=os.path.dirname(path))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m = {}
    for key in ("STATUS", "NEXT", "MARKER"):
        r = re.search(r"^%s:\s*(\S+)\s*$" % key, out, re.MULTILINE)
        m[key] = r.group(1) if r else None
    m["RENDERED"] = bool(re.search(r"^RENDERED:\s*true\s*$", out,
                                  re.MULTILINE | re.IGNORECASE))
    return m


def wait_up(timeout=240):
    log("menunggu lab siap di %s:%d/%d ..." % (HOST, APP_PORT, BROWSER_PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body = req(APP_PORT, "GET", "/")
            if st != 200 or "Publisher Portal" not in body:
                raise OSError("app belum siap")
            st, out = render("<html><head><title>t</title></head></html>")
            if st == 200 and "<title>t</title>" in json.loads(out)["dom"]:
                return True
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(3)
    return False


def compose_down():
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    log("== bersih-bersih container lama ==")
    compose_down()

    # ---------------- FASE 1 ----------------
    log("== FASE 1: membangun lab PRISTINE (rentan) ==")
    run_compose(["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    st, body = req(APP_PORT, "GET", "/")
    check("baseline: GET / -> 200", st == 200, "dapat %s" % st)
    st, body = req(APP_PORT, "GET", "/login?next=/dashboard")
    check("baseline: GET /login -> 200 + form",
          st == 200 and "<form" in body, "dapat %s" % st)
    st, _ = req(APP_PORT, "GET", "/dashboard")
    check("baseline: GET /dashboard -> 200", st == 200, "dapat %s" % st)
    st, _ = post_login("demo", "salah", "/dashboard")
    check("baseline: login salah -> 401", st == 401, "dapat %s" % st)
    st, body = post_login("demo", "demo123", "/dashboard")
    check("baseline: login benar next=/dashboard -> 200 + redirect JS",
          st == 200 and 'window.location.href = "/dashboard"' in body,
          "dapat %s" % st)

    log("== [HEALTH] serangan referensi: open redirect -> javascript: XSS ==")
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    rc, out, err = run_exploit(exp)
    m = parse_exploit_output(out)
    ok_ref = rc == 0 and m["STATUS"] == "200" and m["RENDERED"] and \
        m["MARKER"] == MARKER
    check("serangan referensi: MARKER di DOM hasil render",
          ok_ref, "dapat rc=%s marker=%r" % (rc, m["MARKER"]))
    if not ok_ref:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        log("stdout: %s" % out[-1500:])
        log("stderr: %s" % (err[-1500:] if err else "-"))
        compose_down()
        sys.exit(1)

    log("== FASE 1: menjalankan exploit/exploit.py milik learner ==")
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    rc, out, err = run_exploit(exp)
    if "NotImplementedError" in err:
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    m = parse_exploit_output(out)
    check("exploit: STATUS 200", m["STATUS"] == "200",
          "dapat %r" % m["STATUS"])
    check("exploit: NEXT memakai skema javascript:",
          bool(m["NEXT"]) and m["NEXT"].startswith("javascript:"),
          "dapat %r" % m["NEXT"])
    check("exploit: RENDERED true", m["RENDERED"], "")
    check("exploit: MARKER == %s (JS dieksekusi browser)" % MARKER,
          m["MARKER"] == MARKER, "dapat %r" % m["MARKER"])

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine = os.path.join(LAB_DIR, "app", "app.py")
    fixed = os.path.join(LAB_DIR, "fix", "app", "app.py")
    if filecmp.cmp(pristine, fixed, shallow=False):
        log("fix/app/app.py masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    st, _ = post_login("demo", "demo123", JS_PAYLOAD)
    check("serangan referensi GAGAL: next=javascript: -> 400",
          st == 400, "dapat %s" % st)
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    rc, out, _ = run_exploit(exp)
    m = parse_exploit_output(out)
    check("serangan referensi GAGAL: tidak ada MARKER",
          m["MARKER"] != MARKER, "dapat marker=%r" % m["MARKER"])

    st, body = post_login("demo", "demo123", "/dashboard")
    check("fungsi normal: next=/dashboard tetap redirect",
          st == 200 and 'window.location.href = "/dashboard"' in body,
          "dapat %s" % st)
    st, _ = post_login("demo", "salah", "/dashboard")
    check("fungsi normal: login salah tetap 401", st == 401,
          "dapat %s" % st)
    st, _ = req(APP_PORT, "GET", "/dashboard")
    check("fungsi normal: GET /dashboard -> 200", st == 200,
          "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" %
        (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
