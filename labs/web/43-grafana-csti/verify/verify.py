#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 43.

Rantai: Grafana AngularJS client-side template injection (CVE-2021-41174,
GHSA-3j9m-hcv9-rpj8).

  1. Aplikasi merefleksikan URL yang diminta (path + query, sudah
     di-decode) ke href tautan "Masuk" pada navbar halaman publik, untuk
     dipakai sebagai tujuan kembali setelah login.
  2. Halaman publik dirender oleh mesin template sisi klien yang
     menginterpolasi binding {{ }} di seluruh DOM, termasuk nilai atribut.
  3. URL tercraft berisi ekspresi AngularJS
     {{constructor.constructor('...')()}} lolos ke konteks binding itu dan
     dieksekusi sebagai JavaScript di browser korban yang belum login.

Eksekusi JS dibuktikan dengan service `browser` (headless Chromium +
shim POST /render): exploit mem-post HTML halaman ke shim dan memeriksa
apakah document.title berubah menjadi marker. Tanpa WebSocket/CDP,
tanpa dependency di host.

Alur:
  FASE 1 (pristine): bangun lab, pastikan
      - GET / -> 200, probe {{7*7}} terefleksi utuh di href tautan Masuk
      - GET /login -> 200 (form), login salah -> 200 tanpa cookie sesi
      - login demo/demo123 -> 302 ke redirectTo + cookie; GET / bersesi
        -> 200 dasbor
      - serangan referensi (health): solutions/exploit.py -> MARKER
      - exploit/exploit.py milik learner -> STATUS 200, URL berbinding
        {{ }}, RENDERED true, MARKER == CSTI-XSS-OK
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - URL payload terefleksi dengan kurung kurawal ter-encode
        (%7B%7B / %7D%7D) di href tautan Masuk
      - serangan referensi GAGAL: tidak ada MARKER
      - fungsi normal utuh: login + redirect tetap jalan, halaman 200

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
from urllib.parse import quote, unquote, urlencode

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = "127.0.0.1"
APP_PORT, BROWSER_PORT = 8080, 8081
MARKER = "CSTI-XSS-OK"
EXPR = "{{constructor.constructor('document.title=\"%s\"')()}}" % MARKER
PAYLOAD_PATH = "/dash/" + quote(EXPR, safe="")
PROBE_PATH = "/dash/%7B%7B7*7%7D%7D"
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


def req(port, method, path, body=None, ctype=None, headers=None,
        timeout=15):
    c = HTTPConnection(HOST, port, timeout=timeout)
    try:
        hdrs = dict(headers or {})
        if body is not None:
            hdrs["Content-Type"] = ctype or "application/octet-stream"
            hdrs["Content-Length"] = str(len(body))
        c.request(method, path, body=body, headers=hdrs)
        r = c.getresponse()
        return (r.status, {k.lower(): v for k, v in r.getheaders()},
                r.read().decode("utf-8", "replace"))
    finally:
        c.close()


def post_login(username, password, rt):
    body = urlencode({"username": username, "password": password,
                      "redirectTo": rt}).encode()
    return req(APP_PORT, "POST", "/login", body,
               "application/x-www-form-urlencoded")


def render(html):
    body = json.dumps({"html": html}).encode()
    st, _, out = req(BROWSER_PORT, "POST", "/render", body,
                     "application/json", timeout=120)
    return st, out


def nav_login_href(body):
    m = re.search(r'nav-login" href="([^"]*)"', body)
    return m.group(1) if m else ""


def run_exploit(path):
    p = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, timeout=180,
                       cwd=os.path.dirname(path))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m = {}
    for key in ("STATUS", "URL", "MARKER"):
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
            st, _, body = req(APP_PORT, "GET", "/")
            if st != 200 or "Pantau" not in body:
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

    st, _, body = req(APP_PORT, "GET", "/")
    check("baseline: GET / -> 200", st == 200, "dapat %s" % st)
    st, _, body = req(APP_PORT, "GET", PROBE_PATH)
    check("baseline: probe {{7*7}} terefleksi utuh di href tautan Masuk",
          "/dash/{{7*7}}" in nav_login_href(body),
          "href=%r" % nav_login_href(body))
    st, _, body = req(APP_PORT, "GET", "/login?redirectTo=/dash")
    check("baseline: GET /login -> 200 + form",
          st == 200 and "<form" in body, "dapat %s" % st)
    st, hdrs, _ = post_login("demo", "salah", "/dash")
    check("baseline: login salah -> 200 tanpa cookie sesi",
          st == 200 and "sess=" not in hdrs.get("set-cookie", ""),
          "dapat %s" % st)
    st, hdrs, _ = post_login("demo", "demo123", "/dash")
    cookie = hdrs.get("set-cookie", "").split(";")[0]
    check("baseline: login benar -> 302 ke redirectTo + cookie sesi",
          st == 302 and hdrs.get("location") == "/dash"
          and cookie.startswith("sess="),
          "dapat %s location=%r" % (st, hdrs.get("location")))
    st, _, body = req(APP_PORT, "GET", "/",
                      headers={"Cookie": cookie})
    check("baseline: GET / bersesi -> 200 dasbor",
          st == 200 and "Dasbor utama" in body, "dapat %s" % st)

    log("== [HEALTH] serangan referensi: CSTI -> eksekusi JS ==")
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    rc, out, err = run_exploit(exp)
    m = parse_exploit_output(out)
    ok_ref = rc == 0 and m["STATUS"] == "200" and m["RENDERED"] and \
        m["MARKER"] == MARKER
    check("serangan referensi: document.title == MARKER di DOM hasil render",
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
    check("exploit: URL membawa binding {{ }}",
          bool(m["URL"]) and "{{" in unquote(m["URL"]),
          "dapat %r" % m["URL"])
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

    st, _, body = req(APP_PORT, "GET", PAYLOAD_PATH)
    href = nav_login_href(body)
    check("fix: payload terefleksi ter-encode (%7B%7B) di href tautan Masuk",
          "%7B%7B" in href and "{{" not in href, "href=%r" % href)
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    rc, out, _ = run_exploit(exp)
    m = parse_exploit_output(out)
    check("serangan referensi GAGAL: tidak ada MARKER",
          m["MARKER"] != MARKER, "dapat marker=%r" % m["MARKER"])

    st, hdrs, _ = post_login("demo", "demo123", "/dash")
    cookie = hdrs.get("set-cookie", "").split(";")[0]
    check("fungsi normal: login benar -> 302 ke redirectTo",
          st == 302 and hdrs.get("location") == "/dash",
          "dapat %s" % st)
    st, _, body = req(APP_PORT, "GET", "/",
                      headers={"Cookie": cookie})
    check("fungsi normal: GET / bersesi -> 200 dasbor",
          st == 200 and "Dasbor utama" in body, "dapat %s" % st)
    st, _, _ = post_login("demo", "salah", "/dash")
    check("fungsi normal: login salah tetap 200 tanpa sesi",
          st == 200, "dapat %s" % st)
    st, _, _ = req(APP_PORT, "GET", "/")
    check("fungsi normal: GET / -> 200", st == 200, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" %
        (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
