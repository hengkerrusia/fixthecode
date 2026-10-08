#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 18.

Rantai: username Basic auth (ter-decode dari base64) -> ditulis mentah
ke access log ala morgan -> CRLF injection -> baris log palsu (log
forging), ala morgan CVE-2026-5078 (GHSA-4vj7-5mj6-jm8m, fixed di
1.11.0).

  Portal mencatat setiap request dengan format `IP - user "METHOD
  path" status size`. Username dari header Authorization ditulis tanpa
  netralisasi karakter kontrol, sehingga satu request dapat melahirkan
  banyak baris log — termasuk baris palsu yang mengklaim admin sukses.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / -> 200; GET /admin tanpa auth -> 401; /logs satu baris
        per request
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 401 dan FORGED: <marker>; baris palsu berisi marker
        dan klaim 200 teramati di /logs
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 401 dan FORGED: <marker>; verifier membaca /logs dan
        memastikan baris palsu dengan marker learner ada
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - serangan referensi TIDAK menambah baris palsu: satu request =
        satu baris log tepat
      - fungsi normal utuh: GET /, login valid, /logs

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/app/app.py identik byte-per-byte dengan app/app.py
    -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import base64
import filecmp
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
HEALTH_MARKER = "health18"
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


def get(path, headers=None, timeout=10):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read().decode("latin-1", "replace")
    finally:
        c.close()


def basic(user, pwd):
    creds = base64.b64encode(("%s:%s" % (user, pwd)).encode("latin-1"))
    return "Basic " + creds.decode("latin-1")


def forged_user(marker):
    return 'x\r\n127.0.0.1 - admin "GET /admin" 200 99 "%s"\r\n' % marker


def get_logs():
    st, body = get("/logs")
    assert st == 200, "GET /logs -> %s" % st
    return [ln for ln in body.strip().split("\n") if ln]


def forged_line(lines, marker):
    pat = re.compile(
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - admin "GET /admin" 200.*'
        + re.escape(marker))
    return any(pat.search(ln) for ln in lines)


def reference_attack():
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_forged = re.search(r"^FORGED:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_forged.group(1) if m_forged else None))


def valid_marker(m):
    return bool(m) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", m)


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

    st, _ = get("/")
    check("baseline: GET / -> 200", st == 200, "dapat %s" % st)
    st, _ = get("/admin")
    check("fungsi normal: GET /admin tanpa auth -> 401", st == 401,
          "dapat %s" % st)
    # get_logs() sendiri menambah 1 baris yang baru terlihat di panggilan
    # berikutnya; jadi delta 2 = 1 request biasa + 1 get_logs.
    n0 = len(get_logs())
    st, _ = get("/")
    n1 = len(get_logs())
    check("baseline: satu baris per request di log", st == 200 and n1 - n0 == 2,
          "dapat +%d baris" % (n1 - n0))

    log("== [HEALTH] serangan referensi: CRLF di username -> log forging ==")
    rc, out, err = reference_attack()
    status, forged = parse_exploit_output(out)
    ok_ref = (rc == 0 and status == "401" and valid_marker(forged)
              and forged_line(get_logs(), forged))
    check("serangan referensi: STATUS 401 + baris palsu di log",
          ok_ref, "dapat rc=%s status=%r forged=%r" % (rc, status, forged))
    if not ok_ref:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        log("stderr: %s" % (err[-1500:] if err else "-"))
        compose_down()
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
    status, forged = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 401", status == "401",
          "dapat %r" % status)
    check("exploit mencetak FORGED (alfanumerik)", valid_marker(forged),
          "dapat %r" % forged)
    ok_forged = valid_marker(forged) and forged_line(get_logs(), forged)
    check("FORGED terbukti: baris palsu dengan marker di log",
          ok_forged, "dapat terbukti=%s" % ok_forged)

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

    n0 = len(get_logs())
    st, _ = get("/admin",
                headers={"Authorization": basic(forged_user(HEALTH_MARKER),
                                                "wrong")})
    lines = get_logs()
    # Delta 2 = 1 request penyerang + 1 get_logs; bila injeksi lolos,
    # deltanya 4 (3 baris dari 1 request + 1 get_logs).
    check("serangan referensi GAGAL: 401 dan satu baris per request",
          st == 401 and len(lines) - n0 == 2,
          "dapat %s, +%d baris" % (st, len(lines) - n0))
    check("serangan referensi GAGAL: tidak ada baris palsu",
          not forged_line(lines, HEALTH_MARKER),
          "dapat bersih=%s" % (not forged_line(lines, HEALTH_MARKER)))

    st, _ = get("/")
    check("fungsi normal: GET / -> 200", st == 200, "dapat %s" % st)
    st, _ = get("/admin",
                headers={"Authorization": basic("admin", "s3cr3t!")})
    check("fungsi normal: login valid -> 200", st == 200, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
