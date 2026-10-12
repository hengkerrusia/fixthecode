#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 22 (CVE-2023-3452, Canto RFI).

Rantai: GET /includes/lib/get.php dengan parameter wp_abspath.
Server membangun path include langsung dari input tanpa validasi
("<wp_abspath>/wp-admin/admin.php"), dan PHP berjalan dengan
allow_url_include=On sehingga wrapper URL seperti data:// dieksekusi
sebagai kode PHP — remote file inclusion satu request menjadi RCE.
Pelajaran inti dari temuan Marco Wotschka / Wordfence (2023).

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / -> 200 halaman depan;
        GET /includes/lib/get.php -> 200 halaman normal
        ("Canto Media Library", tanpa marker).
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 200 dan MARKER: CANTO-RFI-RCE-OK;
        gagal di sini = lab rusak, bukan learner gagal.
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 dan MARKER: CANTO-RFI-RCE-OK.
  FASE 2 (dengan fix/): bangun ulang dengan fix/includes/lib/get.php,
      pastikan
      - serangan referensi GAGAL: marker tidak muncul di respons
        (fix mengabaikan wp_abspath sehingga include selalu lokal).
      - fungsi normal utuh: GET / dan GET /includes/lib/get.php
        tetap 200 dengan halaman normal.

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/includes/lib/get.php identik byte-per-byte
    dengan app/includes/lib/get.php -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
MARKER = "CANTO-RFI-RCE-OK"
FIX_FILES = ["includes/lib/get.php"]
PASS, FAIL = "LULUS", "GAGAL"
results = []


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    log("  [%s] %s%s" % (PASS if ok else FAIL, name,
                         " -- " + detail if detail else ""))
    return ok


def run(cmd):
    p = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True,
                       text=True, timeout=600)
    if p.returncode != 0:
        log("perintah gagal: %s\n%s" % (" ".join(cmd), p.stderr[-2000:]))
        sys.exit(1)
    return p


def compose_base():
    return ["docker", "compose"]


def compose_fix():
    return ["docker", "compose", "-f", "docker-compose.yml",
            "-f", "docker-compose.fix.yml"]


def compose_down():
    run(compose_fix() + ["down", "--remove-orphans"])
    run(compose_base() + ["down", "--remove-orphans"])


def wait_port(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = HTTPConnection(HOST, PORT, timeout=3)
            c.request("GET", "/")
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 200:
                return True
        except OSError:
            time.sleep(2)
    return False


def get(path, timeout=30):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def reference_attack():
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def learner_exploit():
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_marker = re.search(r"^MARKER:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_marker.group(1) if m_marker else None))


def baseline_checks(label):
    ok = True
    s, body = get("/")
    ok &= check("%s: GET / -> 200" % label, s == 200, "status=%s" % s)
    s, body = get("/includes/lib/get.php?subdomain=test")
    body = body.decode("utf-8", "replace")
    ok &= check("%s: halaman normal ter-render" % label,
                s == 200 and "Canto Media Library" in body
                and MARKER not in body, "status=%s" % s)
    s, _ = get("/includes/lib/get.php?wp_abspath=")
    ok &= check("%s: wp_abspath kosong -> 200" % label, s == 200,
                "status=%s" % s)
    return ok


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    if not os.path.isfile(exp):
        log("exploit/exploit.py belum ada.")
        sys.exit(3)
    rc, _, err = learner_exploit()
    if "NotImplementedError" in err:
        log("Fase 1 belum dikerjakan (exploit.py masih scaffold).")
        sys.exit(3)

    untouched = True
    for rel in FIX_FILES:
        a = os.path.join(LAB_DIR, "app", rel)
        b = os.path.join(LAB_DIR, "fix", rel)
        if not (os.path.isfile(a) and os.path.isfile(b)):
            untouched = False
            break
        with open(a, "rb") as fa, open(b, "rb") as fb:
            if fa.read() != fb.read():
                untouched = False
                break
    if untouched:
        log("Fase 2 belum dikerjakan (fix/* identik dengan app/*).")
        sys.exit(2)

    compose_down()

    # ---------- FASE 1: pristine ----------
    log("== FASE 1: rakitan rentan (pristine) ==")
    run(compose_base() + ["up", "--build", "-d"])
    try:
        if not wait_port():
            check("lab menyala", False, "port tidak merespons")
            sys.exit(1)
        ok = baseline_checks("baseline")

        log("[HEALTH] serangan referensi builder...")
        rc, out, err = reference_attack()
        st, mk = parse_exploit_output(out)
        ok &= check("[HEALTH] serangan referensi berhasil",
                    st == "200" and mk == MARKER,
                    "rc=%s out=%r" % (rc, out.strip()[:120]))

        log("menjalankan exploit/exploit.py milik learner...")
        rc, out, err = learner_exploit()
        st, mk = parse_exploit_output(out)
        ok &= check("exploit: STATUS 200", st == "200",
                    "out=%r" % out.strip()[:120])
        ok &= check("exploit: MARKER cocok", mk == MARKER,
                    "marker=%r" % mk)
    finally:
        compose_down()

    # ---------- FASE 2: dengan fix ----------
    log("== FASE 2: rakitan dengan fix/ ==")
    run(compose_fix() + ["up", "--build", "-d"])
    try:
        if not wait_port():
            check("lab (fix) menyala", False, "port tidak merespons")
            sys.exit(1)
        ok2 = baseline_checks("baseline+fix")

        log("[HEALTH] serangan referensi terhadap rakitan fix...")
        rc, out, err = reference_attack()
        st, mk = parse_exploit_output(out)
        attack_blocked = (mk != MARKER)
        ok2 &= check("serangan referensi digagalkan fix", attack_blocked,
                     "STATUS=%s MARKER=%r" % (st, mk))
    finally:
        compose_down()

    total = len(results)
    passed = sum(1 for _, ok_ in results if ok_)
    log("== ringkasan: %s %d/%d ==" % (PASS if passed == total else FAIL,
                                       passed, total))
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
